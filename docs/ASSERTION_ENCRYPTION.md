# SAML assertion encryption

Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
See [LICENSE](../LICENSE) for copyright ownership and licensing terms.

**Availability:** supported since
[v0.7.0](https://github.com/SupiVPN/supivpn/releases/tag/v0.7.0).
Upgrade from v0.6.1 or earlier before adding its configuration.

Encryption hides assertion contents from the browser and intermediaries that
terminate HTTPS before the controller. It does not replace HTTPS, IdP signatures,
access policy or replay protection. The controller sees the plaintext after
decryption; keep request-body logging and tracing disabled.

## Modes

| `assertion_encryption.mode` | Plaintext assertion | Encrypted assertion |
| --- | --- | --- |
| `disabled` (default, including an omitted block) | Accepted after normal verification | Rejected |
| `optional` | Accepted after normal verification | Decrypted, then verified |
| `required` | Rejected | Decrypted, then verified |

Every accepted assertion must be authenticated by a trusted IdP signature on
the Response, the Assertion, or both, as before. Every present signature must
verify. Prefer signing both in the IdP. An outer signature is verified over the
original ciphertext before decryption; an inner signature is verified after
decryption. Encryption without either signature is rejected.

Issuer, audience, recipient, request ID, bearer confirmation, validity,
browser binding, group selection and one-use PostgreSQL state remain mandatory.
Both VPN login and profile download use the same policy. Mixing plaintext and
encrypted assertions in one response is rejected.

## Controller configuration

Add this block to the controller JSON, for example
`/etc/supivpn/controller/controller.json` on Debian:

```json
{
  "assertion_encryption": {
    "mode": "optional",
    "certificate_file": "/etc/supivpn/controller/saml-encryption.crt",
    "private_key_file": "/etc/supivpn/controller/saml-encryption.key"
  }
}
```

Merge the block into the existing configuration; it is not a complete controller
configuration. The setup-helper leaves encryption disabled. Apply this setting
during [post-setup customization](../DEPLOYMENT.md#customize-the-generated-configuration).
The remote node agent does not need this key or block. A legacy embedded
controller accepts the same block in its agent configuration.

Use a **dedicated RSA key**, separate from HTTPS, IdP signing, GPG and OpenVPN
wrapping keys. The matching X.509 certificate must be within its validity period;
if it has KeyUsage, it must allow keyEncipherment. RSA 2048–8192 is accepted;
3072 bits is a reasonable starting point.

The certificate file contains one PEM certificate; the private key contains
one unencrypted PKCS#8 or PKCS#1 RSA PEM block. The service must be able to read
them at startup without an interactive prompt. Keep private keys out of JSON,
source control, images, ZIPs, logs and support bundles. Files must be regular
files, not symlinks, and not writable by group/others. Private-key permissions
may be `0600` or `0640` (read-only equivalents are also accepted).

For a new Debian deployment, provision a key without overwriting existing files.
Run the following as root only when both paths are unused:

```bash
set -e
test ! -e /etc/supivpn/controller/saml-encryption.key
test ! -e /etc/supivpn/controller/saml-encryption.crt
umask 077
openssl req -x509 -newkey rsa:3072 -noenc -days 365 \
  -keyout /etc/supivpn/controller/saml-encryption.key \
  -out /etc/supivpn/controller/saml-encryption.crt \
  -subj '/CN=SupiVPN assertion encryption' \
  -addext 'basicConstraints=critical,CA:FALSE' \
  -addext 'keyUsage=critical,keyEncipherment'
chown root:supivpn-controller /etc/supivpn/controller/saml-encryption.{key,crt}
chmod 0640 /etc/supivpn/controller/saml-encryption.{key,crt}
```

Use a root shell with `set -e` so a failed precondition stops the sequence.
A public CA certificate is not required: the IdP pins the uploaded public key.
The process loads the files once at startup; restart after provisioning changes.
Invalid modes, missing or mismatched files, unsafe permissions and invalid
certificates fail startup. Certificate expiry also stops encrypted logins.

## Public Lambda: Secrets Manager

Secrets Manager delivery requires **v0.7.1 or later**; v0.7.0 only supports files.
VM and Lambda share the same PEM, certificate and decryption validation.
For public Lambda, replace `private_key_file` with `private_key_secret_arn`:

```json
{
  "assertion_encryption": {
    "mode": "required",
    "certificate_file": "/opt/saml-encryption.crt",
    "private_key_secret_arn": "arn:aws:secretsmanager:eu-west-1:123456789012:secret:saml-recipient-Ab12Cd"
  }
}
```

Merge this block into the public controller configuration. Use the **complete
ARN**, including the generated six-character suffix. The adapter selects the
secret's region from the ARN. Exactly one private-key source is allowed.
The certificate is public and may be delivered in a Lambda layer at the path
above. Never include the private key in a layer, ZIP, image or environment value.

Provision a dedicated secret through your existing secure deployment process.
Its **SecretString must be the raw, multiline PEM**, containing one unencrypted
PKCS#8 or PKCS#1 RSA private key (at most 64 KiB). JSON key/value wrappers,
base64-wrapped strings and SecretBinary are not accepted. Do not reuse the
database credential or OpenVPN wrapping-key secret.

Only the **public execution role** needs `secretsmanager:GetSecretValue` on the
exact secret ARN. With a customer-managed KMS key, also grant `kms:Decrypt` on
that exact key, with the corresponding key policy and Secrets Manager service
conditions. Agent and recovery roles must not receive these grants or the SAML
configuration. The runtime does not need create, update, list or rotation rights.
See [AWS GetSecretValue permissions](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html)
and [Lambda isolation](LAMBDA_ISOLATION.md).

The public function reads **AWSCURRENT once during initialization**, with a
five-second load budget inside the existing 20-second initialization deadline
and at most two SDK request attempts. Keep a reachable Secrets Manager endpoint
(for example a VPC interface endpoint) when the function runs in a VPC.
The parsed key stays in memory; it is never written to `/tmp`. Caller-owned PEM
buffers are cleared after parsing, but this is not a guarantee that Go or SDK
memory contains no residual copies. An unavailable secret, invalid payload,
certificate mismatch or expired certificate fails initialization with a generic
error. There is no fallback to a file, plaintext policy or previous secret version.

Warm execution environments retain their initialized key. Updating AWSCURRENT
does **not** reload them. Coordinate a new Lambda version/deployment, certificate
and IdP change, and retire old environments; do not rotate only the secret label.
The single-key rotation limitations below apply to Lambda as well as VM.

## IdP configuration and rollout

1. Deploy the key and `optional` configuration on **every** controller replica.
   Restart them and verify ordinary login and profile download.
2. Fetch `<public_url>/saml/metadata`. It now contains a
   `KeyDescriptor use="encryption"` with the public certificate and the supported
   AES-GCM algorithms. It contains no private material.
3. Import that metadata or upload **only the public certificate** in the IdP's
   encryption settings. Retain RSA-SHA256/SHA256 signatures. Choose AES-256-GCM
   (or AES-128-GCM) and RSA-OAEP; do not select CBC or RSA v1.5.
4. Test a new VPN login, a new profile download and a user without an allowed
   group. IdP algorithm names differ: verify the emitted XML algorithms against
   the supported list below. A provider's encryption checkbox alone is not
   evidence of AES-GCM support.
5. Switch every controller to `required`, restart, and test again. A plaintext
   response must now fail. This is the enforcement step; `optional` deliberately
   still permits plaintext.

For rollback, switch controllers to `optional` **before** disabling encryption
in the IdP. To return to `disabled`, remove the certificate and private-key
file/secret settings as well.
Do not silently relax `required` in response to a login error.

All replicas need the same intended mode and recipient key. Only one recipient
key is loaded per process; overlapping decryption keys and automatic rotation
are not implemented. Plan a coordinated rotation or a controlled transition
through `optional` with the temporary loss of the encryption guarantee made
explicit. Back up and protect the key using the deployment's secret procedures.
Renew the certificate before expiry.

## Accepted XML Encryption subset

- Exactly one SAML `EncryptedAssertion` containing one `EncryptedData` with
  `Type="http://www.w3.org/2001/04/xmlenc#Element"`.
- AES-GCM URIs:
  `http://www.w3.org/2009/xmlenc11#aes128-gcm` and
  `http://www.w3.org/2009/xmlenc11#aes256-gcm`.
  A 12-byte nonce precedes ciphertext and a 16-byte authentication tag.
- One inline `EncryptedKey` under `EncryptedData/ds:KeyInfo`, or one immediate
  sibling `EncryptedKey` inside the same `EncryptedAssertion` (Okta's layout).
  The sibling layout requires exactly one `ds:RetrievalMethod` in the data's
  KeyInfo, with Type `http://www.w3.org/2001/04/xmlenc#EncryptedKey` and URI
  exactly `#<sibling-key-Id>`. Its reverse ReferenceList must contain exactly one
  DataReference targeting `#<EncryptedData-Id>`. No transforms or wider key lookup
  are performed; mixed inline/sibling keys and ambiguous references fail.
  An optional Recipient must equal the SP Entity ID. For inline keys, an optional
  DataReference must likewise target the same EncryptedData ID.
- RSA-OAEP: XML Encryption 1.1
  `http://www.w3.org/2009/xmlenc11#rsa-oaep` with SHA-1 or SHA-256 for the
  OAEP digest and MGF1, or the XML Encryption 1.0
  `http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p` with its fixed MGF1-SHA1.
  Omitted OAEP digest/MGF parameters use the standard SHA-1 defaults.
  These defaults concern key wrapping only: **SHA-1 XML signatures remain rejected**.
  Prefer explicit SHA-256 digest and MGF1-SHA256 when the IdP supports them.
- Optional OAEP label: empty or at most 64 decoded bytes.
- No CBC, RSA PKCS#1 v1.5 key transport, CipherReference, external or transformed
  RetrievalMethod, keys outside the current EncryptedAssertion, EncryptedID or
  encrypted attributes. Unknown algorithms or structures fail without fallback.

The existing 1 MiB XML limit applies to the encrypted response and separately to
decrypted XML; base64/encryption overhead reduces the usable assertion size.
Depth, element, attribute, namespace and duplicate-ID checks also apply after
decryption. IDs cannot collide across the outer and decrypted documents.
Authentication failures remain generic and reveal no key, ciphertext or assertion.

## Verification

`make test` covers modes, metadata, key loading, malformed ciphertext,
authentication tags, unsupported algorithms, signatures and wrapping attacks.
It also checks Secrets Manager requests and failures with a mock client, plus
decryption and mode enforcement with synthetic keys delivered by a loader.
These tests do not establish deployed IAM/KMS or VPC endpoint connectivity;
verify public startup, metadata and encrypted login/profile issuance in the
target deployment, along with denied secret access for agent/recovery roles.
`make test-xmlsec` uses independent XMLSec encryption/signing plus OpenSSL for
OAEP-SHA256/MGF1-SHA256 (Debian's XMLSec lacks that XML Encryption 1.1 URI).
`make integration` covers encrypted profile downloads and replay/group/browser
binding across PostgreSQL-backed controllers, and VM/Lambda adapter flows.
Signed-claim fuzzing includes encrypted responses.

[Real Okta acceptance](OKTA_TESTS.md) exercises AES-256-GCM with RSA-OAEP,
including the sibling-key layout, successful profile issuance in optional and
required modes, and wrong-key/plaintext-policy rejection. The runner checks
the actual encrypted wire format to prevent a silent plaintext fallback.

Synthetic interoperability does not establish that every IdP emits this subset.
Test the configured real IdP before requiring encryption.
