# SAML assertion encryption

Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
See [LICENSE](../LICENSE) for copyright ownership and licensing terms.

**Availability:** implemented on this development branch; not included in v0.6.1.
Install a release containing this feature before adding its configuration.

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

VM and Lambda share the decryption implementation. For Lambda, the deployment
must securely provision readable private files before runtime initialization;
this change does not add a Secrets Manager loader for the SAML key. Never place
the key in the Lambda package or environment JSON. Only the public component
needs it; agent and recovery components must not receive it.

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
in the IdP. To return to `disabled`, remove both key-file settings as well.
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
