// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

// Create only disposable fixtures. Never contact the Okta management API.
const fs = require('node:fs');
const path = require('node:path');
const https = require('node:https');
const dns = require('node:dns').promises;
const crypto = require('node:crypto');
const {execFileSync, spawn} = require('node:child_process');
const {once} = require('node:events');
const project = path.resolve(__dirname,'../..');
const origin = 'https://test.supivpn.com:18443';
function check(ok) { if(!ok) throw Error('invalid_test_configuration'); }

function settings(env) {
  check(env.OKTA_TEST_ORIGIN===origin);
  const tenant=new URL(env.OKTA_TENANT_ORIGIN);
  check(tenant.protocol==='https:' && !tenant.username && !tenant.password && !tenant.port &&
    tenant.pathname==='/' && !tenant.search && !tenant.hash &&
    /^[a-z0-9-]+\.(okta\.com|oktapreview\.com|okta-emea\.com)$/.test(tenant.hostname));
  const metadataURL=value=>{
    const url=new URL(value);
    check(url.origin===tenant.origin && !url.username && !url.password &&
      !url.search && !url.hash && /^\/app\/[A-Za-z0-9_-]+\/sso\/saml\/metadata$/.test(url.pathname));
    return url;
  };
  const metadata=metadataURL(env.OKTA_METADATA_URL);
  const encryptedMetadata=metadataURL(env.OKTA_ENCRYPTED_METADATA_URL);
  check(metadata.href!==encryptedMetadata.href);
  check(env.OKTA_TEST_USERNAME && env.OKTA_TEST_USERNAME.length<=256 &&
    !/[\r\n\0]/.test(env.OKTA_TEST_USERNAME));
  check(env.OKTA_TEST_PASSWORD && env.OKTA_TEST_PASSWORD.length<=1024);
  for (const name of ['OKTA_TEST_ALLOWED_GROUP','OKTA_TEST_DENIED_GROUP'])
    check(/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(env[name]||''));
  check(env.OKTA_TEST_ALLOWED_GROUP!==env.OKTA_TEST_DENIED_GROUP);
  check(!env.DEBUG && !env.PWDEBUG && !env.NODE_OPTIONS && !env.NODE_TLS_REJECT_UNAUTHORIZED);
  const port=Number(env.OKTA_TEST_DB_PORT||'55432');
  check(Number.isInteger(port) && port>=1024 && port<=65535);
  return {metadata, encryptedMetadata, port};
}
function childEnvironment(env) {
  const clean={...env};
  delete clean.OKTA_TEST_PASSWORD;
  delete clean.OKTA_ENCRYPTION_PRIVATE_KEY;
  return clean;
}
function assertionFormat(data,encrypted) {
  // Wire-format evidence only. The production Go parser verifies XML structure,
  // decryption, every present signature and claims before authorizing a profile.
  check(Buffer.isBuffer(data) && data.length>0 && data.length<=1048576);
  const xml=data.toString('utf8');
  const count=name=>(xml.match(new RegExp('<(?:[A-Za-z0-9_]+:)?'+name+'[\\s>]','g'))||[]).length;
  if(!encrypted) {
    check(count('Assertion')===1 && count('EncryptedAssertion')===0);
    return;
  }
  check(count('EncryptedAssertion')===1 && count('Assertion')===0 && count('EncryptedData')===1 && count('EncryptedKey')===1);
  const algorithms=[...xml.matchAll(/<(?:[A-Za-z0-9_]+:)?EncryptionMethod\b[^>]*\bAlgorithm=["']([^"']+)["']/g)].map(m=>m[1]);
  check(algorithms.length===2 && algorithms.includes('http://www.w3.org/2009/xmlenc11#aes256-gcm') &&
    algorithms.includes('http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p'));
}
function command(exe,args,root) {
  const env=childEnvironment(process.env);
  try {execFileSync(exe,args,{cwd:root,env,stdio:'ignore',timeout:60000});}
  catch {throw Error('fixture_preparation_failed');}
}
function recipient(root,env) {
  // This dedicated test key is provisioned once in the encrypted Okta app.
  // Never send an admin token to the runner to rotate app settings per run.
  let material;
  try {
    check(typeof env.OKTA_ENCRYPTION_CERTIFICATE==='string' && env.OKTA_ENCRYPTION_CERTIFICATE.length<=16384);
    check(typeof env.OKTA_ENCRYPTION_PRIVATE_KEY==='string' && env.OKTA_ENCRYPTION_PRIVATE_KEY.length<=16384);
    const pem=(value,type)=>{
      const match=/^-----BEGIN ([A-Z ]+)-----\r?\n[A-Za-z0-9+/=\r\n]+-----END \1-----\s*$/.exec(value);
      check(match && match[1]===type);
    };
    pem(env.OKTA_ENCRYPTION_CERTIFICATE,'CERTIFICATE');
    pem(env.OKTA_ENCRYPTION_PRIVATE_KEY,'PRIVATE KEY');
    material=Buffer.from(env.OKTA_ENCRYPTION_PRIVATE_KEY);
    const cert=new crypto.X509Certificate(env.OKTA_ENCRYPTION_CERTIFICATE);
    const key=crypto.createPrivateKey(material);
    check(key.asymmetricKeyType==='rsa' && key.asymmetricKeyDetails.modulusLength>=2048 &&
      key.asymmetricKeyDetails.modulusLength<=8192 && cert.checkPrivateKey(key) && !cert.ca);
    check(Date.parse(cert.validFrom)<=Date.now() && Date.parse(cert.validTo)>Date.now()+7*86400000);
    fs.writeFileSync(path.join(root,'encrypted-saml.crt'),env.OKTA_ENCRYPTION_CERTIFICATE,{mode:0o600,flag:'wx'});
    fs.writeFileSync(path.join(root,'encrypted-saml.key'),material,{mode:0o600,flag:'wx'});
  } catch {throw Error('invalid_encryption_fixture');}
  finally {if(material)material.fill(0);}
}
function certificates(root) {
  const req=(name,extra)=>command('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-days','1',
    '-keyout',name+'.key','-out',name+'.crt','-subj','/CN=SupiVPN temporary '+name,...extra],root);
  req('ca',['-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign']);
  req('saml',['-addext','basicConstraints=critical,CA:FALSE','-addext','keyUsage=critical,keyEncipherment']);
  command('openssl',['req','-new','-newkey','rsa:2048','-nodes','-keyout','server.key','-out','server.csr',
    '-subj','/CN=test.supivpn.com'],root);
  fs.writeFileSync(path.join(root,'server.ext'),
    'subjectAltName=DNS:test.supivpn.com\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n',{mode:0o600});
  command('openssl',['x509','-req','-in','server.csr','-CA','ca.crt','-CAkey','ca.key','-CAcreateserial',
    '-days','1','-extfile','server.ext','-out','server.crt'],root);
}
function metadata(url) {
  return new Promise((resolve,reject)=>{
    const req=https.get(url,{timeout:15000},res=>{
      if(res.statusCode!==200){res.resume();reject(Error('metadata_unavailable'));return;}
      const chunks=[];let size=0;
      res.on('data',chunk=>{size+=chunk.length;if(size>1048576){req.destroy(Error('metadata_too_large'));return;}chunks.push(chunk);});
      res.on('end',()=>resolve(Buffer.concat(chunks)));
      res.on('error',()=>reject(Error('metadata_unavailable')));
    });
    req.on('error',()=>reject(Error('metadata_unavailable')));
    req.on('timeout',()=>req.destroy(Error('metadata_timeout')));
  });
}
async function main() {
  process.umask(0o077);
  let root,child,stage='configuration';
  try {
    const config=settings(process.env);
    // The callback must stay on this runner. No public listener or DNS mutation.
    const addresses=await dns.lookup('test.supivpn.com',{all:true});
    check(addresses.length && addresses.every(a=>a.address==='127.0.0.1'));
    const parent=path.join(project,'local/okta-ci');
    fs.mkdirSync(parent,{recursive:true,mode:0o700});
    root=fs.mkdtempSync(path.join(parent,'run-'));
    fs.chmodSync(root,0o700);
    stage='ephemeral_tls';
    certificates(root);
    stage='encryption_recipient';
    recipient(root,process.env);
    delete process.env.OKTA_ENCRYPTION_PRIVATE_KEY;
    stage='public_idp_metadata';
    fs.writeFileSync(path.join(root,'idp-metadata.xml'),await metadata(config.metadata),{mode:0o600});
    fs.writeFileSync(path.join(root,'encrypted-idp-metadata.xml'),await metadata(config.encryptedMetadata),{mode:0o600});
    stage='browser_acceptance';
    child=spawn(process.execPath,[path.join(__dirname,'profile.cjs'),root],{
      cwd:project,stdio:['ignore','inherit','inherit'],
      env:{...process.env,NODE_EXTRA_CA_CERTS:path.join(root,'ca.crt')}
    });
    const [code,signal]=await once(child,'exit');
    if(code!==0 || signal)throw Error('acceptance_failed');
  } catch {
    console.error(JSON.stringify({passed:false,stage,raw_diagnostics_withheld:true}));
    process.exitCode=1;
  } finally {
    if(child && child.exitCode===null && child.signalCode===null)child.kill('SIGTERM');
    if(root)fs.rmSync(root,{recursive:true,force:false});
  }
}
module.exports={settings,certificates,recipient,childEnvironment,assertionFormat};
if(require.main===module)main();
