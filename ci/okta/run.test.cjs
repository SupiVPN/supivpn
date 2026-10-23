// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const https=require('node:https');
const {execFileSync}=require('node:child_process');
const {once}=require('node:events');
const {settings,certificates,recipient,childEnvironment,assertionFormat}=require('./run.cjs');
const base={
 OKTA_TEST_ORIGIN:'https://test.supivpn.com:18443',
 OKTA_TENANT_ORIGIN:'https://integrator-example.okta.com',
 OKTA_METADATA_URL:'https://integrator-example.okta.com/app/example/sso/saml/metadata',
 OKTA_ENCRYPTED_METADATA_URL:'https://integrator-example.okta.com/app/encrypted/sso/saml/metadata',
 OKTA_TEST_USERNAME:'synthetic-user',
 OKTA_TEST_PASSWORD:'synthetic-password',
 OKTA_TEST_ALLOWED_GROUP:'users-vpn',OKTA_TEST_DENIED_GROUP:'empty-vpn',
};
test('only the intended loopback app and tenant receive browser credentials',()=>{
 assert.doesNotThrow(()=>settings(base));
 for(const change of [
  {OKTA_TEST_ORIGIN:'https://public.example.test:18443'},
  {OKTA_TENANT_ORIGIN:'http://integrator-example.okta.com'},
  {OKTA_TENANT_ORIGIN:'https://okta.com.attacker.example.test'},
  {OKTA_TENANT_ORIGIN:'https://user@integrator-example.okta.com'},
  {OKTA_METADATA_URL:'https://other.okta.com/app/example/sso/saml/metadata'},
  {OKTA_METADATA_URL:'https://integrator-example.okta.com/api/v1/users'},
  {OKTA_METADATA_URL:'https://integrator-example.okta.com/app/example/sso/saml/metadata?token=synthetic'},
  {OKTA_ENCRYPTED_METADATA_URL:base.OKTA_METADATA_URL},
  {OKTA_ENCRYPTED_METADATA_URL:'https://other.okta.com/app/encrypted/sso/saml/metadata'},
  {OKTA_ENCRYPTED_METADATA_URL:''},
  {OKTA_TEST_PASSWORD:''}, {OKTA_TEST_ALLOWED_GROUP:'empty-vpn'},
  {OKTA_TEST_DB_PORT:'5432;invalid'}, {DEBUG:'pw:*'}, {PWDEBUG:'1'},
  {NODE_OPTIONS:'--inspect'},{NODE_TLS_REJECT_UNAUTHORIZED:'0'},
 ])assert.throws(()=>settings({...base,...change}));
});
test('wire evidence refuses plaintext fallback, mixed assertions and unsupported algorithms',()=>{
 const plaintext=Buffer.from('<saml:Response><saml:Assertion /></saml:Response>');
 const encrypted=Buffer.from('<saml:Response><saml:EncryptedAssertion><xenc:EncryptedData>'+
  '<xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"/>'+
  '<xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/>'+
  '</xenc:EncryptedKey></xenc:EncryptedData></saml:EncryptedAssertion></saml:Response>');
 assert.doesNotThrow(()=>assertionFormat(plaintext,false));
 assert.doesNotThrow(()=>assertionFormat(encrypted,true));
 assert.throws(()=>assertionFormat(plaintext,true));
 assert.throws(()=>assertionFormat(encrypted,false));
 assert.throws(()=>assertionFormat(Buffer.concat([plaintext,encrypted]),true));
 for(const [from,to] of [['aes256-gcm','aes256-cbc'],['rsa-oaep-mgf1p','rsa-1_5']])
  assert.throws(()=>assertionFormat(Buffer.from(encrypted.toString().replace(from,to)),true));
});
test('only matching, current test recipient material is written, with private permissions',()=>{
 const oldMask=process.umask(0o077);
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'supivpn-ci-recipient-'));
 const command=args=>execFileSync('openssl',args,{cwd:root,stdio:'ignore'});
 try {
  command(['req','-x509','-newkey','rsa:2048','-nodes','-days','30','-subj','/CN=synthetic-recipient',
   '-keyout','source.key','-out','source.crt','-addext','basicConstraints=critical,CA:FALSE',
   '-addext','keyUsage=critical,keyEncipherment']);
  command(['genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:2048','-out','wrong.key']);
  const env={OKTA_ENCRYPTION_CERTIFICATE:fs.readFileSync(path.join(root,'source.crt'),'utf8'),
   OKTA_ENCRYPTION_PRIVATE_KEY:fs.readFileSync(path.join(root,'source.key'),'utf8')};
  assert.throws(()=>recipient(root,{...env,OKTA_ENCRYPTION_PRIVATE_KEY:fs.readFileSync(path.join(root,'wrong.key'),'utf8')}),/invalid_encryption_fixture/);
  assert.throws(()=>recipient(root,{...env,OKTA_ENCRYPTION_PRIVATE_KEY:''}),/invalid_encryption_fixture/);
  assert.throws(()=>recipient(root,{...env,OKTA_ENCRYPTION_PRIVATE_KEY:env.OKTA_ENCRYPTION_PRIVATE_KEY+env.OKTA_ENCRYPTION_PRIVATE_KEY}),/invalid_encryption_fixture/);
  assert.throws(()=>recipient(root,{...env,OKTA_ENCRYPTION_PRIVATE_KEY:env.OKTA_ENCRYPTION_CERTIFICATE}),/invalid_encryption_fixture/);
  recipient(root,env);
  assert.equal(fs.statSync(path.join(root,'encrypted-saml.key')).mode&0o777,0o600);
  assert.throws(()=>recipient(root,env),/invalid_encryption_fixture/);
  const clean=childEnvironment({...env,OKTA_TEST_PASSWORD:'synthetic',PATH:'/synthetic'});
  assert.equal(Object.hasOwn(clean,'OKTA_TEST_PASSWORD'),false);
  assert.equal(Object.hasOwn(clean,'OKTA_ENCRYPTION_PRIVATE_KEY'),false);
  assert.equal(clean.PATH,'/synthetic');
  command(['req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=synthetic-expiring',
   '-keyout','short.key','-out','short.crt','-addext','basicConstraints=critical,CA:FALSE']);
  assert.throws(()=>recipient(root,{OKTA_ENCRYPTION_CERTIFICATE:fs.readFileSync(path.join(root,'short.crt'),'utf8'),
   OKTA_ENCRYPTION_PRIVATE_KEY:fs.readFileSync(path.join(root,'short.key'),'utf8')}),/invalid_encryption_fixture/);
 } finally {
  fs.rmSync(root,{recursive:true,force:false});
  process.umask(oldMask);
 }
});
test('temporary CA is required and hostname validation remains active',async()=>{
 const oldMask=process.umask(0o077);
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'supivpn-ci-tls-'));
 let server;
 try {
  certificates(root);
  const key=fs.readFileSync(path.join(root,'server.key'));
  const cert=fs.readFileSync(path.join(root,'server.crt'));
  const ca=fs.readFileSync(path.join(root,'ca.crt'));
  for(const name of ['server.key','ca.key','saml.key'])
   assert.equal(fs.statSync(path.join(root,name)).mode&0o077,0);
  server=https.createServer({key,cert},(_req,res)=>res.end('ok'));
  server.listen(0,'127.0.0.1');await once(server,'listening');
  const get=(servername,trust)=>new Promise((resolve,reject)=>{
   const req=https.get({hostname:'127.0.0.1',port:server.address().port,servername,ca:trust,timeout:5000},res=>{
    res.resume();res.on('end',()=>resolve(res.statusCode));
   });
   req.on('error',reject);req.on('timeout',()=>req.destroy(Error('timeout')));
  });
  assert.equal(await get('test.supivpn.com',ca),200);
  await assert.rejects(get('test.supivpn.com',undefined));
  await assert.rejects(get('wrong.example.test',ca));
 } finally {
  if(server)await new Promise(resolve=>server.close(resolve));
  fs.rmSync(root,{recursive:true,force:false});
  process.umask(oldMask);
 }
});
