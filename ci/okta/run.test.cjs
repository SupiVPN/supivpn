// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const https=require('node:https');
const {once}=require('node:events');
const {settings,certificates}=require('./run.cjs');
const base={
 OKTA_TEST_ORIGIN:'https://test.supivpn.com:18443',
 OKTA_TENANT_ORIGIN:'https://integrator-example.okta.com',
 OKTA_METADATA_URL:'https://integrator-example.okta.com/app/example/sso/saml/metadata',
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
  {OKTA_TEST_PASSWORD:''}, {OKTA_TEST_ALLOWED_GROUP:'empty-vpn'},
  {OKTA_TEST_DB_PORT:'5432;invalid'}, {DEBUG:'pw:*'}, {PWDEBUG:'1'},
  {NODE_OPTIONS:'--inspect'},{NODE_TLS_REJECT_UNAUTHORIZED:'0'},
 ])assert.throws(()=>settings({...base,...change}));
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
