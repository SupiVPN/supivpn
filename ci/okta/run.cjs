// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

// Create only disposable fixtures. Never contact the Okta management API.
const fs = require('node:fs');
const path = require('node:path');
const https = require('node:https');
const dns = require('node:dns').promises;
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
  const metadata=new URL(env.OKTA_METADATA_URL);
  check(metadata.origin===tenant.origin && !metadata.username && !metadata.password &&
    !metadata.search && !metadata.hash && metadata.pathname.endsWith('/sso/saml/metadata'));
  check(env.OKTA_TEST_USERNAME && env.OKTA_TEST_USERNAME.length<=256 &&
    !/[\r\n\0]/.test(env.OKTA_TEST_USERNAME));
  check(env.OKTA_TEST_PASSWORD && env.OKTA_TEST_PASSWORD.length<=1024);
  for (const name of ['OKTA_TEST_ALLOWED_GROUP','OKTA_TEST_DENIED_GROUP'])
    check(/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(env[name]||''));
  check(env.OKTA_TEST_ALLOWED_GROUP!==env.OKTA_TEST_DENIED_GROUP);
  check(!env.DEBUG && !env.PWDEBUG && !env.NODE_OPTIONS && !env.NODE_TLS_REJECT_UNAUTHORIZED);
  const port=Number(env.OKTA_TEST_DB_PORT||'55432');
  check(Number.isInteger(port) && port>=1024 && port<=65535);
  return {metadata, port};
}
function command(exe,args,root) {
  const env={...process.env};
  delete env.OKTA_TEST_PASSWORD;
  try {execFileSync(exe,args,{cwd:root,env,stdio:'ignore',timeout:60000});}
  catch {throw Error('fixture_preparation_failed');}
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
    stage='public_idp_metadata';
    fs.writeFileSync(path.join(root,'idp-metadata.xml'),await metadata(config.metadata),{mode:0o600});
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
module.exports={settings,certificates};
if(require.main===module)main();
