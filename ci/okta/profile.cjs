// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

// Real Okta -> production controller + disposable PostgreSQL -> browser .ovpn.
// Never print credentials, request bodies, cookies, profiles or raw exceptions.
const fs = require('node:fs');
const path = require('node:path');
const https = require('node:https');
const crypto = require('node:crypto');
const {spawn, execFileSync} = require('node:child_process');
const {once} = require('node:events');
const {assertionFormat,childEnvironment:sanitizedEnvironment} = require('./run.cjs');
const project = path.resolve(__dirname, '../..');
const {firefox, request} = require(path.join(project,'local/okta-ci/node_modules/playwright'));
const root = process.argv[2];
const origin = process.env.OKTA_TEST_ORIGIN;
const tenant = process.env.OKTA_TENANT_ORIGIN;
const login = process.env.OKTA_TEST_USERNAME;
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
process.umask(0o077);

let phase='initialization', failure='external_tool_or_network';
function check(ok, code) { if (!ok) {failure=code;throw Error(code);} }
function command(exe, args, options={}) {
  try { return execFileSync(exe,args,{cwd:project,encoding:'utf8',stdio:['ignore','pipe','pipe'],timeout:120000,env:childEnvironment(),...options}); }
  catch { failure='local_command_failed';throw Error(failure); }
}
function password() {
  check(process.env.OKTA_TEST_PASSWORD && process.env.OKTA_TEST_PASSWORD.length<=1024,'missing_test_password');
  return process.env.OKTA_TEST_PASSWORD;
}
function childEnvironment() {
  const env=sanitizedEnvironment(process.env);
  delete env.DEBUG;delete env.PWDEBUG;delete env.NODE_OPTIONS;
  return env;
}
async function browserContext() {
  phase='browser_trust';
  const profile=fs.mkdtempSync(path.join(root,'firefox-'));
  command('certutil',['-N','-d','sql:'+profile,'--empty-password']);
  command('certutil',['-A','-d','sql:'+profile,'-n','supivpn-run-ca','-t','C,,','-i',path.join(root,'ca.crt')]);
  // NSS trust is confined to this throwaway Firefox profile, never a user profile.
  phase='browser_launch';
  return firefox.launchPersistentContext(profile,{headless:true,ignoreHTTPSErrors:false,
    timeout:30000,locale:'en-US',acceptDownloads:true,downloadsPath:downloadsDir,env:childEnvironment()});
}
function status() {
  return new Promise((resolve,reject)=>{
    const req=https.get(origin+'/lab/status',{timeout:3000},res=>{
      let body='';
      res.on('data',chunk=>{body+=chunk;if(body.length>4096)req.destroy(Error('status_too_large'));});
      res.on('error',()=>reject(Error('status_unavailable')));
      res.on('end',()=>{try{check(res.statusCode===200,'status_http');resolve(JSON.parse(body));}catch{reject(Error('status_failed'));}});
    });
    req.on('error',()=>reject(Error('status_unavailable')));
    req.on('timeout',()=>req.destroy(Error('status_timeout')));
  });
}
function validateProfile(data, cookie) {
  check(data.length>1000 && data.length<=65536,'profile_size');
  const text=data.toString('utf8');
  check(/^client$/m.test(text) && /^dev tun$/m.test(text) && /^proto udp4$/m.test(text),'profile_directives');
  check((text.match(/^remote /gm)||[]).length===1 && /^remote test\.supivpn\.com 1194$/m.test(text),'profile_endpoint');
  check(!text.includes('{{') && !text.includes('OpenVPN tls-crypt-v2 server key'),'profile_placeholder_or_server_key');
  check(!/^\s*(auth-user-pass|auth-token|cert|key)\b/m.test(text) && !/<(?:cert|key)>/.test(text),'embedded_client_credentials');
  for(const secret of [login,password(),cookie.split('=').slice(1).join('='),'SAMLResponse=','RelayState=','<saml','SSWS ']) {
    check(secret && !text.includes(secret),'authentication_material_in_profile');
  }
  const ca=text.match(/<ca>\s*([\s\S]*?)\s*<\/ca>/);
  check(ca && new crypto.X509Certificate(ca[1]).ca,'profile_ca');
  const match=text.match(/<tls-crypt-v2>\s*-----BEGIN OpenVPN tls-crypt-v2 client key-----\s*([A-Za-z0-9+/=\r\n]+)\s*-----END OpenVPN tls-crypt-v2 client key-----\s*<\/tls-crypt-v2>/);
  check(match && (text.match(/<tls-crypt-v2>/g)||[]).length===1,'profile_client_key');
  const key=Buffer.from(match[1].replace(/\s/g,''),'base64');
  check(key.length===555,'client_key_size');
  const digest=crypto.createHash('sha256').update(key).digest('hex');
  key.fill(0);
  return digest;
}

let stage='prepare',server,downloadsDir;
const result={};
async function stopServer() {
  if (server && server.exitCode===null && server.signalCode===null) {
    const ended=once(server,'exit');
    server.kill('SIGTERM');
    await Promise.race([ended,pause(6000)]);
    if(server.exitCode===null && server.signalCode===null) {server.kill('SIGKILL');await ended;}
  }
  server=undefined;
}
async function startServer(port,deny,mode='optional',encrypted=false,wrongKey=false) {
  const id=crypto.randomBytes(12).toString('hex');
  server=spawn(path.join(project,'local/okta-ci/profile-probe'),['--root',root,'--db-port',String(port),'--run-id',id,'--encryption-mode',mode,
    ...(deny?['--deny-group']:[]),...(encrypted?['--encrypted-app']:[]),...(wrongKey?['--wrong-encryption-key']:[])],
    {cwd:project,stdio:['ignore','pipe','pipe'],env:childEnvironment()});
  server.stdout.on('data',()=>{});
  server.stderr.on('data',()=>{});
  let spawnFailed=false;
  server.on('error',()=>{spawnFailed=true;});
  for(let i=0;i<80;i++) {
    check(!spawnFailed && server.exitCode===null && server.signalCode===null,'profile_server_exited');
    try {const s=await status();if(s.run_id===id && s.ready)return s;} catch {}
    await pause(250);
  }
  throw Error('profile_server_not_ready');
}

async function signInAndDownload(expectDenied, expectedCount, encrypted=false) {
  const context=await browserContext();
  const api=await request.newContext({ignoreHTTPSErrors:false,timeout:15000});
  const page=await context.newPage();
  page.setDefaultTimeout(10000);
  let body,cookie,download,reply,routeFailure,callbackCompleted=false;
  let identifierSent=false,passwordSent=false;
  let missingRefused=false,wrongRefused=false;
  try {
    const initial=await status();
    await page.route('**/*',async route=>{
      if(route.request().isNavigationRequest() && ![origin,tenant].includes(new URL(route.request().url()).origin))return route.abort();
      return route.continue();
    });
    page.on('download',d=>{download=d;});
    await page.route(origin+'/saml/acs',async route=>{
      try {
        phase='callback_validation';
        const req=route.request();
        check(req.method()==='POST' && new URL(req.url()).origin===origin,'unexpected_callback');
        check(!body,'duplicate_callback');
        body=req.postDataBuffer();
        const headers=await req.allHeaders();
        cookie=headers.cookie;
        check(body && body.length<1048576 && cookie && /^__Host-supivpn-/.test(cookie),'callback_binding');
        const assertionXML=Buffer.from(new URLSearchParams(body.toString('utf8')).get('SAMLResponse')||'','base64');
        try {
          phase=encrypted?'encrypted_assertion_wire_format':'plaintext_assertion_wire_format';
          assertionFormat(assertionXML,encrypted);
        } finally {assertionXML.fill(0);}
        const baseHeaders={'content-type':'application/x-www-form-urlencoded','origin':tenant};
        let r=await api.post(origin+'/saml/acs',{headers:baseHeaders,data:body,maxRedirects:0});
        missingRefused=r.status()===403;
        await r.dispose();
        r=await api.post(origin+'/saml/acs',{headers:{...baseHeaders,cookie:cookie.split('=')[0]+'=synthetic-wrong-browser'},data:body,maxRedirects:0});
        wrongRefused=r.status()===410;
        await r.dispose();
        check(missingRefused && wrongRefused,'browser_binding_not_enforced');
        check((await status()).key_loads===expectedCount,'key_access_before_authorization');
        const response=await route.fetch({maxRedirects:0,timeout:20000});
        reply={status:response.status(),headers:response.headers()};
        await route.fulfill({response});
        await response.dispose();
        callbackCompleted=true;
      } catch {
        routeFailure=true;
        await route.abort().catch(()=>{});
      }
    });
    phase='profile_navigation';
    await page.goto(origin+'/profile',{waitUntil:'domcontentloaded',timeout:30000});
    phase='okta_password_login';
    for(let i=0;i<75;i++) {
      check(!routeFailure,'callback_checks_failed');
      if(callbackCompleted && (expectDenied || download))break;
      if(new URL(page.url()).origin!==tenant){await pause(500);continue;}
      const identifier=page.locator('input[name="identifier"],input[name="username"]').first();
      const secret=page.locator('input[type="password"]').first();
      const submit=page.locator('input[type="submit"]:visible,button[type="submit"]:visible').first();
      if(!identifierSent && await identifier.isVisible()) {
        await identifier.fill(login);identifierSent=true;
        if(await secret.isVisible()){await secret.fill(password());passwordSent=true;}
        await submit.click();
      } else if(!passwordSent && await secret.isVisible()) {
        await secret.fill(password());passwordSent=true;await submit.click();
      } else {
        const later=page.getByRole('link',{name:/^(Set up later|Skip for now)$/i}).first();
        if(await later.isVisible())await later.click();
      }
      await pause(700);
    }
    check(!routeFailure && callbackCompleted && passwordSent,'fresh_password_login_incomplete');
    phase='profile_validation';
    let digest;
    if(['plaintext-required','encrypted-disabled','wrong-recipient-key'].includes(expectDenied)) {
      check(reply.status===403 && !download,'encryption_policy_or_key_not_enforced');
      const s=await status();
      check(s.allowed===0 && s.denied===0 && s.key_loads===0,'invalid_encryption_reached_authorization');
      check(s.assertions===initial.assertions && s.consumed_logins===initial.consumed_logins,
        'rejected_encryption_consumed_state');
      check(s.vpn_logins===0 && s.nodes===0,'rejected_encryption_created_session');
      return;
    }
    if(expectDenied) {
      check(reply.status===403 && !download,'unauthorized_group_not_denied');
      const s=await status();
      check(s.denied===1 && s.allowed===0 && s.key_loads===0,'denied_group_loaded_key');
    } else {
      check(reply.status===200 && download,'download_missing');
      check(reply.headers['content-type']==='application/x-openvpn-profile' &&
        reply.headers['content-disposition']==='attachment; filename="supivpn.ovpn"' &&
        reply.headers['cache-control']==='no-store, private','download_headers');
      check(download.suggestedFilename()==='supivpn.ovpn' && await download.failure()===null,'download_failed');
      const stream=await download.createReadStream(),chunks=[];
      let size=0;
      for await(const chunk of stream) {size+=chunk.length;check(size<=65536,'download_too_large');chunks.push(chunk);}
      const data=Buffer.concat(chunks);
      try {digest=validateProfile(data,cookie);} finally {data.fill(0);chunks.forEach(c=>c.fill(0));}
      await download.delete();
      const s=await status();
      check(s.allowed===expectedCount+1 && s.verified_identity_and_group===s.allowed &&
        s.key_loads===s.allowed,'profile_authorization_or_issuance_count');
    }
    const before=await status();
    const replay=await api.post(origin+'/saml/acs',{headers:{'content-type':'application/x-www-form-urlencoded','origin':tenant,cookie},data:body,maxRedirects:0});
    check(replay.status()===410,'replayed_assertion_accepted');
    await replay.dispose();
    const after=await status();
    check(after.key_loads===before.key_loads && after.allowed===before.allowed,'replay_issued_profile');
    check(after.vpn_logins===0 && after.nodes===0,'profile_created_vpn_session');
    // Earlier intentionally rejected logins remain pending. Measure this login's
    // state changes instead of treating unrelated pending rows as consumed.
    check(after.profile_logins-initial.profile_logins===1 &&
      after.consumed_logins-initial.consumed_logins===1 && after.assertions-initial.assertions===1,
      'one_use_state_not_consumed');
    return digest;
  } finally {
    if(body)body.fill(0);
    body=undefined;cookie=undefined;
    await api.dispose();
    await context.close();
  }
}

(async()=>{
  let passed=false,cleanupOK=true;
  try {
    check(root && path.isAbsolute(root) && fs.statSync(root).isDirectory() && !(fs.statSync(root).mode&0o077),'unsafe_run_directory');
    check(process.env.NODE_EXTRA_CA_CERTS===path.join(root,'ca.crt'),'missing_scoped_ca');
    check(!process.env.DEBUG && !process.env.PWDEBUG && !process.env.NODE_OPTIONS,'debug_logging_not_allowed');
    const port=Number(process.env.OKTA_TEST_DB_PORT||'55432');
    check(Number.isInteger(port) && port>=1024 && port<=65535,'invalid_database_port');
    stage='start_profile_controller';
    const initial=await startServer(port,false);
    check(initial.profile_logins===0 && initial.assertions===0,'database_not_empty');
    downloadsDir=fs.mkdtempSync(path.join(root,'profile-downloads-'));
    fs.chmodSync(downloadsDir,0o700);
    stage='first_profile_download';
    const first=await signInAndDownload(false,0);
    console.log('First real-Okta profile download and browser/replay checks passed');
    stage='second_profile_download';
    const second=await signInAndDownload(false,1);
    check(first!==second,'client_keys_reused');
    await stopServer();
    stage='group_denial_controller';
    await startServer(port,true);
    stage='group_denial_login';
    await signInAndDownload(true,0);
    await stopServer();
    stage='required_encryption_rejects_plaintext';
    await startServer(port,false,'required');
    await signInAndDownload('plaintext-required',0);
    await stopServer();
    const keys=new Set([first,second]);
    for(const mode of ['optional','required']) {
      stage=mode+'_encrypted_profiles';
      await startServer(port,false,mode,true);
      for(let count=0;count<2;count++) {
        const digest=await signInAndDownload(false,count,true);
        check(!keys.has(digest),'client_keys_reused');
        keys.add(digest);
      }
      await stopServer();
      result[mode+'_accepts_encrypted']=true;
      stage=mode+'_wrong_recipient_key';
      await startServer(port,false,mode,true,true);
      await signInAndDownload('wrong-recipient-key',0,true);
      await stopServer();
      result[mode+'_rejects_wrong_recipient_key']=true;
    }
    stage='encrypted_group_denial';
    await startServer(port,true,'required',true);
    await signInAndDownload(true,0,true);
    await stopServer();
    stage='disabled_rejects_encrypted';
    await startServer(port,false,'disabled',true);
    await signInAndDownload('encrypted-disabled',0,true);
    Object.assign(result,{real_okta_password_login:true,production_controller:true,postgresql_18:true,
      optional_accepts_plaintext:true,required_rejects_plaintext:true,scoped_ephemeral_https:true,
      encrypted_wire_aes256_gcm_rsa_oaep:true,encrypted_group_denial:true,disabled_rejects_encrypted:true,
      browser_profile_downloads:6,profile_format_and_endpoint:true,unique_client_keys:true,
      no_saml_or_password_in_profile:true,missing_and_wrong_cookie_refused:true,replay_refused:true,
      unauthorized_group_refused:true,wrapping_key_loaded_only_after_authorization:true,no_vpn_session_created:true});
    passed=true;
  } catch {
    console.error(JSON.stringify({passed:false,stage,phase,failure,raw_diagnostics_withheld:true}));
    process.exitCode=1;
  } finally {
    try{await stopServer();}catch{cleanupOK=false;}
    try{if(downloadsDir)fs.rmSync(downloadsDir,{recursive:true,force:false});}catch{cleanupOK=false;}
    if(!cleanupOK){console.error('Task resource cleanup needs inspection');process.exitCode=1;}
    const report={checked_at:new Date().toISOString(),passed:passed&&cleanupOK,stage,cleanup_complete:cleanupOK,...result};
    console.log(JSON.stringify(report));
  }
})();
