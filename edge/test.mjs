import {test,before,after} from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdtempSync,readFileSync,writeFileSync,existsSync,rmSync,readdirSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {execFileSync} from 'node:child_process';
import {Database} from './local-db.mjs';
import prune from './retention.mjs';

const root = fileURLToPath(new URL('../',import.meta.url));
const host = 'https://lab.nicolasmgioanni.dev';
const runtime = mkdtempSync(join(tmpdir(),'lab-edge-'));
const encoder = new TextEncoder();
const algorithm = {name:'ECDSA',namedCurve:'P-256'};
let handle;
before(async () => {
  execFileSync('python3',['edge/package.py',runtime],{cwd:root});
  writeFileSync(join(runtime,'worker.mjs'),readFileSync(join(runtime,'_worker.js'),'utf8')+'\nexport {handle};');
  ({handle} = await import(pathToFileURL(join(runtime,'worker.mjs'))));
});
after(() => rmSync(runtime,{force:true,recursive:true}));

function env() {
  return {BOT_CONTROL:'turnstile',LAB_EVENTS:new Database(),TURNSTILE_SITE_KEY:'public_test_key',TURNSTILE_SECRET_KEY:'fixture-secret',
    ASSETS:{fetch:async () => new Response('static design asset')}};
}
function call(e,path,opts={}) {
  const {method='GET',cookie,body,origin=host,headers={},fetcher,otherHost=host} = opts;
  const h = new Headers({'CF-Connecting-IP':'192.0.2.10','User-Agent':'synthetic-agent',...headers});
  if (cookie) h.set('Cookie',cookie);
  if (method === 'POST') h.set('Origin',origin);
  const request = new Request(otherHost+path,{method,body,headers:h});
  Object.defineProperty(request,'cf',{value:{country:'US'}});
  return handle(request,e,fetcher);
}
const select = (e,sql,...params) => e.LAB_EVENTS.engine.prepare(sql).all(...params);
async function identity() {
  const key = await crypto.subtle.generateKey(algorithm,false,['sign','verify']);
  const raw = Buffer.from(await crypto.subtle.exportKey('raw',key.publicKey));
  return {privateKey:key.privateKey,publicKey:raw.toString('base64'),keyId:createHash('sha256').update(raw).digest('hex')};
}
function issue(e,id,opts={}) {
  const fetcher = async (url,init) => {
    assert.equal(url,'https://challenges.cloudflare.com/turnstile/v0/siteverify');
    assert.equal(init.redirect,'manual');
    assert.equal(init.body.get('secret'),'fixture-secret');
    assert.equal(init.body.get('remoteip'),'192.0.2.10');
    assert.equal(init.body.get('response'),'fixture-token');
    return Response.json({success:true,hostname:'lab.nicolasmgioanni.dev',action:'lab_admission',cdata:id.keyId});
  };
  return call(e,'/access/verify',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({token:'fixture-token',publicKey:id.publicKey}),fetcher,...opts});
}
async function notice(e,id,opts={}) {
  const result = await issue(e,id,opts);
  assert.equal(result.status,200);
  const cookie = result.headers.getSetCookie()[0];
  assert.match(cookie,/^__Host-lab_visit_[0-9a-f]{64}=[0-9a-f]{64}; Path=\/; Secure; HttpOnly; SameSite=Strict$/);
  return {...await result.json(),cookie:cookie.split(';')[0],setCookies:result.headers.getSetCookie()};
}
async function sign(id,challenge,overrides={}) {
  const {nonce,keyId,target}= {...challenge,...overrides};
  const params='("@method" "@target-uri");keyid="'+keyId+'";nonce="'+nonce+'";alg="ecdsa-p256-sha256"';
  const message='"@method": POST\n"@target-uri": '+target+'\n"@signature-params": '+params;
  const signature=await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},id.privateKey,encoder.encode(message));
  return {'Signature-Input':'lab='+params,'Signature':'lab=:'+Buffer.from(signature).toString('base64')+':'};
}
const accept=(e,n,headers,opts={}) => call(e,'/access/accept',{method:'POST',cookie:n.cookie,headers,...opts});

test('all document loads, aliases and data links with any legacy cookie go through the empty verification shell',async()=>{
  const e=env();
  for (const path of ['/','/index.html','/entry','/entry.html','/challenge','/research','/data/worker-1.json?token=sensitive']) {
    const res=await call(e,path,{cookie:'__Host-lab_access=previous-accepted-cookie'});
    assert.equal(res.headers.get('Location'),'/verify');
    assert.equal(res.status,303);
    assert.doesNotMatch(await res.text(),/Gitleaks/i);
  }
  const gate=await call(e,'/verify',{cookie:'__Host-lab_access=old'});
  const html=await gate.text();
  assert.match(html,/data-sitekey="public_test_key"/);
  assert.match(html,/id="turnstile-widget"/);
  assert.match(html,/id="notice-stage"[^>]+hidden/);
  assert.doesNotMatch(html,/Gitleaks|8 of 8|127\.0\.0\.1|console\.login|__TURNSTILE_SITEKEY__/i);
  assert.match(gate.headers.get('Set-Cookie'),/Max-Age=0/);
  assert.match(gate.headers.get('Cache-Control'),/no-store/);
  assert.equal(gate.headers.get('Referrer-Policy'),'same-origin');
  assert.match(gate.headers.get('Content-Security-Policy'),/frame-src https:\/\/challenges.cloudflare.com/);
  assert.equal((await call(e,'/verify',{method:'HEAD'})).headers.get('Set-Cookie'),null);
  assert.equal((await call(e,'/data/worker-1.json',{otherHost:'https://demo.pages.dev'})).headers.get('Location'),host+'/verify');
  assert.equal((await call(e,'/access/accept',{otherHost:'https://demo.pages.dev',method:'POST'})).status,403);
  assert.equal((await call({},'/exit')).status,200);
  assert.equal((await call(e,'/_worker.js')).status,404);
  for (const p of ['index.html','entry.html','exit.html','data']) assert.equal(existsSync(join(runtime,p)),false);
  assert.deepEqual(JSON.parse(readFileSync(join(runtime,'_routes.json'))),{version:1,include:['/*'],exclude:[]});
  assert.match(readFileSync(join(runtime,'404.html'),'utf8'),/unavailable/);
});

test('provider validation is bound to the hostname, action and page public key, including under concurrency',async()=>{
  const e=env(),id=await identity();
  for (const change of [{success:false},{hostname:'other.example'},{action:'other'},{cdata:'other'}]) {
    const result=await issue(e,id,{fetcher:async()=>Response.json({success:true,hostname:'lab.nicolasmgioanni.dev',action:'lab_admission',cdata:id.keyId,...change})});
    assert.equal(result.status,403); assert.equal(result.headers.get('Set-Cookie'),null);
  }
  for (const status of [302,503]) {
    assert.equal((await issue(e,id,{fetcher:async()=>new Response(null,{status})})).status,503);
  }
  assert.equal((await issue(e,id,{origin:'https://elsewhere.example'})).status,403);
  assert.equal((await issue(e,id,{body:'{"token":"invalid","publicKey":""}'})).status,403);
  assert.equal((await issue(e,id,{body:'x'.repeat(5000)})).status,403);
  assert.equal((await call(e,'/access/verify')).status,405);
  assert.deepEqual((await Promise.all([issue(e,id),issue(e,id)])).map(r=>r.status).sort(),[200,409]);
  assert.equal(select(e,'SELECT * FROM admission_proofs').length,1);
});

test('only one duplicate signed acceptance succeeds and only its POST returns the research',async()=>{
  const e=env(),id=await identity(),wrong=await identity();
  assert.equal(id.privateKey.extractable,false);
  const n=await notice(e,id);
  const proof=await sign(id,n);
  assert.equal((await accept(e,n,{})).status,403);
  assert.equal((await accept(e,n,await sign(wrong,n))).status,403);
  assert.equal((await accept(e,n,await sign(id,n,{target:host+'/different'}))).status,403);
  assert.equal((await accept(e,n,await sign(id,n,{nonce:'0'.repeat(64)}))).status,403);
  assert.equal((await accept(e,n,proof,{origin:'https://elsewhere.example'})).status,403);
  assert.equal((await accept(e,n,{...proof,'Sec-Fetch-Site':'cross-site'})).status,403);
  assert.equal((await accept(e,n,proof,{cookie:n.cookie+'; '+n.cookie})).status,403);
  assert.equal((await accept(e,n,proof,{cookie:''})).status,403);
  const responses=await Promise.all([accept(e,n,proof),accept(e,n,proof)]);
  assert.deepEqual(responses.map(r=>r.status).sort(),[200,403]);
  const win=responses.find(r=>r.ok);
  assert.match(await win.text(),/Gitleaks/);
  assert.match(win.headers.get('Set-Cookie'),/Max-Age=0/);
  assert.match(win.headers.get('Cache-Control'),/no-store/);
  assert.equal((await accept(e,n,proof)).status,403);
  for (const p of ['/','/data/worker-1.json']) assert.equal((await call(e,p,{cookie:n.cookie})).headers.get('Location'),'/verify');
  assert.equal((await issue(e,id)).status,409);
  const events=select(e,"SELECT * FROM access_events WHERE event='accepted'");
  assert.equal(events.length,1); assert.equal(events[0].country,'US'); assert.equal(events[0].ip,'192.0.2.10');
  const all=JSON.stringify(select(e,'SELECT * FROM access_events'));
  for (const sensitive of [n.cookie,n.nonce,id.publicKey,proof.Signature,'fixture-token']) assert.ok(!all.includes(sensitive));
});

test('independent tabs can finish together, decline and expiry revoke only the matching page',async()=>{
  const e=env(),first=await identity(),second=await identity(),third=await identity();
  const [a,b,c]=await Promise.all([notice(e,first),notice(e,second),notice(e,third)]);
  const jar=[a.cookie,b.cookie,c.cookie].join('; ');
  const denied=await call(e,'/access/decline',{method:'POST',cookie:jar,headers:{'X-Lab-Visit':first.keyId}});
  assert.equal(denied.status,204);
  assert.match(denied.headers.get('Set-Cookie'),/Max-Age=0/);
  assert.equal((await accept(e,a,await sign(first,a),{cookie:jar})).status,403);
  const [resultB,resultC]=await Promise.all([
    accept(e,b,await sign(second,b),{cookie:jar}),accept(e,c,await sign(third,c),{cookie:jar})
  ]);
  assert.equal(resultB.status,200); assert.equal(resultC.status,200);
  const fourth=await identity(),d=await notice(e,fourth);
  e.LAB_EVENTS.engine.prepare("UPDATE admission_grants SET expires=0 WHERE stage='notice'").run();
  assert.equal((await accept(e,d,await sign(fourth,d))).status,403);
  assert.equal((await call(e,'/verify',{cookie:a.cookie})).headers.get('Set-Cookie'),null);
});

test('abandoned pending cookies are bounded and the independent retention job also prunes page proofs',async()=>{
  const e=env(),id=await identity();
  const cookies=Array.from({length:14},(_,i)=>'__Host-lab_visit_'+i.toString(16).padStart(64,'0')+'='+'a'.repeat(64));
  const n=await notice(e,id,{cookie:cookies.join('; ')});
  assert.equal(n.setCookies.length,4);
  assert.ok(n.setCookies.slice(1).every(item=>item.endsWith('Max-Age=0')));
  e.LAB_EVENTS.engine.exec("UPDATE admission_grants SET expires=0; INSERT INTO access_events(at,event,path) VALUES(0,'notice','/verify')");
  await prune.scheduled(null,e);
  assert.equal(select(e,'SELECT * FROM admission_proofs').length,0);
  assert.equal(select(e,'SELECT * FROM access_events WHERE at=0').length,0);
  assert.equal(select(e,'SELECT * FROM access_events').length,1);
  e.LAB_EVENTS.engine.exec("INSERT INTO access_events(id,at,event,path) VALUES(25005,unixepoch(),'verification_opened','/verify')");
  await call(e,'/verify');
  assert.equal(select(e,'SELECT * FROM access_events WHERE id=1').length,0);
});
test('disabled edge or missing database fails closed, with immutable shell assets',async()=>{
  const e=env();
  for (const invalid of [{...e,BOT_CONTROL:'managed_challenge'},{...e,TURNSTILE_SECRET_KEY:''},{}])
    assert.equal((await call(invalid,'/verify')).status,503);
  const html=await (await call(e,'/verify')).text();
  const assets=readdirSync(join(runtime,'assets'));
  const urls=[...html.matchAll(/(?:href|src)="(\/assets\/[^"]+)"/g)].map(match=>match[1]);
  for (const suffix of ['.css','.js','.png']) assert.ok(urls.some(url=>url.endsWith(suffix)));
  for (const url of urls) {
    const name=url.split('/').at(-1);
    assert.ok(assets.includes(name),name);
    const data=readFileSync(join(runtime,'assets',name));
    assert.ok(name.includes('.'+createHash('sha256').update(data).digest('hex').slice(0,16)+'.'),name);
    assert.match((await call(e,url)).headers.get('Cache-Control'),/immutable/);
  }
  const current=await call(e,'/assets/study.css');
  const stale=await call(e,'/assets/study.0000000000000000.css');
  assert.equal(current.status,303);
  assert.equal(current.headers.get('Location'),stale.headers.get('Location'));
  e.LAB_EVENTS.engine.close();
  assert.equal((await call(e,'/verify')).status,503);
});
