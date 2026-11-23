import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, existsSync, rmSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { execFileSync } from 'node:child_process';
import { Database } from './local-db.mjs';
import prune from './retention.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const host = 'https://lab.nicolasmgioanni.dev';
const runtime = mkdtempSync(join(tmpdir(), 'lab-edge-'));
let handle;
before(async () => {
  execFileSync('python3', ['edge/package.py', runtime], {cwd:root});
  writeFileSync(join(runtime, 'worker.mjs'), readFileSync(join(runtime, '_worker.js'), 'utf8') + '\nexport { handle };');
  ({handle} = await import(pathToFileURL(join(runtime, 'worker.mjs'))));
});
after(() => rmSync(runtime, {force:true,recursive:true}));

function env(mode = 'managed_challenge') {
  return {BOT_CONTROL:mode,LAB_EVENTS:new Database(),TURNSTILE_SITE_KEY:'public_test_key',
    TURNSTILE_SECRET_KEY:'mock_secret',ASSETS:{fetch:async () => new Response('static design asset')}};
}
function call(env, path, opts = {}) {
  const { method='GET', cookie, origin=host, body, fetcher, otherHost=host, headers={} } = opts;
  const h = new Headers({'CF-Connecting-IP':'192.0.2.10','User-Agent':'synthetic-agent', ...headers});
  if (cookie) h.set('Cookie',cookie);
  if (method === 'POST') h.set('Origin',origin);
  const request = new Request(otherHost+path,{method,headers:h,body});
  Object.defineProperty(request,'cf',{value:{country:'US'}});
  return handle(request,env,fetcher);
}
function jar(response) { return response.headers.get('Set-Cookie')?.split(';')[0]; }
function sql(env, query, ...params) { return env.LAB_EVENTS.engine.prepare(query).all(...params); }

test('build contains only a maintenance document, cosmetics, and the protected Worker', () => {
  assert.equal(existsSync(join(runtime,'index.html')),false);
  assert.equal(existsSync(join(runtime,'entry.html')),false);
  assert.equal(existsSync(join(runtime,'data')),false);
  assert.deepEqual(JSON.parse(readFileSync(join(runtime,'_routes.json'))),{version:1,include:['/*'],exclude:[]});
  assert.match(readFileSync(join(runtime,'404.html'),'utf8'),/unavailable/);
  assert.ok(readdirSync(join(runtime,'assets')).includes('portfolio-tokens.css'));
});
test('notice grants admit one session; duplicate or cross-origin acceptance cannot transition it', async () => {
  const e=env();
  for (const path of ['/', '/index.html','/data/worker-1.json?private=sensitive']) {
    const r=await call(e,path);
    assert.equal(r.status,303); assert.equal(r.headers.get('Location'),'/entry');
    assert.equal(r.headers.get('Set-Cookie'),null);
  }
  assert.equal((await call(e,'/access/accept')).status,405);
  assert.equal((await call(e,'/access/accept',{method:'POST'})).status,403);
  const notice=await call(e,'/entry.html');
  assert.equal(notice.status,200);
  assert.match(await notice.text(),/action="\/access\/accept"/);
  assert.match(notice.headers.get('Set-Cookie'), /Path=\/; HttpOnly; Secure; SameSite=Strict; Max-Age=600$/);
  assert.equal(notice.headers.get('Referrer-Policy'),'same-origin');
  const noticeCookie=jar(notice);
  assert.equal((await call(e,'/access/accept',{method:'POST',cookie:noticeCookie,origin:'https://other.example'})).status,403);
  const accepted=await call(e,'/access/accept',{method:'POST',cookie:noticeCookie});
  assert.equal(accepted.headers.get('Location'),'/');
  assert.match(accepted.headers.get('Set-Cookie'),/Max-Age=3600$/);
  assert.equal((await call(e,'/access/accept',{method:'POST',cookie:noticeCookie})).status,403);
  const c=jar(accepted);
  const entered=await call(e,'/',{cookie:c});
  assert.equal(entered.status,200); assert.match(entered.headers.get('Cache-Control'),/no-store/);
  const raw=await call(e,'/data/worker-1.json?password=secret',{cookie:c});
  assert.equal(raw.status,200); assert.equal((await raw.json()).experiment,'history-scope');
  const edited=c.slice(0,-1)+(c.endsWith('0')?'1':'0');
  assert.equal((await call(e,'/',{cookie:edited})).status,303);
  assert.equal((await call(e,'/',{cookie:c+'; '+c})).status,303);
  const departed=await call(e,'/access/leave',{method:'POST',cookie:c});
  assert.match(departed.headers.get('Set-Cookie'),/Max-Age=0$/);
  assert.equal(departed.headers.get('Location'),'https://nicolasmgioanni.dev/');
  assert.equal((await call(e,'/',{cookie:c})).status,303);
  const events=sql(e,'SELECT * FROM access_events');
  for (const event of ['notice','accepted','workspace','evidence','session_ended']) assert.ok(events.some(i=>i.event===event));
  assert.equal(events[0].ip,'192.0.2.10'); assert.equal(events[0].country,'US');
  assert.ok(!JSON.stringify(events).match(/password|sensitive|secret|__Host|private=/));
});
test('decline revokes grant, expired grants fail, hostname aliases redirect, unavailable storage blocks content',async()=>{
  const e=env();
  const c=jar(await call(e,'/entry'));
  const r=await call(e,'/access/decline',{method:'POST',cookie:c});
  assert.match(r.headers.get('Set-Cookie'),/Max-Age=0/);
  assert.equal((await call(e,'/access/accept',{method:'POST',cookie:c})).status,403);
  const c2=jar(await call(e,'/entry'));
  e.LAB_EVENTS.engine.exec('UPDATE admission_grants SET expires=0');
  assert.equal((await call(e,'/access/accept',{method:'POST',cookie:c2})).status,403);
  assert.equal((await call(e,'/data/worker-1.json',{otherHost:'https://example.pages.dev'})).headers.get('Location'),host+'/');
  e.LAB_EVENTS.engine.close();
  assert.equal((await call(e,'/')).status,503);
  assert.equal((await call({},'/entry')).status,503);
  assert.equal((await call({...env(),BOT_CONTROL:'none'},'/entry')).status,503);
});
test('Turnstile must succeed on the expected hostname and action before the notice is served',async()=>{
  const e=env('turnstile');
  assert.equal((await call(e,'/')).headers.get('Location'),'/challenge');
  assert.equal((await call(e,'/entry')).headers.get('Location'),'/challenge');
  const challenge=await call(e,'/challenge');
  assert.match(await challenge.text(),/challenges.cloudflare.com\/turnstile/);
  assert.match(challenge.headers.get('Content-Security-Policy'),/frame-src https:\/\/challenges.cloudflare.com/);
  const opts={method:'POST',body:'cf-turnstile-response=synthetic',headers:{'Content-Type':'application/x-www-form-urlencoded'}};
  for (const data of [{success:false},{success:true,hostname:'other.example',action:'lab_admission'},{success:true,hostname:'lab.nicolasmgioanni.dev',action:'other'}]) {
    const rejected=await call(e,'/access/verify',{...opts,fetcher:async()=>Response.json(data)});
    assert.equal(rejected.status,403); assert.equal(jar(rejected),undefined);
  }
  assert.equal((await call(e,'/access/verify',{...opts,fetcher:async()=>new Response(null,{status:503})})).status,503);
  const good=await call(e,'/access/verify',{...opts,fetcher:async(url, init)=>{
    assert.equal(url,'https://challenges.cloudflare.com/turnstile/v0/siteverify');
    assert.equal(init.body.get('response'),'synthetic'); assert.equal(init.body.get('remoteip'),'192.0.2.10');
    return Response.json({success:true,hostname:'lab.nicolasmgioanni.dev',action:'lab_admission'});
  }});
  assert.equal(good.headers.get('Location'),'/entry');
  assert.equal((await call(e,'/access/accept',{method:'POST',cookie:jar(good)})).status,403);
  const notice=await call(e,'/entry',{cookie:jar(good)});
  assert.equal(notice.status,200);
  const allowed=await call(e,'/access/accept',{method:'POST',cookie:jar(notice)});
  assert.equal((await call(e,'/',{cookie:jar(allowed)})).status,200);
});
test('retention worker deletes expired records without traffic and data is bounded',async()=>{
  const e=env();
  await call(e,'/entry');
  const db=e.LAB_EVENTS.engine;
  db.exec("INSERT INTO access_events(at,event,path,ip) VALUES(0,'notice','/entry','192.0.2.1')");
  db.exec("INSERT INTO admission_grants(digest,stage,expires) VALUES('expired','notice',0)");
  await prune.scheduled(null,e);
  assert.equal(sql(e,'SELECT * FROM access_events WHERE at=0').length,0);
  assert.equal(sql(e,"SELECT * FROM admission_grants WHERE digest='expired'").length,0);
  assert.equal(sql(e,'SELECT * FROM access_events').length,1);
  db.exec("INSERT INTO access_events(id,at,event,path) VALUES(25005,unixepoch(),'workspace','/')");
  await call(e,'/');
  assert.equal(sql(e,'SELECT * FROM access_events WHERE id=1').length,0);
});
