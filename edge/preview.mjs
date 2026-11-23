// Loopback-only development harness. Production bundles only edge/worker.mjs, never this test provider.
import { createServer } from 'node:http';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { execFileSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Database } from './local-db.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const dir = mkdtempSync(join(tmpdir(), 'lab-preview-'));
const canonical = 'https://lab.nicolasmgioanni.dev';
const port = Number(process.argv[2] || 8194);
const local = 'http://127.0.0.1:' + port;
execFileSync('python3',['edge/package.py',dir],{cwd:root});
writeFileSync(join(dir,'worker.mjs'),readFileSync(join(dir,'_worker.js'),'utf8') + '\nexport {handle};');
const {handle} = await import(pathToFileURL(join(dir,'worker.mjs')));
const types = {css:'text/css',js:'text/javascript',png:'image/png',woff2:'font/woff2',txt:'text/plain'};
const env = {BOT_CONTROL:'turnstile',TURNSTILE_SITE_KEY:'1x00000000000000000000AA',
  TURNSTILE_SECRET_KEY:'local-fixture-only', LAB_EVENTS:new Database(), ASSETS:{
    fetch: async request => {
      const path = new URL(request.url).pathname;
      const content = readFileSync(join(dir,path));
      return new Response(request.method === 'HEAD' ? null : content,{headers:{'Content-Type':types[path.split('.').at(-1)]}});
    },
  }};
const server = createServer(async (incoming, outgoing) => {
  try {
    if (incoming.headers.host !== new URL(local).host) { outgoing.writeHead(403).end(); return; }
    const headers = new Headers(incoming.headers);
    if (headers.get('Origin') === local) headers.set('Origin',canonical);
    headers.delete('CF-Connecting-IP');
    const opts = {method:incoming.method, headers};
    if (!['GET','HEAD'].includes(incoming.method)) Object.assign(opts,{body:incoming,duplex:'half'});
    const request = new Request(canonical+incoming.url,opts);
    const verification = incoming.url === '/access/verify' ? await request.clone().json() : null;
    const provider = async (_url, init) => {
      const token = init.body.get('response');
      return Response.json({success: token === 'XXXX.DUMMY.TOKEN.XXXX' || token?.includes('.DUMMY.TOKEN.'),
        hostname:new URL(canonical).hostname,action:'lab_admission',
        cdata:createHash('sha256').update(Buffer.from(verification.publicKey,'base64')).digest('hex')});
    };
    const result = await handle(request,env,provider);
    const outgoingHeaders = Object.fromEntries(result.headers);
    if (result.headers.has('Set-Cookie')) outgoingHeaders['set-cookie'] = result.headers.getSetCookie();
    outgoing.writeHead(result.status,outgoingHeaders);
    outgoing.end(Buffer.from(await result.arrayBuffer()));
  } catch {
    outgoing.writeHead(503).end('Local fixture unavailable.');
  }
}).listen(port,'127.0.0.1', () => console.log('Local Turnstile test-key fixture: '+local));
function close() { server.close(); rmSync(dir,{recursive:true,force:true}); process.exit(); }
process.on('SIGINT', close);
process.on('SIGTERM', close);
