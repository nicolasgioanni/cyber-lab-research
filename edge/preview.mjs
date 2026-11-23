// Local developer fixture only. Cloudflare's live WAF challenge is verified independently on the public hostname.
import { createServer } from 'node:http';
import { mkdtempSync, readFileSync, copyFileSync, rmSync } from 'node:fs';
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
copyFileSync(join(dir,'_worker.js'),join(dir,'worker.mjs'));
const worker = (await import(pathToFileURL(join(dir,'worker.mjs')))).default;
const types = {css:'text/css',js:'text/javascript',png:'image/png',woff2:'font/woff2',txt:'text/plain'};
const env = {BOT_CONTROL:'managed_challenge', LAB_EVENTS:new Database(), ASSETS:{
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
    const result = await worker.fetch(new Request(canonical+incoming.url,opts),env);
    outgoing.writeHead(result.status,Object.fromEntries(result.headers));
    outgoing.end(Buffer.from(await result.arrayBuffer()));
  } catch {
    outgoing.writeHead(503).end('Local fixture unavailable.');
  }
}).listen(port,'127.0.0.1', () => console.log('Local admission fixture (no edge WAF): '+local));
function close() { server.close(); rmSync(dir,{recursive:true,force:true}); process.exit(); }
process.on('SIGINT', close);
process.on('SIGTERM', close);
