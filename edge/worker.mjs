// The packager injects reviewed documents and schema into this module, never the static fallback.
const DOCUMENTS = /* PACK:DOCUMENTS */ null;
const SCHEMA = /* PACK:SCHEMA */ null;
const ASSET_URLS = /* PACK:ASSETS */ null;
const HOST = 'lab.nicolasmgioanni.dev';
const ORIGIN = 'https://' + HOST;
const COOKIE = '__Host-lab_access';
const WEEK = 7 * 86400;
const TEN_MINUTES = 600;
const HOUR = 3600;
const text = new TextEncoder();
const CSP = "default-src 'none'; style-src 'self'; script-src 'self'; font-src 'self'; img-src 'self'; connect-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
const CHALLENGE_CSP = "default-src 'none'; style-src 'self'; font-src 'self'; script-src https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
const dbKeys = new WeakMap();

function response(body, status = 200, extra = {}) {
  return new Response(body, { status, headers: {
    'Content-Type': 'text/plain; charset=utf-8', 'Content-Security-Policy': CSP,
    'Cache-Control': 'private, no-store', 'Cloudflare-CDN-Cache-Control': 'no-store',
    'Referrer-Policy': 'same-origin', 'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY', 'Permissions-Policy': 'camera=(), microphone=(), geolocation=()', ...extra
  } });
}

function cookie(value, ttl) {
  return COOKIE + '=' + value + '; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=' + ttl;
}
function redirect(to, setCookie) {
  return response(null, 303, { Location: to, ...(setCookie ? { 'Set-Cookie': setCookie } : {}) });
}
function hex(bytes) {
  return Array.from(new Uint8Array(bytes), n => n.toString(16).padStart(2, '0')).join('');
}
function bytes(value) {
  return Uint8Array.from(value.match(/../g), n => parseInt(n, 16));
}
function random() {
  return hex(crypto.getRandomValues(new Uint8Array(32)));
}
async function keyFor(db, provided) {
  if (provided && !/^[a-f0-9]{64}$/i.test(provided)) throw Error('Invalid signing key');
  if (dbKeys.has(db)) return dbKeys.get(db);
  async function fromDatabase() {
    let row;
    try {
      row = await db.prepare('SELECT secret FROM admission_keys WHERE id=1').first();
    } catch (error) {
      if (!String(error.message).includes('no such table')) throw error;
      await db.batch(SCHEMA.map(sql => db.prepare(sql)));
    }
    if (!row) {
      await db.prepare('INSERT OR IGNORE INTO admission_keys(id,secret) VALUES(1,?)').bind(random()).run();
      row = await db.prepare('SELECT secret FROM admission_keys WHERE id=1').first();
    }
    // A DB reader cannot use this key to construct a grant: only the SHA-256 hashes
    // of 256-bit random bearer values are retained. Signed cookies are never logged.
    return crypto.subtle.importKey('raw', bytes(provided || row.secret),
      { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
  }
  const pending = fromDatabase();
  dbKeys.set(db, pending);
  try { return await pending; } catch (error) { dbKeys.delete(db); throw error; }
}
async function readGrant(request, db, key, now) {
  const values = (request.headers.get('Cookie') || '').split(';').map(v => v.trim())
    .filter(v => v.startsWith(COOKIE + '=')).map(v => v.slice(COOKIE.length + 1));
  if (values.length !== 1 || !/^[0-9a-f]{64}\.[0-9a-f]{64}$/.test(values[0])) return null;
  const [token, signature] = values[0].split('.');
  if (!await crypto.subtle.verify('HMAC', key, bytes(signature), text.encode(token))) return null;
  const digest = hex(await crypto.subtle.digest('SHA-256', text.encode(token)));
  return db.prepare('SELECT digest,stage,expires FROM admission_grants WHERE digest=? AND expires>?').bind(digest, now).first();
}
function eventStatement(db, request, event, path, now) {
  return db.prepare('INSERT INTO access_events(at,event,path,ip,country,user_agent) VALUES(?,?,?,?,?,?)')
    .bind(now, event, path, ...eventMetadata(request));
}
function maintenance(db, now) {
  return [
    db.prepare('DELETE FROM access_events WHERE at<=?').bind(now - WEEK),
    db.prepare('DELETE FROM access_events WHERE id <= (SELECT max(id)-25000 FROM access_events)'),
    db.prepare('DELETE FROM admission_grants WHERE expires<=?').bind(now),
    db.prepare('DELETE FROM admission_grants WHERE id <= (SELECT max(id)-25000 FROM admission_grants)'),
  ];
}
async function log(db, request, event, path, now) {
  await db.batch([eventStatement(db, request, event, path, now), ...maintenance(db, now)]);
}
async function issue(db, key, old, stage, ttl, request, event, path, now) {
  const token = random();
  const digest = hex(await crypto.subtle.digest('SHA-256', text.encode(token)));
  const signature = hex(await crypto.subtle.sign('HMAC', key, text.encode(token)));
  const statements = [];
  if (old) {
    // Updating the old row atomically makes an admission transition single-use across concurrent requests.
    statements.push(db.prepare('UPDATE admission_grants SET digest=?,stage=?,expires=? WHERE digest=? AND stage=? AND expires>?')
      .bind(digest, stage, now + ttl, old.digest, old.stage, now));
  } else {
    statements.push(db.prepare('INSERT INTO admission_grants(digest,stage,expires) VALUES(?,?,?)').bind(digest, stage, now + ttl));
  }
  // A concurrent request may already have consumed the old grant. Only journal an issued grant.
  const results = await db.batch([...statements, db.prepare(
    'INSERT INTO access_events(at,event,path,ip,country,user_agent) SELECT ?,?,?,?,?,? WHERE EXISTS (SELECT 1 FROM admission_grants WHERE digest=?)'
  ).bind(now, event, path, ...eventMetadata(request), digest), ...maintenance(db, now)]);
  if (results[0].meta.changes !== 1) return null;
  return cookie(token + '.' + signature, ttl);
}
function eventMetadata(request) {
  const ip = request.headers.get('CF-Connecting-IP') || '';
  const country = request.cf?.country || '';
  const ua = (request.headers.get('User-Agent') || '').replace(/[\x00-\x1f\x7f]/g, ' ').slice(0, 240);
  return [/^[0-9a-f.:]{2,45}$/i.test(ip) ? ip : null, /^[A-Z]{2}$/.test(country) ? country : null, ua || null];
}
function documentResponse(path, method, setCookie) {
  const type = path.startsWith('/data/') ? 'application/json' : 'text/html';
  return response(method === 'HEAD' ? null : DOCUMENTS[path], 200,
    { 'Content-Type': type + '; charset=utf-8', ...(setCookie ? { 'Set-Cookie': setCookie } : {}) });
}
function challenge(sitekey, head) {
  const html = `<!doctype html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Connection verification · Cyber Lab</title>
  <link rel="stylesheet" href="${ASSET_URLS['/assets/portfolio-tokens.css']}">
  <link rel="stylesheet" href="${ASSET_URLS['/assets/study.css']}">
  <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
</head>
<body>
  <main class="entry-stage"><section class="access-card">
    <h1>Verify your connection</h1>
    <p>Cloudflare checks your browser before the lab opens its access notice.</p>
    <form method="post" action="/access/verify">
      <div class="cf-turnstile" data-sitekey="${sitekey}" data-action="lab_admission"></div>
      <button class="button primary" type="submit">Continue to access notice</button>
    </form>
    <p><a href="/exit">Leave the lab</a></p>
  </section></main>
</body></html>`;
  return response(head ? null : html, 200, { 'Content-Type': 'text/html; charset=utf-8', 'Content-Security-Policy': CHALLENGE_CSP });
}
async function formToken(request) {
  if (!request.body || !/^application\/x-www-form-urlencoded(?:\s*;|$)/i.test(request.headers.get('Content-Type') || '')) return '';
  const reader = request.body.getReader();
  const chunks = [];
  let size = 0;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > 8192) { await reader.cancel(); return ''; }
    chunks.push(value);
  }
  const fields = new URLSearchParams(await new Blob(chunks).text()).getAll('cf-turnstile-response');
  return fields.length === 1 && fields[0].length <= 2048 ? fields[0] : '';
}
async function verifyBot(request, secret, fetcher) {
  const token = await formToken(request);
  if (!token) return false;
  const body = new URLSearchParams({secret,response:token});
  const ip = request.headers.get('CF-Connecting-IP');
  if (ip) body.set('remoteip', ip);
  const result = await fetcher('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    method: 'POST', body, redirect: 'error', signal: AbortSignal.timeout(6000)
  });
  if (!result.ok) throw Error('Verification provider unavailable');
  const data = await result.json();
  return data.success === true && data.hostname === HOST && data.action === 'lab_admission';
}
async function serve(request, env, fetcher) {
  const url = new URL(request.url);
  const method = request.method;
  const path = url.pathname;
  if (url.origin !== ORIGIN) return method === 'GET' || method === 'HEAD' ? redirect(ORIGIN + '/') : response('Forbidden', 403);
  if (method === 'GET' || method === 'HEAD') {
    // Old bookmarks or in-flight HTML may request a previous content hash.
    // Redirect without caching that redirect; only exact immutable bytes get a long cache lifetime.
    const source = path.replace(/\.[0-9a-f]{16}(?=\.[^./]+$)/, '');
    if (Object.hasOwn(ASSET_URLS, source)) {
      const current = ASSET_URLS[source];
      if (path !== current) return redirect(current);
      const result = await env.ASSETS.fetch(request);
      if (!result.ok || path === source) return result;
      const headers = new Headers(result.headers);
      headers.set('Cache-Control', 'public, max-age=31536000, immutable');
      return new Response(result.body, { status: result.status, headers });
    }
    if (path === '/exit' && !(request.headers.get('Cookie') || '').split(';').some(c => c.trim().startsWith(COOKIE + '='))) {
      return documentResponse('/exit', method);
    }
  }
  const posts = ['/access/accept', '/access/decline', '/access/leave', '/access/verify'];
  const mode = env.BOT_CONTROL;
  const turnstile = mode === 'turnstile';
  if ((!turnstile && mode !== 'managed_challenge') || !env.LAB_EVENTS ||
      (turnstile && (!/^[A-Za-z0-9_-]{8,120}$/.test(env.TURNSTILE_SITE_KEY || '') || !env.TURNSTILE_SECRET_KEY)))
    return response('Lab admission is temporarily unavailable.', 503, { 'Retry-After': '120' });
  const now = Math.floor(Date.now()/1000);
  const db = env.LAB_EVENTS;
  const key = await keyFor(db, env.SESSION_SIGNING_KEY);
  const deny = async (message, status, headers) => {
    const known = Object.hasOwn(DOCUMENTS, path) || posts.includes(path) || path === '/challenge';
    await log(db, request, 'request_denied', known ? path : '/unknown', now);
    return response(message, status, headers);
  };
  if (posts.includes(path) ? method !== 'POST' : !['GET','HEAD'].includes(method))
    return deny('Method not allowed', 405, { Allow: posts.includes(path) ? 'POST' : 'GET, HEAD' });
  if (method === 'POST' && (request.headers.get('Origin') !== ORIGIN ||
      (request.headers.has('Sec-Fetch-Site') && request.headers.get('Sec-Fetch-Site') !== 'same-origin')))
    return deny('Forbidden', 403);
  const grant = await readGrant(request, db, key, now);
  if (path === '/exit') return grant?.stage === 'accepted' ? redirect('/') : documentResponse('/exit', method);
  if (path === '/access/leave' || path === '/access/decline') {
    const event = path.endsWith('leave') || grant?.stage === 'accepted' ? 'session_ended' : 'declined';
    const statements = grant ? [db.prepare('DELETE FROM admission_grants WHERE digest=?').bind(grant.digest)] : [];
    await db.batch([...statements, eventStatement(db, request, event, path, now), ...maintenance(db, now)]);
    return redirect('/exit', cookie('', 0));
  }
  if (path === '/access/verify') {
    if (!turnstile) return deny('Not found', 404);
    if (!await verifyBot(request, env.TURNSTILE_SECRET_KEY, fetcher)) {
      await log(db, request, 'bot_denied', path, now);
      return response('Connection verification failed. Return to /challenge to try again.', 403);
    }
    if (grant?.stage === 'accepted' || grant?.stage === 'notice') return redirect('/entry');
    const set = await issue(db, key, grant, 'bot', TEN_MINUTES, request, 'bot_passed', path, now);
    return set ? redirect('/entry', set) : response('Admission expired. Reopen the lab.', 403);
  }
  if (path === '/access/accept') {
    if (grant?.stage === 'accepted') return redirect('/');
    if (grant?.stage !== 'notice') return deny('Open the access notice before accepting.', 403);
    const set = await issue(db, key, grant, 'accepted', HOUR, request, 'accepted', path, now);
    return set ? redirect('/', set) : response('Admission expired. Reopen the lab.', 403);
  }
  if (path === '/challenge') return turnstile && !grant ? challenge(env.TURNSTILE_SITE_KEY, method === 'HEAD') : redirect('/entry');
  const resource = path === '/entry.html' || path === '/entry/' ? '/entry' : path === '/index.html' || path === '/index' ? '/' : path;
  if (!Object.hasOwn(DOCUMENTS, resource)) return deny('Not found', 404);
  if (resource === '/entry') {
    if (turnstile && !grant) return redirect('/challenge');
    if (method === 'HEAD') return documentResponse(resource, method);
    if (grant && grant.stage !== 'bot') {
      await log(db, request, 'notice', resource, now);
      return documentResponse(resource, method);
    }
    const set = await issue(db, key, grant, 'notice', TEN_MINUTES, request, 'notice', resource, now);
    return set ? documentResponse(resource, method,set) : response('Admission expired. Reopen the lab.',403);
  }
  if (grant?.stage !== 'accepted') {
    await log(db, request, 'admission_required', resource, now);
    return redirect(turnstile && !grant ? '/challenge' : '/entry');
  }
  await log(db, request, resource === '/' ? 'workspace' : 'evidence', resource, now);
  return documentResponse(resource, method);
}
async function handle(request, env, fetcher = fetch) {
  try { return await serve(request, env, fetcher); }
  catch { return response('Lab admission is temporarily unavailable.', 503, { 'Retry-After': '120' }); }
}
export default { fetch: (request, env) => handle(request,env) };
