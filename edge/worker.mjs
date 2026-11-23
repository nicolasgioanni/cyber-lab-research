// The Pages package exposes only presentation assets. Both documents live in the Worker.
const DOCUMENTS = /* PACK:DOCUMENTS */ null;
const SCHEMA = /* PACK:SCHEMA */ null;
const ASSET_URLS = /* PACK:ASSETS */ null;
const HOST = 'lab.nicolasmgioanni.dev';
const ORIGIN = 'https://' + HOST;
const ACCEPT = '/access/accept';
const VERIFY = '/access/verify';
const DECLINE = '/access/decline';
const POST_PATHS = [ACCEPT, VERIFY, DECLINE];
const COOKIE_PREFIX = '__Host-lab_visit_';
const WEEK = 7 * 86400;
const HOUR = 3600;
const NOTICE_TTL = 600;
const text = new TextEncoder();
const schemas = new WeakMap();
const CSP = "default-src 'none'; style-src 'self'; script-src 'self' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; connect-src 'self'; font-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

function response(body, status = 200, headers = {}) {
  return new Response(body, { status, headers: {
    'Content-Type': 'text/plain; charset=utf-8', 'Content-Security-Policy': CSP,
    'Cache-Control': 'private, no-store', 'Cloudflare-CDN-Cache-Control': 'no-store',
    'Referrer-Policy': 'same-origin', 'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY', 'Permissions-Policy': 'camera=(), microphone=(), geolocation=()', ...headers
  } });
}
function redirect(location) { return response(null, 303, {Location: location}); }
function documentResponse(html, method, headers) {
  return response(method === 'HEAD' ? null : html, 200, {'Content-Type': 'text/html; charset=utf-8', ...headers});
}
function cookie(keyId, value) {
  return COOKIE_PREFIX + keyId + '=' + value + '; Path=/; Secure; HttpOnly; SameSite=Strict' +
    (value === '' ? '; Max-Age=0' : '');
}
// Cookie names are tab-specific so two first visits cannot overwrite one another.
// Browsers send same-path cookies in creation order. Retire the oldest abandoned
// handles once twelve concurrently pending notices would otherwise be exceeded.
function limitPendingCookies(request, result) {
  const names = new Set();
  for (const part of (request.headers.get('Cookie') || '').split(';')) {
    const match = /^__Host-lab_visit_([a-f0-9]{64})=/.exec(part.trim());
    if (match) names.add(match[1]);
  }
  for (const name of Array.from(names).slice(0, Math.max(0, names.size - 11))) {
    result.headers.append('Set-Cookie', cookie(name, ''));
  }
  return result;
}
function cookieValue(request, keyId) {
  const prefix = COOKIE_PREFIX + keyId + '=';
  const values = (request.headers.get('Cookie') || '').split(';').map(value => value.trim())
    .filter(value => value.startsWith(prefix)).map(value => value.slice(prefix.length));
  return values.length === 1 && /^[a-f0-9]{64}$/.test(values[0]) ? values[0] : null;
}
function hex(data) { return Array.from(new Uint8Array(data), byte => byte.toString(16).padStart(2, '0')).join(''); }
function random() { return hex(crypto.getRandomValues(new Uint8Array(32))); }
async function digest(data) { return hex(await crypto.subtle.digest('SHA-256', data)); }
function fromBase64(value) { return Uint8Array.from(atob(value), character => character.charCodeAt(0)); }
const algorithm = {name: 'ECDSA', namedCurve: 'P-256'};

async function prepareDatabase(db) {
  if (!schemas.has(db)) {
    const pending = db.batch(SCHEMA.map(statement => db.prepare(statement))).catch(error => {
      schemas.delete(db);
      throw error;
    });
    schemas.set(db, pending);
  }
  await schemas.get(db);
}
function eventFields(request, event, path, now) {
  const ip = request.headers.get('CF-Connecting-IP') || '';
  const country = request.cf?.country || '';
  const ua = (request.headers.get('User-Agent') || '').replace(/[\x00-\x1f\x7f]/g, ' ').slice(0, 240);
  return [now, event, path, /^[0-9a-f.:]{2,45}$/i.test(ip) ? ip : null,
    /^[A-Z]{2}$/.test(country) ? country : null, ua || null];
}
const eventInsert = 'INSERT INTO access_events(at,event,path,ip,country,user_agent) ';
function eventStatement(db, request, event, path, now) {
  return db.prepare(eventInsert + 'VALUES(?,?,?,?,?,?)').bind(...eventFields(request,event,path,now));
}
function maintenance(db, now) {
  // Proofs expire with their parent grants, including when the independent hourly job runs.
  return [
    db.prepare('DELETE FROM access_events WHERE at<=?').bind(now - WEEK),
    db.prepare('DELETE FROM access_events WHERE id <= (SELECT max(id)-25000 FROM access_events)'),
    db.prepare('DELETE FROM admission_grants WHERE expires<=?').bind(now),
    db.prepare('DELETE FROM admission_grants WHERE id <= (SELECT max(id)-25000 FROM admission_grants)'),
  ];
}
async function record(db, request, event, path, now) {
  await db.batch([eventStatement(db, request, event, path, now), ...maintenance(db, now)]);
}
async function verificationInput(request) {
  if (!request.body || !/^application\/json(?:\s*;|$)/i.test(request.headers.get('Content-Type') || '')) return null;
  const reader = request.body.getReader();
  const chunks = [];
  let size = 0;
  for (;;) {
    const {value, done} = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > 4096) { await reader.cancel(); return null; }
    chunks.push(value);
  }
  try {
    const {token, publicKey} = JSON.parse(await new Blob(chunks).text());
    if (typeof token !== 'string' || token.length < 1 || token.length > 2048 ||
        typeof publicKey !== 'string' || !/^[A-Za-z0-9+/]{87}=$/.test(publicKey)) return null;
    const rawKey = fromBase64(publicKey);
    if (rawKey.length !== 65 || rawKey[0] !== 4) return null;
    await crypto.subtle.importKey('raw', rawKey, algorithm, false, ['verify']);
    return {token, publicKey, keyId: await digest(rawKey)};
  } catch { return null; }
}
async function verifyBot(request, secret, input, fetcher) {
  const body = new URLSearchParams({secret, response: input.token});
  const ip = request.headers.get('CF-Connecting-IP');
  if (ip) body.set('remoteip', ip);
  const result = await fetcher('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    method: 'POST', body, redirect: 'error', signal: AbortSignal.timeout(8000)
  });
  if (!result.ok) throw Error('Verification provider unavailable');
  const data = await result.json();
  return data.success === true && data.hostname === HOST && data.action === 'lab_admission' &&
    data.cdata === input.keyId;
}
async function issueNotice(db, request, input, now) {
  const secret = random();
  const cookieHash = await digest(text.encode(secret));
  const nonce = random();
  const results = await db.batch([
    // A key is bound to one verified page. D1 serializes concurrent token redemptions.
    db.prepare("INSERT INTO admission_grants(digest,stage,expires) SELECT ?,'notice',? WHERE NOT EXISTS (SELECT 1 FROM admission_proofs WHERE key_id=?)")
      .bind(cookieHash, now + NOTICE_TTL, input.keyId),
    db.prepare('INSERT INTO admission_proofs(grant_digest,key_id,public_key,nonce) SELECT digest,?,?,? FROM admission_grants WHERE digest=?')
      .bind(input.keyId, input.publicKey, nonce, cookieHash),
    db.prepare(eventInsert + 'SELECT ?,?,?,?,?,? WHERE EXISTS (SELECT 1 FROM admission_proofs WHERE grant_digest=?)')
      .bind(...eventFields(request,'notice',VERIFY,now), cookieHash), ...maintenance(db, now)
  ]);
  if (results[0].meta.changes !== 1) return response('Verification already used. Reopen the lab.', 409);
  return limitPendingCookies(request, response(JSON.stringify({keyId: input.keyId, nonce, target: ORIGIN + ACCEPT}), 200, {
    'Content-Type': 'application/json', 'Set-Cookie': cookie(input.keyId, secret)
  }));
}

// RFC 9421 profile: fixed method/target components, one key per page and a single-use server nonce.
const signatureInput = /^lab=\("@method" "@target-uri"\);keyid="([a-f0-9]{64})";nonce="([a-f0-9]{64})";alg="ecdsa-p256-sha256"$/;
async function accept(db, request, now) {
  const header = request.headers.get('Signature-Input') || '';
  const params = signatureInput.exec(header);
  const signature = /^lab=:([A-Za-z0-9+/]{86}==):$/.exec(request.headers.get('Signature') || '');
  if (!params || !signature) return null;
  const [,keyId,nonce] = params;
  const secret = cookieValue(request, keyId);
  if (!secret) return null;
  const cookieHash = await digest(text.encode(secret));
  const row = await db.prepare(`SELECT p.public_key FROM admission_proofs p JOIN admission_grants g ON p.grant_digest=g.digest
    WHERE g.digest=? AND g.stage='notice' AND g.expires>? AND p.key_id=? AND p.nonce=?`)
    .bind(cookieHash, now, keyId, nonce).first();
  if (!row) return null;
  const publicKey = await crypto.subtle.importKey('raw', fromBase64(row.public_key), algorithm, false, ['verify']);
  const signed = '"@method": POST\n"@target-uri": ' + request.url + '\n"@signature-params": ' + header.slice(4);
  const valid = await crypto.subtle.verify({name:'ECDSA', hash:'SHA-256'}, publicKey,
    fromBase64(signature[1]), text.encode(signed));
  if (!valid) return null;
  const receipt = random();
  const results = await db.batch([
    db.prepare(`UPDATE admission_proofs SET nonce=? WHERE grant_digest=? AND nonce=? AND EXISTS
      (SELECT 1 FROM admission_grants WHERE digest=? AND stage='notice' AND expires>?)`).bind(receipt,cookieHash,nonce,cookieHash,now),
    db.prepare(`UPDATE admission_grants SET stage='accepted', expires=? WHERE digest=? AND EXISTS
      (SELECT 1 FROM admission_proofs WHERE grant_digest=? AND nonce=?)`).bind(now + HOUR,cookieHash,cookieHash,receipt),
    db.prepare(eventInsert + 'SELECT ?,?,?,?,?,? WHERE EXISTS (SELECT 1 FROM admission_proofs WHERE grant_digest=? AND nonce=?)')
      .bind(...eventFields(request,'accepted',ACCEPT,now),cookieHash,receipt), ...maintenance(db,now)
  ]);
  if (results[0].meta.changes !== 1) return null;
  // No bearer grant survives acceptance. The reviewed document is delivered in this response only.
  return documentResponse(DOCUMENTS['/'], 'POST', {'Set-Cookie': cookie(keyId, '')});
}
async function decline(db, request, now) {
  const keyId = request.headers.get('X-Lab-Visit') || '';
  const secret = /^[a-f0-9]{64}$/.test(keyId) && cookieValue(request, keyId);
  const statements = [];
  if (secret) {
    const cookieHash = await digest(text.encode(secret));
    statements.push(db.prepare('DELETE FROM admission_grants WHERE digest=? AND stage=\'notice\' AND EXISTS (SELECT 1 FROM admission_proofs WHERE grant_digest=? AND key_id=?)')
      .bind(cookieHash,cookieHash,keyId));
  }
  await db.batch([...statements, eventStatement(db,request,'declined',DECLINE,now), ...maintenance(db,now)]);
  return response(null, 204, secret ? {'Set-Cookie':cookie(keyId,'')} : {});
}
async function serve(request, env, fetcher) {
  const url = new URL(request.url);
  const {method} = request;
  const path = url.pathname;
  const read = method === 'GET' || method === 'HEAD';
  if (url.origin !== ORIGIN) return read ? redirect(ORIGIN + '/verify') : response('Forbidden',403);
  if (read) {
    // Old documents can request a previous fingerprint; only immutable, current bytes are cached.
    const source = path.replace(/\.[0-9a-f]{16}(?=\.[^./]+$)/, '');
    if (Object.hasOwn(ASSET_URLS, source)) {
      const current = ASSET_URLS[source];
      if (path !== current) return redirect(current);
      const result = await env.ASSETS.fetch(request);
      if (!result.ok || path === source) return result;
      const headers = new Headers(result.headers);
      headers.set('Cache-Control', 'public, max-age=31536000, immutable');
      return new Response(result.body, {status:result.status, headers});
    }
    if (path === '/exit') return documentResponse(DOCUMENTS['/exit'], method);
  }
  const db = env.LAB_EVENTS;
  if (!db || env.BOT_CONTROL !== 'turnstile' ||
      !/^[A-Za-z0-9_-]{8,120}$/.test(env.TURNSTILE_SITE_KEY || '') || !env.TURNSTILE_SECRET_KEY)
    return response('Lab admission is temporarily unavailable.',503,{'Retry-After':'120'});
  await prepareDatabase(db);
  const now = Math.floor(Date.now()/1000);
  const deny = async (message, status, headers = {}) => {
    await record(db,request,'request_denied',POST_PATHS.includes(path) ? path : '/unknown',now);
    return response(message,status,headers);
  };
  if (POST_PATHS.includes(path) ? method !== 'POST' : !read)
    return deny('Method not allowed',405,{Allow:POST_PATHS.includes(path) ? 'POST' : 'GET, HEAD'});
  if (method === 'POST' && (url.search || request.headers.get('Origin') !== ORIGIN ||
      (request.headers.has('Sec-Fetch-Site') && request.headers.get('Sec-Fetch-Site') !== 'same-origin')))
    return deny('Forbidden',403);
  if (path === VERIFY) {
    const input = await verificationInput(request);
    if (!input || !await verifyBot(request, env.TURNSTILE_SECRET_KEY, input, fetcher)) {
      await record(db,request,'bot_denied',VERIFY,now);
      return response('Browser verification failed. Restart verification.',403);
    }
    return issueNotice(db,request,input,now);
  }
  if (path === ACCEPT) return await accept(db,request,now) || deny('Admission expired or proof invalid. Restart verification.',403);
  if (path === DECLINE) return decline(db,request,now);
  if (path === '/verify') {
    if (method === 'GET') await record(db,request,'verification_opened','/verify',now);
    const html = DOCUMENTS['/entry'].replace('__TURNSTILE_SITEKEY__',env.TURNSTILE_SITE_KEY);
    // The retired one-hour cookie from the previous site can never authorize a request here.
    const clear = /(?:^|;\s*)__Host-lab_access=/.test(request.headers.get('Cookie') || '');
    return documentResponse(html,method,clear ? {'Set-Cookie':'__Host-lab_access=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0'} : {});
  }
  if (path.startsWith('/assets/') || path.startsWith('/_')) return response('Not found',404);
  return redirect('/verify');
}
async function handle(request, env, fetcher = fetch) {
  try { return await serve(request,env,fetcher); }
  catch { return response('Lab admission is temporarily unavailable.',503,{'Retry-After':'120'}); }
}
export default {fetch: (request, env) => handle(request,env)};
