(() => {
  'use strict';
  const byId = id => document.getElementById(id);
  const dialog = byId('visitor-dialog');
  if (!dialog) return;
  const check = byId('verification-stage');
  const notice = byId('notice-stage');
  const status = byId('verification-status');
  const retry = byId('verification-retry');
  const accept = byId('accept-entry');
  const encoder = new TextEncoder();
  let phase = 'checking';
  let pageKey;
  let publicKey;
  let keyId;
  let challenge;
  let widget;
  let timer;

  const base64 = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes)));
  const post = (path, options = {}) => fetch(path, {
    method: 'POST', credentials: 'same-origin', mode: 'same-origin', cache: 'no-store',
    redirect: 'error', referrerPolicy: 'same-origin', signal: AbortSignal.timeout(15000), ...options
  });

  function fail(message) {
    if (phase === 'leaving' || phase === 'admitted' || phase === 'failed') return;
    phase = 'failed';
    clearTimeout(timer);
    if (widget !== undefined) window.turnstile?.remove(widget);
    pageKey = null;
    challenge = null;
    check.hidden = false;
    notice.hidden = true;
    dialog.setAttribute('aria-labelledby', 'gate-title');
    dialog.setAttribute('aria-describedby', 'verification-status');
    status.textContent = message;
    retry.hidden = false;
    retry.focus({preventScroll: true});
  }
  async function verified(token) {
    if (phase !== 'checking') return;
    phase = 'verifying';
    clearTimeout(timer);
    try {
      const result = await post('/access/verify', {
        headers: {'Content-Type': 'application/json'}, body: JSON.stringify({token, publicKey})
      });
      if (result.headers.get('cf-mitigated') === 'challenge') {
        fail('Cloudflare requested another browser check. Restart verification to continue.');
        return;
      }
      if (result.status === 503) {
        fail('The lab verification service is temporarily unavailable. Try again shortly.');
        return;
      }
      if (!result.ok) {
        fail('The lab could not confirm this browser check. Restart verification for a fresh check.');
        return;
      }
      challenge = await result.json();
      if (challenge.keyId !== keyId || !/^[a-f0-9]{64}$/.test(challenge.nonce)) throw Error();
      if (phase !== 'verifying') return;
      phase = 'notice';
      if (widget !== undefined) window.turnstile.remove(widget);
      widget = undefined;
      check.hidden = true;
      notice.hidden = false;
      dialog.setAttribute('aria-labelledby', 'notice-title');
      dialog.setAttribute('aria-describedby', 'notice-intro');
      byId('notice-title').focus({preventScroll: true});
    } catch {
      fail('The browser check could not be verified. Try again to continue.');
    }
  }
  function loadWidget() {
    return new Promise((resolve, reject) => {
      if (window.turnstile) { resolve(window.turnstile); return; }
      window.labTurnstileReady = () => { delete window.labTurnstileReady; resolve(window.turnstile); };
      const script = document.createElement('script');
      script.async = true;
      script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit&onload=labTurnstileReady';
      script.addEventListener('error', reject, {once:true});
      document.head.append(script);
    });
  }
  async function start() {
    timer = setTimeout(() => fail('The browser check timed out. Try again to continue.'), 60000);
    try {
      const [turnstile, keys] = await Promise.all([loadWidget(),
        crypto.subtle.generateKey({name:'ECDSA', namedCurve:'P-256'}, false, ['sign','verify'])]);
      if (phase !== 'checking') return;
      // The private key stays non-exportable in this document's memory, including across the notice.
      pageKey = keys.privateKey;
      const raw = await crypto.subtle.exportKey('raw', keys.publicKey);
      publicKey = base64(raw);
      keyId = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',raw)),
        byte => byte.toString(16).padStart(2,'0')).join('');
      const theme = document.documentElement.dataset.theme === 'light' ? 'light' : 'dark';
      widget = turnstile.render(byId('turnstile-widget'), {
        sitekey: document.body.dataset.sitekey, action: 'lab_admission', cData: keyId,
        appearance: 'always', execution: 'render', theme,
        size: byId('turnstile-widget').clientWidth < 300 ? 'compact' : 'flexible', retry: 'never',
        'response-field': false, callback: verified,
        'error-callback': () => { fail('Cloudflare could not complete the browser check. Try again to continue.'); return true; },
        'expired-callback': () => fail('The browser check expired. Restart verification.'),
        'unsupported-callback': () => fail('This browser could not complete verification. Try a supported browser.')
      });
    } catch {
      fail('The browser check could not start. Check your connection and try again.');
    }
  }
  async function enter() {
    if (phase !== 'notice') return;
    phase = 'accepting';
    accept.disabled = true;
    try {
      const params = '("@method" "@target-uri");keyid="' + keyId + '";nonce="' + challenge.nonce +
        '";alg="ecdsa-p256-sha256"';
      const signed = '"@method": POST\n"@target-uri": ' + challenge.target + '\n"@signature-params": ' + params;
      const signature = await crypto.subtle.sign({name:'ECDSA', hash:'SHA-256'},pageKey,encoder.encode(signed));
      const result = await post('/access/accept', {headers:{
        'Signature-Input': 'lab=' + params, Signature: 'lab=:' + base64(signature) + ':'
      }});
      if (!result.ok || !result.headers.get('Content-Type')?.startsWith('text/html')) throw Error();
      const html = await result.text();
      if (phase !== 'accepting') return;
      const page = new DOMParser().parseFromString(html, 'text/html');
      pageKey = null;
      challenge = null;
      phase = 'admitted';
      dialog.close();
      document.title = page.title;
      const description = page.querySelector('meta[name="description"]');
      if (description) document.querySelector('meta[name="description"]').content = description.content;
      document.body.replaceWith(document.adoptNode(page.body));
      history.replaceState(null,'','/');
      document.dispatchEvent(new Event('lab:admitted'));
      const heading = document.querySelector('main h1');
      if (heading) { heading.tabIndex = -1; heading.focus({preventScroll:true}); }
      window.scrollTo(0,0);
      timer = setTimeout(() => location.replace('/verify'), 3600000);
    } catch {
      fail('Your admission expired or could not be confirmed. Restart verification to enter.');
    }
  }

  retry.addEventListener('click', () => location.replace('/verify'));
  accept.addEventListener('click', enter);
  byId('decline-entry').addEventListener('click', async () => {
    phase = 'leaving';
    clearTimeout(timer);
    pageKey = null;
    try { await post('/access/decline', {headers: keyId ? {'X-Lab-Visit':keyId} : {}}); }
    catch { /* The temporary grant also expires if the connection is lost. */ }
    location.replace('/exit');
  });
  dialog.addEventListener('cancel', event => event.preventDefault());
  // Some browsers retain no-store pages in their back/forward cache. Discard rendered content on departure.
  window.addEventListener('pagehide', () => {
    phase = 'leaving';
    clearTimeout(timer);
    pageKey = null;
    challenge = null;
    document.body.replaceChildren();
  });
  window.addEventListener('pageshow', event => { if (event.persisted) location.replace('/verify'); });
  start();
})();
