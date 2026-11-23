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
  const researchPaths = ['/', '/agents', '/validation', '/retrieval'];
  const policyPaths = ['/access-notice', '/privacy', '/cookies', '/terms', '/security', '/ai-disclosure'];
  const revision = document.body.dataset.policyRevision;
  const requested = '/' + (new URL(location.href).searchParams.get('view') || '');
  const initialPath = researchPaths.includes(requested) ? requested : '/';
  let phase = 'checking';
  let pageKey;
  let publicKey;
  let keyId;
  let challenge;
  let widget;
  let timer;
  let sessionDeadline = 0;
  let lastResearchPath = initialPath;
  let disposeNavigation;

  function gateUrl(path = initialPath, hash = location.hash) {
    const route = researchPaths.includes(path) ? path : '/';
    const query = route === '/' ? '' : '?view=' + route.slice(1);
    return '/verify' + query + (route === '/validation' && hash === '#study' ? hash : '');
  }

  function discard() {
    phase = 'leaving';
    clearTimeout(timer);
    pageKey = null;
    challenge = null;
    disposeNavigation?.();
    disposeNavigation = null;
    document.body.replaceChildren();
  }

  function restart() {
    const path = location.pathname;
    discard();
    // An expired reader on a policy may finish reading its public, standalone document.
    const researchPath = researchPaths.includes(path) ? path : lastResearchPath;
    const destination = policyPaths.includes(path) ? path + location.hash : gateUrl(researchPath);
    if (destination === location.pathname + location.search + location.hash) location.reload();
    else location.replace(destination);
  }

  function sessionActive() {
    if (phase !== 'admitted') return false;
    if (Date.now() < sessionDeadline) return true;
    restart();
    return false;
  }

  const base64 = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes)));
  const post = (path, options = {}) => fetch(path, {
    method: 'POST', credentials: 'same-origin', mode: 'same-origin', cache: 'no-store',
    redirect: 'error', referrerPolicy: 'same-origin', signal: AbortSignal.timeout(15000), ...options
  });

  function fail(message, retryAfterSeconds = 0) {
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
    retry.disabled = retryAfterSeconds > 0;
    if (retry.disabled) {
      byId('gate-title').focus({preventScroll: true});
      timer = setTimeout(() => {
        retry.disabled = false;
        status.textContent = 'You can restart verification now.';
      }, retryAfterSeconds * 1000);
    } else {
      retry.focus({preventScroll: true});
    }
  }

  function handleRateLimit(result) {
    if (result.status !== 429) return false;
    const header = (result.headers.get('Retry-After') || '').trim();
    const seconds = /^\d+$/.test(header) ? Number(header) : Math.ceil((Date.parse(header) - Date.now()) / 1000);
    const wait = Number.isFinite(seconds) ? Math.max(0, seconds) : 10;
    const when = wait > 0 ? `in ${wait} second${wait === 1 ? '' : 's'}` : 'now';
    fail(`Too many admission requests from this connection. You can restart verification ${when}.`, wait);
    return true;
  }
  async function verified(token) {
    if (phase !== 'checking') return;
    phase = 'verifying';
    clearTimeout(timer);
    try {
      const result = await post('/access/verify', {
        headers: {'Content-Type': 'application/json'}, body: JSON.stringify({token, publicKey})
      });
      if (handleRateLimit(result)) return;
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
      if (challenge.policyRevision !== revision) { restart(); return; }
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

  function attachNavigation(main) {
    // Keep only the current view in the DOM. The other admitted views live in this
    // document's memory; nothing containing research or admission is written to history.
    const views = new Map(Array.from(main.querySelectorAll('[data-research-view]'),
      element => [element.dataset.researchView, element]));
    if (!researchPaths.every(path => views.has(path))) throw Error('Incomplete research document');
    const listeners = new AbortController();
    const signal = listeners.signal;
    let request;
    let serial = 0;
    let nextEntry = 0;
    let entry = 0;
    let currentPath;
    const scrollPositions = new Map();
    history.scrollRestoration = 'manual';

    async function navigate(url, mode) {
      if (!sessionActive()) return;
      const turn = ++serial;
      request?.abort();
      request = null;
      const path = url.pathname;
      const view = views.get(path);
      let nodes, title, description;
      if (view) {
        nodes = [view];
        title = view.dataset.title || ((path === '/' ? 'Home' : path[1].toUpperCase() + path.slice(2)) + ' · Research Lab');
        description = view.querySelector('.page-description, h1 + p')?.textContent;
      } else if (policyPaths.includes(path)) {
        if (path !== currentPath) {
          request = new AbortController();
          try {
            const result = await fetch(path, {
              credentials: 'same-origin', mode: 'same-origin', cache: 'no-store', redirect: 'error',
              headers: {Accept: 'text/html'}, signal: request.signal
            });
            if (!result.ok || !result.headers.get('Content-Type')?.startsWith('text/html')) throw Error();
            const policy = new DOMParser().parseFromString(await result.text(), 'text/html');
            const policyMain = policy.querySelector('main');
            if (!policyMain?.querySelector('h1') || policy.querySelector('#visitor-dialog, [data-research-view]')) throw Error();
            nodes = Array.from(policyMain.children);
            title = policy.title;
            description = policy.querySelector('meta[name="description"]')?.content;
          } catch {
            if (turn === serial && !signal.aborted) {
              if (mode === 'push') location.assign(url.href);
              else location.replace(url.href);
            }
            return;
          }
        }
      } else {
        location.replace(url.href);
        return;
      }
      if (turn !== serial || !sessionActive()) return;
      const previousPath = currentPath;
      scrollPositions.set(entry, window.scrollY);
      if (mode === 'push') {
        entry = ++nextEntry;
        history.pushState({labEntry: entry}, '', url);
      } else if (mode === 'replace') {
        history.replaceState({labEntry: entry}, '', url);
      } else {
        entry = history.state?.labEntry ?? 0;
      }
      currentPath = path;
      if (view) {
        lastResearchPath = path;
        view.hidden = false;
      }
      if (nodes && previousPath !== path) main.replaceChildren(...nodes);
      document.body.classList.toggle('policy-page', !view);
      document.body.classList.toggle('workspace-page', Boolean(view));
      if (title) document.title = title;
      const meta = document.querySelector('meta[name="description"]');
      if (meta && description) meta.content = description;
      document.dispatchEvent(new Event('lab:navigate'));
      const target = (url.hash && document.getElementById(url.hash.slice(1))) || main.querySelector('h1');
      if (target && main.contains(target)) {
        target.tabIndex = -1;
        target.focus({preventScroll: true});
      }
      if (mode === 'pop' && scrollPositions.has(entry)) {
        window.scrollTo({top: scrollPositions.get(entry), behavior: 'instant'});
      } else if (url.hash && target && main.contains(target)) {
        target.scrollIntoView({behavior: 'instant', block: 'start'});
      } else window.scrollTo({top: 0, behavior: 'instant'});
    }

    document.addEventListener('click', event => {
      if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
      const link = event.target.closest?.('a[href]');
      if (!link || link.hasAttribute('download') || (link.target && link.target !== '_self')) return;
      const url = new URL(link.href);
      if (url.origin !== location.origin || url.search ||
          !(views.has(url.pathname) || policyPaths.includes(url.pathname))) return;
      event.preventDefault();
      navigate(url, url.href === location.href ? 'replace' : 'push');
    }, {signal});
    window.addEventListener('popstate', () => navigate(new URL(location.href), 'pop'), {signal});
    const hash = initialPath === '/validation' && location.hash === '#study' ? '#study' : '';
    navigate(new URL(initialPath + hash, location.origin), 'replace');
    return () => {
      serial++;
      listeners.abort();
      request?.abort();
      views.clear();
      scrollPositions.clear();
    };
  }

  async function enter() {
    if (phase !== 'notice') return;
    phase = 'accepting';
    accept.disabled = true;
    try {
      const params = '("@method" "@target-uri" "x-lab-policy-revision");keyid="' + keyId + '";nonce="' + challenge.nonce +
        '";alg="ecdsa-p256-sha256"';
      const signed = '"@method": POST\n"@target-uri": ' + challenge.target +
        '\n"x-lab-policy-revision": ' + revision + '\n"@signature-params": ' + params;
      const signature = await crypto.subtle.sign({name:'ECDSA', hash:'SHA-256'},pageKey,encoder.encode(signed));
      const startTime = Date.now();
      const result = await post('/access/accept', {headers:{
        'Signature-Input': 'lab=' + params, Signature: 'lab=:' + base64(signature) + ':', 'X-Lab-Policy-Revision': revision
      }});
      if (phase !== 'accepting') return;
      if (handleRateLimit(result)) return;
      if (result.status === 409) { restart(); return; }
      if (!result.ok || !result.headers.get('Content-Type')?.startsWith('text/html')) throw Error();
      const html = await result.text();
      if (phase !== 'accepting') return;
      const page = new DOMParser().parseFromString(html, 'text/html');
      const main = page.querySelector('main');
      if (!researchPaths.every(path => main?.querySelector(`[data-research-view="${path}"]`))) throw Error();
      const seconds = Number(result.headers.get('X-Lab-Session-Seconds') || 3600);
      if (!Number.isFinite(seconds) || seconds <= 0) throw Error();
      sessionDeadline = startTime + Math.min(seconds, 3600) * 1000;
      pageKey = null;
      challenge = null;
      phase = 'admitted';
      dialog.close();
      document.title = page.title;
      const description = page.querySelector('meta[name="description"]');
      if (description) document.querySelector('meta[name="description"]').content = description.content;
      document.body.replaceWith(document.adoptNode(page.body));
      disposeNavigation = attachNavigation(main);
      document.dispatchEvent(new Event('lab:admitted'));
      timer = setTimeout(restart, Math.max(0, sessionDeadline - Date.now()));
    } catch {
      fail('Your admission expired or could not be confirmed. Restart verification to enter.');
    }
  }

  retry.addEventListener('click', restart);
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
  window.addEventListener('pagehide', discard);
  window.addEventListener('pageshow', event => { if (event.persisted) restart(); });
  window.addEventListener('focus', sessionActive);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) sessionActive(); });
  start();
})();
