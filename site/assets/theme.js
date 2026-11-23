/* A buildless version of Smart-Porfolio's theme picker and interactive shell. */
(() => {
  const root = document.documentElement;
  const key = 'portfolio-theme';
  const names = { system: 'System', navy: 'My mode', dark: 'Dark', light: 'Light' };
  const deviceDark = matchMedia('(prefers-color-scheme: dark)');
  const reduceMotion = matchMedia('(prefers-reduced-motion: reduce)');
  const finePointer = matchMedia('(hover: hover) and (pointer: fine)');
  let preference = 'navy';
  try {
    const saved = localStorage.getItem(key);
    if (Object.hasOwn(names, saved)) preference = saved;
  } catch { /* Disabled local storage still allows an in-page preference. */ }

  function paint() {
    const effective = preference === 'system' ? (deviceDark.matches ? 'dark' : 'light') : preference;
    root.dataset.theme = effective;
    const trigger = document.querySelector('.theme-switcher__trigger');
    trigger?.setAttribute('aria-label', 'Choose color theme. Current setting: ' + names[preference]);
    for (const option of document.querySelectorAll('[data-preference]')) {
      option.setAttribute('aria-pressed', String(option.dataset.preference === preference));
    }
  }
  paint();
  deviceDark.addEventListener('change', paint);
  window.addEventListener('storage', event => {
    if (event.key === key) {
      preference = Object.hasOwn(names, event.newValue) ? event.newValue : 'navy';
      paint();
    }
  });

  let menuTimer;
  function showMenu(open) {
    clearTimeout(menuTimer);
    const menu = document.querySelector('.theme-switcher');
    if (!menu) return;
    const popup = menu.querySelector('.theme-switcher__popover');
    menu.dataset.open = String(open);
    menu.querySelector('button').setAttribute('aria-expanded', String(open));
    popup.dataset.state = open ? 'open' : 'closed';
    popup.setAttribute('aria-hidden', String(!open));
    popup.inert = !open;
  }

  function footerExpanded(footer, expanded) {
    footer.dataset.footerState = expanded ? 'expanded' : 'compact';
    footer.classList.toggle('blob-footer--compact', !expanded);
    footer.classList.toggle('blob-footer--expanded', expanded);
    const button = footer.querySelector('button');
    const details = footer.querySelector('.blob-footer__details');
    button.setAttribute('aria-expanded', String(expanded));
    button.textContent = expanded ? 'Collapse' : 'Details';
    details.inert = !expanded;
    details.setAttribute('aria-hidden', String(!expanded));
  }
  let lastY = 0;
  let nearHeader = false;
  let compact = false;
  let manuallyCollapsed = false;
  function updateHeader() {
    const header = document.querySelector('.blob-header');
    if (!header || document.querySelector('.theme-switcher[data-open="true"]')) return;
    const shrink = innerWidth > 980 && compact && !nearHeader;
    header.classList.toggle('blob-header--compact', shrink);
    header.dataset.headerState = shrink ? 'compact' : 'expanded';
  }
  window.addEventListener('pointermove', event => {
    const near = finePointer.matches && event.clientY <= 128;
    if (near !== nearHeader) { nearHeader = near; updateHeader(); }
  }, { passive: true });
  window.addEventListener('scroll', () => {
    const y = window.scrollY;
    const delta = y - lastY;
    if (y <= 72 || delta < -4) compact = false;
    if (y > 72 && delta > 4) compact = true;
    updateHeader();
    const footer = document.querySelector('.blob-footer');
    if (footer && !footer.closest('[inert]')) {
      const box = footer.querySelector('.blob-footer__runway-sentinel').getBoundingClientRect();
      if (delta > 0 && box.top >= 0 && box.bottom <= innerHeight && !manuallyCollapsed) footerExpanded(footer, true);
      if (delta < 0 && box.top >= innerHeight && !footer.contains(document.activeElement)) {
        manuallyCollapsed = false;
        footerExpanded(footer, false);
      }
    }
    lastY = y;
  }, { passive: true });

  document.addEventListener('click', event => {
    const item = event.target.closest('[data-preference]');
    if (item) {
      preference = item.dataset.preference;
      try { localStorage.setItem(key, preference); } catch { /* Optional persistence. */ }
      if (document.startViewTransition && !reduceMotion.matches) document.startViewTransition(paint);
      else paint();
      return;
    }
    if (event.target.closest('.theme-switcher__trigger')) {
      const menu = event.target.closest('.theme-switcher');
      showMenu(finePointer.matches || menu.dataset.open !== 'true');
    } else if (!event.target.closest('.theme-switcher')) showMenu(false);
    const footerButton = event.target.closest('.blob-footer__toggle');
    if (footerButton) {
      const expanded = footerButton.getAttribute('aria-expanded') !== 'true';
      manuallyCollapsed = !expanded;
      footerExpanded(footerButton.closest('footer'), expanded);
    }
  });
  document.addEventListener('pointerover', event => {
    if (finePointer.matches && event.target.closest('.theme-switcher')) showMenu(true);
  });
  document.addEventListener('pointerout', event => {
    if (finePointer.matches && event.target.closest('.theme-switcher') && !event.relatedTarget?.closest?.('.theme-switcher')) {
      menuTimer = setTimeout(() => showMenu(false), 180);
    }
  });
  document.addEventListener('focusin', event => {
    const menu = event.target.closest('.theme-switcher');
    if (menu && finePointer.matches) showMenu(true);
    if (!menu) showMenu(false);
  });
  document.addEventListener('keydown', event => {
    const menu = document.querySelector('.theme-switcher[data-open="true"]');
    if (menu && event.key === 'Escape') {
      event.preventDefault();
      menu.querySelector('button').focus();
      showMenu(false);
    }
  });

  function initializeShell() {
    paint();
    const dialog = document.getElementById('visitor-dialog');
    if (dialog && !dialog.matches(':modal')) {
      if (dialog.open) dialog.close();
      dialog.dataset.state = 'opening';
      dialog.addEventListener('cancel', event => event.preventDefault());
      dialog.showModal();
      requestAnimationFrame(() => requestAnimationFrame(() => { dialog.dataset.state = 'open'; }));
    }
    const intro = document.querySelector('.motion-reveal');
    if (intro && !reduceMotion.matches && 'IntersectionObserver' in window) {
      intro.classList.add('motion-ready');
      const observer = new IntersectionObserver(entries => {
        if (entries.some(entry => entry.isIntersecting)) {
          intro.classList.add('is-visible');
          observer.disconnect();
        }
      });
      observer.observe(intro);
    }
    lastY = window.scrollY;
    manuallyCollapsed = false;
  }
  document.addEventListener('DOMContentLoaded', initializeShell, { once: true });
  document.addEventListener('lab:admitted', initializeShell);
})();
