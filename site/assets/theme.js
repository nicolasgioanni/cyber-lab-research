(() => {
  const savedKey = 'portfolio-theme';
  const options = new Set(['system', 'light', 'navy', 'dark']);
  const system = window.matchMedia('(prefers-color-scheme: dark)');
  let selected = 'system';
  try {
    const saved = localStorage.getItem(savedKey);
    if (options.has(saved)) selected = saved;
  } catch { /* A preference still works for this page with storage disabled. */ }
  function apply() {
    document.documentElement.dataset.theme = selected === 'system'
      ? (system.matches ? 'dark' : 'light') : selected;
  }
  apply();
  system.addEventListener('change', apply);
  document.addEventListener('DOMContentLoaded', () => {
    const menu = document.querySelector('#appearance');
    const toggle = menu.querySelector('summary');
    menu.hidden = false;
    for (const radio of menu.querySelectorAll('input')) {
      radio.checked = radio.value === selected;
      radio.addEventListener('change', () => {
        selected = radio.value;
        apply();
        try { localStorage.setItem(savedKey, selected); } catch { /* Optional storage. */ }
        menu.open = false;
        toggle.focus();
      });
    }
    document.addEventListener('keydown', event => {
      if (event.key === 'Escape' && menu.open) { menu.open = false; toggle.focus(); }
    });
    document.addEventListener('click', event => {
      if (!menu.contains(event.target)) menu.open = false;
    });
  });
})();
