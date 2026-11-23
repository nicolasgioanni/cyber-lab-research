(() => {
  const preferenceKey = 'cyber-lab-color-mode';
  let mode = 'dark';
  try {
    if (localStorage.getItem(preferenceKey) === 'light') mode = 'light';
  } catch { /* Storage is optional. */ }
  document.documentElement.dataset.theme = mode;

  document.addEventListener('DOMContentLoaded', () => {
    const picker = document.querySelector('.theme-picker');
    if (picker) {
      picker.hidden = false;
      const options = picker.querySelectorAll('input');
      for (const option of options) {
        option.checked = option.value === mode;
        option.addEventListener('change', () => {
          if (!option.checked) return;
          mode = option.value;
          document.documentElement.dataset.theme = mode;
          try { localStorage.setItem(preferenceKey, mode); } catch { /* Storage is optional. */ }
        });
      }
    }

    const dialog = document.querySelector('#visitor-dialog');
    if (!dialog || typeof dialog.showModal !== 'function') return;
    dialog.addEventListener('cancel', event => event.preventDefault());
    dialog.removeAttribute('open');
    try {
      dialog.showModal();
    } catch {
      dialog.setAttribute('open', '');
    }
  });
})();
