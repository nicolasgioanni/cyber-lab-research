const view = document.querySelector('#view');
const panels = document.querySelectorAll('.disclosure');
const buttons = view.querySelectorAll('button');
view.hidden = false;
function updateView() {
  const technical = Array.from(panels).every(panel => panel.open);
  const overview = Array.from(panels).every(panel => !panel.open);
  for (const button of buttons) {
    button.setAttribute('aria-pressed', String(button.dataset.view === 'technical' ? technical : overview));
  }
}
for (const button of buttons) {
  button.addEventListener('click', () => {
    for (const panel of panels) panel.open = button.dataset.view === 'technical';
    updateView();
  });
}
for (const panel of panels) panel.addEventListener('toggle', updateView);
function revealFragment() {
  const section = Array.from(panels).find(panel => '#' + panel.id === location.hash);
  if (section) section.open = true;
}
revealFragment();
window.addEventListener('hashchange', revealFragment);
