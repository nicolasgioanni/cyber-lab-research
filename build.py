"""Render the buildless public site from reviewed measurements only."""
import hashlib
import json
from pathlib import Path
from html import escape

from policies import NOTICE_AGREEMENT, POLICY_REVISION, POLICY_TITLES, build_policies, notice_html

ROOT = Path(__file__).resolve().parent
SITE = ROOT / 'site'
REPO = 'https://github.com/nicolasgioanni/cyber-lab-research'
CASES = [('removed-marker', 'dir', 0), ('removed-marker', 'git', 1),
         ('clean-control', 'dir', 0), ('clean-control', 'git', 0)]
LABELS = {'removed-marker': 'Removed marker', 'clean-control': 'Clean control',
          'git': 'Git history', 'dir': 'Current files'}


def load_measurement(path):
    data = json.loads(path.read_text())
    if any(data.get(k) != value for k, value in {
        'experiment': 'history-scope', 'tool': 'Gitleaks', 'version': '8.30.1',
        'rule_sha256': hashlib.sha256((ROOT / 'experiment/rule.toml').read_bytes()).hexdigest()
    }.items()):
        raise ValueError(f'Mismatched measurement metadata in {path.name}')
    checks = data['checks']
    actual = [(c['sample'], c['mode'], c['expected']) for c in checks]
    if actual != CASES or any(type(c['observed']) is not int or c['observed'] < 0 for c in checks):
        raise ValueError('Measurement does not match the study design')
    return data


def render_page(content, destination, title, description, values, kind):
    shell = (ROOT / 'shell.html').read_text()
    is_entry = kind == 'entry'
    options = []
    for name, label in [('system', 'System'), ('light', 'Light'), ('navy', 'My mode'), ('dark', 'Dark')]:
        detail = '<span class="theme-switcher__option-detail" aria-hidden="true">Auto</span>' if name == 'system' else ''
        options.append(f'<button type="button" class="theme-switcher__option hover-base-1 hover-base-1--compact hover-base-1--inline" '
                       f'data-preference="{name}" aria-pressed="{str(name == "navy").lower()}"><span>{label}</span>{detail}</button>')
    page = shell.replace('{{MAIN}}', '' if is_entry else content).replace('{{DIALOG}}', content if is_entry else '')
    layout = dict(TITLE=escape(title), DESCRIPTION=escape(description, quote=True), REPO=REPO, PAGE_CLASS=kind + '-page',
                  THEME_OPTIONS=''.join(options),
                  ADMISSION_SCRIPT='<script defer src="/assets/admission.js"></script>' if is_entry else '',
                  GATE_CONFIG=f' data-sitekey="__TURNSTILE_SITEKEY__" data-policy-revision="{POLICY_REVISION}"' if is_entry else '',
                  SHELL_STATE=' inert' if is_entry else '')
    for key, value in dict(values, **layout).items():
        page = page.replace('{{' + key + '}}', value)
    if '{{' in page or '}}' in page:
        raise ValueError(f'Unfilled template field in {destination}')
    (SITE / destination).write_text('\n'.join(line.rstrip() for line in page.splitlines()) + '\n')


def render():
    files = sorted((SITE / 'data').glob('worker-*.json'))
    runs = [load_measurement(f) for f in files]
    headers = ''.join(f'<th scope="col">Run {i + 1}</th>' for i in range(len(runs)))
    rows = []
    for index, (sample, mode, expected) in enumerate(CASES):
        observed = ''.join(f'<td>{run["checks"][index]["observed"]}</td>' for run in runs)
        rows.append(f'<tr><th scope="row">{LABELS[sample]}</th><td>{LABELS[mode]}</td><td>{expected}</td>{observed}</tr>')
    if not runs:
        raise ValueError('Publishing the study requires reviewed measurements')
    date = escape(runs[-1]['timestamp'].split('T')[0])
    expected = all(check['observed'] == check['expected'] for run in runs for check in run['checks'])
    if not expected or len(runs) != 2:
        raise ValueError('Review the study narrative before publishing different measurements')
    values = dict(HEADERS=headers, ROWS=''.join(rows),
                  NOTE=f'Last measured {date} UTC. Each run used fresh fixtures.',
                  EVIDENCE_COMMIT='0f4f6c90a2702266de6bf1d9873cc4f084f637ea',
                  FINDING='In both runs, Gitleaks found the deleted synthetic marker in Git history. '
                          'Scanning the current files found nothing.')
    render_page((ROOT / 'template.html').read_text(), 'index.html', 'Home',
                'Independent research into security controls and AI-assisted defense.', values, 'workspace')
    # A policy opened from the modal keeps the pending browser check in its original tab.
    def modal_links(copy):
        return copy.replace('<a ', '<a target="_blank" rel="noopener noreferrer" ')

    notice = dict(NOTICE=modal_links(notice_html()), AGREEMENT=modal_links(NOTICE_AGREEMENT))
    render_page((ROOT / 'entry-template.html').read_text(), 'entry.html', 'Visitor verification',
                'Verify this browser and review the visitor access notice.', notice, 'entry')
    render_page((ROOT / 'exit-template.html').read_text(), 'exit.html', 'Session closed',
                'Your Research Lab visit has ended.', {}, 'closed')
    for path, article in build_policies().items():
        title = POLICY_TITLES[path]
        render_page(article, path[1:] + '.html', title, f'{title} for the Research Lab.', {}, 'policy')


if __name__ == '__main__':
    render()
