"""Render the buildless public site from reviewed measurements only."""
import hashlib
import json
from pathlib import Path
from html import escape

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


def render_page(source, destination, title, description, values, kind):
    shell = (ROOT / 'shell.html').read_text()
    content = (ROOT / source).read_text().rstrip()
    is_entry = kind == 'entry'
    options = []
    for name, label in [('system', 'System'), ('light', 'Light'), ('navy', 'My mode'), ('dark', 'Dark')]:
        detail = '<span class="theme-switcher__option-detail" aria-hidden="true">Auto</span>' if name == 'system' else ''
        options.append(f'<button type="button" class="theme-switcher__option hover-base-1 hover-base-1--compact hover-base-1--inline" '
                       f'data-preference="{name}" aria-pressed="{str(name == "navy").lower()}"><span>{label}</span>{detail}</button>')
    source_link = (f'<nav class="blob-footer__column" aria-label="Resources"><h2 class="blob-footer__heading">Resources</h2>'
                   f'<ul class="blob-footer__links"><li><a class="blob-footer__link hover-base-1 hover-base-1--compact" '
                   f'href="{REPO}">Research repository</a></li></ul></nav>')
    page = shell.replace('{{MAIN}}', '' if is_entry else content).replace('{{DIALOG}}', content if is_entry else '')
    layout = dict(TITLE=title, DESCRIPTION=description, REPO=REPO, PAGE_CLASS=kind + '-page',
                  FOOTER_RESOURCE=source_link if kind == 'workspace' else '', THEME_OPTIONS=''.join(options),
                  ADMISSION_SCRIPT='<script defer src="/assets/admission.js"></script>' if is_entry else '',
                  GATE_CONFIG=' data-sitekey="__TURNSTILE_SITEKEY__"' if is_entry else '',
                  SHELL_STATE=' inert' if is_entry else '')
    for key, value in dict(values, **layout).items():
        page = page.replace('{{' + key + '}}', value)
    (SITE / destination).write_text('\n'.join(line.rstrip() for line in page.splitlines()) + '\n')


def render():
    files = sorted((SITE / 'data').glob('worker-*.json'))
    runs = [load_measurement(f) for f in files]
    headers = ''.join(f'<th scope="col">Run {i + 1}</th>' for i in range(len(runs)))
    rows = []
    for index, (sample, mode, expected) in enumerate(CASES):
        observed = ''.join(f'<td>{run["checks"][index]["observed"]}</td>' for run in runs)
        rows.append(f'<tr><th scope="row">{LABELS[sample]}</th><td>{LABELS[mode]}</td><td>{expected}</td>{observed}</tr>')
    matched = sum(c['expected'] == c['observed'] for run in runs for c in run['checks'])
    observations = sum(len(run['checks']) for run in runs)
    if runs:
        verdict = f'{matched} of {observations} observations matched across {len(runs)} independent runs.'
        date = escape(runs[-1]['timestamp'].split('T')[0])
        note = f'Last measured {date} UTC. Each run used fresh fixtures.'
    else:
        verdict = 'Measurements are pending.'
        note = 'The table lists the expected counts for each case.'

    def count_summary(case):
        counts = {run['checks'][case]['observed'] for run in runs}
        if not counts:
            return 'Pending'
        if len(counts) != 1:
            return 'Varied by run'
        number = counts.pop()
        return f'{number} finding' + ('' if number == 1 else 's') + ' per run'

    finding = ('The working-tree scan found no trace of the synthetic secret after deletion. '
               'Scanning the commit history recovered it in each run.'
               if runs and all(r['checks'][0]['observed'] == 0 and r['checks'][1]['observed'] == 1 for r in runs)
               else 'The study compares scans of the current files and the commit history after a synthetic secret was removed.')
    values = dict(HEADERS=headers, ROWS=''.join(rows), VERDICT=verdict, NOTE=note, FINDING=finding,
                  DIRECTORY_COUNT=count_summary(0), HISTORY_COUNT=count_summary(1))
    render_page('template.html', 'index.html', 'Security research',
                'Reproducible experiments in defensive security.', values, 'workspace')
    render_page('entry-template.html', 'entry.html', 'Visitor verification',
                'Verify this browser and review the visitor access notice.', {}, 'entry')
    render_page('exit-template.html', 'exit.html', 'Session closed',
                'Your Research Lab visit has ended.', {}, 'closed')


if __name__ == '__main__':
    render()
