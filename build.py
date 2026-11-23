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
    page = shell.replace('{{MAIN}}', content)
    is_entry = kind == 'entry'
    footer = ('<nav aria-label="Visitor session"><a href="/entry">Access notice</a>'
              '<form action="/access/leave" method="post"><button type="submit">End visitor session</button></form></nav>'
              if kind == 'workspace' else '<span class="host">lab.nicolasmgioanni.dev</span>')
    layout = dict(TITLE=title, DESCRIPTION=description, REPO=REPO, PAGE_CLASS=kind + '-page',
                  FOOTER=footer, DIALOG_CLOSE='</dialog>' if is_entry else '',
                  DIALOG_OPEN=('<dialog id="visitor-dialog" aria-labelledby="notice-title" '
                               'aria-describedby="notice-intro" closedby="none" open>') if is_entry else '')
    for key, value in dict(values, **layout).items():
        page = page.replace('{{' + key + '}}', value)
    (SITE / destination).write_text(page)


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
        verdict = f'{matched} of {observations} observations matched the expected counts.'
        if matched == 4 * len(runs):
            verdict += ' Git history preserved the marker after the working tree was clean.'
        links = ' '.join(f'<a href="data/{escape(f.name)}">Run {i + 1} JSON</a>' for i, f in enumerate(files))
        date = escape(runs[-1]['timestamp'].split('T')[0])
        note = f'Measured {date} UTC. Each measurement ran in a fresh ARM64 Linux VM using two new Git repositories. {links}'
    else:
        verdict = 'The expected counts below define the experiment. Measured runs are pending.'
        note = 'Measurements will appear here after review.'
    values = dict(HEADERS=headers, ROWS=''.join(rows), VERDICT=verdict, NOTE=note,
                  RUN_COUNT=str(len(runs)), MATCHED=str(matched), OBSERVATIONS=str(observations))
    render_page('template.html', 'index.html', 'Defense operations',
                'Defensive tools, private monitoring and reproducible scanner evidence.', values, 'workspace')
    render_page('entry-template.html', 'entry.html', 'Lab access notice',
                'Review visitor permissions, security monitoring and session handling.', {}, 'entry')
    render_page('exit-template.html', 'exit.html', 'Session closed',
                'Your Cyber Lab visitor session is closed.', {}, 'closed')


if __name__ == '__main__':
    render()
