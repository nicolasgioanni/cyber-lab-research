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


def render():
    files = sorted((SITE / 'data').glob('worker-*.json'))
    runs = [load_measurement(f) for f in files]
    headers = ''.join(f'<th scope="col">Run {i + 1}</th>' for i in range(len(runs)))
    rows = []
    for index, (sample, mode, expected) in enumerate(CASES):
        observed = ''.join(f'<td>{run["checks"][index]["observed"]}</td>' for run in runs)
        rows.append(f'<tr><th scope="row">{LABELS[sample]}</th><td>{LABELS[mode]}</td><td>{expected}</td>{observed}</tr>')
    if runs:
        matched = sum(c['expected'] == c['observed'] for r in runs for c in r['checks'])
        verdict = f'{matched} of {sum(len(r["checks"]) for r in runs)} observations matched the expected counts.'
        if matched == 4 * len(runs):
            verdict += ' Git history preserved the marker after the working tree was clean.'
        status = 'Measured'
        links = ' '.join(f'<a href="data/{escape(f.name)}">Run {i + 1} JSON</a>' for i, f in enumerate(files))
        date = escape(runs[-1]['timestamp'].split('T')[0])
        note = f'Measured {date} UTC. Each run starts with two new local repositories. {links}'
    else:
        status = 'Protocol'
        verdict = 'The expected counts below define the experiment. Measured runs are pending.'
        note = 'Measurements will appear here after review.'
    template = (ROOT / 'template.html').read_text()
    values = dict(REPO=REPO, HEADERS=headers, ROWS=''.join(rows), STATUS=status, VERDICT=verdict, NOTE=note)
    for key, value in values.items():
        template = template.replace('{{' + key + '}}', value)
    (SITE / 'index.html').write_text(template)


if __name__ == '__main__':
    render()
