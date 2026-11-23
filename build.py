"""Render the buildless public site from reviewed measurements only."""
import hashlib
import json
from pathlib import Path
from html import escape

from policies import NOTICE_AGREEMENT, POLICY_REVISION, POLICY_TITLES, build_policies, notice_html

ROOT = Path(__file__).resolve().parent
SITE = ROOT / 'site'
REPO = 'https://github.com/nicolasgioanni/cyber-lab-research'
REMEDIATION = ROOT / 'experiment/remediation'
REMEDIATION_COMMIT = 'f95fc3f41184de459827a7d775554ee016bfeaf7'
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


def remediation_study():
    trial = json.loads((REMEDIATION / 'trial.json').read_text())
    replay = json.loads((REMEDIATION / 'replay.json').read_text())
    advisory = json.loads((REMEDIATION / 'advisory.json').read_text())
    if (trial['cve'] != replay['cve'] or trial['cve'] not in advisory['aliases'] or
            trial['advisory_id'] != replay['advisory'] or replay['advisory'] != advisory['id'] or
            trial['attempts'] != 1 or replay['outcome'] not in ('pass', 'fail', 'incomplete')):
        raise ValueError('Trial, replay, and advisory do not describe the same study')
    for key in ('fixture_sha256', 'patch_sha256'):
        if key in replay and trial[key] != replay[key]:
            raise ValueError('The trial and replay must use the same fixture and submitted patch')
    for file, key in [('candidate.patch', 'patch_sha256'), ('advisory.json', 'advisory_sha256')]:
        if key in replay and hashlib.sha256((REMEDIATION / file).read_bytes()).hexdigest() != replay[key]:
            raise ValueError(f'Replay evidence does not match the published {file}')

    before, after = replay.get('before', {}), replay.get('after', {})
    if replay['outcome'] == 'pass':
        for row in (before, after):
            if row['installed_version'] != row['lock_version'] or not row['clean_install']:
                raise ValueError('Installed and locked versions disagree in a passing replay')
        if not (before['target_findings'] == 1 and after['target_findings'] == 0 and
                before['tests']['tests'] == before['tests']['pass'] ==
                after['tests']['tests'] == after['tests']['pass'] == 6):
            raise ValueError('Review the study before publishing different replay results')
        old, new = before['installed_version'], after['installed_version']
        finding = (f"Given {trial['cve']}, the agent traced the advisory to the release utility’s direct "
                   f"semver dependency and updated it from {old} to {new}. The independent replay cleared "
                   f"the advisory finding and passed all {after['tests']['tests']} original tests.")
        teaser = f"The agent updated semver from {old} to {new} and kept all {after['tests']['tests']} tests passing."
        scope = ('This agent completed one repair in a small project with a direct dependency. '
                 'The tests cover release selection and terminal output. Both scans used a frozen copy of the specified advisory. '
                 'A single trial cannot estimate the agent’s success rate across other repositories or CVEs.')
    else:
        outcome = 'did not complete' if replay['outcome'] == 'incomplete' else 'did not pass'
        finding = f"The patch submitted for {trial['cve']} {outcome} independent verification. {replay['reason']}"
        teaser = 'Read the submitted change and the checks the independent replay could complete.'
        scope = 'The recorded checks describe one attempt in a small project with a direct dependency. An unmeasured check offers no evidence that the fix worked.'

    def tests(row):
        counts = row.get('tests')
        return f"{counts['pass']} of {counts['tests']} passed" if counts else 'Unmeasured'

    scanner = replay.get('tools', {}).get('osv_scanner')
    scan_label = f'OSV-Scanner {scanner} target findings' if scanner else 'Target advisory findings'
    comparisons = [
        ('Installed semver', before.get('installed_version'), after.get('installed_version')),
        (scan_label, before.get('target_findings'), after.get('target_findings')),
        ('Behavior tests', tests(before), tests(after)),
    ]
    rows = []
    for label, original, patched in comparisons:
        cells = ''.join(f"<td>{escape(str(value)) if value is not None else 'Unmeasured'}</td>"
                        for value in (original, patched))
        rows.append(f'<tr><th scope="row">{escape(label)}</th>{cells}</tr>')
    steps = ''.join(f'<li>{escape(step)}</li>' for step in trial['trace'])
    return dict(
        AGENT_EVIDENCE=f'{REPO}/blob/{REMEDIATION_COMMIT}/experiment/remediation',
        AGENT_FINDING=escape(finding), AGENT_TEASER=escape(teaser), AGENT_SCOPE=escape(scope),
        AGENT_SETUP=escape(trial['setup']),
        AGENT_METHOD=("The agent was asked to identify the affected version and dependency path, apply the "
                      "smallest compatible update, and verify the result. The evaluator separately replayed "
                      "the submitted patch against the original fixture."),
        AGENT_CONFIG=escape(f"One trial on {trial['submitted_at'][:10]} UTC using {trial['model']} "
                            f"with {trial['reasoning_effort']} reasoning effort."),
        AGENT_ROWS=''.join(rows), AGENT_TRACE=f'<ol>{steps}</ol>',
    )


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
    values.update(remediation_study())
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
