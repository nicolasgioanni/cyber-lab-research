#!/usr/bin/env python3
"""Compare two scan modes using a disposable repository and an inert marker."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

RULE = Path(__file__).with_name('rule.toml')
VERSION = '8.30.1'
RULE_ID = 'research-fixture-marker'


def execute(args, cwd, env, allowed=(0,)):
    result = subprocess.run(args, cwd=cwd, env=env, text=True, capture_output=True, timeout=60)
    if result.returncode not in allowed:
        raise RuntimeError(f'{Path(args[0]).name} returned {result.returncode}')
    return result


def case(root, binary, env, name, add_marker):
    repo = root / name
    repo.mkdir()
    def git(*args):
        return execute(['git', '-c', 'user.name=Research Fixture', '-c',
                        'user.email=fixture@example.invalid', '-c', 'core.hooksPath=/dev/null', *args], repo, env)
    git('init', '-q')
    sample = repo / 'sample.txt'
    marker = 'CYBERLAB_SAMPLE_' + '0123456789ABCDEF0123'
    sample.write_text((marker if add_marker else 'ordinary sample') + '\n')
    git('add', 'sample.txt')
    git('commit', '-qm', 'Record sample')
    sample.write_text('retired sample\n')
    git('add', 'sample.txt')
    git('commit', '-qm', 'Replace sample')
    rows = []
    for mode in ('dir', 'git'):
        report = root / f'{name}-{mode}.json'
        process = execute([binary, mode, '.', '--config', str(RULE.resolve()), '--no-banner',
                           '--redact=100', '--exit-code', '42', '--report-format', 'json',
                           '--report-path', str(report)], repo, env, allowed=(0, 42))
        findings = json.loads(report.read_text())
        if not isinstance(findings, list) or marker in report.read_text():
            raise ValueError('Invalid or unredacted Gitleaks output')
        if any(f.get('RuleID') != RULE_ID or f.get('File') != 'sample.txt' for f in findings):
            raise ValueError('Unexpected rule or source file in report')
        if (process.returncode == 42) != bool(findings):
            raise ValueError('Gitleaks status disagrees with its report')
        expected = int(add_marker and mode == 'git')
        rows.append(dict(sample=name, mode=mode, expected=expected, observed=len(findings)))
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gitleaks', default='gitleaks')
    parser.add_argument('--output', type=Path, required=True)
    options = parser.parse_args()
    binary = shutil.which(options.gitleaks)
    if not binary:
        parser.error('Gitleaks 8.30.1 is required')
    binary = str(Path(binary).resolve())
    with tempfile.TemporaryDirectory(prefix='history-study-') as work:
        root = Path(work)
        env = {'PATH': os.environ['PATH'], 'HOME': str(root), 'LANG': 'C', 'GIT_CONFIG_NOSYSTEM': '1'}
        version = execute([binary, 'version'], root, env).stdout.strip().lstrip('v')
        if version != VERSION:
            raise ValueError(f'Expected {VERSION}, found {version}')
        rows = case(root, binary, env, 'removed-marker', True) + case(root, binary, env, 'clean-control', False)
    data = dict(experiment='history-scope', tool='Gitleaks', version=version,
                timestamp=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                rule_sha256=hashlib.sha256(RULE.read_bytes()).hexdigest(), checks=rows)
    options.output.parent.mkdir(parents=True, exist_ok=True)
    options.output.write_text(json.dumps(data, indent=2) + '\n')
    return int(any(item['expected'] != item['observed'] for item in rows))


if __name__ == '__main__':
    sys.exit(main())
