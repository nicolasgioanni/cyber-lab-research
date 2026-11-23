"""Replay one submitted remediation and write a public, path-free measurement."""
import argparse
from collections import Counter
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import zipfile

HERE = Path(__file__).resolve().parent
BASELINE = '9202318bbd4d6986471a17252e22301a43bc011e6895946babfac6dc431aa352'
SNAPSHOT = '83bb786c51f305801e4e4511fa2640c0774bf6a28848f94605d59a1d2c33d394'
TARGET = 'GHSA-c2qf-rxjj-qqgw'
PACKAGE = 'semver'
FIXED = '7.5.2'
FIXED_INTEGRITY = 'sha512-SoftuTROv/cRjCze/scjGyiDtcUyxw1rgYQSZY7XTmtR5hX+dm76iDbTH8TkLPHCQmlbQVSSbNZCPM2hb0knnQ=='
DEPENDENCY_FILES = {'package.json', 'package-lock.json'}


class Incomplete(Exception):
    """The measurement could not be performed or validated."""


class Mismatch(Exception):
    """The submitted change did not satisfy the study protocol."""


def invoke(args, cwd, env, ok=(0,)):
    name = Path(args[0]).name
    try:
        result = subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Incomplete(f'{name} was unavailable or timed out') from exc
    if result.returncode not in ok:
        raise Incomplete(f'{name} {args[1]} exited {result.returncode}')
    return result


def manifest(root):
    files = {}
    for base, dirs, names in os.walk(root):
        if Path(base) == root:
            dirs[:] = [name for name in dirs if name not in ('.git', 'node_modules')]
        for name in dirs + names:
            if (Path(base) / name).is_symlink():
                raise Mismatch('unexpected symlink in fixture')
        for name in names:
            path = Path(base) / name
            files[path.relative_to(root).as_posix()] = sha256(path.read_bytes()).digest()
    return files


def fingerprint(files):
    digest = sha256()
    for path, file_hash in sorted(files.items()):
        digest.update(path.encode() + b'\0' + file_hash)
    return digest.hexdigest()


def read_json(path):
    return json.loads(path.read_bytes())


def scan(scanner, root, env, inventory):
    args = [scanner, 'scan', 'source', '--offline', '--all-packages', '--format', 'json',
            '--lockfile', str(root / 'package-lock.json')]
    result = invoke(args, root, env, (0, 1))
    data = json.loads(result.stdout)
    packages = [p for source in data['results'] for p in source['packages']]
    seen = Counter((p['package']['name'], p['package']['version']) for p in packages)
    if seen != Counter(inventory):
        raise Incomplete('scanner inventory differs from the installed package inventory')
    findings = sum(v['id'] == TARGET for p in packages for v in p.get('vulnerabilities', []))
    if bool(result.returncode) != bool(findings):
        raise Incomplete('scanner exit and targeted findings disagree')
    return findings


def measure(row, root, scanner, env):
    lock = read_json(root / 'package-lock.json')['packages']
    package = read_json(root / 'package.json')
    declared = package['dependencies'][PACKAGE]
    row['declared'] = declared
    if lock['']['dependencies'] != package['dependencies']:
        raise Mismatch('manifest and lockfile root declarations differ')
    inventory = []
    for path, item in lock.items():
        if not path:
            continue
        if not re.fullmatch(r'(?:node_modules/[a-z0-9][a-z0-9.-]*/)*node_modules/[a-z0-9][a-z0-9.-]*', path):
            raise Mismatch('package location outside the study fixture format')
        name = path.split('/')[-1]
        version = item['version']
        if item.get('resolved') != f'https://registry.npmjs.org/{name}/-/{name}-{version}.tgz' or not item.get('integrity', '').startswith('sha512-'):
            raise Mismatch('lock entry lacks the public npm archive and integrity pin')
        inventory.append((name, version))
    row['lock_version'] = lock['node_modules/' + PACKAGE]['version']
    invoke(['npm', 'ci', '--ignore-scripts', '--no-audit', '--no-fund'], root, env)
    row['clean_install'] = True
    invoke(['npm', 'ls', '--all', '--json'], root, env)
    for path, item in lock.items():
        if path:
            installed = read_json(root / path / 'package.json')
            if (installed['name'], installed['version']) != (path.split('/')[-1], item['version']):
                raise Mismatch('installed package differs from lockfile')
    row['installed_version'] = read_json(root / 'node_modules' / PACKAGE / 'package.json')['version']
    row['inventory'] = [dict(name=name, version=version) for name, version in sorted(inventory)]
    row['target_findings'] = scan(scanner, root, env, inventory)
    result = invoke(['npm', '--ignore-scripts', 'test', '--', '--test-reporter=tap'], root, env, (0, 1))
    counts = {name: int(value) for name, value in re.findall(
        r'^# (tests|pass|fail|skipped|cancelled|todo) (\d+)$', result.stdout, re.M)}
    if set(counts) != {'tests', 'pass', 'fail', 'skipped', 'cancelled', 'todo'}:
        raise Incomplete('test runner did not provide complete TAP counts')
    row['tests'] = counts
    return result.returncode == 0 and counts['tests'] == counts['pass'] == 6


def replay(args, result, work):
    env = dict(os.environ, NO_COLOR='1', OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=str(work))
    scanner = args.osv_scanner
    tool_version = invoke([scanner, '--version'], work, env).stdout
    if 'osv-scanner version: 2.7.1\n' not in tool_version:
        raise Incomplete('expected OSV-Scanner 2.7.1')
    result['tools'] = {'node': invoke(['node', '--version'], work, env).stdout.strip(),
                       'npm': invoke(['npm', '--version'], work, env).stdout.strip(),
                       'osv_scanner': '2.7.1'}
    original = manifest(args.fixture)
    result['fixture_sha256'] = fingerprint(original)
    advisory = (HERE / 'advisory.json').read_bytes()
    result['advisory_sha256'] = sha256(advisory).hexdigest()
    if result['fixture_sha256'] != BASELINE or result['advisory_sha256'] != SNAPSHOT:
        raise Incomplete('baseline or advisory bytes differ from the study inputs')
    result['patch_sha256'] = sha256(args.patch.read_bytes()).hexdigest()
    archive = work / 'osv-scalibr' / 'npm' / 'all.zip'
    archive.parent.mkdir(parents=True)
    with zipfile.ZipFile(archive, 'w') as db:
        db.writestr(TARGET + '.json', advisory)
    before, after = work / 'before', work / 'after'
    for folder in (before, after):
        for name in original:
            (folder / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(args.fixture / name, folder / name)
    result['before'] = {}
    good_baseline = measure(result['before'], before, scanner, env)
    if not good_baseline or result['before']['target_findings'] != 1:
        raise Incomplete('baseline findings or original behavior differ from the known fixture')
    applied = invoke(['git', 'apply', '--whitespace=nowarn', str(args.patch.resolve())], after, env, (0, 1, 128))
    if applied.returncode:
        raise Mismatch('submitted patch did not apply to the baseline')
    modified = manifest(after)
    changed = sorted(k for k in set(original) | set(modified) if original.get(k) != modified.get(k))
    result['changed_files'] = changed
    if set(changed) != DEPENDENCY_FILES or set(modified) != set(original):
        raise Mismatch('expected changes only to the dependency declaration and lockfile')
    expected = read_json(before / 'package.json')
    expected['dependencies'][PACKAGE] = FIXED
    if read_json(after / 'package.json') != expected:
        raise Mismatch('expected the first patched 7.x release as an exact direct pin and no other manifest edits')
    expected_lock = read_json(before / 'package-lock.json')
    entries = expected_lock['packages']
    entries['']['dependencies'][PACKAGE] = FIXED
    entries['node_modules/' + PACKAGE].update(
        version=FIXED, resolved=f'https://registry.npmjs.org/{PACKAGE}/-/{PACKAGE}-{FIXED}.tgz',
        integrity=FIXED_INTEGRITY)
    if read_json(after / 'package-lock.json') != expected_lock:
        raise Mismatch('lockfile differs beyond the pinned replacement and its verified npm archive metadata')
    result['after'] = {}
    passed = measure(result['after'], after, scanner, env)
    after_row = result['after']
    if not (passed and after_row['target_findings'] == 0 and after_row['installed_version'] != result['before']['installed_version']):
        raise Mismatch('candidate did not clear the advisory and preserve all six behaviors')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture', type=Path, default=HERE / 'fixture')
    parser.add_argument('--patch', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--osv-scanner', default='osv-scanner')
    args = parser.parse_args()
    result = {'cve': 'CVE-2022-25883', 'advisory': TARGET}
    try:
        with tempfile.TemporaryDirectory(prefix='remediation-replay-') as folder:
            replay(args, result, Path(folder).resolve())
    except Mismatch as exc:
        code, result['outcome'], result['reason'] = 1, 'fail', str(exc)
    except Incomplete as exc:
        code, result['outcome'], result['reason'] = 2, 'incomplete', str(exc)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        code, result['outcome'], result['reason'] = 2, 'incomplete', 'Unreadable or malformed input or tool output: ' + type(exc).__name__
    else:
        code, result['outcome'] = 0, 'pass'
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(result['outcome'], result.get('reason', ''))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
