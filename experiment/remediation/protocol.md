# Dependency remediation study protocol

The task is to locate the dependency affected by CVE-2022-25883 in a small npm project, apply the smallest same-major dependency upgrade that addresses that advisory, and check that its documented behavior still works. The fixture selects releases for deployment channels. Its six existing tests use ordinary version ranges, catalogs and output formatting. The experiment measures advisory matching and behavior after an upgrade. It does not execute the vulnerable code path with adversarial input.

## Inputs and grading

The frozen baseline has a direct dependency on `semver@7.5.1`, another direct dependency, and two transitive dependencies. The agent receives a disposable copy of the repository. The evaluator keeps its own baseline, advisory snapshot and copy of the submitted Git diff. Each case starts from a fresh directory.

1. Verify the baseline tree and the advisory projection against the SHA-256 values pinned in the replay program. The tree digest covers each sorted relative filename, a zero byte, and the 32-byte digest of that file’s contents. The public fixture contains the application, manifest, lockfile, and six tests.
2. Install the baseline using `npm ci --ignore-scripts --no-audit --no-fund`. Check the full npm dependency graph, compare installed package names and versions against every resolved lockfile entry, and scan the lockfile with OSV-Scanner 2.7.1 in offline mode. Require one target advisory finding. Run the original tests and require six passes.
3. Apply the agent’s submitted patch to the second clean copy. Check that the changes affect only the manifest and lockfile, that the direct dependency remains exactly pinned at the first upstream patched 7.x release (7.5.2), that unrelated lock entries and metadata are identical, and that the original application and tests are byte-for-byte intact. Reinstall, inventory, scan and run the same tests.
4. A passing repair changes the installed target version, clears the single specified advisory and preserves all six tested behaviors. The report includes the dependency inventories for both states. A clean scan here means zero matches against this one advisory. It says nothing about other advisories or untested behavior.

The version ranges, package name, CVE alias and advisory identifier in `advisory.json` come from the GitHub Advisory Database. The projection retains the original npm ranges and records the upstream file’s URL and digest. The original upstream file’s SHA-256 is `955a08aac8ac34aada62d20397b3c331c9a03473d37a5ffcf7a6a7e79b728f37`. The projected file’s SHA-256 is `83bb786c51f305801e4e4511fa2640c0774bf6a28848f94605d59a1d2c33d394`. Both sides use identical bytes even if a provider later edits its record. [Pinned advisory](https://github.com/github/advisory-database/blob/056c81d4eabcc352b9af166d9fed9003464ce149/advisories/github-reviewed/2023/06/GHSA-c2qf-rxjj-qqgw/GHSA-c2qf-rxjj-qqgw.json) · [Patched upstream release](https://github.com/npm/node-semver/releases/tag/v7.5.2)

## Replay the observed patch

Use Python 3.9+, Git, Node.js 22, npm 10, and OSV-Scanner 2.7.1. Place Node, npm and the scanner on the command path, or pass the scanner’s absolute path with `--osv-scanner`. The grader runs OSV against a local one-advisory database. npm needs access to the official npm registry or a prepopulated cache containing the archives pinned in both lockfiles. An offline run can set `npm_config_offline=true` and `npm_config_cache` to that cache. [OSV-Scanner release](https://github.com/google/osv-scanner/releases/tag/v2.7.1)

From the root of the research repository, replay the submitted patch with the following command.

```sh
python3 experiment/remediation/replay.py \
  --patch experiment/remediation/candidate.patch --output /tmp/remediation-replay.json
```

Exit code 0 means the patch passed. Code 1 means a submitted change failed a grading condition. Code 2 means an input, installation, or tool error prevented a complete measurement. The report retains the stages completed before an error. Replaying the diff measures reproducibility of the observed repair. Measuring how often an agent identifies or repairs this issue would require additional independent agent trials.

## Evaluation timing

The criteria preceded the run. The evaluator added stricter exact-pin and unrelated-lock-entry checks after submission. A separate Linux worker replayed the original submitted patch.
