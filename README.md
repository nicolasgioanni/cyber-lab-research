# Nicolas Gioanni’s Cyber Research Lab

This repository contains the public research site and the self-contained experiments behind its findings. The first study compares Gitleaks directory and Git-history scans of an inert marker that was committed and then removed. A second repository with ordinary text provides the negative control.

## Observations

In two disposable ARM64 Linux VMs, Gitleaks 8.30.1 reported the same counts in all four cases. Each VM measured two independently created two-commit repositories. The marker had been removed from the current working tree in both runs.

| Sample | Scan mode | Run 1 | Run 2 |
| --- | --- | ---: | ---: |
| Removed marker | Current files | 0 | 0 |
| Removed marker | Git history | 1 | 1 |
| Clean control | Current files | 0 | 0 |
| Clean control | Git history | 0 | 0 |

The [first](site/data/worker-1.json) and [second](site/data/worker-2.json) measurements include the rule digest, UTC time and expected count for each case. The experiment code was the version in commit `f3a6f48`. A [GitHub-hosted Linux run](https://github.com/nicolasgioanni/cyber-lab-research/actions/runs/45087512165) independently produced the same four counts.

## Reproduce the history study

Use Python 3.9 or newer, Git, and [Gitleaks 8.30.1](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1). The experiment creates disposable repositories under the system temporary directory. It runs without credentials or network access once the scanner is installed.

```sh
python3 experiment/run.py --output .local/findings.json
python3 -m json.tool .local/findings.json
```

The runner checks the scanner version, writes a count for each sample and scan mode, and exits unsuccessfully on a count mismatch or scanner error. Reports containing raw marker text fail validation. The public CI workflow repeats the experiment with a checksum-pinned Linux binary.

## Render the site

```sh
python3 build.py
python3 -m http.server 8080 --bind 127.0.0.1 --directory site
```

The site reuses the [portfolio’s design tokens](https://github.com/nicolasgioanni/Smart-Porfolio), portrait and Space Grotesk font. All assets are served from the site itself. The Cloudflare Pages deployment settings are production branch `main` and output directory `site`, with no build command. Changes to the private lab require a separate review before any findings are selected for this repository. GitHub Actions has read-only contents access.
