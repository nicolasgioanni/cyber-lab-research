# Nicolas Gioanni’s Cyber Research Lab

This repository contains the public research site and the self-contained experiments behind its findings. The first study compares Gitleaks directory and Git-history scans of an inert marker that was committed and then removed. A second repository with ordinary text provides the negative control.

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

Cloudflare Pages serves the committed `site` directory. Its production branch is `main`. Changes to the private lab require a separate review before any findings are selected for this repository. GitHub Actions has read-only contents access.
