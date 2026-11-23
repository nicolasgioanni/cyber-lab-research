"""Package reviewed documents inside the gate and give presentation assets immutable URLs."""
import hashlib
import json
import re
import shutil
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin

ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "site"
# Only files in this list may be served before admission. Dependency order matters:
# styles reference the fingerprinted font, then HTML references the final styles.
ASSETS = ("OFL.txt", "portfolio-LICENSE.txt", "lab-mark.png", "space-grotesk-latin.woff2",
          "theme.js", "admission.js", "portfolio-tokens.css", "portfolio.css", "study.css")
CSS_URL = re.compile(r"""url\(\s*(["']?)([^)'"]+)\1\s*\)""")
HTML_ASSET = re.compile(r"""(\b(?:href|src)\s*=\s*)(["'])((?:\./|/)?assets/[^"']+)\2""")
RELEASE_HASH = re.compile(r"\.[0-9a-f]{16}(?=\.[^.]+$)")
OUTPUT_FILES = {"404.html", "_worker.js", "_routes.json", "_headers"}


class PageAssets(HTMLParser):
    """Track browser-fetched shell dependencies, excluding navigation links."""

    def __init__(self):
        super().__init__()
        self.urls = set()

    def handle_starttag(self, tag, attributes):
        values = dict(attributes)
        if tag in ("script", "img"):
            self.urls.add(values.get("src", ""))
        if tag == "link" and set(values.get("rel", "").split()) & {"stylesheet", "icon", "preload"}:
            self.urls.add(values.get("href", ""))


def render_document(path, asset_urls):
    def rewrite_asset(match):
        prefix, quote, target = match.groups()
        return prefix + quote + asset_urls[urljoin("/", target)] + quote

    page = HTML_ASSET.sub(rewrite_asset, path.read_text())
    assets = PageAssets()
    assets.feed(page)
    required = {asset_urls["/assets/" + name] for name in ("portfolio-tokens.css", "study.css", "theme.js")}
    if not required.issubset(assets.urls) or assets.urls.difference(asset_urls.values()):
        raise ValueError(f"{path.name} references unsupported assets or omits its theme, styles or script")
    return page


def assets_for_release():
    urls = {}
    files = {}
    for name in ASSETS:
        source = SITE / "assets" / name
        data = source.read_bytes()
        if source.suffix == ".css":
            def replace_url(match):
                if match.group(2).strip().startswith("data:"):
                    return match.group(0)
                original = urljoin("/assets/" + name, match.group(2).strip())
                return 'url("' + urls[original] + '")'
            data = CSS_URL.sub(replace_url, data.decode()).encode()
        if source.suffix == ".txt":
            filename = name
        else:
            fingerprint = hashlib.sha256(data).hexdigest()[:16]
            filename = f"{source.stem}.{fingerprint}{source.suffix}"
        urls["/assets/" + name] = "/assets/" + filename
        files["assets/" + filename] = data
    return urls, files


def package(output):
    asset_urls, files = assets_for_release()
    documents = {route: render_document(SITE / name, asset_urls)
                 for route, name in [("/", "index.html"), ("/entry", "entry.html"), ("/exit", "exit.html")]}
    if documents["/entry"].count("__TURNSTILE_SITEKEY__") != 1:
        raise ValueError("Verification page must expose exactly one widget site key placeholder")

    output.mkdir(parents=True, exist_ok=True)
    allowed = set(files) | OUTPUT_FILES
    stale = [p for p in output.rglob("*") if p.is_file() and p.relative_to(output).as_posix() not in allowed]
    # Rebuild outputs from previous releases without accepting arbitrary static files.
    known_assets = set(ASSETS) | {"portrait.png", "study.js"}
    for path in stale:
        if path.parent != output / "assets" or RELEASE_HASH.sub("", path.name) not in known_assets:
            raise ValueError(f"Unexpected file {path}. Use a fresh output directory.")
    for path in stale:
        path.unlink()
    (output / "assets").mkdir(exist_ok=True)
    for filename, data in files.items():
        (output / filename).write_bytes(data)

    schema = [statement.strip() for statement in (ROOT / "edge/schema.sql").read_text().split(";") if statement.strip()]
    source = (ROOT / "edge/worker.mjs").read_text()
    for name, value in [("DOCUMENTS", documents), ("SCHEMA", schema), ("ASSETS", asset_urls)]:
        marker = f"/* PACK:{name} */ null"
        if source.count(marker) != 1:
            raise ValueError(f"Worker pack marker missing or ambiguous: {name}")
        source = source.replace(marker, json.dumps(value, ensure_ascii=True))
    (output / "_worker.js").write_text(source)
    (output / "_routes.json").write_text(json.dumps({"version": 1, "include": ["/*"], "exclude": []}) + "\n")
    (output / "404.html").write_text("<!doctype html><html lang=en><meta charset=utf-8><title>Lab temporarily unavailable</title><h1>Lab temporarily unavailable</h1><p>Admission checks are unavailable. Please try again later.</p></html>\n")
    shutil.copyfile(SITE / "_headers", output / "_headers")


if __name__ == "__main__":
    package(Path(sys.argv[1]) if len(sys.argv) == 2 else ROOT / "dist")
