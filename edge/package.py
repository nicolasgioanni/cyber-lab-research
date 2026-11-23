"""Package only public cosmetics as static files. All gated documents live in the Worker."""
import json
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "site"
COSMETICS = {
    "assets/portfolio-LICENSE.txt", "assets/OFL.txt", "assets/portfolio-tokens.css",
    "assets/portrait.png", "assets/space-grotesk-latin.woff2", "assets/study.css",
    "assets/study.js", "assets/theme.js",
}


def package(output):
    output.mkdir(parents=True, exist_ok=True)
    resources = {"/": (SITE / "index.html").read_text(), "/entry": (SITE / "entry.html").read_text()}
    for path in sorted((SITE / "data").glob("worker-*.json")):
        if not re.fullmatch(r"worker-[0-9]+\.json", path.name):
            raise ValueError(f"Unexpected study file: {path.name}")
        text = path.read_text()
        json.loads(text)
        resources["/data/" + path.name] = text
    if len(resources) < 3:
        raise ValueError("Missing reviewed evidence")
    cosmetics = sorted(name for name in COSMETICS if (SITE / name).is_file())
    # An old static build in the same directory must never re-expose stale documents.
    allowed = set(cosmetics) | {"404.html", "_worker.js", "_routes.json", "_headers"}
    stale = [str(p.relative_to(output)) for p in output.rglob("*")
             if p.is_file() and str(p.relative_to(output)) not in allowed]
    if stale:
        raise ValueError(f"Unexpected files in deployment output: {stale}. Use a fresh output directory.")
    for name in cosmetics:
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(SITE / name, target)
    schema = [statement.strip() for statement in (ROOT / "edge/schema.sql").read_text().split(";") if statement.strip()]
    source = (ROOT / "edge/worker.mjs").read_text()
    for name, value in [("DOCUMENTS", resources), ("SCHEMA", schema), ("COSMETICS", ["/" + c for c in cosmetics])]:
        source = source.replace(f"/* PACK:{name} */ null", json.dumps(value, ensure_ascii=True))
    (output / "_worker.js").write_text(source)
    # No exclusions: even deployment aliases can only serve design assets via the canonical host.
    (output / "_routes.json").write_text(json.dumps({"version": 1, "include": ["/*"], "exclude": []}) + "\n")
    (output / "404.html").write_text("<!doctype html><html lang=en><meta charset=utf-8><title>Lab temporarily unavailable</title><h1>Lab temporarily unavailable</h1><p>Admission checks are unavailable. Please try again later.</p></html>\n")
    shutil.copyfile(SITE / "_headers", output / "_headers")


if __name__ == "__main__":
    package(Path(sys.argv[1]) if len(sys.argv) == 2 else ROOT / "dist")
