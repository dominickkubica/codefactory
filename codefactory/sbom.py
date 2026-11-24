"""`codefactory sbom`: a CycloneDX 1.5 software bill of materials from the repository's lockfiles.

The same lockfiles the vulnerability check reads (npm, yarn, pnpm, Poetry, uv, Pipfile, pinned requirements, Cargo,
Go, Bundler, Composer), so the versions are exactly what's installed. Each component has a package URL (purl), the
lockfile it came from, and scope "optional" when it's development-only. Offline; nothing leaves the machine.

The output is deterministic (sorted, no random serial number, timestamp only from SOURCE_DATE_EPOCH), so the same
lockfiles give the same file and an SBOM can be diffed, signed and attested.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

from . import __version__
from .deps import Package, packages

PURL_TYPE = {"npm": "npm", "PyPI": "pypi", "crates.io": "cargo", "Go": "golang", "RubyGems": "gem", "Packagist": "composer"}


def purl(p: Package) -> str:
    kind = PURL_TYPE[p.ecosystem]
    name = p.name.lower().replace("_", "-") if kind == "pypi" else p.name
    if kind == "npm" and name.startswith("@"):  # pkg:npm/%40scope/name
        scope, _, rest = name.partition("/")
        path = f"{quote(scope)}/{quote(rest)}"
    else:
        path = "/".join(quote(part) for part in name.split("/"))
    return f"pkg:{kind}/{path}@{quote(p.version, safe='')}"


def document(root: Path) -> dict:
    pkgs = sorted(packages(root), key=lambda p: (p.ecosystem, p.name.lower(), p.version, p.source))
    components, seen = [], set()
    for p in pkgs:
        ref = purl(p)
        if ref in seen:  # the same package in two lockfiles: once, from the first
            continue
        seen.add(ref)
        components.append(
            {
                "type": "library",
                "bom-ref": ref,
                "name": p.name,
                "version": p.version,
                "purl": ref,
                "scope": "optional" if p.dev else "required",
                "properties": [{"name": "codefactory:lockfile", "value": p.source}],
            }
        )
    body = json.dumps(components, sort_keys=True)
    meta: dict = {
        "tools": {"components": [{"type": "application", "name": "codefactory", "version": __version__}]},
        "component": {"type": "application", "bom-ref": "root", "name": root.resolve().name},
    }
    if epoch := os.environ.get("SOURCE_DATE_EPOCH"):  # reproducible builds set this; otherwise no clock in the file
        meta["timestamp"] = datetime.fromtimestamp(int(epoch), UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, 'codefactory:' + body)}",  # same content, same id
        "version": 1,
        "metadata": meta,
        "components": components,
        "dependencies": [{"ref": "root", "dependsOn": [c["bom-ref"] for c in components if c["scope"] == "required"]}],
    }


def write(root: Path, out: Path | None) -> str:
    text = json.dumps(document(root), indent=2) + "\n"
    if out:
        out.write_text(text, encoding="utf-8")
    return text
