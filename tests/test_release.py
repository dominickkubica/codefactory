"""Supply-chain properties: the SBOM is correct and deterministic, and analysis output is reproducible byte for byte
(the same code gives the same graph, review and SARIF, so results can be diffed, cached and attested)."""

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from codefactory.cli import build
from codefactory.deps import Package
from codefactory.review import review_markdown
from codefactory.sarif import build_sarif
from codefactory.sbom import document, purl

FIXTURES = Path(__file__).parent / "fixtures"


def _portable(sarif: dict) -> dict:
    """Without the run's absolute root (where this copy happened to be), the one machine-specific field."""
    for run in sarif["runs"]:
        run.pop("originalUriBaseIds", None)
    return sarif


class SbomTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        (self.root / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
            "": {"name": "app"},
            "node_modules/react": {"version": "18.3.1"},
            "node_modules/@babel/core": {"version": "7.24.0", "dev": True},
        }}))  # fmt: skip
        (self.root / "requirements.txt").write_text("Django==5.0.4\nrequests_toolbelt==1.0.0\n")

    def test_components_and_purls(self):
        doc = document(self.root)
        self.assertEqual(doc["bomFormat"], "CycloneDX")
        got = {c["purl"]: c["scope"] for c in doc["components"]}
        self.assertEqual(got, {
            "pkg:npm/%40babel/core@7.24.0": "optional",
            "pkg:npm/react@18.3.1": "required",
            "pkg:pypi/django@5.0.4": "required",
            "pkg:pypi/requests-toolbelt@1.0.0": "required",
        })  # fmt: skip
        self.assertNotIn("pkg:npm/%40babel/core@7.24.0", doc["dependencies"][0]["dependsOn"])

    def test_deterministic(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SOURCE_DATE_EPOCH", None)
            a, b = document(self.root), document(self.root)
        self.assertEqual(json.dumps(a), json.dumps(b))
        self.assertNotIn("timestamp", a["metadata"])
        with mock.patch.dict(os.environ, {"SOURCE_DATE_EPOCH": "1700000000"}):
            self.assertEqual(document(self.root)["metadata"]["timestamp"], "2023-11-14T22:13:20Z")

    def test_purl_names(self):
        self.assertEqual(purl(Package("Go", "github.com/a/b", "v1.2.0", "go.sum")), "pkg:golang/github.com/a/b@v1.2.0")
        self.assertEqual(purl(Package("crates.io", "serde", "1.0.0", "Cargo.lock")), "pkg:cargo/serde@1.0.0")


class ReproducibleTest(unittest.TestCase):
    def test_same_code_same_output(self):
        outputs = []
        for _ in range(2):
            root = Path(tempfile.mkdtemp()) / "shop"
            shutil.copytree(FIXTURES / "shop", root, ignore=shutil.ignore_patterns(".codefactory"))
            g = build(root, cache=False).to_dict()
            g["root"] = "shop"
            outputs.append(
                (
                    json.dumps(g, sort_keys=True),
                    review_markdown(g, root),
                    json.dumps(_portable(build_sarif(g, root)), sort_keys=True),
                )
            )
        graph, review, sarif = zip(*outputs, strict=True)
        self.assertEqual(graph[0], graph[1])
        self.assertEqual(review[0], review[1])
        self.assertEqual(sarif[0], sarif[1])


if __name__ == "__main__":
    unittest.main()
