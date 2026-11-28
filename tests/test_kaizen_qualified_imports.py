"""A qualified import names its package by more than its last part (round 9, kestra): `import org.junit.jupiter.api.Tag`
was linked to whatever file the repository keeps in an `api/` folder (a web controller), so every test importing JUnit
"imported" the controller, and `labels.stream()` there was taken for the controller's `stream()`: wrong loop findings
on ordinary in-memory streams."""

import unittest

from codefactory.analyzers.generic import _import_index, _resolve_import, analyze_generic, available
from codefactory.config import DEFAULT_IGNORE
from tests.test_large_repo import repo

FILES = [
    "web/src/main/java/io/app/web/api/AgentController.java",
    "core/src/main/java/io/app/core/api/Thing.java",
    "core/src/main/java/io/app/core/models/Label.java",
    "core/src/main/java/io/app/core/models/Flow.java",
]


class QualifiedImportTest(unittest.TestCase):
    def setUp(self):
        self.idx = _import_index(FILES)

    def test_a_library_import_is_not_a_folder_of_the_same_last_name(self):
        for imp in ("org.junit.jupiter.api.Tag", "com.github.dockerjava.api.DockerClient", "org.junit.jupiter.api.*"):
            self.assertEqual([], _resolve_import(imp, self.idx, "java"), imp)

    def test_the_repositorys_own_imports_still_resolve(self):
        self.assertEqual(["core/src/main/java/io/app/core/api/Thing.java"],
                         _resolve_import("io.app.core.api.Thing", self.idx, "java"))  # fmt: skip
        self.assertEqual(1, len(_resolve_import("io.app.core.models.*", self.idx, "java")))  # a package: one file of it
        self.assertEqual(["core/src/main/java/io/app/core/models/Label.java"], _resolve_import("./models/Label", self.idx, "ts"))

    @unittest.skipUnless(available(), "needs the language pack (tree-sitter)")
    def test_a_stream_is_not_a_controller_method(self):
        root = repo({
            "web/api/AgentController.java": "package web.api;\npublic class AgentController {\n"
                                            "  public Object stream(String q) { return client.exchange(q); }\n}\n",
            "core/Labels.java": "package core;\nimport com.github.dockerjava.api.DockerClient;\nimport java.util.List;\n"
                                "public class Labels {\n  DockerClient docker;\n"
                                "  long count(List<List<String>> groups) {\n    long n = 0;\n"
                                "    for (List<String> g : groups) { n += g.stream().filter(l -> !l.isEmpty()).count(); }\n"
                                "    return n;\n  }\n}\n",
        })  # fmt: skip
        g = analyze_generic(root, list(DEFAULT_IGNORE), cache=False)
        # (a "may refer to" link stays: it only keeps a function from being reported unused; a call is what loops count)
        self.assertFalse([e for e in g.edges if e.kind == "call" and e.src.startswith("core/") and "AgentController" in e.dst])
        self.assertFalse([s for s in g.sites if s.fn.startswith("core/") and "AgentController" in s.target])


if __name__ == "__main__":
    unittest.main()
