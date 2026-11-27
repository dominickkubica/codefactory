"""A test that mocks a function doesn't run it: "Important code no test reaches" was hidden for cal.com's
CredentialRepository.findFirstByIdWithKeyAndUser, which its only test replaces with vi.mock / vi.mocked (and the one
that would run it is a describe.skip). Each rule is pinned next to a real call that must still count."""

import unittest

from codefactory.cli import build
from codefactory.review import Review
from tests.test_large_repo import repo
from tests.test_typescript import available

REPO_TS = (
    "export class CredentialRepository {\n"
    "  static async findFirstByIdWithKeyAndUser({ id }: { id: number }) {\n"
    "    const res = await fetch(`https://db.internal/credentials/${id}`);\n    return res.json();\n  }\n"
    "  static async countAll() {\n    const res = await fetch('https://db.internal/credentials');\n"
    "    return (await res.json()).length;\n  }\n}\n"
)
SERVICE_TS = (
    "import { CredentialRepository } from './CredentialRepository';\n"
    "export class CredentialAccessService {\n"
    "  async ensure(id: number) {\n    return CredentialRepository.findFirstByIdWithKeyAndUser({ id });\n  }\n"
    "  async total() {\n    return CredentialRepository.countAll();\n  }\n}\n"
)
FORMAT_TS = "export function formatCredentialName(name: string) {\n  return name.trim().toUpperCase();\n}\n"


def review(files: dict[str, str]) -> Review:
    root = repo(files)
    return Review(build(root, cache=False).to_dict(), root)


def reached(files: dict[str, str]) -> set[str]:
    r = review(files)
    return {r.v.fn[fid]["qualname"] for fid in r.reached if fid in r.v.fn}


def ts(test: str, **more: str) -> dict[str, str]:
    files = {"src/CredentialRepository.ts": REPO_TS, "src/CredentialAccessService.ts": SERVICE_TS,
             "src/format.ts": FORMAT_TS, "src/CredentialAccessService.test.ts": test}  # fmt: skip
    return files | {f"src/{k.replace('__', '.')}.ts": v for k, v in more.items()}


@unittest.skipUnless(available(), "Node.js and the typescript package are needed")
class JsMockTest(unittest.TestCase):
    def test_a_module_mocked_with_a_factory_is_not_reached_through_the_code_under_test(self):  # cal.com
        test = (
            "import { vi, test, expect } from 'vitest';\n"
            "import { CredentialRepository } from './CredentialRepository';\n"
            "import { CredentialAccessService } from './CredentialAccessService';\n"
            "import { formatCredentialName } from './format';\n"
            "vi.mock('./CredentialRepository', () => ({\n"
            "  CredentialRepository: { findFirstByIdWithKeyAndUser: vi.fn(), countAll: vi.fn() },\n}));\n"
            "test('ensure', async () => {\n"
            "  vi.mocked(CredentialRepository.findFirstByIdWithKeyAndUser).mockResolvedValue({ id: 1 });\n"
            "  await new CredentialAccessService().ensure(1);\n"
            "  expect(formatCredentialName(' a ')).toBe('A');\n});\n"
        )
        files = ts(test)
        names = reached(files)
        self.assertIn("CredentialAccessService.ensure", names)
        self.assertIn("formatCredentialName", names)  # called for real in the same file
        self.assertNotIn("CredentialRepository.findFirstByIdWithKeyAndUser", names)
        r = review(files)
        r.run()
        found = next(f for f in r.findings if f.title.startswith("Important code no test reaches"))
        self.assertTrue(any("findFirstByIdWithKeyAndUser" in e for e in found.evidence), found.evidence)
        # a test that runs the real query reaches it
        repo_test = ("import { test } from 'vitest';\nimport { CredentialRepository } from './CredentialRepository';\n"
                     "test('find', async () => {\n"
                     "  await CredentialRepository.findFirstByIdWithKeyAndUser({ id: 1 });\n});\n")  # fmt: skip
        names = reached(ts(test, CredentialRepository__test=repo_test))
        self.assertIn("CredentialRepository.findFirstByIdWithKeyAndUser", names)
        # and so does one named for the service (reached by name) that mocks nothing
        plain = ("import { test } from 'vitest';\n"
                 "test('loads', async () => { await import('./CredentialAccessService'); });\n")  # fmt: skip
        names = reached(ts(test, CredentialAccessService__spec=plain))
        self.assertIn("CredentialRepository.findFirstByIdWithKeyAndUser", names)

    def test_a_partial_mock_replaces_only_what_it_names(self):
        test = (
            "import { vi, test } from 'vitest';\n"
            "import { CredentialAccessService } from './CredentialAccessService';\n"
            "vi.mock('./format', async (importOriginal) => ({\n"
            "  ...(await importOriginal()), formatCredentialName: vi.fn() }));\n"
            "vi.mock('./CredentialRepository', async () => {\n"
            "  const actual = await vi.importActual('./CredentialRepository');\n"
            "  return { ...actual, findFirstByIdWithKeyAndUser: vi.fn() };\n});\n"
            "test('both', async () => {\n  const s = new CredentialAccessService();\n"
            "  await s.ensure(1);\n  await s.total();\n});\n"
        )
        names = reached(ts(test))
        self.assertNotIn("CredentialRepository.findFirstByIdWithKeyAndUser", names)
        self.assertIn("CredentialRepository.countAll", names)  # the real one runs

    def test_jest_automock_and_jest_mocked(self):
        test = (
            "import { CredentialRepository } from './CredentialRepository';\n"
            "import { CredentialAccessService } from './CredentialAccessService';\n"
            "import { formatCredentialName } from './format';\n"
            "jest.mock('./CredentialRepository');\n"
            "it('ensure', async () => {\n"
            "  jest.mocked(CredentialRepository.countAll).mockResolvedValue(3);\n"
            "  await new CredentialAccessService().total();\n  formatCredentialName('x');\n});\n"
        )
        names = reached(ts(test))
        self.assertIn("CredentialAccessService.total", names)
        self.assertIn("formatCredentialName", names)
        self.assertNotIn("CredentialRepository.countAll", names)

    def test_spy_with_a_fake_result_replaces_it_and_a_bare_spy_calls_through(self):
        test = (
            "import { vi, test } from 'vitest';\n"
            "import { CredentialRepository } from './CredentialRepository';\n"
            "import { CredentialAccessService } from './CredentialAccessService';\n"
            "test('ensure', async () => {\n"
            "  vi.spyOn(CredentialRepository, 'findFirstByIdWithKeyAndUser').mockResolvedValue(null);\n"
            "  vi.spyOn(CredentialRepository, 'countAll');\n"
            "  const s = new CredentialAccessService();\n  await s.ensure(1);\n  await s.total();\n});\n"
        )
        names = reached(ts(test))
        self.assertNotIn("CredentialRepository.findFirstByIdWithKeyAndUser", names)
        self.assertIn("CredentialRepository.countAll", names)

    def test_references_that_only_set_up_or_check_a_mock(self):
        lib = ("export const api = {\n  load() { return fetch('/a'); },\n  save() { return fetch('/b'); },\n"
               "  drop() { return fetch('/c'); },\n  sync() { return fetch('/d'); },\n"
               "  ping() { return fetch('/e'); },\n};\n")  # fmt: skip
        test = (
            "import { vi, test, expect, type Mock } from 'vitest';\nimport { api } from './api';\n"
            "test('mocks', async () => {\n"
            "  api.load = vi.fn();\n"
            "  (api.save as Mock).mockReturnValue(1);\n"
            "  (api.drop as unknown as Mock).mockClear();\n"
            "  expect(api.sync).not.toHaveBeenCalled();\n"
            "  await api.ping();\n});\n"
        )
        names = reached({"src/api.ts": lib, "src/api.test.ts": test})
        self.assertIn("ping", names)  # the one real call
        for name in ("load", "save", "drop", "sync"):
            self.assertNotIn(name, names)

    def test_skipped_tests_reach_nothing(self):
        test = (
            "import { describe, it, test, expect } from 'vitest';\n"
            "import { CredentialRepository } from './CredentialRepository';\n"
            "import { formatCredentialName } from './format';\n"
            "describe.skip('repo', () => {\n"
            "  it('finds', async () => { await CredentialRepository.findFirstByIdWithKeyAndUser({ id: 1 }); });\n});\n"
            "xit('counts', async () => { await CredentialRepository.countAll(); });\n"
            "test('formats', () => { expect(formatCredentialName(' a ')).toBe('A'); });\n"
        )
        files = {"src/CredentialRepository.ts": REPO_TS, "src/format.ts": FORMAT_TS, "src/credentials.test.ts": test}
        names = reached(files)
        self.assertIn("formatCredentialName", names)
        self.assertNotIn("CredentialRepository.findFirstByIdWithKeyAndUser", names)
        self.assertNotIn("CredentialRepository.countAll", names)


PY_REPO = (
    "import requests\n\n\nclass Repo:\n    def find(self, i):\n        return requests.get(f'https://db/{i}')\n\n"
    "    def save(self, x):\n        return requests.post('https://db', json=x)\n\n\n"
    "def fetch_credential(i):\n    return requests.get(f'https://db/c/{i}')\n\n\n"
    "def count_credentials():\n    return len(requests.get('https://db/c').json())\n\n\n"
    "def load_settings():\n    return requests.get('https://db/s').json()\n"
)
PY_SERVICE = (
    "from app.repo import Repo, count_credentials, fetch_credential, load_settings\n\n\n"
    "def ensure(i):\n    return fetch_credential(i)\n\n\n"
    "def total():\n    return count_credentials()\n\n\n"
    "def find_one(i):\n    return Repo().find(i)\n\n\n"
    "def store(x):\n    return Repo().save(x)\n\n\n"
    "def settings():\n    return load_settings()\n"
)


def py(test: str) -> dict[str, str]:
    return {"app/__init__.py": "", "app/repo.py": PY_REPO, "app/service.py": PY_SERVICE, "tests/test_service.py": test}


class PythonMockTest(unittest.TestCase):
    def test_patch_by_name_patch_object_and_mocker(self):
        test = (
            "from unittest import mock\nfrom unittest.mock import MagicMock, patch\n\n"
            "from app import repo, service\nfrom app.repo import Repo\n\n\n"
            "@patch('app.service.fetch_credential')\ndef test_ensure(m):\n    service.ensure(1)\n\n\n"
            "def test_find():\n    with mock.patch.object(Repo, 'find'):\n        service.find_one(1)\n\n\n"
            "def test_store(mocker):\n    mocker.patch('app.repo.Repo.save')\n    service.store({})\n\n\n"
            "def test_settings():\n    repo.load_settings = MagicMock()\n    service.settings()\n\n\n"
            "def test_total():\n    assert service.total() >= 0\n"
        )
        names = reached(py(test))
        self.assertTrue({"ensure", "find_one", "store", "settings"} <= names, names)
        self.assertIn("count_credentials", names)  # run for real through service.total
        for name in ("fetch_credential", "Repo.find", "Repo.save", "load_settings"):
            self.assertNotIn(name, names)

    def test_mock_attributes_are_not_a_call(self):
        test = (
            "from unittest.mock import patch\n\nfrom app import repo, service\n\n\n"
            "@patch('app.repo.fetch_credential')\ndef test_ensure(m):\n"
            "    repo.fetch_credential.return_value = 1\n    service.ensure(1)\n"
            "    repo.fetch_credential.assert_called_once_with(1)\n\n\n"
            "def test_count():\n    assert repo.count_credentials() >= 0\n"
        )
        names = reached(py(test))
        self.assertIn("count_credentials", names)
        self.assertNotIn("fetch_credential", names)

    def test_skipped_tests_reach_nothing(self):
        test = (
            "import unittest\n\nimport pytest\n\nfrom app import repo\n\n\n"
            "@pytest.mark.skip(reason='flaky')\ndef test_fetch():\n    repo.fetch_credential(1)\n\n\n"
            "class RepoTest(unittest.TestCase):\n    @unittest.skip('later')\n    def test_settings(self):\n"
            "        repo.load_settings()\n\n    def test_count(self):\n        repo.count_credentials()\n"
        )
        names = reached(py(test))
        self.assertIn("count_credentials", names)
        self.assertNotIn("fetch_credential", names)
        self.assertNotIn("load_settings", names)


class ByNameTest(unittest.TestCase):
    """What tests reach by name or by file name, on the way to the cal.com case."""

    def test_a_test_file_whose_tests_are_all_skipped_is_no_test_of_its_namesake(self):  # editLocation.handler
        test = "import pytest\n\n\n{}def test_charge():\n    pass\n"
        names = reached({"app/billing.py": "def charge_card(x):\n    return x\n",
                         "tests/test_billing.py": test.format("@pytest.mark.skip(reason='needs a db')\n"),
                         "app/invoices.py": "def make_invoice(x):\n    return x\n",
                         "tests/test_invoices.py": test.format("")})  # fmt: skip
        self.assertIn("make_invoice", names)
        self.assertNotIn("charge_card", names)

    def test_a_call_resolved_to_one_function_does_not_name_its_namesakes(self):  # getAllCredentialsInclude…
        fn = "def load_user_profile(i):\n    return i\n"
        test = "from app.profiles import load_user_profile\n\n\ndef test_load():\n    load_user_profile(1)\n"
        names = {fid.split("::")[0] for fid in review({"app/__init__.py": "", "app/profiles.py": fn, "app/admin.py": fn,
                                                        "tests/test_loading.py": test}).reached}  # fmt: skip
        self.assertIn("app/profiles.py", names)
        self.assertNotIn("app/admin.py", names)
        # unresolved (imported through a path the graph doesn't follow): still reached by name
        test = "import importlib\n\n\ndef test_load():\n    importlib.import_module('x').load_user_profile(1)\n"
        names = {fid.split("::")[0] for fid in review({"app/__init__.py": "", "app/admin.py": fn,
                                                        "tests/test_loading.py": test}).reached}  # fmt: skip
        self.assertIn("app/admin.py", names)

    @unittest.skipUnless(available(), "Node.js and the typescript package are needed")
    def test_index_test_is_a_test_of_the_index_next_to_it(self):  # tasker/tasks/index.ts
        index = "export function register{n}() {{\n  return '{n}';\n}}\n"
        names = {fid.split("::")[0] for fid in review({
            "src/widgets/index.ts": index.format(n="Widgets"), "src/tasks/index.ts": index.format(n="Tasks"),
            "src/widgets/__tests__/index.test.ts": "import { test } from 'vitest';\ntest('loads', () => {});\n",
        }).reached}  # fmt: skip
        self.assertIn("src/widgets/index.ts", names)
        self.assertNotIn("src/tasks/index.ts", names)


if __name__ == "__main__":
    unittest.main()
