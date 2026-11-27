"""False positives in "errors silently swallowed" from held-out corpus labels, each next to a true case that must stay
reported."""

import unittest

from codefactory.checks import scan_sources
from tests.test_large_repo import repo


def hits(found, key):
    return [(e.file, e.line) for e in found[key].hits]


class SwallowedTest(unittest.TestCase):
    def scan(self, files):
        return scan_sources(repo(files), list(files))

    def test_a_noop_catch_on_a_promise_awaited_later(self):
        # n8n HttpRequestV2: the catch only stops an unhandled rejection; allSettled sees the failure
        pushed = (
            "async function run(items) {\n"
            "  const requestPromises = [];\n"
            "  for (const item of items) {\n"
            "    const request = helpers.request(item);\n"
            "    request.catch(() => {});\n"
            "    requestPromises.push(request);\n"
            "  }\n"
            "  const responses = await Promise.allSettled(requestPromises);\n"
            "  return responses;\n"
            "}\n"
        )
        awaited = "async function f() {\n  const p = load();\n  p.catch(() => {});\n  await other();\n  return await p;\n}\n"
        lost = "function f() {\n  const p = load();\n  p.catch(() => {});\n  done();\n}\n"
        pushed_never_awaited = (
            "function f() {\n  const p = load();\n  p.catch(() => {});\n  queue.push(p);\n  return queue.length;\n}\n"
        )
        found = self.scan({"pushed.ts": pushed, "awaited.ts": awaited, "lost.ts": lost, "queue.ts": pushed_never_awaited})
        self.assertEqual(sorted(hits(found, "swallowed")), [("lost.ts", 3), ("queue.ts", 3)])

    def test_a_route_loader_warming_the_query_cache(self):
        # appwrite console: React Query keeps a failed prefetch's error in its cache for the page to show
        loader = (
            "export const Route = createFileRoute('/x')({\n"
            "  loader: async ({ context: { queryClient } }) => {\n"
            "    await Promise.all([\n"
            "      queryClient\n"
            "        .ensureQueryData(orgQueryOptions(orgId))\n"
            "        .catch(() => undefined),\n"
            "      queryClient.prefetchQuery(planQueryOptions(orgId)).catch(() => {}),\n"
            "    ])\n"
            "  },\n"
            "})\n"
        )
        assigned = (
            "async function region(queryClient, id) {\n"
            "  const project = await queryClient\n"
            "    .ensureQueryData(projectQueryOptions(id))\n"
            "    .catch(() => null)\n"
            "  return project\n"
            "}\n"
        )
        destructured = (
            "async function load(queryClient) {\n"
            "  const [org] = await Promise.all([\n"
            "    queryClient\n"
            "      .ensureQueryData(orgQueryOptions(id))\n"
            "      .catch(() => {}),\n"
            "  ])\n"
            "  return org\n"
            "}\n"
        )
        plain = "async function f() {\n  await api\n    .fetchOrg(id)\n    .catch(() => {})\n}\n"
        found = self.scan({"loader.tsx": loader, "region.ts": assigned, "pair.ts": destructured, "plain.ts": plain})
        reported = hits(found, "swallowed")
        self.assertNotIn("loader.tsx", [f for f, _ in reported])
        self.assertIn(("plain.ts", 4), reported)
        # the results are used, so the cache isn't the reason (other rules may still judge the value a fallback)
        why = {(e.file, e.line): e.text for e in found["swallowed_ok"].hits}
        self.assertEqual(why[("loader.tsx", 6)], "query cache")
        self.assertNotEqual(why.get(("region.ts", 4)), "query cache")
        self.assertNotEqual(why.get(("pair.ts", 5)), "query cache")


class LongChainsTest(unittest.TestCase):
    def test_a_prefetch_chain_over_many_lines_and_a_realpath_helper(self):
        files = {  # appwrite waf.ts: the chain starts eight lines above the catch; vite config
            "waf.ts": "export function warm(queryClient) {\n  void queryClient\n    .prefetchQuery(\n      wafOptions(\n"
                      "        projectId,\n        range,\n      ),\n    )\n    .catch(() => undefined)\n}\n",
            "config.ts": "let root = cwd\ntry {\n  root = safeRealpathSync(root)\n} catch {}\n",
            "bad.ts": "try {\n  await rm(dir, { force: true })\n} catch {}\n",
        }  # fmt: skip
        found = scan_sources(repo(files), list(files))
        self.assertEqual([e.file for e in found["swallowed"].hits], ["bad.ts"])


class ReturnsAndChainsTest(unittest.TestCase):
    def test_a_return_after_the_throwing_call_and_a_chained_fallback(self):
        files = {  # n8n server.ts (fsAccess then return), tldraw useFetchJson (.catch(() => null).then)
            "server.ts": "if (filePath) {\n  try {\n    await fsAccess(filePath);\n    return send(res, filePath);\n  } catch {}\n}\n",
            "hook.ts": "load()\n  .catch(() => null)\n  .then((data) => setData(data))\n",
            "parse.ts": "function f(s) {\n  try {\n    return JSON.parse(s);\n  } catch {}\n}\n",
            "bad.ts": "try {\n  await save(item);\n  return item;\n} catch {}\n",
        }  # fmt: skip
        found = scan_sources(repo(files), list(files))
        self.assertEqual(sorted({e.file for e in found["swallowed"].hits}), ["bad.ts", "parse.ts"])


if __name__ == "__main__":
    unittest.main()
