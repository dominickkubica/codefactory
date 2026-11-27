"""Browser end-to-end tests (Playwright, Puppeteer, Cypress) open pages by URL, which runs each page's code: "no test
reaches it" was wrong for what those pages render (appwrite's MySQL console, gotify's client list). Each rule sits next
to a page no test opens, which must stay unreached."""

import unittest

from codefactory.cli import build
from codefactory.e2e import route_of, visited
from codefactory.review import Review
from tests.test_large_repo import repo


def reached(files: dict[str, str]) -> set[str]:
    root = repo(files)
    r = Review(build(root, cache=False).to_dict(), root)
    r.run()
    return r.reached


class E2ePagesTest(unittest.TestCase):
    def test_a_tanstack_route_a_playwright_test_opens(self):  # appwrite: projects.$projectId.databases.mysql…tsx
        got = reached({
            "web/package.json": '{"name": "web"}\n',
            "web/src/routes/projects.$projectId.databases.$databaseId.tsx":
                "import { SchemaSidebar } from '../components/SchemaSidebar'\n"
                "export function DatabaseLayout() {\n  return <SchemaSidebar />\n}\n",
            "web/src/routes/projects.$projectId.billing.tsx":
                "import { InvoiceList } from '../components/InvoiceList'\n"
                "export function BillingPage() {\n  return <InvoiceList />\n}\n",
            "web/src/components/SchemaSidebar.tsx":
                "export function useSchemaSelection() {\n  return [1, 2].map((n) => n * 2)\n}\n"
                "export function SchemaSidebar() {\n  const rows = useSchemaSelection()\n  return <ul>{rows}</ul>\n}\n",
            "web/src/components/InvoiceList.tsx":
                "export function formatInvoiceTotal(n: number) {\n  return n.toFixed(2)\n}\n"
                "export function InvoiceList() {\n  return <p>{formatInvoiceTotal(3)}</p>\n}\n",
            "web/e2e/console.spec.ts":
                "import { test } from '@playwright/test'\n"
                "test('opens a database', async ({ page }) => {\n"
                "  await page.goto(`/projects/${project.id}/databases/${db.id}`, { timeout: 60_000 })\n})\n",
        })  # fmt: skip
        self.assertIn("web/src/components/SchemaSidebar.tsx::useSchemaSelection", got)
        self.assertNotIn("web/src/components/InvoiceList.tsx::formatInvoiceTotal", got)  # billing: never opened

    def test_a_hash_route_a_puppeteer_test_opens(self):  # gotify: page.goto(url + '/#/clients')
        store = ("export abstract class BaseStore {\n  protected abstract requestItems(): number[]\n"
                 "  public refresh(): number[] {\n    return this.requestItems()\n  }\n}\n")  # fmt: skip
        got = reached({
            "ui/package.json": '{"name": "ui"}\n',
            "ui/src/common/BaseStore.ts": store,
            "ui/src/client/ClientStore.ts":
                "import { BaseStore } from '../common/BaseStore'\nexport class ClientStore extends BaseStore {\n"
                "  protected requestItems(): number[] {\n    return [1]\n  }\n"
                "  public rename(name: string): string {\n    return name.trim()\n  }\n}\n",
            "ui/src/user/UserStore.ts":
                "import { BaseStore } from '../common/BaseStore'\nexport class UserStore extends BaseStore {\n"
                "  protected requestItems(): number[] {\n    return [2]\n  }\n"
                "  public promote(name: string): string {\n    return name.toUpperCase()\n  }\n}\n",
            "ui/src/client/Clients.tsx":
                "import { ClientStore } from './ClientStore'\nconst clients = new ClientStore()\n"
                "export function Clients() {\n  clients.refresh()\n  clients.rename('a')\n  return <div />\n}\n",
            "ui/src/user/Users.tsx":
                "import { UserStore } from './UserStore'\nconst users = new UserStore()\n"
                "export function Users() {\n  users.refresh()\n  users.promote('a')\n  return <div />\n}\n",
            "ui/src/layout/Layout.tsx":
                "import { HashRouter, Route, Routes } from 'react-router'\n"
                "import { Clients } from '../client/Clients'\nimport { Users } from '../user/Users'\n"
                "export function Layout() {\n  return (\n    <HashRouter><Routes>\n"
                "      <Route path=\"/clients\" element={authed(<Clients />)} />\n"
                "      <Route\n        path=\"/users\"\n        element={<Users />}\n      />\n"
                "    </Routes></HashRouter>\n  )\n}\n",
            "ui/src/tests/elevation.test.ts":
                "it('elevates', async () => {\n  await page.goto(gotify.url + '/#/clients')\n"
                "  expect(page.url()).toContain('/#/clients')\n})\n",
        })  # fmt: skip
        self.assertIn("ui/src/client/ClientStore.ts::ClientStore.requestItems", got)  # through BaseStore.refresh
        self.assertNotIn("ui/src/user/UserStore.ts::UserStore.requestItems", got)  # /users: never opened
        self.assertNotIn("ui/src/user/Users.tsx::Users", got)

    def test_a_next_page_a_cypress_test_visits(self):
        got = reached({
            "package.json": '{"name": "site"}\n',
            "app/dashboard/page.tsx":
                "export default function DashboardPage() {\n  return <h1>{summarizeUsage()}</h1>\n}\n"
                "function summarizeUsage() {\n  return 'ok'\n}\n",
            "app/settings/page.tsx":
                "export default function SettingsPage() {\n  return <h1>{describeSettings()}</h1>\n}\n"
                "function describeSettings() {\n  return 'ok'\n}\n",
            "cypress/e2e/flows.cy.ts":
                "describe('flows', () => {\n  it('shows usage', () => {\n    cy.visit('/dashboard')\n  })\n})\n",
        })  # fmt: skip
        self.assertIn("app/dashboard/page.tsx::summarizeUsage", got)
        self.assertNotIn("app/settings/page.tsx::describeSettings", got)

    def test_route_files_by_framework(self):
        def project(folder: str) -> bool:
            return folder in ("", "apps/web")

        cases = {
            "apps/web/src/routes/_public/projects.$projectId.databases.mysql.$databaseId.index.tsx":
                (("projects", "$", "databases", "mysql", "$"), True),  # TanStack: `_public` is a pathless layout
            "app/routes/notes.$noteId.tsx": (("notes", "$"), True),  # Remix
            "app/routes/_index.tsx": None,  # "/": under every URL
            "src/routes/blog/[slug]/+page.svelte": (("blog", "$"), False),  # SvelteKit
            "pages/users/[id].vue": (("users", "$"), False),  # Nuxt
            "pages/_app.tsx": None,
            "pages/api/users.ts": None,
            "app/(shop)/cart/page.tsx": (("cart",), False),  # Next.js route group
            "app/docs/[...slug]/page.tsx": None,  # a catch-all is as often a not-found page
            "apps/web/src/components/pages/projects/Overview.tsx": None,  # a folder named pages, not a router's
            "lib/routes/users.ts": None,  # not a JavaScript project's folder
        }  # fmt: skip
        for path, want in cases.items():
            self.assertEqual(route_of(path, project), want, path)

    def test_visited_urls(self):
        text = ("await page.goto(`${baseURL}/projects/${id}/sql?tab=1`)\ncy.visit('/')\n"
                "await expect(page).toHaveURL(new RegExp(`/orgs/${org}/settings`))\nawait page.goto(someHelper(id))\n"
                "browser.url('https://example.test/#/messages/1')\n"
                "await expect(page).toHaveURL(/\\/sql/)\n")  # fmt: skip
        self.assertEqual(visited([text]), {("projects", "*", "sql"), ("orgs", "*", "settings"), ("messages", "1")})


if __name__ == "__main__":
    unittest.main()
