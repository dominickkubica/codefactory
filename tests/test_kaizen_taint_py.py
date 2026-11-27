"""Python data flow: each guard real apps put in front of a sink reads as clean, next to the same flow without it."""

import unittest

from codefactory.cli import build
from tests.test_large_repo import repo

HEAD = (
    "import os\nimport requests\nfrom enum import StrEnum\nfrom uuid import UUID\n"
    "from flask import request, redirect, abort, render_template_string\n"
    "from django.utils.safestring import mark_safe\nfrom fastapi import APIRouter\nfrom pydantic import UUID4\n"
    "from starlette.responses import FileResponse\n\nrouter = APIRouter()\nBASE = '/srv/files'\n\n\n"
)


def flows(code: str) -> list[str]:
    root = repo({"app.py": HEAD + code})
    return sorted(f.target.split("::")[-1] for f in build(root, cache=False).flags if f.kind == "taint")


class RedirectGuards(unittest.TestCase):
    def test_validator_on_the_expression_before_the_sink(self):  # CTFd, pretix
        code = (
            "def login():\n"
            "    if request.args.get('next') and is_safe_url(request.args.get('next')):\n"
            "        return redirect(request.args.get('next'))\n"
            "    return redirect('/')\n\n\n"
            "def bad():\n"
            "    if request.args.get('next'):\n"
            "        return redirect(request.args.get('next'))\n"
        )
        self.assertEqual(flows(code), ["bad"])

    def test_failed_check_leaves_or_replaces(self):  # netbox redirect_to_next
        code = (
            "def aborts():\n"
            "    nxt = request.args['next']\n"
            "    if not url_has_allowed_host_and_scheme(nxt, allowed_hosts=None):\n"
            "        abort(400)\n"
            "    return redirect(nxt)\n\n\n"
            "def replaced_in_else():\n"
            "    nxt = request.args['next']\n"
            "    if nxt and safe_for_redirect(nxt):\n"
            "        log(nxt)\n"
            "    else:\n"
            "        nxt = '/home'\n"
            "    return redirect(nxt)\n\n\n"
            "def sibling_branch(flag):\n"
            "    nxt = request.args['next']\n"
            "    if flag:\n"
            "        if not is_safe_url(nxt):\n"
            "            return redirect('/')\n"
            "    else:\n"
            "        return redirect(nxt)\n"
        )
        self.assertEqual(flows(code), ["sibling_branch"])

    def test_sanitizer_helper(self):  # redash get_next_path
        code = (
            "def login():\n"
            "    next_path = get_next_path(request.args.get('next'))\n"
            "    return redirect(next_path)\n\n\n"
            "def bad():\n"
            "    next_path = get_next(request.args.get('next'))\n"
            "    return redirect(next_path)\n"
        )
        self.assertEqual(flows(code), ["bad"])

    def test_inner_functions_keep_their_own_locals(self):  # a blueprint factory: login stores it, authorized cleans it
        code = (
            "def create_blueprint(app):\n"
            "    def login():\n"
            "        next_path = request.args.get('next')\n"
            "        session['next'] = next_path\n"
            "    def authorized():\n"
            "        next_path = get_next_path(session.pop('next'))\n"
            "        return redirect(next_path)\n"
            "    return app\n"
        )
        self.assertEqual(flows(code), [])

    def test_attribute_assignment_does_not_taint_self(self):  # pretix: self.x = request data, then self.get_url()
        code = (
            "class View:\n"
            "    def post(self):\n"
            "        self.comment = self.request.POST.get('comment')\n"
            "        return redirect(self.get_order_url())\n\n"
            "    def bad(self):\n"
            "        self.next = self.request.POST.get('next')\n"
            "        return redirect(self.next)\n"
        )
        self.assertEqual(flows(code), ["View.bad"])

    def test_method_arguments_skip_self(self):  # pretix: self.perform_refund(comment) — comment isn't `self`
        code = (
            "class View:\n"
            "    def post(self):\n"
            "        comment = self.request.POST.get('comment')\n"
            "        self.refund(comment)\n"
            "        self.go(self.request.POST.get('next'))\n\n"
            "    def refund(self, comment):\n"
            "        save(comment)\n"
            "        return redirect(self.get_order_url())\n\n"
            "    def go(self, nxt):\n"
            "        return redirect(nxt)\n"
        )
        self.assertEqual(flows(code), ["View.go"])


class PathGuards(unittest.TestCase):
    def test_containment_and_allow_list(self):
        code = (
            "def contained(name):\n"
            "    p = os.path.realpath(os.path.join(BASE, request.args['f']))\n"
            "    if not p.startswith(BASE):\n"
            "        abort(404)\n"
            "    return open(p).read()\n\n\n"
            "def common():\n"
            "    p = os.path.realpath(os.path.join(BASE, request.args['f']))\n"
            "    if os.path.commonpath([BASE, p]) != BASE:\n"
            "        raise ValueError(p)\n"
            "    return open(p).read()\n\n\n"
            "def listed():\n"
            "    plugin = request.args['p']\n"
            "    if plugin in [n for n in os.listdir(BASE)]:\n"
            "        html = open(os.path.join(BASE, plugin, 'config.html')).read()\n"
            "        return render_template_string(html)\n\n\n"
            "def bad():\n"
            "    p = os.path.realpath(os.path.join(BASE, request.args['f']))\n"
            "    if not p.startswith('/'):\n"
            "        abort(404)\n"
            "    return open(p).read()\n"
        )
        self.assertEqual(flows(code), ["bad"])

    def test_fastapi_is_relative_to_uuid_and_enum(self):  # mealie
        code = (
            "class Image(StrEnum):\n    original = 'original.webp'\n\n\n"
            "@router.get('/{user_id}/{file_name}')\n"
            "async def user_image(user_id: UUID4, file_name: str):\n"
            "    user_dir = get_directory(user_id)\n"
            "    image = (user_dir / file_name).resolve()\n"
            "    if not image.is_relative_to(user_dir.resolve()):\n"
            "        raise HTTPException(400)\n"
            "    return FileResponse(image)\n\n\n"
            "@router.get('/{recipe_id}/images/{file_name}')\n"
            "async def recipe_image(recipe_id: UUID4, file_name: Image):\n"
            "    return FileResponse(directory(recipe_id).joinpath('images', file_name.value))\n\n\n"
            "@router.get('/{user_id}/raw/{file_name}')\n"
            "async def bad(user_id: UUID4, file_name: str):\n"
            "    return FileResponse(get_directory(user_id) / file_name)\n"
        )
        self.assertEqual(flows(code), ["bad"])


class HostAndHtml(unittest.TestCase):
    def test_fixed_host(self):
        code = (
            "def search():\n"
            "    q = request.args['q']\n"
            "    requests.get(f'https://api.example.com/v1/search?q={q}')\n"
            "    requests.get('https://api.example.com/items/' + q)\n"
            "    requests.get('https://api.example.com/items/{}'.format(q))\n"
            "    requests.get(f'{settings.API_URL}/items/{q}')\n\n\n"
            "def bad():\n"
            "    q = request.args['q']\n"
            "    requests.get(f'https://api.example.com{q}')\n\n\n"
            "def bad_scheme():\n"
            "    requests.get(f\"{settings.SCHEME}://{request.args['host']}/x\")\n"
        )
        self.assertEqual(flows(code), ["bad", "bad_scheme"])

    def test_cleaned_before_mark_safe(self):  # netbox render_markdown
        code = (
            "def render():\n"
            "    html = markdown(request.POST['text'])\n"
            "    html = f'<div>{html}</div>'\n"
            "    html = clean_html(html, SCHEMES)\n"
            "    return mark_safe(html)\n\n\n"
            "def bad():\n"
            "    html = markdown(request.POST['text'])\n"
            "    html = f'<div>{html}</div>'\n"
            "    return mark_safe(html)\n\n\n"
            "def context_variable():\n"
            "    return render_template_string('<p>{{ q }}</p>', q=request.args['q'])\n"
        )
        self.assertEqual(flows(code), ["bad"])


if __name__ == "__main__":
    unittest.main()
