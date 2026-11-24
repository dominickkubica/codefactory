"""Swift on Apple platforms: force try/cast, retain cycles, main-thread I/O, weakened entitlements."""

import tempfile
import textwrap
import unittest
from pathlib import Path

from codefactory.apple import scan


def tree(files: dict[str, str]) -> tuple[Path, list[str]]:
    root = Path(tempfile.mkdtemp())
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(textwrap.dedent(text), encoding="utf-8")
    return root, sorted(files)


def lines(checks, key):
    return [e.line for e in checks[key].hits]


class AppleTest(unittest.TestCase):
    def test_swift_checks_and_look_alikes(self):
        root, files = tree({"App/Feed.swift": '''
            final class FeedViewController: UIViewController {
                var onTap: (() -> Void)?
                override func viewDidLoad() {
                    super.viewDidLoad()
                    let data = try! Data(contentsOf: cacheURL)
                    Task { let fresh = try await loader.load() }
                    model.$items.sink { items in
                        self.render(items)
                    }.store(in: &bag)
                    model.$title.sink { [weak self] t in
                        self?.title = t
                    }.store(in: &bag)
                    self.onTap = {
                        self.dismiss(animated: true)
                    }
                    self.onTap = { [unowned self] in self.dismiss(animated: true) }
                    let ok = try? decoder.decode(Feed.self, from: data)
                    // let x = try! risky()
                    let cell = view as! FeedCell
                }
                func reload() {
                    let text = try String(contentsOf: url)
                }
            }
            ''',
            "App/Tests/FeedTests.swift": "let x = try! Data(contentsOf: url)\n",
            "App/App.entitlements": """<plist><dict>
                <key>com.apple.security.cs.disable-library-validation</key>
                <true/>
                <key>com.apple.security.app-sandbox</key>
                <true/>
            </dict></plist>""",
        })  # fmt: skip
        c = scan(root, files)
        self.assertEqual(lines(c, "swift_force"), [6, 20])  # not the comment, try?, or the test file
        self.assertEqual(lines(c, "swift_retain_cycle"), [8, 14])  # not [weak self] / [unowned self]
        self.assertEqual(lines(c, "main_thread_io"), [6])  # viewDidLoad only; reload() isn't a main-thread hook
        self.assertEqual([e.text for e in c["entitlement_weakened"].hits], ["com.apple.security.cs.disable-library-validation"])

    def test_swiftui_body(self):
        root, files = tree({"V.swift": '''
            struct V: View {
                var body: some View {
                    let s = (try? String(contentsOf: url)) ?? ""
                    Text(s)
                }
            }
            '''})  # fmt: skip
        self.assertEqual(lines(scan(root, files), "main_thread_io"), [4])


if __name__ == "__main__":
    unittest.main()
