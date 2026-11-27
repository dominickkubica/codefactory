"""What tests reach in ways the call graph can't follow, from labeled misses on real repositories."""

import unittest

from codefactory.analyzers.generic import available
from codefactory.cli import build
from codefactory.review import Review
from tests.test_large_repo import repo


def reached(files: dict[str, str]) -> set[str]:
    root = repo(files)
    r = Review(build(root, cache=False).to_dict(), root)
    return {r.v.fn[fid]["qualname"] for fid in r.reached if fid in r.v.fn}


class TestReachTest(unittest.TestCase):
    @unittest.skipUnless(available(), "needs the language pack (PHP is parsed with tree-sitter)")
    def test_a_php_method_a_test_calls_with_arrow_or_double_colon(self):  # appwrite: TlsTransport.write
        # five transports share `write`: too many for the call graph to pick one, and the test gets them from a
        # data provider, as `$transport->write()` / `$class::open()`
        transport = ("<?php\nclass {c} {{\n"
                     "  public function write(string $d): void {{\n    fwrite($this->s, $d);\n  }}\n"
                     "  public static function open(string $h): self {{\n    return new self(fsockopen($h));\n  }}\n"
                     "  public function drain(): void {{\n    fflush($this->s);\n  }}\n}}\n")  # fmt: skip
        kinds = ["Tls", "Tcp", "Swoole", "WebSocket", "Fake"]
        files = {f"src/Transport/{k}Transport.php": transport.format(c=f"{k}Transport") for k in kinds}
        files["tests/DeathDetectionTest.php"] = (
            "<?php\nclass DeathDetectionTest extends TestCase {\n"
            "  public static function streamTransportProvider(): array {\n    return [[TlsTransport::class]];\n  }\n"
            "  /** @dataProvider streamTransportProvider */\n"
            "  public function testWrite(string $class): void {\n"
            "    $transport = $class::open('h');\n    $transport->write(\"PING\\r\\n\");\n  }\n}\n"
        )  # fmt: skip
        names = reached(files)
        self.assertTrue({"TlsTransport.write", "TlsTransport.open"} <= names, names)
        self.assertNotIn("TlsTransport.drain", names)  # no test calls it: still unreached


if __name__ == "__main__":
    unittest.main()
