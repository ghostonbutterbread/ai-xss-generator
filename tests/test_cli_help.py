import unittest
from io import StringIO
from contextlib import redirect_stdout

from ai_xss_generator.cli import build_parser, main
from ai_xss_generator.config import DEFAULT_MODEL


class CliHelpTest(unittest.TestCase):
    def test_help_pairs_are_clear(self) -> None:
        help_text = build_parser(DEFAULT_MODEL).format_help()

        self.assertIn("-h, --help", help_text)
        self.assertIn("-u, --url TARGET", help_text)
        self.assertIn("--urls FILE", help_text)
        self.assertIn("-i, --input FILE_OR_SNIPPET", help_text)
        self.assertIn("-l, --list-models", help_text)
        self.assertIn("-s, --search-models QUERY", help_text)
        self.assertIn("-m, --model MODEL", help_text)
        self.assertIn("-o, --output {json,list,heat}", help_text)
        self.assertIn("-t, --top N", help_text)
        self.assertIn("-j, --json-out PATH", help_text)
        self.assertIn("-v, --verbose", help_text)
        self.assertIn("--merge-batch", help_text)
        self.assertIn("--public", help_text)
        self.assertIn("--bypass BYPASS", help_text)
        self.assertIn("--waf WAF", help_text)
        self.assertIn("-V, --version", help_text)
        self.assertNotIn("--html", help_text)
        self.assertNotIn("(default: None)", help_text)

    def test_main_help_exits_cleanly(self) -> None:
        stdout = StringIO()
        with redirect_stdout(stdout):
            with self.assertRaises(SystemExit) as exc:
                main(["--help"])

        self.assertEqual(exc.exception.code, 0)
        help_text = stdout.getvalue()
        self.assertIn("usage: axss", help_text)
        self.assertIn("options:", help_text)
        self.assertIn("-u, --url TARGET", help_text)
        self.assertIn("--public", help_text)


if __name__ == "__main__":
    unittest.main()
