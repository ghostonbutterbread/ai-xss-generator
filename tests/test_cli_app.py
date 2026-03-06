import contextlib
import io
import unittest

from ai_xss_generator import __version__
from ai_xss_generator.cli import build_parser
from ai_xss_generator.config import DEFAULT_MODEL


class CliAppTest(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = build_parser(DEFAULT_MODEL)

    def test_url_short_flags_are_parsed(self) -> None:
        args = self.parser.parse_args(
            [
                "-u",
                "https://example.com",
                "-m",
                "qwen3.5:4b",
                "-o",
                "json",
                "-t",
                "3",
                "-j",
                "result.json",
                "-v",
                "--public",
                "--bypass",
                "<svg/onload=alert(1)>",
                "--waf",
                "cloudflare",
            ]
        )

        self.assertEqual(args.url, "https://example.com")
        self.assertIsNone(args.urls)
        self.assertIsNone(args.input)
        self.assertEqual(args.model, "qwen3.5:4b")
        self.assertEqual(args.output, "json")
        self.assertEqual(args.top, 3)
        self.assertEqual(args.json_out, "result.json")
        self.assertTrue(args.verbose)
        self.assertTrue(args.public)
        self.assertEqual(args.bypass, "<svg/onload=alert(1)>")
        self.assertEqual(args.waf, "cloudflare")
        self.assertFalse(args.merge_batch)

    def test_urls_long_flags_are_parsed(self) -> None:
        args = self.parser.parse_args(
            [
                "--urls",
                "targets.txt",
                "--output",
                "heat",
                "--top",
                "7",
                "--json-out",
                "batch.json",
                "--merge-batch",
            ]
        )

        self.assertIsNone(args.url)
        self.assertEqual(args.urls, "targets.txt")
        self.assertIsNone(args.input)
        self.assertEqual(args.output, "heat")
        self.assertEqual(args.top, 7)
        self.assertEqual(args.json_out, "batch.json")
        self.assertTrue(args.merge_batch)
        self.assertFalse(args.verbose)
        self.assertFalse(args.public)
        self.assertIsNone(args.bypass)
        self.assertIsNone(args.waf)
        self.assertIsNone(args.model)

    def test_input_mode_uses_defaults(self) -> None:
        args = self.parser.parse_args(["-i", "sample_target.html"])

        self.assertEqual(args.input, "sample_target.html")
        self.assertIsNone(args.url)
        self.assertIsNone(args.urls)
        self.assertFalse(args.list_models)
        self.assertIsNone(args.search_models)
        self.assertEqual(args.output, "list")
        self.assertEqual(args.top, 20)
        self.assertFalse(args.verbose)
        self.assertFalse(args.merge_batch)
        self.assertFalse(args.public)
        self.assertIsNone(args.bypass)
        self.assertIsNone(args.waf)
        self.assertIsNone(args.json_out)
        self.assertIsNone(args.model)

    def test_model_listing_and_search_flags_are_parsed(self) -> None:
        list_args = self.parser.parse_args(["-l"])
        search_args = self.parser.parse_args(["-s", "qwen3.5"])

        self.assertTrue(list_args.list_models)
        self.assertIsNone(list_args.search_models)
        self.assertEqual(search_args.search_models, "qwen3.5")
        self.assertFalse(search_args.list_models)

    def test_parser_requires_exactly_one_action_flag(self) -> None:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as no_action:
                self.parser.parse_args([])

            with self.assertRaises(SystemExit) as conflicting_actions:
                self.parser.parse_args(["-u", "https://example.com", "-i", "sample_target.html"])

        self.assertEqual(no_action.exception.code, 2)
        self.assertEqual(conflicting_actions.exception.code, 2)

    def test_version_flag_prints_version(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as exit_info:
                self.parser.parse_args(["-V"])

        self.assertEqual(exit_info.exception.code, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(stdout.getvalue().strip(), f"axss {__version__}")


if __name__ == "__main__":
    unittest.main()
