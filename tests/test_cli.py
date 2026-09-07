"""Unit tests for auto_permissions.cli's rule-file install/uninstall lifecycle."""

import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from auto_permissions import cli


class TestRuleFilePaths(unittest.TestCase):
    def test_get_rules_file_local_is_under_cwd_dot_agents(self):
        with TemporaryDirectory() as tmp:
            with patch("auto_permissions.cli.Path.cwd", return_value=Path(tmp)):
                p = cli.get_rules_file(is_global=False)
        self.assertEqual(p, Path(tmp) / ".agents" / "rules" / "interactive_decisions.md")

    def test_get_rules_file_global_is_under_home_gemini(self):
        with TemporaryDirectory() as tmp:
            with patch("auto_permissions.cli.Path.home", return_value=Path(tmp)):
                p = cli.get_rules_file(is_global=True)
        self.assertEqual(p, Path(tmp) / ".gemini" / "config" / "rules" / "interactive_decisions.md")

    def test_get_bundled_rule_content_returns_packaged_file(self):
        packaged_path = Path(cli.__file__).resolve().parent / "rules" / "interactive_decisions.md"
        content = cli.get_bundled_rule_content()
        self.assertTrue(content)
        self.assertEqual(content, packaged_path.read_text(encoding="utf-8"))


class TestInstallUninstallHook(unittest.TestCase):
    def test_install_hook_writes_hooks_file_and_rule_file_locally(self):
        with TemporaryDirectory() as tmp:
            with patch("auto_permissions.cli.Path.cwd", return_value=Path(tmp)), \
                 redirect_stdout(io.StringIO()):
                ok = cli.install_hook(is_global=False)

            self.assertTrue(ok)
            hooks_file = Path(tmp) / ".agents" / "hooks.json"
            rule_file = Path(tmp) / ".agents" / "rules" / "interactive_decisions.md"
            self.assertTrue(hooks_file.is_file())
            self.assertTrue(rule_file.is_file())

            hooks_data = json.loads(hooks_file.read_text(encoding="utf-8"))
            self.assertIn("auto-permissions-mode", hooks_data)
            self.assertTrue(rule_file.read_text(encoding="utf-8"))

    def test_uninstall_hook_removes_hooks_entry_and_rule_file(self):
        with TemporaryDirectory() as tmp:
            with patch("auto_permissions.cli.Path.cwd", return_value=Path(tmp)), \
                 redirect_stdout(io.StringIO()):
                cli.install_hook(is_global=False)
                cli.uninstall_hook(is_global=False, purge=False)

            hooks_file = Path(tmp) / ".agents" / "hooks.json"
            rule_file = Path(tmp) / ".agents" / "rules" / "interactive_decisions.md"
            hooks_data = json.loads(hooks_file.read_text(encoding="utf-8"))
            self.assertNotIn("auto-permissions-mode", hooks_data)
            self.assertFalse(rule_file.is_file())

    def test_uninstall_hook_purge_removes_local_config_file(self):
        with TemporaryDirectory() as tmp:
            config_dir = Path(tmp) / ".agents"
            config_dir.mkdir(parents=True, exist_ok=True)
            config_file = config_dir / "auto-permissions.json"
            config_file.write_text("{}", encoding="utf-8")

            with patch("auto_permissions.cli.Path.cwd", return_value=Path(tmp)), \
                 redirect_stdout(io.StringIO()):
                cli.install_hook(is_global=False)
                cli.uninstall_hook(is_global=False, purge=True)

            self.assertFalse(config_file.is_file())


if __name__ == "__main__":
    unittest.main()
