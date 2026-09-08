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


class TestIdeWildcardTrust(unittest.TestCase):
    def test_enable_ide_wildcard_trust_creates_new_settings_file(self):
        with TemporaryDirectory() as tmp:
            fake_settings = Path(tmp) / ".gemini" / "antigravity-cli" / "settings.json"
            fake_config = Path(tmp) / ".gemini" / "config" / "config.json"
            fake_tf = Path(tmp) / ".gemini" / "trustedFolders.json"

            with patch("auto_permissions.cli.get_antigravity_cli_settings_file", return_value=fake_settings), \
                 patch("auto_permissions.cli.get_antigravity_config_file", return_value=fake_config), \
                 patch("auto_permissions.cli.get_antigravity_trusted_folders_file", return_value=fake_tf), \
                 redirect_stdout(io.StringIO()):
                ok = cli.enable_ide_wildcard_trust(workspace_path=str(Path(tmp) / "my_project"))

            self.assertTrue(ok)
            self.assertTrue(fake_settings.is_file())
            self.assertTrue(fake_config.is_file())
            self.assertTrue(fake_tf.is_file())

            # CLI settings
            data = json.loads(fake_settings.read_text(encoding="utf-8"))
            self.assertIn("mcp(*)", data["permissions"]["allow"])
            self.assertIn("read_url(*)", data["permissions"]["allow"])
            self.assertIn("command(*)", data["permissions"]["allow"])
            self.assertIn(str((Path(tmp) / "my_project").resolve()), data["trustedWorkspaces"])

            # IDE config
            cfg_data = json.loads(fake_config.read_text(encoding="utf-8"))
            self.assertIn("mcp(*)", cfg_data["userSettings"]["globalPermissionGrants"]["allow"])
            self.assertEqual("AGENT_SETTING_POLICY_ALLOW", cfg_data["userSettings"]["internetPolicy"])

            # IDE trusted folders
            tf_data = json.loads(fake_tf.read_text(encoding="utf-8"))
            my_proj_norm = str((Path(tmp) / "my_project").resolve()).replace("\\", "/").lower()
            self.assertEqual("TRUST_PARENT", tf_data[my_proj_norm])

            with patch("auto_permissions.cli.get_antigravity_cli_settings_file", return_value=fake_settings), \
                 patch("auto_permissions.cli.get_antigravity_trusted_folders_file", return_value=fake_tf):
                self.assertTrue(cli.is_workspace_trusted(str(Path(tmp) / "my_project")))
                self.assertFalse(cli.is_workspace_trusted(str(Path(tmp) / "other_project")))

    def test_enable_ide_wildcard_trust_preserves_existing_rules_and_creates_backup(self):
        with TemporaryDirectory() as tmp:
            fake_settings = Path(tmp) / ".gemini" / "antigravity-cli" / "settings.json"
            fake_config = Path(tmp) / ".gemini" / "config" / "config.json"
            fake_tf = Path(tmp) / ".gemini" / "trustedFolders.json"

            fake_settings.parent.mkdir(parents=True, exist_ok=True)
            initial_data = {
                "permissions": {"allow": ["command(git status)"]},
                "trustedWorkspaces": [str((Path(tmp) / "existing_ws").resolve())]
            }
            fake_settings.write_text(json.dumps(initial_data), encoding="utf-8")

            fake_config.parent.mkdir(parents=True, exist_ok=True)
            initial_cfg = {
                "userSettings": {
                    "globalPermissionGrants": {"allow": ["command(git status)"]}
                }
            }
            fake_config.write_text(json.dumps(initial_cfg), encoding="utf-8")

            with patch("auto_permissions.cli.get_antigravity_cli_settings_file", return_value=fake_settings), \
                 patch("auto_permissions.cli.get_antigravity_config_file", return_value=fake_config), \
                 patch("auto_permissions.cli.get_antigravity_trusted_folders_file", return_value=fake_tf), \
                 redirect_stdout(io.StringIO()):
                ok = cli.enable_ide_wildcard_trust(workspace_path=str(Path(tmp) / "new_ws"))

            self.assertTrue(ok)
            backup_file = fake_settings.with_suffix(".json.bak")
            self.assertTrue(backup_file.is_file())
            bak_data = json.loads(backup_file.read_text(encoding="utf-8"))
            self.assertEqual(bak_data["permissions"]["allow"], ["command(git status)"])

            updated_data = json.loads(fake_settings.read_text(encoding="utf-8"))
            self.assertIn("command(git status)", updated_data["permissions"]["allow"])
            self.assertIn("mcp(*)", updated_data["permissions"]["allow"])

            updated_cfg = json.loads(fake_config.read_text(encoding="utf-8"))
            self.assertIn("command(git status)", updated_cfg["userSettings"]["globalPermissionGrants"]["allow"])
            self.assertIn("mcp(*)", updated_cfg["userSettings"]["globalPermissionGrants"]["allow"])

    def test_enable_ide_wildcard_trust_handles_utf8_bom(self):
        with TemporaryDirectory() as tmp:
            fake_settings = Path(tmp) / ".gemini" / "antigravity-cli" / "settings.json"
            fake_config = Path(tmp) / ".gemini" / "config" / "config.json"
            fake_tf = Path(tmp) / ".gemini" / "trustedFolders.json"

            fake_settings.parent.mkdir(parents=True, exist_ok=True)
            initial_data = {"trustedWorkspaces": []}
            fake_settings.write_text(json.dumps(initial_data), encoding="utf-8-sig")

            with patch("auto_permissions.cli.get_antigravity_cli_settings_file", return_value=fake_settings), \
                 patch("auto_permissions.cli.get_antigravity_config_file", return_value=fake_config), \
                 patch("auto_permissions.cli.get_antigravity_trusted_folders_file", return_value=fake_tf), \
                 redirect_stdout(io.StringIO()):
                ok = cli.enable_ide_wildcard_trust(workspace_path=str(Path(tmp) / "bom_ws"))

            self.assertTrue(ok)
            updated_data = json.loads(fake_settings.read_text(encoding="utf-8"))
            self.assertIn("mcp(*)", updated_data["permissions"]["allow"])

    def test_decline_ide_workspace_trust(self):
        with TemporaryDirectory() as tmp:
            fake_declined = Path(tmp) / ".gemini" / "config" / "declined_workspaces.json"
            target = str((Path(tmp) / "declined_ws").resolve())
            with patch("auto_permissions.cli.get_declined_workspaces_file", return_value=fake_declined), \
                 redirect_stdout(io.StringIO()):
                ok = cli.decline_ide_workspace_trust(workspace_path=target)

            self.assertTrue(ok)
            self.assertTrue(fake_declined.is_file())
            data = json.loads(fake_declined.read_text(encoding="utf-8"))
            self.assertIn(target, data["declined"])

            with patch("auto_permissions.cli.get_declined_workspaces_file", return_value=fake_declined):
                self.assertTrue(cli.is_workspace_declined(target))
                self.assertFalse(cli.is_workspace_declined(str(Path(tmp) / "other_ws")))


if __name__ == "__main__":
    unittest.main()
