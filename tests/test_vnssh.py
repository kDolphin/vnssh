#!/usr/bin/env python3
"""Unit tests for vnssh helpers (no live SSH / Keychain)."""

from __future__ import annotations

import csv
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import vnssh  # noqa: E402


class FatalDetectionTests(unittest.TestCase):
    def test_network_and_auth_are_fatal(self) -> None:
        self.assertTrue(
            vnssh.ssh_pre_session_fatal(
                "ssh: connect to host 1.2.3.4 port 22: Connection timed out"
            )
        )
        self.assertTrue(vnssh.ssh_pre_session_fatal("Permission denied (password)."))
        self.assertTrue(vnssh.ssh_pre_session_fatal("认证失败"))
        self.assertTrue(vnssh.ssh_pre_session_fatal("密码错误"))
        self.assertFalse(vnssh.ssh_pre_session_fatal("Last login: today"))
        self.assertFalse(vnssh.ssh_pre_session_fatal(""))

    def test_preauth_banner_is_not_a_session(self) -> None:
        banner = (
            "** WARNING: connection is not using a post-quantum "
            "key exchange algorithm.\n"
        )
        self.assertTrue(vnssh._preauth_banner_only(banner))
        self.assertFalse(
            vnssh._session_ready_for_log(
                banner, auto_password=False, password_sent=False
            )
        )
        logged_in = banner + "Last login: Tue Nov 3 14:00:00 on ttys000\n"
        self.assertFalse(vnssh._preauth_banner_only(logged_in))
        self.assertTrue(
            vnssh._session_ready_for_log(
                logged_in, auto_password=False, password_sent=False
            )
        )

    def test_rejected_password_after_banner_stays_fatal(self) -> None:
        text = (
            "** WARNING: connection is not using a post-quantum "
            "key exchange algorithm.\n"
            "Permission denied, please try again.\n"
            "cloudops@10.230.200.37's password: "
        )
        self.assertTrue(vnssh.ssh_pre_session_fatal(text))
        self.assertFalse(
            vnssh._session_ready_for_log(
                text, auto_password=False, password_sent=False
            )
        )

    def test_rejected_password_is_fatal_even_if_prompt_returns(self) -> None:
        text = (
            "Permission denied, please try again.\n"
            "cloudops@10.230.200.37's password: "
        )
        self.assertTrue(vnssh.ssh_pre_session_fatal(text))
        self.assertFalse(
            vnssh.ssh_waiting_for_user_input(
                text, auto_password=True, password_sent=True
            )
        )

    def test_banner_does_not_kill_a_live_prompt(self) -> None:
        banner = (
            "WARNING: unauthorized access denied on this device\n"
            "admin@sw's password: "
        )
        self.assertFalse(vnssh.ssh_pre_session_fatal(banner))
        self.assertTrue(
            vnssh.ssh_waiting_for_user_input(
                banner, auto_password=False, password_sent=False
            )
        )

    def test_passphrase_and_bare_password_pause_the_watchdog(self) -> None:
        passphrase = "Enter passphrase for key '/tmp/id_ed25519': "
        bare = "Password:"
        otp = "请输入验证码: "
        for prompt in (passphrase, bare, otp):
            self.assertFalse(vnssh.ssh_pre_session_fatal(prompt))
            self.assertTrue(
                vnssh.ssh_waiting_for_user_input(
                    prompt, auto_password=True, password_sent=True
                )
            )


class WizardValidationTests(unittest.TestCase):
    def test_port_and_yes_no(self) -> None:
        data = vnssh.WizardData()
        self.assertEqual(vnssh.apply_wizard_field("port", data, "abc"), "Port must be a number")
        self.assertIsNone(vnssh.apply_wizard_field("port", data, "2222"))
        self.assertEqual(data.port, "2222")
        self.assertIsNone(vnssh.parse_yes_no("maybe"))
        self.assertTrue(vnssh.parse_yes_no("y"))
        self.assertFalse(vnssh.parse_yes_no("n"))

    def test_twofa_legacy_and_keychain_keep(self) -> None:
        data = vnssh.WizardData()
        self.assertIsNone(vnssh.apply_wizard_field("twofa", data, "y"))
        self.assertTrue(data.twofa)
        self.assertIsNone(vnssh.apply_wizard_field("legacy", data, "y"))
        self.assertTrue(data.legacy)

        edit = vnssh.WizardData(host="a", original_host="a", password="")
        self.assertIsNone(vnssh.wizard_keychain_update(edit))
        edit.password = "secret"
        self.assertEqual(vnssh.wizard_keychain_update(edit), "secret")
        edit.password = "-"
        self.assertEqual(vnssh.wizard_keychain_update(edit), "")
        new = vnssh.WizardData(host="a", password="")
        self.assertEqual(vnssh.wizard_keychain_update(new), "")
        key_only = vnssh.WizardData(
            host="a", original_host="a", auth=vnssh.AUTH_KEY, password="x"
        )
        self.assertEqual(vnssh.wizard_keychain_update(key_only), "")


class FlagAndStatusTests(unittest.TestCase):
    def test_flags_include_twofa_and_legacy(self) -> None:
        conn = vnssh.Connection(
            host="b",
            managed=True,
            has_password=True,
            twofa=True,
            legacy=True,
        )
        self.assertEqual(vnssh.format_conn_flags(conn), "p 2 L")
        ext = vnssh.Connection(host="e", managed=False, identity_file="~/.ssh/id")
        self.assertEqual(vnssh.format_conn_flags(ext), "ext k")

    def test_status_bar_truncates_cjk_by_display_width(self) -> None:
        status = "1-3/10"
        inner = 20
        msg, status_x = vnssh.format_status_message("认证失败了啊啊啊啊啊", status, inner)
        self.assertLessEqual(vnssh.str_display_width(msg) + 1 + len(status), inner)
        self.assertEqual(status_x, inner - len(status))
        self.assertTrue(msg.endswith("…") or vnssh.str_display_width(msg) <= inner - len(status) - 1)


class ConfigFlagWriteTests(unittest.TestCase):
    def test_merged_opts_and_host_block_comments(self) -> None:
        opts = vnssh.merged_opts_from_wizard(
            vnssh.WizardData(host="a", hostname="10.0.0.1", twofa=True, legacy=True)
        )
        self.assertEqual(opts.get("_vnssh_2fa"), "1")
        self.assertEqual(opts.get("_vnssh_legacy"), "1")
        cleared = vnssh.merged_opts_from_wizard(
            vnssh.WizardData(host="a", hostname="10.0.0.1", twofa=False, legacy=False),
            {"_vnssh_2fa": "1", "_vnssh_legacy": "1"},
        )
        self.assertNotIn("_vnssh_2fa", cleared)
        self.assertNotIn("_vnssh_legacy", cleared)
        block = vnssh.format_parsed_host_block(
            "sw1",
            {
                "hostname": "10.0.0.9",
                "user": "admin",
                "_vnssh_2fa": "1",
                "_vnssh_legacy": "1",
            },
            "lab",
        )
        self.assertIn("#v-2fa", block)
        self.assertIn("#v-legacy", block)
        self.assertLess(block.index("#v-2fa"), block.index("#v-legacy"))


class PrivateKeyPermissionTests(unittest.TestCase):
    def test_ensure_private_key_permissions_tightens_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            key = Path(tmp) / "id_test.pem"
            key.write_text("dummy-key\n", encoding="utf-8")
            key.chmod(0o644)
            self.assertIsNone(vnssh.ensure_private_key_permissions(str(key)))
            self.assertEqual(key.stat().st_mode & 0o777, 0o600)

    def test_ensure_private_key_permissions_keeps_owner_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            key = Path(tmp) / "id_ok.pem"
            key.write_text("dummy-key\n", encoding="utf-8")
            key.chmod(0o600)
            self.assertIsNone(vnssh.ensure_private_key_permissions(str(key)))
            self.assertEqual(key.stat().st_mode & 0o777, 0o600)

    def test_ensure_private_key_permissions_missing_path(self) -> None:
        err = vnssh.ensure_private_key_permissions("/no/such/key.pem")
        self.assertIsNotNone(err)
        self.assertIn("not accessible", err or "")


class CsvRoundTripTests(unittest.TestCase):
    def test_row_to_wizard_flags(self) -> None:
        data = vnssh.row_to_wizard(
            {
                "host": "bastion",
                "hostname": "10.0.0.1",
                "user": "alice",
                "twofa": "y",
                "legacy": "n",
            }
        )
        self.assertTrue(data.twofa)
        self.assertFalse(data.legacy)
        preserved = vnssh.row_to_wizard(
            {"host": "x", "hostname": "1.2.3.4", "user": "u"}
        )
        self.assertIsNone(preserved.twofa)
        self.assertIsNone(preserved.legacy)

    def test_export_csv_omits_password(self) -> None:
        conn = vnssh.Connection(
            host="prod-web",
            hostname="203.0.113.10",
            user="alice",
            folder="Production",
            twofa=True,
            legacy=False,
            auth=vnssh.AUTH_PASSWORD,
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "out.csv"
            count = vnssh.write_export_csv(path, [conn])
            self.assertEqual(count, 1)
            with path.open(encoding="utf-8", newline="") as handle:
                reader = csv.DictReader(handle)
                self.assertIsNotNone(reader.fieldnames)
                self.assertNotIn("password", reader.fieldnames)
                row = next(reader)
            self.assertEqual(row["host"], "prod-web")
            self.assertEqual(row["auth"], "password")
            self.assertEqual(row["twofa"], "y")
            self.assertEqual(row["legacy"], "n")


class RollbackSafeBehaviorTests(unittest.TestCase):
    """Covers the 1.0.7 review fixes. Uses a temp config, not ~/.vnssh."""

    def setUp(self) -> None:
        self._saved = {
            "HOSTS_CONF": vnssh.HOSTS_CONF,
            "SSH_CONFIG": vnssh.SSH_CONFIG,
            "VNSSH_DIR": vnssh.VNSSH_DIR,
            "HISTORY_FILE": vnssh.HISTORY_FILE,
            "keychain_has": vnssh.keychain_has,
            "keychain_get": vnssh.keychain_get,
            "keychain_set": vnssh.keychain_set,
            "keychain_delete": vnssh.keychain_delete,
        }
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        vnssh.VNSSH_DIR = root / "vnssh"
        vnssh.VNSSH_DIR.mkdir()
        vnssh.HOSTS_CONF = vnssh.VNSSH_DIR / "hosts.conf"
        vnssh.HISTORY_FILE = vnssh.VNSSH_DIR / "history.json"
        vnssh.SSH_CONFIG = root / "ssh_config"
        vnssh.SSH_CONFIG.write_text(
            "Host extone\n    HostName 10.1.1.1\n    User ext\n",
            encoding="utf-8",
        )
        vnssh._RAW_HOSTS_CACHE = None
        vnssh._SSH_G_CACHE = {}
        vnssh._SSH_G_IDENTITY_CACHE = {}
        self.keychain_ops: list = []
        vnssh.keychain_has = lambda _account: False
        vnssh.keychain_get = lambda _account: None
        vnssh.keychain_set = lambda account, password: self.keychain_ops.append(
            ("set", account, password)
        )
        vnssh.keychain_delete = lambda account, invalidate=True: self.keychain_ops.append(
            ("del", account)
        )

    def tearDown(self) -> None:
        for name, value in self._saved.items():
            setattr(vnssh, name, value)
        vnssh._RAW_HOSTS_CACHE = None
        vnssh._SSH_G_CACHE = {}
        vnssh._SSH_G_IDENTITY_CACHE = {}
        self.tmp.cleanup()

    def test_empty_query_sorts_by_last_used_not_count(self) -> None:
        vnssh.HISTORY_FILE.write_text(
            '{"old": {"count": 50, "last_used": "2020-01-01T00:00:00+00:00"},'
            ' "new": {"count": 1, "last_used": "2026-10-13T00:00:00+00:00"}}',
            encoding="utf-8",
        )
        ordered = [
            conn.host
            for conn in vnssh.sorted_connections(
                [
                    vnssh.Connection(host="old"),
                    vnssh.Connection(host="plain"),
                    vnssh.Connection(host="new"),
                ],
                "",
            )
        ]
        self.assertEqual(ordered, ["new", "old", "plain"])

    def test_upsert_replaces_one_block_and_keeps_the_rest(self) -> None:
        original = (
            "# Managed by vnssh\n"
            "#v-f:Keep\n"
            "Host keep\n"
            "    HostName 10.0.0.1\n"
            "    User root\n"
            "    ProxyJump bastion\n"
            "    # hand note\n"
            "#v-f:Edit\n"
            "Host editme\n"
            "    HostName 10.0.0.2\n"
            "    User admin\n"
        )
        vnssh.HOSTS_CONF.write_text(original, encoding="utf-8")
        vnssh.upsert_host_block(
            vnssh.WizardData(
                host="editme",
                hostname="10.9.9.9",
                user="admin",
                port="22",
                folder="Edit",
                auth=vnssh.AUTH_PASSWORD,
                original_host="editme",
            )
        )
        text = vnssh.HOSTS_CONF.read_text(encoding="utf-8")
        keep = text.split("#v-f:Edit", 1)[0]
        self.assertIn("Host keep", keep)
        self.assertIn("ProxyJump bastion", keep)
        self.assertIn("# hand note", keep)
        self.assertIn("HostName 10.9.9.9", text)
        self.assertNotIn("HostName 10.0.0.2", text)
        self.assertTrue((vnssh.VNSSH_DIR / "hosts.conf.bak").exists())

    def test_remove_drops_one_block_only(self) -> None:
        vnssh.HOSTS_CONF.write_text(
            "# Managed by vnssh\n"
            "#v-f:Keep\n"
            "Host keep\n"
            "    HostName 10.0.0.1\n"
            "    LocalForward 127.0.0.1:80 10.0.0.1:80\n"
            "#v-f:Gone\n"
            "Host gone\n"
            "    HostName 10.0.0.2\n",
            encoding="utf-8",
        )
        self.assertTrue(vnssh.remove_host_block("gone"))
        text = vnssh.HOSTS_CONF.read_text(encoding="utf-8")
        self.assertIn("LocalForward 127.0.0.1:80 10.0.0.1:80", text)
        self.assertNotIn("Host gone", text)
        self.assertIn("Host keep", text)

    def test_dedupe_keeps_the_first_host(self) -> None:
        entries = [
            ("a", {"hostname": "1.1.1.1"}, "F"),
            ("a", {"hostname": "2.2.2.2"}, "F"),
        ]
        deduped = vnssh.dedupe_config_entries(entries)
        self.assertEqual(len(deduped), 1)
        self.assertEqual(deduped[0][1]["hostname"], "1.1.1.1")

    def test_ascii_alias_does_not_pin_identity_or_pubkey(self) -> None:
        vnssh.HOSTS_CONF.write_text(
            "#v-f:W\n"
            "Host jumphost\n"
            "    HostName 10.0.0.5\n"
            "    User alice\n"
            "    Port 2222\n"
            "    IdentityFile /tmp/key.pem\n",
            encoding="utf-8",
        )
        vnssh._RAW_HOSTS_CACHE = None
        args = vnssh.build_ssh_argv("jumphost")
        self.assertIn("jumphost", args)
        self.assertIn("2222", args)
        self.assertNotIn("-i", args)
        self.assertFalse(any("IdentitiesOnly" in arg for arg in args))
        self.assertFalse(any("PubkeyAuthentication" in arg for arg in args))
        self.assertFalse(any("PreferredAuthentications" in arg for arg in args))

    def test_non_ascii_alias_still_passes_the_key(self) -> None:
        vnssh.HOSTS_CONF.write_text(
            "#v-f:W\n"
            "Host 堡垒\n"
            "    HostName 10.9.9.9\n"
            "    User bob\n"
            "    IdentityFile /tmp/key.pem\n",
            encoding="utf-8",
        )
        vnssh._RAW_HOSTS_CACHE = None
        args = vnssh.build_ssh_argv("堡垒")
        self.assertIn("-i", args)
        self.assertIn("/tmp/key.pem", args)
        self.assertIn("IdentitiesOnly=yes", args)
        self.assertIn("bob@10.9.9.9", args)
        self.assertNotIn("堡垒", args)

    def test_import_password_column_rules(self) -> None:
        absent = vnssh.WizardData(host="a", password_specified=False, password="")
        blank = vnssh.WizardData(host="a", password_specified=True, password="")
        dash = vnssh.WizardData(host="a", password_specified=True, password="-")
        stored = vnssh.WizardData(host="a", password_specified=True, password="s3cret")
        self.assertIsNone(vnssh.import_password_update(absent))
        self.assertEqual(vnssh.import_password_update(blank), "")
        self.assertEqual(vnssh.import_password_update(dash), "")
        self.assertEqual(vnssh.import_password_update(stored), "s3cret")

    def test_import_force_skips_ext_and_keeps_keychain_without_password(self) -> None:
        vnssh.HOSTS_CONF.write_text(
            "# Managed by vnssh\n"
            "#v-f:Lab\n"
            "Host kept\n"
            "    HostName 10.0.0.1\n"
            "    User root\n"
            "    SendEnv LANG\n",
            encoding="utf-8",
        )
        csv_path = Path(self.tmp.name) / "hosts.csv"
        csv_path.write_text(
            "category,host,hostname,user,port,auth\n"
            "Lab,kept,10.0.0.9,root,22,password\n"
            "Lab,extone,10.1.1.1,ext,22,password\n"
            "Lab,newone,10.2.2.2,neo,22,key\n",
            encoding="utf-8",
        )
        vnssh._RAW_HOSTS_CACHE = None
        for row in vnssh.read_import_csv(csv_path):
            self.assertFalse(row.password_specified)
            vnssh.import_wizard_data(row, force=True)
        text = vnssh.HOSTS_CONF.read_text(encoding="utf-8")
        self.assertIn("HostName 10.0.0.9", text)
        self.assertIn("sendenv LANG", text)
        self.assertNotIn("Host extone", text)
        self.assertIn("Host newone", text)
        self.assertEqual(self.keychain_ops, [])

    def test_search_window_uses_display_columns(self) -> None:
        visible, columns = vnssh.search_query_window("生产环境", 4)
        self.assertEqual(visible, "环境")
        self.assertEqual(columns, 4)
        visible, columns = vnssh.search_query_window("ab", 10)
        self.assertEqual((visible, columns), ("ab", 2))

    def test_help_hints_follow_focus(self) -> None:
        listed = vnssh.help_hints_for_focus("list")
        typing = vnssh.help_hints_for_focus("input")
        self.assertIn(("e", "edit"), listed)
        self.assertIn(("Enter", "connect"), listed)
        self.assertIn(("type", "filter"), typing)
        self.assertIn(("Esc", "clear/quit"), typing)
        self.assertNotIn(("e", "edit"), typing)


if __name__ == "__main__":
    unittest.main()
