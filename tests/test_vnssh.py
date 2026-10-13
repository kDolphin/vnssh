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


if __name__ == "__main__":
    unittest.main()
