from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ci import run_make_target, run_packet_argv


def descriptor(packet: str, targets: list[dict[str, object]] | None = None) -> dict[str, object]:
    return {
        "schemaVersion": run_make_target.SCHEMA,
        "packetId": packet,
        "targets": targets or [{"name": "check", "acceptedVariables": {}, "argvTemplate": [["python3", "-c", "pass"]]}],
    }


class DispatcherTests(unittest.TestCase):
    def write(self, directory: Path, packet: str, value: dict[str, object] | None = None) -> Path:
        path = directory / f"{packet.lower()}.json"
        path.write_text(json.dumps(value or descriptor(packet)), encoding="utf-8")
        return path

    def test_valid_descriptor_loads(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            self.write(directory, "KN-001")
            rules = run_make_target.load_rules(directory)
            self.assertEqual((rules[0].packet_id, rules[0].target), ("KN-001", "check"))

    def test_duplicate_unknown_shell_owner_and_overlap_vectors_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            path = directory / "kn-001.json"
            vectors = [
                '{"schemaVersion":"x","schemaVersion":"x","packetId":"KN-001","targets":[]}',
                json.dumps(descriptor("KN-002")),
                json.dumps(descriptor("KN-001", [{"name": "check", "acceptedVariables": {"UNDECLARED": {"const": "x"}}, "argvTemplate": [["python3", "-c", "pass"]]}])),
                json.dumps(descriptor("KN-001", [{"name": "check", "acceptedVariables": {}, "argvTemplate": [["sh", "-c", "true"]]}])),
                json.dumps(descriptor("KN-001", [
                    {"name": "check", "acceptedVariables": {}, "argvTemplate": [["python3", "-c", "pass"]]},
                    {"name": "check", "acceptedVariables": {}, "argvTemplate": [["python3", "-c", "pass"]]},
                ])),
            ]
            for raw_value in vectors:
                path.write_text(raw_value, encoding="utf-8")
                with self.subTest(raw=raw_value[:40]), self.assertRaises(run_make_target.DescriptorError):
                    run_make_target.load_rules(directory)

    def test_zero_handler_and_undeclared_make_variable_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            self.write(directory, "KN-001")
            with self.assertRaises(run_make_target.DescriptorError):
                run_make_target.dispatch("missing", {}, directory)
            with self.assertRaises(run_make_target.DescriptorError):
                run_make_target.supplied_variables({"MAKEOVERRIDES": "FOO=bar", "FOO": "bar"})

    def test_different_packet_handlers_run_cumulatively_in_lexical_order(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            self.write(directory, "KN-002")
            self.write(directory, "KN-001")
            completed = mock.Mock(returncode=0)
            with mock.patch.object(run_make_target.subprocess, "run", return_value=completed) as runner:
                self.assertEqual(run_make_target.dispatch("check", {}, directory), 0)
            commands = [call.args[0] for call in runner.call_args_list]
            self.assertEqual(commands, [("python3", "-c", "pass"), ("python3", "-c", "pass")])

    def test_packet_children_never_receive_packet_or_warm_paths(self) -> None:
        self.assertNotIn(run_packet_argv.PACKET_ENV, run_packet_argv.CHILD_ENV)
        self.assertNotIn("HARNESS_WARM_SOURCE_ROOTS", run_packet_argv.CHILD_ENV)
        self.assertEqual(run_packet_argv.EXPECTED_EXECUTION["commandTransport"], "ARGV_ARRAY_V1")
        self.assertEqual(run_packet_argv.EXPECTED_EXECUTION["isolation"], "OS_ENFORCED_DENY_ALL_OUTBOUND")


if __name__ == "__main__":
    unittest.main()
