from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
RUNNER_PATH = ROOT / "ci/run_packet_argv.py"
SPEC = importlib.util.spec_from_file_location("kn_dom_packet_runner", RUNNER_PATH)
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


def packet(acceptance: list[list[str]], *, prefetch: list[list[str]] | None = None, execution: dict | None = None) -> str:
    return "\n".join((
        "id: TEST-001",
        "prefetchCommands: " + json.dumps(prefetch if prefetch is not None else [["make", "prefetch"]], separators=(",", ":")),
        "offlineAcceptanceCommands: " + json.dumps(acceptance, separators=(",", ":")),
        "offlineExecution: " + json.dumps(execution or runner.EXPECTED_EXECUTION, separators=(",", ":")),
    )) + "\n"


class PacketTransportTests(unittest.TestCase):
    def run_packet(self, text: str):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "packet.yaml"
            path.write_text(text, encoding="utf-8")
            environment = {
                "HARNESS_TASK_PACKET": str(path),
                "HARNESS_OFFLINE_ENFORCED": "1",
                "HARNESS_OFFLINE_BACKEND": "darwin-sandbox",
                "HARNESS_OFFLINE_SESSION_ID": "test-session",
                "UV_OFFLINE": "1",
                "UV_FROZEN": "1",
                "UV_NO_SYNC": "1",
                "PATH": os.environ["PATH"],
                "HOME": directory,
            }
            observed = []

            def completed(command, **kwargs):
                observed.append((command, kwargs))
                return SimpleNamespace(returncode=0)

            with patch.dict(os.environ, environment, clear=True), patch.object(runner.subprocess, "run", side_effect=completed):
                result = runner.main()
            return result, observed

    def test_unchanged_kn001_and_declared_kn_dom_sequences_are_both_admitted(self) -> None:
        sequences = (
            [["make", "common-contract"], ["make", "security"]],
            [["make", "domain-contract"], ["make", "white-goods-domain-parity"], ["make", "security"]],
        )
        for acceptance in sequences:
            with self.subTest(acceptance=acceptance):
                result, observed = self.run_packet(packet(acceptance))
                self.assertEqual(result, 0)
                self.assertEqual([item[0] for item in observed][1:], [["make", "prefetch"], *acceptance])
                for _command, kwargs in observed:
                    child = kwargs["env"]
                    self.assertNotIn("HARNESS_TASK_PACKET", child)
                    self.assertNotIn("HARNESS_WARM_SOURCE_ROOTS", child)
                    self.assertFalse(kwargs["shell"])

    def test_empty_malformed_shell_recursive_and_network_argv_are_denied(self) -> None:
        vectors = (
            packet([]),
            packet([["sh", "-c", "true"]]),
            packet([["make", "verify-offline"]]),
            packet([["python3", "download"]]),
            packet([["make", "domain-contract"]], prefetch=[["python3", "prefetch.py"]]),
        )
        for text in vectors:
            with self.subTest(text=text):
                with self.assertRaises(runner.PacketError):
                    self.run_packet(text)

    def test_execution_contract_drift_and_packet_mutation_are_denied(self) -> None:
        drift = dict(runner.EXPECTED_EXECUTION)
        drift["isolation"] = "BEST_EFFORT"
        with self.assertRaisesRegex(runner.PacketError, "offlineExecution contract mismatch"):
            self.run_packet(packet([["make", "domain-contract"]], execution=drift))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "packet.yaml"
            path.write_text(packet([["make", "domain-contract"]]), encoding="utf-8")
            environment = {
                "HARNESS_TASK_PACKET": str(path), "HARNESS_OFFLINE_ENFORCED": "1",
                "HARNESS_OFFLINE_BACKEND": "darwin-sandbox", "HARNESS_OFFLINE_SESSION_ID": "mutation",
                "UV_OFFLINE": "1", "UV_FROZEN": "1", "UV_NO_SYNC": "1", "PATH": os.environ["PATH"], "HOME": directory,
            }

            def mutate(_command, **_kwargs):
                path.write_text(path.read_text(encoding="utf-8") + "changed: true\n", encoding="utf-8")
                return SimpleNamespace(returncode=0)

            with patch.dict(os.environ, environment, clear=True), patch.object(runner.subprocess, "run", side_effect=mutate):
                with self.assertRaisesRegex(runner.PacketError, "packet authority changed"):
                    runner.main()

    def test_transport_source_has_no_packet_specific_acceptance_equality(self) -> None:
        source = RUNNER_PATH.read_text(encoding="utf-8")
        self.assertNotIn("KN-001 command sequence mismatch", source)
        self.assertNotIn('acceptance != [["make", "common-contract"]', source)
        self.assertIn("recursive verify-offline is forbidden", source)
        self.assertIn('"prefetch"', source)


if __name__ == "__main__":
    unittest.main()
