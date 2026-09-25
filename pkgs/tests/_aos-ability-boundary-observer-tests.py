"""Focused checks for the fleet observer's self-interruption protocol."""

import importlib.util
import json
import os
import socket
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


def load_observer(path: Path):
    """Import the packaged controller source without changing its CLI entry point."""
    specification = importlib.util.spec_from_file_location("boundary_observer", path)
    if specification is None or specification.loader is None:
        raise RuntimeError("cannot load the packaged boundary observer")
    observer = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(observer)
    return observer


OBSERVER = load_observer(Path(sys.argv[1]))


class PeerConnection:
    """Return controlled kernel credentials at the observer's peer check."""

    def __init__(self, pid: int, uid: int):
        self.pid = pid
        self.uid = uid

    def getsockopt(self, level: int, option: int, length: int) -> bytes:
        if (level, option, length) != (
            socket.SOL_SOCKET,
            socket.SO_PEERCRED,
            struct.calcsize("3i"),
        ):
            raise AssertionError("unexpected peer credential request")
        return struct.pack("3i", self.pid, self.uid, 0)


class ObserverInterruptionTests(unittest.TestCase):
    def setUp(self):
        self.state = tempfile.TemporaryDirectory()
        self.addCleanup(self.state.cleanup)
        OBSERVER.configure_state_root(self.state.name)
        self.operation = {"operation": {"key": "selected"}, "plan": "plan"}
        self.event = {
            "boundary": "effect-returned",
            "operation": self.operation,
            "purpose": "effect",
            "schema": OBSERVER.EVENT_SCHEMA,
        }
        self.payload = OBSERVER.canonical_bytes(self.event)
        self.target = {
            "action": "terminate-peer",
            "boundary": "effect-returned",
            "purpose": "effect",
            "sequence": "initrd-interruption",
        }

    def test_first_effect_target_selects_one_exact_recovery(self):
        OBSERVER.replace_canonical(OBSERVER.TARGET, self.target)
        selected = OBSERVER.load_target()
        self.assertTrue(OBSERVER.matches_initial_boundary(self.event, selected))

        with mock.patch.object(os, "kill") as kill:
            def check_recorded_before_kill(pid, signal):
                self.assertEqual(pid, 123)
                held = json.loads(OBSERVER.HELD_EVENT.read_bytes())
                self.assertEqual(held["event"], self.event)
                self.assertEqual(held["sequence"], self.target["sequence"])

            kill.side_effect = check_recorded_before_kill
            OBSERVER.terminate_peer_once(
                PeerConnection(123, 0),
                self.event,
                self.payload,
                self.target["sequence"],
                None,
            )
            kill.assert_called_once()

        self.assertFalse(OBSERVER.matches_initial_boundary(self.event, selected))
        recovery = {
            **self.event,
            "boundary": "reconciliation-returned",
            "purpose": "reconcile",
        }
        self.assertTrue(OBSERVER.matches_recovery_boundary(recovery, selected))
        unrelated = {**recovery, "operation": {"operation": {"key": "other"}}}
        self.assertFalse(OBSERVER.matches_recovery_boundary(unrelated, selected))

        sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        with sender, receiver:
            recovery_payload = OBSERVER.canonical_bytes(recovery)
            OBSERVER.continue_reconciliation(
                sender,
                recovery,
                recovery_payload,
                self.target["sequence"],
                None,
            )
            acknowledgement = json.loads(OBSERVER.read_frame(receiver))
            self.assertEqual(
                acknowledgement["event_digest"],
                OBSERVER.event_digest(recovery_payload),
            )

        resumed = json.loads(OBSERVER.RESUMED_EVENT.read_bytes())
        self.assertEqual(resumed["event"], recovery)
        self.assertFalse(OBSERVER.matches_recovery_boundary(recovery, selected))

    def test_untrusted_peer_cannot_arm_interruption(self):
        with mock.patch.object(os, "kill") as kill:
            with self.assertRaisesRegex(ValueError, "root-owned runner"):
                OBSERVER.terminate_peer_once(
                    PeerConnection(123, 1000),
                    self.event,
                    self.payload,
                    self.target["sequence"],
                    None,
                )
            kill.assert_not_called()
        self.assertFalse(OBSERVER.HELD_EVENT.exists())

    def test_first_effect_target_rejects_other_boundaries(self):
        invalid = {**self.target, "boundary": "effect-intent-durable"}
        OBSERVER.replace_canonical(OBSERVER.TARGET, invalid)
        with self.assertRaisesRegex(ValueError, "effect return"):
            OBSERVER.load_target()


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
