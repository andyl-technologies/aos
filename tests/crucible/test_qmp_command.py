"""Exercises QMP reply correlation, fragmented frames, delays, and deadlines."""

import importlib.util
import io
import json
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock, patch


spec = importlib.util.spec_from_file_location(
    "qmp_command", Path(__file__).with_name("_qmp-command.py")
)
qmp_command = importlib.util.module_from_spec(spec)
spec.loader.exec_module(qmp_command)


class QmpCommandTests(unittest.TestCase):
    def exercise(self, reply):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "qmp.sock")
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(path)
                listener.listen(1)
                errors = []

                def server():
                    try:
                        with listener.accept()[0] as connection:
                            connection.settimeout(5)
                            with connection.makefile("rb") as stream:
                                connection.sendall(b'{"QMP": {}}\r\n')
                                capabilities = json.loads(stream.readline())
                                frame = {"return": {}, "id": capabilities["id"]}
                                connection.sendall(json.dumps(frame).encode() + b"\r\n")
                                request = json.loads(stream.readline())
                                reply(connection, request)
                    except Exception as error:
                        errors.append(error)

                worker = threading.Thread(target=server)
                worker.start()
                output = io.StringIO()
                try:
                    qmp_command.command(
                        path, {"execute": "query-status"}, output, timeout=5
                    )
                finally:
                    worker.join(timeout=6)

                self.assertFalse(worker.is_alive())
                self.assertEqual(errors, [])
                return [json.loads(line) for line in output.getvalue().splitlines()]

    def test_delayed_fragmented_reply_ignores_events_and_other_ids(self):
        def reply(connection, request):
            connection.sendall(
                b'{"event":"STOP"}\r\n{"return":{},"id":"unrelated"}\r\n'
            )
            # The previous harness closed the connection after a one-second
            # idle gap, even if a valid migration reply was still pending.
            time.sleep(1.1)
            frame = json.dumps(
                {"return": {"status": "paused"}, "id": request["id"]}
            ).encode() + b"\r\n"
            connection.sendall(frame[:8])
            connection.sendall(frame[8:])

        messages = self.exercise(reply)

        self.assertEqual(messages[-1]["return"], {"status": "paused"})
        self.assertEqual(messages[-1]["id"], "request")
        self.assertEqual(len(messages), 5)

    def test_command_error_fails_with_transcript(self):
        def reply(connection, request):
            frame = {
                "error": {"class": "GenericError", "desc": "rejected"},
                "id": request["id"],
            }
            connection.sendall(json.dumps(frame).encode() + b"\r\n")

        with self.assertRaisesRegex(ValueError, "QMP rejected"):
            self.exercise(reply)

    def test_closed_socket_cannot_count_as_a_reply(self):
        with self.assertRaisesRegex(ValueError, "QMP reply is missing"):
            self.exercise(lambda connection, request: None)

    def test_deadline_covers_the_entire_exchange(self):
        connection = MagicMock()
        connection.__enter__.return_value = connection
        connection.makefile.return_value = io.BytesIO(
            b'{"QMP":{}}\r\n{"return":{},"id":"capabilities"}\r\n'
        )

        with patch.object(qmp_command.socket, "socket", return_value=connection):
            with patch.object(
                qmp_command.time, "monotonic", side_effect=[0, 0, 0, 16]
            ):
                with self.assertRaisesRegex(TimeoutError, "exceeded its deadline"):
                    qmp_command.command("fixture", {"execute": "query-status"}, io.StringIO())


if __name__ == "__main__":
    unittest.main()
