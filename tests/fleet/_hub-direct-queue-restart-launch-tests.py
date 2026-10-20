"""Exercise real launcher exec transitions without starting storage work."""

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import textwrap
import unittest


SOURCE = Path(sys.argv.pop(1)) if len(sys.argv) > 1 else Path(__file__).with_name(
    "_hub-direct-queue-restart.py")


class LauncherTests(unittest.TestCase):
    def run_launcher(self, execute):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            launcher = root / "node-launcher"
            pid_file = root / "process.json"
            launcher.write_text(f"#!{sys.executable}\n" + textwrap.dedent(f"""
                import json, os, sys, time
                from pathlib import Path
                fields = Path('/proc/self/stat').read_text().rpartition(') ')[2].split()
                Path({str(pid_file)!r}).write_text(json.dumps({{'pid':os.getpid(), 'startTicks':fields[19]}}))
                time.sleep(0.2)
                {'os.execv(sys.executable, [sys.argv[0], *sys.argv[1:]])' if execute else 'time.sleep(10)'}
            """))
            launcher.chmod(0o700)
            driver = root / "driver.py"
            driver.write_text("import time\ntime.sleep(10)\n")
            namespace = {"__name__": "launch_fixture"}
            exec(compile(SOURCE.read_text(), str(SOURCE), "exec"), namespace)

            def guest(_worker, _python, program, selected):
                selected = {**selected, "root": str(root / "original")}
                result = subprocess.run([sys.executable, "-c",
                    "import json\nselected = json.loads(" + repr(json.dumps(selected)) + ")\n"
                    + textwrap.dedent(program)], capture_output=True, text=True)
                if result.returncode:
                    raise RuntimeError("actual guest refused launcher identity")
                return result.stdout

            namespace["direct_guest_python"] = guest
            try:
                result = namespace["start_direct_restart_original"](
                    None, {"python": sys.executable, "node": str(launcher),
                        "qualificationDriver": str(driver)},
                    "https://executor.fleet.test", "unused.key", "unused.identity",
                    {}, {"metadata": False, "byte_size": 2147483648,
                        "sha256": "a" * 64, "file": "unused-source"})
                self.assertEqual(result["arguments"][0], str(launcher))
                self.assertEqual(result["ownerUid"], os.getuid())
                return result
            finally:
                if pid_file.exists():
                    pin = json.loads(pid_file.read_text())
                    process = Path("/proc") / str(pin["pid"])
                    if process.exists():
                        fields = (process / "stat").read_text().rpartition(") ")[2].split()
                        if fields[19] == pin["startTicks"] and process.stat().st_uid == os.getuid():
                            os.kill(pin["pid"], signal.SIGTERM)

    def test_delayed_exec_retains_the_exact_process_lifetime(self):
        self.run_launcher(True)

    def test_a_launcher_that_never_executes_the_selected_command_is_refused(self):
        with self.assertRaisesRegex(RuntimeError, "refused launcher identity"):
            self.run_launcher(False)


if __name__ == "__main__":
    unittest.main()
