"""Checks fixed verity-unit publication ordering and failure boundaries."""

import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile


def check_case(source, bash, selinux, coreutils, case):
    with tempfile.TemporaryDirectory(prefix="aos-verity-publish-") as temporary:
        root = Path(temporary)
        commands = root / "bin"
        commands.mkdir()
        units = root / "units"
        events = root / "events"
        if case != "disabled":
            (root / "enforce").touch()

        mock = f"#!{sys.executable}\n" + '''
import json
import os
from pathlib import Path
import sys

name = Path(sys.argv[0]).name
arguments = sys.argv[1:]
case = os.environ["AOS_VERITY_TEST_CASE"]
with open(os.environ["AOS_VERITY_TEST_EVENTS"], "a") as log:
    log.write(json.dumps([name, *arguments]) + "\\n")

if name == "generator":
    if case != "missing-unit":
        (Path(arguments[0]) / "systemd-veritysetup@root.service").write_text("[Service]\\n")
elif name == "matchpathcon":
    if case == "lookup-failure":
        sys.exit(1)
    print("system_u:object_r:systemd_unit_t")
elif name == "setfilecon" and case == "relabel-failure":
    sys.exit(2)
'''
        for name in ("generator", "matchpathcon", "setfilecon", "systemctl", "udevadm"):
            command = commands / name
            command.write_text(mock)
            command.chmod(0o755)

        replacements = {
            "staging=/run/aos/systemd-verity-generator.$$":
                f"staging={shlex.quote(str(root / 'staging'))}.$$",
            "/lib/systemd/aos-systemd-veritysetup-generator": str(commands / "generator"),
            "/run/systemd/system": str(units),
            "/sys/fs/selinux/enforce": str(root / "enforce"),
            f"{selinux}/sbin/matchpathcon": str(commands / "matchpathcon"),
            f"{selinux}/sbin/setfilecon": str(commands / "setfilecon"),
        }
        script = source
        for original, replacement in replacements.items():
            assert original in script, original
            script = script.replace(original, replacement)

        environment = os.environ | {
            "PATH": f"{commands}:{coreutils}",
            "AOS_VERITY_TEST_CASE": case,
            "AOS_VERITY_TEST_EVENTS": str(events),
        }
        result = subprocess.run(
            [bash, "-c", script], env=environment, capture_output=True, text=True
        )
        calls = [json.loads(line) for line in events.read_text().splitlines()]
        names = [call[0] for call in calls]

        if case in ("disabled", "enabled"):
            assert result.returncode == 0, result.stderr
            expected = ["generator"]
            if case == "enabled":
                expected += ["matchpathcon", "setfilecon"]
            expected += ["systemctl", "systemctl", "udevadm", "udevadm"]
            assert names == expected, calls
            assert calls[-4] == ["systemctl", "daemon-reload"], calls
            assert calls[-3] == ["systemctl", "start", "systemd-veritysetup@root.service"], calls
            assert (units / "systemd-veritysetup@root.service").read_text() == "[Service]\n"
        else:
            assert result.returncode != 0, case
            assert "systemctl" not in names and "udevadm" not in names, calls
            expected = ["generator"]
            if case != "missing-unit":
                expected += ["matchpathcon"]
            if case == "relabel-failure":
                expected += ["setfilecon"]
            assert names == expected, calls

        if "matchpathcon" in names:
            assert calls[1] == [
                "matchpathcon", "-n", "-m", "file",
                "/usr/lib/systemd/system/systemd-veritysetup@root.service",
            ], calls
        if "setfilecon" in names:
            assert calls[2] == [
                "setfilecon", "system_u:object_r:systemd_unit_t",
                str(units / "systemd-veritysetup@root.service"),
            ], calls
        assert not list(root.glob("staging.*")), "generator scratch directory leaked"


source = Path(sys.argv[1]).read_text()
for case in ("disabled", "enabled", "lookup-failure", "relabel-failure", "missing-unit"):
    check_case(source, *sys.argv[2:5], case)
print("verity publication: five lifecycle and failure cases passed")
