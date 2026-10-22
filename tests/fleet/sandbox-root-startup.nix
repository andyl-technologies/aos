# Qualifies the installed Root startup over PID 1-delivered signed inputs.
{
  lib,
  pkgs,
  systems,
  ...
} @ args: let
  base = import ./sandbox-source-startup.nix args;
  probe = import ./_sandbox-q04-probe.nix {inherit lib pkgs;};
  command = "${probe}/bin/aos-sandbox-q04-bootstrap-vm-probe";
in
  base
  // {
    name = "sandbox-root-startup";
    timeout = 3000;

    testScript =
      base.testScript
      + ''
        unit = "aos-sandbox-policy-authorityd.service"
        project_key = "/run/credentials/@system/qualification-root-projectPublicKey"
        original_project_key = "/run/root-startup-project-public-key"
        history_unit = "aos-sandbox-policy-cache-recovery.service"

        def wait_for_history_accept():
            vm.wait_for_unit(history_unit, timeout=120)
            check = (
                "import pathlib, subprocess; "
                f"pid = int(subprocess.check_output(['systemctl', 'show', {history_unit!r}, "
                "'--property=MainPID', '--value'])); "
                "assert pid > 0; "
                "assert pathlib.Path(f'/proc/{pid}/syscall').read_text().split()[0] == '288'"
            )
            vm.wait_until_succeeds(f"{python} -c {shlex.quote(check)}", timeout=120)
            pid = int(vm.succeed(f"systemctl show {history_unit} --property=MainPID --value").strip())
            status = dict(line.split(":", 1) for line in vm.succeed(f"cat /proc/{pid}/status").splitlines() if ":" in line)
            assert status["Uid"].split() == ["0"] * 4, status["Uid"]
            assert status["Gid"].split() == ["811"] * 4, status["Gid"]
            assert int(status["CapEff"].strip(), 16) == 0, status["CapEff"]
            assert status["NoNewPrivs"].strip() == "1", status["NoNewPrivs"]
            assert vm.succeed(f"cat /proc/{pid}/attr/current").strip().split(":")[2] == "aos_sandbox_policy_recovery_t"

            protected = "/var/lib/aos/sandbox/policy-compiler"
            mounts = [line.split() for line in vm.succeed(f"cat /proc/{pid}/mountinfo").splitlines()]
            ancestors = [fields for fields in mounts if protected == fields[4] or protected.startswith(fields[4].rstrip("/") + "/")]
            closest = max(ancestors, key=lambda fields: len(fields[4]))
            assert "ro" in closest[5].split(","), closest
            vm.succeed("test -S /run/aos/sandbox-policy-cache-recovery/recovery.sock")
            return pid

        def wait_for_root_accept():
            check = (
                "import pathlib, subprocess; "
                f"pid = int(subprocess.check_output(['systemctl', 'show', {unit!r}, "
                "'--property=MainPID', '--value'])); "
                "assert pid > 0; "
                "assert pathlib.Path(f'/proc/{pid}/syscall').read_text().split()[0] == '288'"
            )
            vm.wait_until_succeeds(f"{python} -c {shlex.quote(check)}", timeout=120)
            pid = int(vm.succeed(f"systemctl show {unit} --property=MainPID --value").strip())
            status = dict(line.split(":", 1) for line in vm.succeed(f"cat /proc/{pid}/status").splitlines() if ":" in line)
            assert status["Uid"].split() == ["0"] * 4, status["Uid"]
            assert status["PPid"].strip() == "1", status["PPid"]
            assert vm.succeed(f"cat /proc/{pid}/attr/current").strip().split(":")[2] == "aos_sandbox_policy_authority_t"
            return pid

        def start_root():
            vm.succeed(f"systemctl reset-failed {unit}")
            vm.succeed(f"systemctl start {unit}")
            return wait_for_root_accept()

        # The history listener must enter its own confined role before any
        # normal Root credentials exist, and survive normal Root's lifecycle.
        history = wait_for_history_accept()
        vm.succeed("${command} external-root-credentials-bootstrap")
        first = start_root()
        assert wait_for_history_accept() == history
        vm.succeed(f"systemctl restart {unit}")
        second = wait_for_root_accept()
        assert first != second, (first, second)
        assert wait_for_history_accept() == history

        # Change the external pin while PID 1's prior credential mount is gone.
        # The real startup must reject the same signed source under another key.
        vm.succeed(f"systemctl stop {unit}")
        vm.succeed(f"cp {project_key} {original_project_key}")
        change = (
            "import hashlib; from pathlib import Path; "
            f"path = Path({project_key!r}); pin = bytearray(path.read_bytes()); "
            "assert len(pin) == 80 and pin[:8] == b'AOSPPK01'; "
            "pin[16:48] = bytes.fromhex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'); "
            "pin[48:] = hashlib.sha256(b'aos.sandbox.policy-project-verifier.v1\\0' + pin[:48]).digest(); "
            "path.write_bytes(pin)"
        )
        vm.succeed(f"{python} -c {shlex.quote(change)}")
        vm.execute(f"systemctl start {unit}")
        vm.wait_until_succeeds(
            f"test $(systemctl show {unit} --property=ExecMainStatus --value) -ne 0",
            timeout=60,
        )
        assert wait_for_history_accept() == history
        vm.succeed(f"systemctl stop {unit}")
        vm.succeed(f"cp {original_project_key} {project_key}")
        start_root()

        # Reboot removes only the volatile inputs. The installed startup and
        # persistent owner state must still admit the freshly delivered pins.
        vm.reboot()
        vm.wait_for_unit("multi-user.target", timeout=300)
        wait_for_history_accept()
        vm.succeed("${command} external-source-credentials-bootstrap")
        vm.succeed("systemctl start aos-sandbox-source-signerd.service")
        vm.succeed("${command} external-root-credentials-bootstrap")
        start_root()
      '';
  }
