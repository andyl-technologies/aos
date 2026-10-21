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

        vm.succeed("${command} external-root-credentials-bootstrap")
        first = start_root()
        vm.succeed(f"systemctl restart {unit}")
        second = wait_for_root_accept()
        assert first != second, (first, second)

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
        vm.succeed(f"systemctl stop {unit}")
        vm.succeed(f"cp {original_project_key} {project_key}")
        start_root()

        # Reboot removes only the volatile inputs. The installed startup and
        # persistent owner state must still admit the freshly delivered pins.
        vm.reboot()
        vm.wait_for_unit("multi-user.target", timeout=300)
        vm.succeed("${command} external-source-credentials-bootstrap")
        vm.succeed("systemctl start aos-sandbox-source-signerd.service")
        vm.succeed("${command} external-root-credentials-bootstrap")
        start_root()
      '';
  }
