# Qualifies genuine installed Source startup without provisioning a Source hold.
{
  lib,
  pkgs,
  systems,
  ...
} @ args: let
  base = import ./sandbox-funded-startup.nix args;
  probe = import ./_sandbox-q04-probe.nix {inherit lib pkgs;};
  system = base.machines.vm.system.extendModules {
    modules = [
      {
        environment.systemPackages = [probe pkgs.python3];
        # Retain the genuine Controller and its reserved envelope while this
        # fixture provisions only Source inputs. Starting dependent brokers
        # without their credentials would fence the shared bank first.
        systemd.services.aos-sandboxd.wantedBy = lib.mkForce [];
      }
    ];
  };
  command = "${probe}/bin/aos-sandbox-q04-bootstrap-vm-probe";
in
  base
  // {
    name = "sandbox-source-startup";
    timeout = 2400;
    machines.vm = base.machines.vm // {inherit system;};

    testScript =
      base.testScript
      + ''
        import shlex

        unit = "aos-sandbox-source-signerd.service"
        seed = "/run/credentials/@system/qualification-source-private-seed"
        source_journal = "/var/lib/aos/sandbox/source-domains/source-domains-v1.journal"
        python = "${pkgs.python3}/bin/python3"

        def wait_for_original_accept():
            # This x86_64 guest reaches accept4 only after the real executable
            # captures its PID 1/Parent originals, pays for credential capture,
            # validates the independent pin and prepares its fixed Root inputs.
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
            assert status["Uid"].split() == ["814"] * 4, status["Uid"]
            assert int(status["CapEff"].strip(), 16) == 0, status["CapEff"]
            assert vm.succeed(f"cat /proc/{pid}/attr/current").strip().split(":")[2] == "aos_sandbox_source_signer_t"
            vm.succeed(f"test ! -e {source_journal}")
            return pid

        def start_source():
            vm.succeed(f"systemctl reset-failed {unit}")
            vm.succeed(f"systemctl start {unit}")
            return wait_for_original_accept()

        with startup_diagnostics(vm, unit):
            assert vm.succeed(
                "systemctl show aos-sandboxd.service --property=LoadState --value"
            ).strip() == "loaded"
            assert vm.succeed(
                "systemctl show aos-sandboxd.service --property=ActiveState --value"
            ).strip() == "inactive"
            vm.succeed("${command} external-source-credentials-bootstrap")
            first = start_source()
            vm.succeed(f"systemctl restart {unit}")
            second = wait_for_original_accept()
            assert first != second, (first, second)

            # Rotate the external input, never PID 1's read-only credential mount.
            # The same genuine unit must refuse a private seed/public pin mismatch.
            vm.succeed(f"systemctl stop {unit}")
            change = f"from pathlib import Path; Path({seed!r}).write_bytes(bytes([7]) * 32)"
            vm.succeed(f"{python} -c {shlex.quote(change)}")
            vm.execute(f"systemctl start {unit}")
            vm.wait_until_succeeds(
                f"test $(systemctl show {unit} --property=ExecMainStatus --value) = 6",
                timeout=60,
            )
            vm.succeed(f"systemctl stop {unit}")
            vm.succeed(f"test ! -e {source_journal}")

            change = f"from pathlib import Path; Path({seed!r}).write_bytes(bytes([8]) * 32)"
            vm.succeed(f"{python} -c {shlex.quote(change)}")
            start_source()

            # Cold restart discards volatile credentials while retaining the
            # same disk and TPM state. Reprovision only those external inputs.
            power_cycle_and_require_new_boot(vm)
            vm.wait_for_unit("multi-user.target", timeout=300)
            vm.succeed("${command} external-source-credentials-bootstrap")
            start_source()
      '';
  }
