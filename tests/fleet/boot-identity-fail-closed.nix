# Boot-identity guard negative test.
#
# The signed image tuple already contains root=. Appending a recovery marker
# is therefore unambiguously outside the supported normal posture. The
# runtime identity guard must reject it before the generated mapper unit can
# execute, select the passive failure target, and leave root and /var untouched.
{
  lib,
  mkSystem,
  pkgs,
  ...
}: let
  failClosedSystem = mkSystem [
    ../../systems/server.nix
    {
      # Keep PID1 on its normal target so the identity guard actually runs.
      aos.boot.kernelParams = [
        "aos.recovery=1"
        # The image's final console is VGA; mirror journal events into the
        # kernel log so the serial transcript observes the guard's result.
        "systemd.journald.forward_to_kmsg=1"
        "systemd.journald.max_level_kmsg=info"
      ];
      aos.image.erofsCompressionLevel = 1;
      # Fast compression with the test agent produces a roughly 666 MiB root
      # and 769 MiB compressed image.
      aos.image.budgets.maxRootMiB = 704;
      aos.image.budgets.maxDownloadMiB = 800;

      # This negative boot fixture deliberately bundles the fleet agent.
      aos.image.allowTestArtifacts = true;
      aos.packages.aos-test-agent = {
        package = pkgs.aos-test-agent;
        bundle = true;
      };
    }
  ];
  initrdRequests = failClosedSystem.config.system.build.initrdAbilityGraph.requests;
  request = name: initrdRequests."aos-verity-root-guard:${name}".parameters;
  output = name: {
    _type = "aos-request-output-reference";
    request = "aos-verity-root-guard:${name}";
    output = "resource";
  };
  rootVerifyLifecycle = request "aos-verity-root-verify-lifecycle";
  rootVerifyDependencies = request "aos-verity-root-verify-dependencies";
  rootVerifyFailure = request "aos-verity-root-verify-failure_policy";
  mountVarDependencies = initrdRequests."aos-boot-preparations:mount-var-dependencies".parameters;
in
  assert builtins.elem {
    _type = "aos-request-output-reference";
    request = "aos-boot-preparations:boot-identity";
    output = "resource";
  }
  mountVarDependencies.requires;
  assert (builtins.head rootVerifyLifecycle.start).executable.entry_point == "bin/aos-verity-root-verify";
  assert builtins.elem (output "boot-identity") rootVerifyDependencies.requires;
  assert builtins.elem (output "persistent-state") rootVerifyDependencies.required_by;
  assert builtins.elem (output "initrd-filesystems") rootVerifyDependencies.required_by;
  assert rootVerifyFailure.handlers == [(output "integrity-failure")];
  assert rootVerifyFailure.dispatch == "isolate-active-goal"; {
    name = "boot-identity-fail-closed";
    timeout = 600;
    bootTimeout = 120;

    machines.target = {
      system = failClosedSystem;
      bootMode = "image";
      imageDiskMiB = 16384;
      expectAgent = false;
    };

    testScript =
      # python
      ''
        import time
        from pathlib import Path

        serial_log = Path(target.serial_log_path)
        # Allow firmware and hardened-kernel startup on a busy builder.
        deadline = time.monotonic() + 300
        transcript = ""

        while time.monotonic() < deadline:
            if serial_log.exists():
                transcript = serial_log.read_text(errors="replace")
                if (
                    "AOS boot identity failure: verity root absent; /var unmounted" in transcript
                    and "Reached target AOS boot identity rejected" in transcript
                ):
                    break
            time.sleep(1)

        assert "aos-boot-identity: rejected normal boot" in transcript, transcript[-8000:]
        assert "aos.recovery" in transcript, transcript[-8000:]
        assert "AOS boot identity failure: verity root absent; /var unmounted" in transcript, transcript[-8000:]
        assert "Reached target AOS boot identity rejected" in transcript, transcript[-8000:]
        assert "Reached target Emergency Mode" not in transcript, transcript[-8000:]
        assert "Starting Mount /var Partition" not in transcript, transcript[-8000:]
        assert "Encrypt and TPM2-seal /var" not in transcript, transcript[-8000:]
        assert "Switching root" not in transcript, transcript[-8000:]
        assert "Press Enter for maintenance" not in transcript, transcript[-8000:]
        assert "Give root password for maintenance" not in transcript, transcript[-8000:]
        assert "target login:" not in transcript, transcript[-8000:]
        assert "Initrd Debug Shell" not in transcript, transcript[-8000:]
      '';
  }
