# Boot-identity guard negative test.
#
# The signed image tuple already contains root=. Appending an alternate initrd
# target is therefore unambiguously outside the supported normal posture. The
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
      aos.boot.kernelParams = ["rd.systemd.unit=emergency.target"];
      aos.image.erofsCompressionLevel = 1;
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
    timeout = 300;
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
        deadline = time.monotonic() + 60
        transcript = ""

        while time.monotonic() < deadline:
            if serial_log.exists():
                transcript = serial_log.read_text(errors="replace")
                if "AOS boot identity failure: verity root absent; /var unmounted" in transcript:
                    break
            time.sleep(1)

        assert "aos-boot-identity: rejected normal boot" in transcript, transcript[-8000:]
        assert "rd.systemd.unit" in transcript, transcript[-8000:]
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
