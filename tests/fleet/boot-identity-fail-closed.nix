# Boot-identity guard negative test.
#
# The signed image tuple does not select recovery. Appending even a false
# recovery selector is therefore unambiguously outside the supported normal
# posture without changing systemd's initial target. The runtime identity guard
# must reject it before the generated mapper unit can execute, select the
# passive failure target, and leave root and /var untouched.
{
  lib,
  mkSystem,
  ...
}: let
  failClosedSystem = mkSystem [
    ../../systems/server.nix
    {
      aos.boot.kernelParams = ["aos.recovery=0"];
    }
  ];
  rootVerify = failClosedSystem.config.boot.initrd.systemd.services."aos-verity-root-verify";
in
  assert builtins.elem "aos-boot-identity-guard.service" failClosedSystem.config.boot.initrd.systemd.services."mount-var".requires;
  assert builtins.elem "aos-verity-root-verify.service" failClosedSystem.config.boot.initrd.systemd.services."mount-var".requires;
  assert builtins.elem "aos-boot-identity-guard.service" failClosedSystem.config.boot.initrd.systemd.services."systemd-veritysetup@root".requires;
  assert builtins.elem "aos-boot-identity-guard.service" rootVerify.requires;
  assert lib.hasInfix "systemctl start systemd-veritysetup@root.service" rootVerify.script;
  assert builtins.elem "initrd-fs.target" rootVerify.requiredBy;
  assert rootVerify.unitConfig.OnFailure == "aos-boot-identity-failure.target"; {
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
        # First-boot provisioning is bounded by a 30-second repart attempt,
        # a 15-second verification pass, udev settlement, and label discovery.
        # The identity guard runs after that transaction so its generated
        # verity unit observes the final device topology.
        deadline = time.monotonic() + 180
        transcript = ""

        while time.monotonic() < deadline:
            if serial_log.exists():
                transcript = serial_log.read_text(errors="replace")
                if "Reached target AOS boot identity rejected" in transcript:
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
