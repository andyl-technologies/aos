# Boot-identity guard negative test.
#
# The signed image tuple already contains root=. Appending a recovery marker
# is therefore unambiguously outside the supported normal posture. The
# runtime identity guard must reject it before the generated mapper unit can
# execute, select the passive failure target, and leave root and /var untouched.
{
  lib,
  mkSystem,
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
