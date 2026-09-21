# Normal initrd emergency-mode negative test.
#
# The fixture deliberately selects emergency.target as PID1's initial target.
# Verity initrds mask both emergency and rescue targets as well as their shell
# services. PID1 must reject both targets and freeze, proving the requested
# failure path remains noninteractive before mounting the root or /var.
{
  mkSystem,
  pkgs,
  ...
}: let
  failClosedSystem = mkSystem [
    ../../systems/server.nix
    {
      aos.boot.kernelParams = ["rd.systemd.unit=emergency.target"];
      aos.image.erofsCompressionLevel = 1;
      # Fast compression with the test agent produces a roughly 666 MiB root.
      aos.image.budgets.maxRootMiB = 704;

      # This negative boot fixture deliberately bundles the fleet agent.
      aos.image.allowTestArtifacts = true;
      aos.packages.aos-test-agent = {
        package = pkgs.aos-test-agent;
        bundle = true;
      };
    }
  ];
in
  assert failClosedSystem.config.aos.security.verity.enable;
  assert builtins.elem "emergency.service" failClosedSystem.config.boot.initrd.systemd.maskedUnits;
  assert builtins.elem "rescue.service" failClosedSystem.config.boot.initrd.systemd.maskedUnits; {
    name = "initrd-emergency-fail-closed";
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
                if "Freezing execution." in transcript:
                    break
            time.sleep(1)

        assert "Unit emergency.target is masked." in transcript, transcript[-8000:]
        assert "Unit rescue.target is masked." in transcript, transcript[-8000:]
        assert "Freezing execution." in transcript, transcript[-8000:]
        assert "Reached target Emergency Mode" not in transcript, transcript[-8000:]
        assert "Mounting /sysroot" not in transcript, transcript[-8000:]
        assert "Mounted /sysroot" not in transcript, transcript[-8000:]
        assert "Starting Mount /var Partition" not in transcript, transcript[-8000:]
        assert "Encrypt and TPM2-seal /var" not in transcript, transcript[-8000:]
        assert "Switching root" not in transcript, transcript[-8000:]
        assert "Press Enter for maintenance" not in transcript, transcript[-8000:]
        assert "Give root password for maintenance" not in transcript, transcript[-8000:]
        assert "target login:" not in transcript, transcript[-8000:]
        assert "Initrd Debug Shell" not in transcript, transcript[-8000:]
      '';
  }
