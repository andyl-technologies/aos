# Normal initrd emergency-mode negative test.
#
# The signed fixture selects systemd's emergency target directly. Production
# initrds mask that target and its interactive service, so PID 1 must reject
# the transaction without exposing sulogin, a login prompt, or an AOS debug
# shell. The runtime transcript and rendered unit topology together prove the
# failure is both fail-closed and noninteractive.
{mkSystem, ...}: let
  failClosedSystem = mkSystem [
    ../../systems/server.nix
    {
      aos.boot.kernelParams = ["rd.systemd.unit=emergency.target"];
    }
  ];
in
  assert builtins.elem "emergency.target" failClosedSystem.config.boot.initrd.systemd.maskedUnits;
  assert builtins.elem "rescue.target" failClosedSystem.config.boot.initrd.systemd.maskedUnits;
  assert builtins.elem "emergency.service" failClosedSystem.config.boot.initrd.systemd.maskedUnits;
  assert builtins.elem "rescue.service" failClosedSystem.config.boot.initrd.systemd.maskedUnits; {
    name = "initrd-emergency-fail-closed";
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
                if "emergency.target" in transcript and "masked" in transcript:
                    break
            time.sleep(1)

        assert "emergency.target" in transcript, transcript[-8000:]
        assert "masked" in transcript, transcript[-8000:]
        assert "Reached target Emergency Mode" not in transcript, transcript[-8000:]
        assert "Switching root" not in transcript, transcript[-8000:]
        assert "Press Enter for maintenance" not in transcript, transcript[-8000:]
        assert "Give root password for maintenance" not in transcript, transcript[-8000:]
        assert "target login:" not in transcript, transcript[-8000:]
        assert "Initrd Debug Shell" not in transcript, transcript[-8000:]
      '';
  }
