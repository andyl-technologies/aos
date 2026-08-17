# Normal initrd emergency-mode negative test.
#
# The machine deliberately selects emergency.target as its initrd boot target.
# It must reach that target, proving the initrd ran far enough to activate an
# emergency path, while exposing neither sulogin nor an AOS debug shell. The
# base initrd builder independently materializes emergency.service and
# rescue.service as /dev/null masks, so the runtime transcript and rendered
# unit topology together prove the failure is noninteractive.
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
      aos.packages.aos-test-agent = {
        package = pkgs.aos-test-agent;
        bundle = true;
      };
    }
  ];
in
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
              if "Reached target Emergency Mode" in transcript:
                  break
          time.sleep(1)

      assert "Reached target Emergency Mode" in transcript, transcript[-8000:]
      assert "Switching root" not in transcript, transcript[-8000:]
      assert "Press Enter for maintenance" not in transcript, transcript[-8000:]
      assert "Give root password for maintenance" not in transcript, transcript[-8000:]
      assert "target login:" not in transcript, transcript[-8000:]
      assert "Initrd Debug Shell" not in transcript, transcript[-8000:]
    '';
}
