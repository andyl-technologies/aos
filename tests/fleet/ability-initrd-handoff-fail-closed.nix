# Initrd ability ownership handoff barrier negative test.
#
# The initrd controller first publishes a real durable journal and preserved
# checkpoint. A deliberately ordered test service then replaces that checkpoint
# before the handoff barrier authenticates it. The barrier must fail and keep
# initrd-switch-root.target from reaching stage 2.
{
  lib,
  mkSystem,
  pkgs,
  ...
}: let
  failClosedSystem = mkSystem [
    ../../systems/server-test.nix
    {
      aos.image.erofsCompressionLevel = 1;
      aos.packages.aos-test-agent = {
        package = pkgs.aos-test-agent;
        bundle = true;
      };

      boot.initrd.systemd.services.aos-ability-checkpoint-tamper = {
        description = "Corrupt the Initrd Ability Handoff Checkpoint";
        requiredBy = [
          "initrd-fs.target"
          "initrd-switch-root.target"
        ];
        requires = ["aos-ability-initrd-controller.service"];
        after = ["aos-ability-initrd-controller.service"];
        before = ["aos-ability-initrd-handoff-barrier.service"];
        unitConfig.DefaultDependencies = "no";
        serviceConfig.Type = "oneshot";
        script = ''
          printf '%s\n' '{}' > /run/aos/ability-stage-handoff/initrd.json
          printf '%s\n' \
            'aos-ability-checkpoint-tamper: replaced released checkpoint' \
            > /dev/kmsg
        '';
      };

      boot.initrd.systemd.services.aos-ability-initrd-handoff-barrier = {
        requires = ["aos-ability-checkpoint-tamper.service"];
        after = ["aos-ability-checkpoint-tamper.service"];
      };
    }
  ];
  barrier =
    failClosedSystem.config.boot.initrd.systemd.services.aos-ability-initrd-handoff-barrier;
in
  assert lib.all
  (unit: builtins.elem unit barrier.requires && builtins.elem unit barrier.after)
  [
    "aos-ability-initrd-controller.service"
    "aos-ability-checkpoint-tamper.service"
  ]; {
    name = "ability-initrd-handoff-fail-closed";
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
        tamper_marker = (
            "aos-ability-checkpoint-tamper: replaced released checkpoint"
        )
        rejection_marker = "decoding preserved initrd stage checkpoint"
        barrier_failure_marker = (
            "Failed to start Authenticate released initrd ability ownership"
        )
        failure_markers = (
            tamper_marker,
            rejection_marker,
            barrier_failure_marker,
        )

        while time.monotonic() < deadline:
            if serial_log.exists():
                transcript = serial_log.read_text(errors="replace")
                if all(marker in transcript for marker in failure_markers):
                    break
            time.sleep(1)

        for marker in failure_markers:
            assert marker in transcript, transcript[-8000:]

        grace_deadline = time.monotonic() + 10
        while time.monotonic() < grace_deadline:
            transcript = serial_log.read_text(errors="replace")
            time.sleep(0.5)

        assert "Switching root" not in transcript, transcript[-8000:]
        assert "target login:" not in transcript, transcript[-8000:]
      '';
  }
