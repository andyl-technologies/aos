# Initrd ability ownership handoff barrier negative test.
#
# The initrd controller first publishes a real durable journal and retained
# completion journal. A deliberately ordered test service then corrupts that journal
# before the handoff barrier verifies it. The barrier must fail and keep
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

      aos.activation.stages.initrd.configuration = [
        (builtins.path {
          path = ./_initrd-handoff-tamper-policy.nix;
          name = "aos-initrd-handoff-tamper-policy.nix";
        })
      ];

      boot.initrd.systemd.services.aos-ability-journal-tamper = {
        description = "Corrupt the Initrd Ability Completion Journal";
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
          journal=${failClosedSystem.config.aos.boot.substrateServices.initrdStateDirectory}/generations.journal
          test -s "$journal"
          printf X | ${pkgs.coreutils}/bin/dd of="$journal" bs=1 count=1 conv=notrunc status=none
          ${pkgs.coreutils}/bin/sync "$journal"
          printf '%s\n' \
            'aos-ability-journal-tamper: corrupted completed journal' \
            > /dev/kmsg
        '';
      };
    }
  ];
  initrdGraph = failClosedSystem.config.system.build.initrdDeploymentBundle.nativeTransaction.graph;
  barrier =
    (builtins.head (builtins.filter
      (node: builtins.elem "boot-preparations.aos-ability-initrd-handoff-barrier" node.identity)
      (builtins.attrValues initrdGraph.nodes))).input;
in
  assert lib.all
  (unit: builtins.elem unit barrier.dependencies.requires && builtins.elem unit barrier.dependencies.after)
  [
    "aos-ability-initrd-controller.service"
    "aos-ability-journal-tamper.service"
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
            "aos-ability-journal-tamper: corrupted completed journal"
        )
        rejection_marker = "header digest mismatch"
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
