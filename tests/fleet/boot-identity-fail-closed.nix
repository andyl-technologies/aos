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
    ({
      lib,
      initrdAbilityEvaluation ? null,
      ...
    }: {
      options.aos.tests.bootIdentityGraph = lib.mkOption {
        type = lib.types.raw;
        internal = true;
        readOnly = true;
        description = "Native initrd graph inspected by this image acceptance fixture.";
      };
      aos.tests.bootIdentityGraph =
        if initrdAbilityEvaluation == null
        then {nodes = {};}
        else initrdAbilityEvaluation._withoutProvenance initrdAbilityEvaluation.config.aos.activation.graph;
    })
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
  nodes = builtins.attrValues failClosedSystem.config.aos.tests.bootIdentityGraph.nodes;
  service = instance: name: let
    selected = builtins.filter (node:
      node.owner
      == "service-management"
      && builtins.elem instance node.identity
      && (node.input.service or null) == name)
    nodes;
  in
    if builtins.length selected == 1
    then (builtins.head selected).input
    else throw "The native initrd graph must contain exactly one ${instance}/${name} service.";
  verification = service "verity-root-verification.aos-verity-root-verify" "aos-verity-root-verify";
  mountVar = service "boot-preparations.mount-var" "mount-var";
in
  assert builtins.elem "aos-boot-identity-guard.service" mountVar.dependencies.requires;
  assert (builtins.head verification.lifecycle.start).executable.path == "${pkgs.aos-verity-root-guard}/bin/aos-verity-root-verify";
  assert builtins.elem "aos-boot-identity-guard.service" verification.dependencies.requires;
  assert builtins.elem "mount-var.service" verification.dependencies.required_by;
  assert builtins.elem "initrd-fs.target" verification.dependencies.required_by;
  assert verification.failure_policy.handlers == ["aos-boot-integrity-failure.target"];
  assert verification.failure_policy.dispatch == "isolate-active-goal"; {
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
