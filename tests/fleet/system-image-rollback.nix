# Authenticated A/B image acceptance through native public operations.
# Exercises real counted boot exhaustion, successful executor handoff, rollback,
# candidate health failure, boot-commit replay, and explicit expired retirement.
{
  lib,
  mkSystem,
  pkgs,
  systems,
  extraFixtureModules ? [],
  extraTestArtifactRoots ? [],
  replaceExecutor ? true,
}: let
  testPackages = [
    pkgs.diffutils
  ];

  rolloutPolicy = import ./_image-rollout-production.nix {inherit pkgs;};
  bootFaultHook =
    (pkgs.writeShellScriptBin "aos-image-acceptance-boot-fault" ''
      set -eu
      if test -f /var/lib/aos-test/blocked-image-toplevel; then
        IFS= read -r blocked < /var/lib/aos-test/blocked-image-toplevel
        running=$(${pkgs.coreutils}/bin/readlink /run/current-system)
        test "$running" != "$blocked"
      fi
    '').overrideAttrs (_: {
      module = ./_image-acceptance-boot-policy;
      moduleDeps = [pkgs.service-management];
    });
  bootFaultModule = {
    aos.packages.aos-image-acceptance-boot-fault = {
      package = bootFaultHook;
      bundle = true;
    };
    aos.activation.stages.host.configuration = [
      (builtins.path {
        path = ./_image-acceptance-agent-policy.nix;
        name = "aos-image-acceptance-agent-policy.nix";
      })
    ];
  };
  candidateAos =
    if !replaceExecutor
    then pkgs.aos
    else
      pkgs.aos.overrideAttrs (previous: {
        postInstall =
          previous.postInstall
          + ''
            printf '%s\n' candidate-executor > "$packageRuntime/rollout-test-identity"
          '';
      });
  candidatePackageRuntime = assert (
    !replaceExecutor || toString candidateAos.packageRuntime != toString pkgs.aos.packageRuntime
  );
    candidateAos.packageRuntime;
  candidatePkgs =
    pkgs
    // {
      aos = candidateAos;
    };
  candidateAgentUnit = pkgs.writeTextFile {
    name = "aos-fleet-test-agent-runtime-unit";
    destination = "/aos-test-agent.service";
    text = ''
      [Unit]
      Description=AOS VM Test Guest Agent
      RefuseManualStop=true

      [Service]
      Type=simple
      ExecStart=${pkgs.aos-test-agent}/share/aos-test-agent/aos-test-agent
      Restart=on-failure
      RestartSec=1
      Environment=PATH=${pkgs.coreutils}/bin:${pkgs.bash}/bin:${pkgs.systemd}/bin:${pkgs.systemd}/sbin
    '';
  };
  drainScript = rolloutPolicy.module.aos.apm.drainScript;
  healthScript = rolloutPolicy.module.aos.apm.healthScript;
  predecessorHealthScript = healthScript;
  initrdControlFallback = {
    aos.boot.initrd.packageRoots = [pkgs.aos-test-agent];
    boot.initrd.systemd.services.aos-test-agent-initrd-fallback = {
      description = "Expose test control for stalled initrd boots";
      requiredBy = ["initrd-fs.target"];
      before = ["initrd-fs.target"];
      unitConfig.DefaultDependencies = "no";
      environment.PATH = "${pkgs.coreutils}/bin:${pkgs.bash}/bin:${pkgs.systemd}/bin:${pkgs.systemd}/sbin";
      serviceConfig = {
        Type = "simple";
        Restart = "on-failure";
        RestartSec = "1s";
        StandardOutput = "journal+console";
        StandardError = "journal+console";
      };
      script = ''
        echo "starting initrd test control"
        exec ${pkgs.aos-test-agent}/share/aos-test-agent/aos-test-agent
      '';
    };
  };

  # The candidate changes image identity and realizes its package runtime as a
  # distinct immutable executor. Keeping the module ABI fixed isolates the
  # executor ownership handoff from cross-ABI state migration.
  candidate = mkSystem {
    specialArgs.pkgs = candidatePkgs;
    modules =
      [
        ../../systems/server-verity.nix
        ../../systems/_server-test-packages.nix
        initrdControlFallback
        rolloutPolicy.module
        bootFaultModule
        {
          aos.system.version = "9999.0.0-image-rollback";

          # This qualification image deliberately carries the guest agent and
          # binutils-backed recovery inspection used by the A/B rollout harness.
          # Structured-ability callers also name the Python interpreter for
          # their in-guest boundary observer. Keep those exact roots explicit
          # while inheriting the measured full-host image limits.
          aos.image.allowTestArtifacts = true;
          aos.image.testArtifactRoots = [pkgs.binutils] ++ extraTestArtifactRoots;

          # The fleet machine module bakes deterministic interface naming into the
          # initial UKI. Preserve that test-machine ABI in the independently built
          # candidate and seed its fleet address so first-boot evaluation can run
          # before the retained host configuration is rebound.
          aos.boot.kernelParams = ["net.ifnames=0"];
          aos.apm.drainScript = drainScript;
          aos.apm.healthScript = healthScript;
          aos.packages.aos-test-agent = {
            package = pkgs.aos-test-agent;
            bundle = true;
          };
          environment.systemPackages = testPackages;
          aos.networking.interfaces.fleet-eth0 = {
            matchMACAddress = "52:54:00:12:00:02";
            address = "192.168.50.11/24";
          };
          systemd.services.aos-test-agent = {
            description = "AOS VM Test Guest Agent";
            wantedBy = ["multi-user.target"];
            restartIfChanged = false;
            stopIfChanged = false;
            unitConfig.RefuseManualStop = true;
            serviceConfig = {
              Type = "simple";
              ExecStart = "${pkgs.aos-test-agent}/share/aos-test-agent/aos-test-agent";
              Restart = "on-failure";
              RestartSec = 1;
              Environment = "PATH=${pkgs.coreutils}/bin:${pkgs.bash}/bin:${pkgs.systemd}/bin:${pkgs.systemd}/sbin";
            };
          };
          systemd.services.aos-test-agent-bootstrap = {
            description = "Install the AOS VM test control channel";
            wantedBy = ["multi-user.target"];
            before = ["aos-activate.service"];
            stopOnRemoval = false;
            unitConfig.RefuseManualStop = true;
            serviceConfig.Type = "oneshot";
            script = ''
              ${pkgs.coreutils}/bin/mkdir -p /run/systemd/system
              ${pkgs.coreutils}/bin/ln -sfn ${candidateAgentUnit}/aos-test-agent.service \
                /run/systemd/system/aos-test-agent.service
              ${pkgs.systemd}/bin/systemctl daemon-reload
              ${pkgs.systemd}/bin/systemctl start aos-test-agent.service
            '';
          };
        }
      ]
      ++ extraFixtureModules;
  };
  candidateTop = candidate.config.system.build.toplevel;
  # Transfer the source closure without realizing its compiler outputs.
  candidateSourceDrv = builtins.unsafeDiscardOutputDependency candidateTop.drvPath;
  candidateImage = candidate.config.system.build.image.raw;
  candidateImageDisk = candidate.config.system.build.imageArtifacts.raw.disk;
  candidateImageInfo = candidate.config.system.build.imageArtifacts.raw.info;
  candidateUki = candidate.config.system.build.initialBootExecutable;

  rolloutFixtureRoots = lib.unique (
    [candidateTop candidateImage candidateImageDisk candidateImageInfo candidateUki candidatePackageRuntime]
    # APR's complete cache includes the published source derivation closure.
    ++ [candidateSourceDrv]
    ++ rolloutPolicy.extraClosures
    ++ [bootFaultHook]
    ++ [pkgs.aos.apr pkgs.sbsigntools pkgs.binutils pkgs.efitools pkgs.gawk pkgs.git pkgs.secure-boot-test-keys]
  );
  rolloutClosureInfo = lib.build.closureInfo {inherit pkgs;} {
    rootPaths = rolloutFixtureRoots;
  };
  # Sequential NAR reads avoid walking the complete source tree over 9p.
  # This transport is a host fixture artifact, not a published image input.
  rolloutTransport = pkgs.mkDerivation {
    pname = "aos-native-image-fixture-transport";
    version = "1";
    src = null;
    buildDeps = [pkgs.bash pkgs.nix pkgs.zstd pkgs.coreutils];
    exportReferencesGraph.roots = rolloutFixtureRoots;
    outputChecks.out = {};
    dontStrip = true;
    dontNukeRefs = true;

    phases = [
      {
        name = "build";
        script = ''
          set -eu
          ${pkgs.coreutils}/bin/mkdir -p "$out/nars"
          ${pkgs.coreutils}/bin/cp ${rolloutClosureInfo}/registration ${rolloutClosureInfo}/store-paths "$out/"
          export out
          ${pkgs.bash}/bin/bash -euo pipefail -c ${lib.escapeShellArg ''
            while IFS= read -r store_path; do
              name=$(${pkgs.coreutils}/bin/basename "$store_path")
              ${pkgs.nix}/bin/nix-store --dump "$store_path" \
                | ${pkgs.zstd}/bin/zstd -q -3 -T1 -c > "$out/nars/$name.nar.zst"
            done < ${rolloutClosureInfo}/store-paths
          ''}
        '';
      }
    ];
  };
  enrollmentFixtureRoots = [pkgs.efitools pkgs.secure-boot-test-keys];
  enrollmentClosureInfo = lib.build.closureInfo {inherit pkgs;} {
    rootPaths = enrollmentFixtureRoots;
  };

  # Image-mode machines boot the system image directly. Keep only the exact
  # byte-comparison tool needed by the slot assertions in that image; APM's
  # production libgit2 path performs the target-side registry clone.
  targetModules =
    [
      ../../systems/server-verity.nix
      ../../systems/_server-test-packages.nix
      initrdControlFallback
      rolloutPolicy.module
      bootFaultModule
      {
        environment.systemPackages = testPackages;
        aos.packages.aos-test-agent = {
          package = pkgs.aos-test-agent;
          bundle = true;
        };
        aos.apm.drainScript = drainScript;
        aos.apm.healthScript = predecessorHealthScript;
      }
    ]
    ++ extraFixtureModules;
  targetSystem = mkSystem targetModules;
in {
  name = "system-image-rollback";
  timeout = 5400;
  bootTimeout = 600;

  # Reuse the exact measured candidate and image-mode machines in the
  # structured-ability rollout acceptance test. Keeping one construction avoids
  # qualifying two independently evaluated image identities.
  abilityRolloutFixture = {
    inherit candidate targetSystem targetModules;
    predecessorTop = targetSystem.config.system.build.toplevel;
    predecessorBootContract = targetSystem.config.system.build.bootArtifactContract;
    candidateBootContract = candidate.config.system.build.bootArtifactContract;
    baselineEvaluation = targetSystem.config.system.build.hostDeploymentBundle;
    baselineProjection = targetSystem.qualificationProjection;
    inherit
      candidateImage
      candidateImageDisk
      candidateImageInfo
      candidatePackageRuntime
      candidateTop
      candidateUki
      drainScript
      healthScript
      predecessorHealthScript
      ;
  };

  machines = {
    target = {
      system = targetSystem;
      bootMode = "image";
      # Staging retains both evaluator closures before overwriting a slot and
      # concurrently holds the downloaded raw-image NAR. Give the lifecycle
      # fixture enough durable workspace to exercise that safety property.
      imageDiskMiB = 49152;
      # Importing the multi-gigabyte raw image NAR runs the package client and
      # nix-store concurrently. Leave enough headroom for both decompression
      # pipelines so the acceptance test measures rollback behavior rather
      # than the VM's OOM policy.
      memoryMiB = 8192;
      tpm = true;
      packages = ["aos-test-agent"];
      extraClosures = rolloutFixtureRoots ++ [rolloutTransport];
      hostStoreMount = true;
      extraModules = [
        {
          aos.activation.stages.host.configuration = [
            (builtins.toFile "aos-rollback-store-transport.nix" ''
              { lib, ... }: {
                aos.kernel.modules = lib.mkAfter [ "9pnet_virtio" "9p" ];
              }
            '')
          ];
        }
      ];
      # The same authenticated leaf is replayed after each image transition.
      # It keeps the fleet address stable after the candidate's base library
      # replaces the image-baked test identity.
      metadata."host.nix" = ''
        {
          aos.provisioning.storage.partitions.var.sizeMin = "24G";
          aos.networking.hostName = "target";
          aos.networking.useDHCP = false;
          aos.networking.interfaces.eth0.address = "192.168.50.11/24";
          aos.apm.desiredPackages = [ "aos-test-agent" ];

          ${rolloutPolicy.qualificationSetupBody}

          aos.abilities.configuration.operations.file.effects.rollback-hosts = {
            lifetime = "instance";
            input = {
              path = "/etc/hosts";
              content = "127.0.0.1 localhost\n192.168.50.11 target\n";
              owner = "root";
              group = "root";
              mode = "0444";
            };
          };
        }
      '';
    };
  };

  testScript =
    rolloutPolicy.testPrelude
    + ''
      import sys
      import types
      import textwrap

      runtime = target
      SYSTEMCTL = "${pkgs.systemd}/bin/systemctl"
      SYSTEMD_RUN = "${pkgs.systemd}/bin/systemd-run"
      BOOTCTL = "${pkgs.systemd}/bin/bootctl"
      DATE = "${pkgs.coreutils}/bin/date"
      SHA256SUM = "${pkgs.coreutils}/bin/sha256sum"
      OD = "${pkgs.coreutils}/bin/od"
      EFI_UPDATEVAR = "${pkgs.efitools}/bin/efi-updatevar"
      SECURE_BOOT_KEYS = "${pkgs.secure-boot-test-keys}"
      UTIL_LINUX = "${pkgs.util-linux}/bin"
      GIT_BIN = "${pkgs.git}/bin"
      CANDIDATE_TOP = "${candidateTop}"
      CANDIDATE_SOURCE_DRV = "${candidateSourceDrv}"
      CANDIDATE_IMAGE = "${candidateImage}"
      CANDIDATE_IMAGE_DISK = "${candidateImageDisk}"
      CANDIDATE_IMAGE_INFO = "${candidateImageInfo}"
      CANDIDATE_UKI = "${candidateUki}"
      CANDIDATE_EXECUTOR = "${candidatePackageRuntime}"
      BOOT_FAULT_HOOK = "${bootFaultHook}/bin/aos-image-acceptance-boot-fault"
      CANDIDATE_BOOT_CONTRACT = "${candidate.config.system.build.bootArtifactContract}"
      OBSERVER_HOST_MODULE = ${builtins.toJSON rolloutPolicy.qualificationSetupBody}
      IMAGE_ACCEPTANCE = types.ModuleType("native_image_acceptance")
      IMAGE_ACCEPTANCE.__dict__.update(globals())
      exec(compile(${builtins.toJSON (builtins.readFile ./native-image-acceptance.py)},
          "native-image-acceptance.py", "exec"), IMAGE_ACCEPTANCE.__dict__)

      def install_fixture_closure(closure_name, roots, transport_name=""):
          """Copies and verifies exact fixture objects through a read-only export."""
          runtime.succeed(textwrap.dedent(f"""
              set -eu
              export NIX_REMOTE=""
              export NIX_CONF_DIR=/tmp/native-image-nix-conf
              ${pkgs.coreutils}/bin/mkdir -p "$NIX_CONF_DIR" /run/aos-host-store
              printf 'experimental-features = nix-command\\nsandbox = false\\nbuild-users-group =\\n' > "$NIX_CONF_DIR/nix.conf"
              ${pkgs.util-linux}/bin/mount -t 9p \
                -o trans=virtio,version=9p2000.L,msize=1048576,ro \
                aos-host-store /run/aos-host-store
              closure=/run/aos-host-store/{shlex.quote(closure_name)}
              test -r "$closure/registration"
              transport_name={shlex.quote(transport_name)}
              stage=""
              trap 'if test -n "$stage"; then ${pkgs.coreutils}/bin/rm -rf -- "$stage"; fi' EXIT
              if test -n "$transport_name"; then
                transport="/run/aos-host-store/$transport_name"
                ${pkgs.diffutils}/bin/cmp "$closure/registration" "$transport/registration"
                ${pkgs.diffutils}/bin/cmp "$closure/store-paths" "$transport/store-paths"
              fi
              while IFS= read -r store_path; do
                if test ! -e "$store_path" && test ! -L "$store_path"; then
                  if test -n "$transport_name"; then
                    source_path="$transport/nars/$(${pkgs.coreutils}/bin/basename "$store_path").nar.zst"
                    # The private directory shares the /var-backed store overlay,
                    # so publication is a rename, never a second copy or overwrite.
                    stage=$(${pkgs.coreutils}/bin/mktemp -d /nix/store/.aos-fixture-nar.XXXXXX)
                    ${pkgs.bash}/bin/bash -euo pipefail -c \
                      '${pkgs.zstd}/bin/zstd -q -d -c -- "$1" | ${pkgs.nix}/bin/nix-store --restore "$2"' \
                      aos-fixture-nar "$source_path" "$stage/object"
                    # NAR restoration preserves executable bits but grants owner
                    # write access. Normalize only this tree, never link targets.
                    ${pkgs.coreutils}/bin/chmod -R -P --no-dereference a-w -- "$stage/object"
                    ${pkgs.coreutils}/bin/mv --no-copy --no-target-directory --update=none-fail \
                      "$stage/object" "$store_path"
                    ${pkgs.coreutils}/bin/rmdir -- "$stage"
                    stage=""
                  else
                    source_path="/run/aos-host-store/$(${pkgs.coreutils}/bin/basename "$store_path")"
                    ${pkgs.coreutils}/bin/cp --archive --no-target-directory --no-clobber \
                      "$source_path" "$store_path"
                  fi
                fi
              done < "$closure/store-paths"
              ${pkgs.nix}/bin/nix-store --load-db < "$closure/registration"
              while IFS= read -r store_path; do
                ${pkgs.nix}/bin/nix-store --verify-path "$store_path"
              done < "$closure/store-paths"
              ${pkgs.nix}/bin/nix-store --check-validity {shlex.join(roots)}
              options=$(${pkgs.util-linux}/bin/findmnt --first-only --direction backward \
                --noheadings --raw --output OPTIONS --target /run/aos-host-store)
              case ",$options," in *,ro,*) ;; *) exit 1 ;; esac
              case ",$options," in *,rw,*) exit 1 ;; esac
              ${pkgs.util-linux}/bin/umount /run/aos-host-store
          """), timeout=1800)

      runtime.wait_until_succeeds(f"{SYSTEMCTL} is-active --quiet aos-image-boot-commit.service", timeout=600)
      # The first enforcing boot replaces the disposable Setup Mode /var.
      # Import enrollment tools first, then stage the rollout in the sealed upper.
      install_fixture_closure(
          ${builtins.toJSON (baseNameOf enrollmentClosureInfo)},
          ${builtins.toJSON (map builtins.toString enrollmentFixtureRoots)},
      )
      IMAGE_ACCEPTANCE.secure_boot()
      install_fixture_closure(
          ${builtins.toJSON (baseNameOf rolloutClosureInfo)},
          ${builtins.toJSON (map builtins.toString rolloutFixtureRoots)},
          transport_name=${builtins.toJSON (baseNameOf rolloutTransport)},
      )
      IMAGE_ACCEPTANCE.run()
    '';
}
