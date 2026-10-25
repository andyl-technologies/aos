# Source-bound fresh enrollment evidence. This is no Store readiness or gate credit.
{
  pkgs,
  lib,
  sourceGateWithInputs,
  configuredSdkProof,
  surfaceImage,
}: let
  testing = import ../../lib/testing {inherit pkgs lib;};
  image =
    sourceGateWithInputs {
      preserveArtifactBytes = true;
      runtimeDeps = [pkgs.rust pkgs.rust.dev] ++ (pkgs.rust.runtimeDeps or []);
      nukeRefsKeep = [pkgs.terrane.src];
      extraBuildDeps = [pkgs.binutils];
    } "initial-enrollment-image" ''
      cd crates
      if cargo build --frozen --offline -p aos-terrane-integration \
        --example initial_enrollment_fixture --message-format=json \
        > "$TMPDIR/initial-enrollment-build.jsonl" 2> "$TMPDIR/initial-enrollment-build.stderr"; then
        cat "$TMPDIR/initial-enrollment-build.stderr"
      else
        build_status=$?
        cat "$TMPDIR/initial-enrollment-build.stderr" >&2
        python3 ${./initial_enrollment_image.py} errors "$TMPDIR/initial-enrollment-build.jsonl" >&2
        exit "$build_status"
      fi
      cargo metadata --frozen --offline --no-deps --format-version=1 > "$TMPDIR/initial-enrollment-packages.json"
      rustc --print target-libdir > "$TMPDIR/initial-enrollment-target-libdir"
      python3 ${./initial_enrollment_image.py} build ${./.}
    '';
  # This consumes the completed immutable image before constructing or booting
  # the VM. Guest verification repeats it; neither stage executes a role here.
  verified =
    sourceGateWithInputs {
      runtimeDeps = [image];
      nukeRefsKeep = [image pkgs.terrane.src];
      extraBuildDeps = [pkgs.binutils];
    } "initial-enrollment-image-verified" ''
      python3 ${image}/share/initial_enrollment_image.py verify ${image} ${pkgs.terrane.src}
      printf '%s\n' ${lib.escapeShellArg (toString image)} > "$out/verified-image"
    '';
  vmFor = scenario:
    testing.mkVMTest {
      name =
        if scenario == "enrollment"
        then "terrane-native-initial-enrollment-ext4"
        else if scenario == "reassembly"
        then "terrane-native-reassembly-ext4"
        else if scenario == "cold-private-release"
        then "terrane-native-cold-private-release-ext4"
        else if scenario == "cold-manifest-release"
        then "terrane-native-cold-manifest-release-ext4"
        else if scenario == "cold-public-pressure"
        then "terrane-native-cold-public-pressure-ext4"
        else if scenario == "cold-manifest-pressure"
        then "terrane-native-cold-manifest-pressure-ext4"
        else if scenario == "private-release"
        then "terrane-native-private-release-ext4"
        else if scenario == "surface"
        then "terrane-native-configured-surface-index-ext4"
        else if scenario == "worker-mounted-manifest"
        then "terrane-native-configured-mounted-manifest-ext4"
        else if scenario == "worker-mounted-expiry"
        then "terrane-native-configured-mounted-expiry-ext4"
        else if scenario == "worker-mounted-late"
        then "terrane-native-configured-mounted-late-ext4"
        else if scenario == "worker-mounted"
        then "terrane-native-configured-mounted-worker-ext4"
        else if scenario == "worker"
        then "terrane-native-configured-worker-ext4"
        else if scenario == "maintenance"
        then "terrane-native-configured-maintenance-ext4"
        else if scenario == "sdk-refusals"
        then "terrane-native-sdk-refusals-ext4"
        else if scenario == "sdk-wipe"
        then "terrane-native-sdk-wipe-ext4"
        else "terrane-native-sdk-cache-ext4";
      memory = 1024;
      rootfsDeps =
        [image verified pkgs.coreutils pkgs.util-linux pkgs.e2fsprogs pkgs.python3 pkgs.binutils]
        ++ lib.optional (builtins.elem scenario ["sdk" "sdk-refusals" "sdk-wipe" "maintenance" "surface" "worker" "worker-mounted" "worker-mounted-late" "worker-mounted-expiry" "worker-mounted-manifest"]) configuredSdkProof.image
        ++ lib.optional (builtins.elem scenario ["surface" "worker" "worker-mounted" "worker-mounted-late" "worker-mounted-expiry" "worker-mounted-manifest"]) surfaceImage;
      testScript = ''
        set -eu
        test "$(cat ${verified}/verified-image)" = ${lib.escapeShellArg (toString image)}
        mount -o remount,rw /
        mkdir -p /var/lib/terrane-enrollment-proof /var/lib/terrane-host
        chmod 700 /var/lib/terrane-host
        # Production opens a protected registry supplied by host administration;
        # enrollment itself must create every actual anchor and claim record.
        mkdir /var/lib/terrane-host/project-claims
        chmod 700 /var/lib/terrane-host/project-claims
        for registry_directory in /var/lib/terrane-host /var/lib/terrane-host/project-claims; do
          test -d "$registry_directory" && test ! -L "$registry_directory"
          test "$(stat -c '%u:%g:%a' "$registry_directory")" = 0:0:700
        done
        test -z "$(ls -A /var/lib/terrane-host/project-claims)"
        export TERRANE_INITIAL_FIXTURE_ROOT=/var/lib/terrane-enrollment-proof/data
        proof_disk=/var/lib/terrane-enrollment-proof/data.img
        mkdir "$TERRANE_INITIAL_FIXTURE_ROOT"
        proof_mounted=0
        cleanup() {
          if test "$proof_mounted" = 1; then
            umount "$TERRANE_INITIAL_FIXTURE_ROOT" || return
          fi
          rm -f "$proof_disk"
          rmdir "$TERRANE_INITIAL_FIXTURE_ROOT" /var/lib/terrane-enrollment-proof
        }
        trap cleanup EXIT
        # Ten independent two-owner partitions plus the genuine reused-project
        # preclaim fit with explicit journal/metadata headroom; this is guest disk.
        truncate -s 768M "$proof_disk"
        mkfs.ext4 -F -b 4096 -O project,quota,verity -E quotatype=prjquota "$proof_disk"
        mount -t ext4 -o loop,prjquota "$proof_disk" "$TERRANE_INITIAL_FIXTURE_ROOT"
        proof_mounted=1
        chmod 755 "$TERRANE_INITIAL_FIXTURE_ROOT"
        # Minimal guest init mounts /run with tmpfs's permissive default. Match
        # production runtime ancestry before the real publisher's protected walk.
        chmod 755 /run
        test "$(stat -c '%u:%g:%a' /run)" = 0:0:755
        mkdir /run/terrane-initial-publisher
        chown 841:845 /run/terrane-initial-publisher
        chmod 2750 /run/terrane-initial-publisher
        mkdir "$TERRANE_INITIAL_FIXTURE_ROOT/scratch"
        chmod 700 "$TERRANE_INITIAL_FIXTURE_ROOT/scratch"
        export TMPDIR="$TERRANE_INITIAL_FIXTURE_ROOT/scratch"
        export TERRANE_INITIAL_VM_IMAGE="$proof_disk"
        ${lib.optionalString (builtins.elem scenario ["sdk" "sdk-refusals" "sdk-wipe" "maintenance" "surface" "worker" "worker-mounted" "worker-mounted-late" "worker-mounted-expiry" "worker-mounted-manifest"]) ''
          export TERRANE_CONFIGURED_SDK_IMAGE=${configuredSdkProof.image}
        ''}
        ${lib.optionalString (builtins.elem scenario ["surface" "worker" "worker-mounted" "worker-mounted-late" "worker-mounted-expiry" "worker-mounted-manifest"]) ''
          export TERRANE_CONFIGURED_SURFACE_IMAGE=${surfaceImage}
        ''}
        export LD_LIBRARY_PATH="$(cat ${image}/share/runtime-library-path)"
        ${pkgs.python3}/bin/python3 ${image}/share/initial_enrollment_image.py verify ${image} ${pkgs.terrane.src}
        ${pkgs.python3}/bin/python3 ${image}/share/initial_enrollment_vm.py ${image} ${pkgs.terrane.src} ${lib.optionalString (scenario != "enrollment") scenario}
      '';
    };
  # The headless harness does not forward mkVMTest's system-mode timeout.
  # Bound its complete host supervisor too, including boot and guest cleanup.
  nativeFor = scenario: let
    vm = vmFor scenario;
  in
    vm.overrideAttrs (previous: {
      phases = map (phase:
        phase
        // {
          script = ''
            timeout --signal=TERM --kill-after=10 300 "$CONFIG_SHELL" -c ${lib.escapeShellArg phase.script}
          '';
        })
      previous.phases;
    });
  sdkMaintained = nativeFor "sdk";
  sdkRefusals = nativeFor "sdk-refusals";
in {
  inherit image sdkMaintained sdkRefusals;
  native = nativeFor "enrollment";
  reassembly = nativeFor "reassembly";
  privateRelease = nativeFor "private-release";
  coldPrivateRelease = nativeFor "cold-private-release";
  coldManifestRelease = nativeFor "cold-manifest-release";
  coldPublicPressure = nativeFor "cold-public-pressure";
  coldManifestPressure = nativeFor "cold-manifest-pressure";
  # Both independent native lifecycles must finish their complete original root
  # controls within the unchanged per-actor and per-VM bounds.
  sdk = pkgs.mkDerivation {
    pname = "terrane-native-sdk-cache-proof";
    version = "0.1.0";
    src = null;
    phases = [
      {
        name = "qualify";
        script = ''
          test "$(cat ${sdkMaintained}/result)" = PASS
          test "$(cat ${sdkRefusals}/result)" = PASS
          mkdir -p "$out/nix-support"
          printf '%s\n' ${sdkMaintained} ${sdkRefusals} > "$out/nix-support/native-proofs"
          printf 'PASS\n' > "$out/result"
        '';
      }
    ];
  };
  sdkWipe = nativeFor "sdk-wipe";
  maintenance = nativeFor "maintenance";
  surface = nativeFor "surface";
  worker = nativeFor "worker";
  mountedWorker = nativeFor "worker-mounted";
  mountedManifest = nativeFor "worker-mounted-manifest";
  mountedExpiry = nativeFor "worker-mounted-expiry";
  mountedLate = nativeFor "worker-mounted-late";
}
