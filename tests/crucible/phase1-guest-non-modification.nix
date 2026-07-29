{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.guestNonModification",
  taskIds ? ["T-DET-21"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  qemuLaunch =
    builtins.readFile ../../crates/crucible-qemu/src/launch.rs
    + builtins.readFile ../../crates/crucible-qemu/src/launch/modes.rs;
  qemuLib = builtins.readFile ../../crates/crucible-qemu/src/lib.rs;
  qemuValidation = builtins.readFile ../../crates/crucible-qemu/src/launch/validation.rs;
  qemuTest =
    builtins.readFile ../../crates/crucible-qemu/tests/deterministic_launch.rs
    + builtins.readFile ../../crates/crucible-qemu/tests/deterministic_launch/launch_artifacts.rs;
  deterministicLaunchCheck = builtins.readFile ./phase1-deterministic-launch.nix;
  defaultChecks = builtins.readFile ./default.nix;
  determinismContract = builtins.readFile ../../docs/rfcs/0010-crucible/04-determinism-contract.md;
  invariants = builtins.readFile ../../docs/rfcs/0010-crucible/01-goals-nongoals-invariants.md;
  qemuIntegration = builtins.readFile ../../docs/rfcs/0010-crucible/10-qemu-integration.md;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;


  failures =
    failuresFor "crates/crucible-qemu/src/launch.rs" qemuLaunch [
      {
        label = "disk image mode contract";
        needle = "pub enum DiskImageMode";
      }
      {
        label = "copy-on-write overlay mode";
        needle = "CopyOnWriteOverlay";
      }
      {
        label = "writable backing negative mode";
        needle = "WritableBacking";
      }
      {
        label = "copy-on-write disk default";
        needle = "disk_image_mode: DiskImageMode::CopyOnWriteOverlay,";
      }
      {
        label = "genesis backing-state mode contract";
        needle = "pub enum GuestBackingStateMode";
      }
      {
        label = "byte-identical genesis backing mode";
        needle = "ByteIdenticalGenesis";
      }
      {
        label = "host-mutable genesis negative mode";
        needle = "HostMutableGenesis";
      }
      {
        label = "byte-identical genesis default";
        needle = "guest_backing_state: GuestBackingStateMode::ByteIdenticalGenesis,";
      }
      {
        label = "disk image policy setter";
        needle = "pub fn with_disk_image_mode(mut self, disk_image_mode: DiskImageMode) -> Self";
      }
      {
        label = "genesis backing-state policy setter";
        needle = "pub fn with_guest_backing_state(";
      }
      # The storage-mode validation refactored from two independent `if !=`
      # guards into one exhaustive match over the (disk_image_mode,
      # guest_backing_state) pair when the diskless firmware-pinned launch
      # landed. The invariant is unchanged (stronger: mismatched pairs are
      # also rejected); these needles pin the match's load-bearing arms.
      {
        label = "storage-mode pair validation";
        needle = "match (self.disk_image_mode, self.guest_backing_state)";
      }
      {
        label = "copy-on-write canonical pair";
        needle = "(DiskImageMode::CopyOnWriteOverlay, GuestBackingStateMode::ByteIdenticalGenesis)";
      }
      {
        label = "diskless coherent pair";
        needle = "(DiskImageMode::NoBlockDevice, GuestBackingStateMode::NoBlockDevice)";
      }
      {
        label = "writable-backing rejection";
        needle = "LaunchProfileError::DiskImageMutatesBacking";
      }
      {
        label = "byte-identical genesis rejection";
        needle = "LaunchProfileError::GuestBackingStateNotByteIdentical";
      }
      {
        label = "guest core content mode contract";
        needle = "pub enum GuestCoreContentMode";
      }
      {
        label = "host-side-only mode";
        needle = "HostSideOnly";
      }
      {
        label = "guest-injected content negative mode";
        needle = "GuestInjectedContent";
      }
      {
        label = "host-side-only default";
        needle = "guest_core_content: GuestCoreContentMode::HostSideOnly,";
      }
      {
        label = "guest core content setter";
        needle = "pub fn with_guest_core_content(mut self, guest_core_content: GuestCoreContentMode) -> Self";
      }
      {
        label = "host-side-only validation";
        needle = "if self.guest_core_content != GuestCoreContentMode::HostSideOnly";
      }
      {
        label = "disk mode in scenario hash";
        needle = "format!(\"disk_image_mode={}\", self.disk_image_mode),";
      }
      {
        label = "guest write policy in scenario hash";
        needle = "format!(\"guest_write_policy={}\", self.disk_image_mode),";
      }
      {
        label = "byte-identical genesis in scenario hash";
        needle = "format!(\"guest_backing_state={}\", self.guest_backing_state),";
      }
      {
        label = "guest disk non-mutation in scenario hash";
        needle = "\"guest_on_disk_mutation_policy=forbidden-by-launch-profile\".to_owned(),";
      }
      {
        label = "host-side-only core content in scenario hash";
        needle = "format!(\"guest_core_content={}\", self.guest_core_content),";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/lib.rs" qemuLib [
      {
        label = "guest core content public export";
        needle = "GuestCoreContentMode";
      }
      {
        label = "guest backing-state public export";
        needle = "GuestBackingStateMode";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/launch/validation.rs" qemuValidation [
      {
        label = "writable backing rejection error";
        needle = "DiskImageMutatesBacking";
      }
      {
        label = "host-mutable genesis backing rejection error";
        needle = "GuestBackingStateNotByteIdentical";
      }
      {
        label = "guest-injected core content rejection error";
        needle = "GuestCoreContentRequired";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/tests/deterministic_launch.rs" qemuTest [
      {
        label = "guest non-modification regression test";
        needle = "launch_profile_enforces_guest_non_modification";
      }
      {
        label = "writable backing negative assertion";
        needle = "with_disk_image_mode(DiskImageMode::WritableBacking)";
      }
      {
        label = "disk mutation error assertion";
        needle = "LaunchProfileError::DiskImageMutatesBacking";
      }
      {
        label = "host-mutable genesis negative assertion";
        needle = "with_guest_backing_state(GuestBackingStateMode::HostMutableGenesis)";
      }
      {
        label = "host-mutable genesis error assertion";
        needle = "LaunchProfileError::GuestBackingStateNotByteIdentical";
      }
      {
        label = "guest-injected content negative assertion";
        needle = "with_guest_core_content(GuestCoreContentMode::GuestInjectedContent)";
      }
      {
        label = "guest core content error assertion";
        needle = "LaunchProfileError::GuestCoreContentRequired";
      }
      {
        label = "no drive flag assertion";
        needle = "\"-drive\"";
      }
      {
        label = "no writable block device assertion";
        needle = "\"virtio-blk\"";
      }
      {
        label = "byte-identical genesis assertion";
        needle = "guest_backing_state=byte-identical-genesis";
      }
      {
        label = "guest disk mutation policy assertion";
        needle = "guest_on_disk_mutation_policy=forbidden-by-launch-profile";
      }
      {
        label = "host-side-only content assertion";
        needle = "guest_core_content=host-side-only";
      }
    ]
    ++ failuresFor "tests/crucible/phase1-deterministic-launch.nix" deterministicLaunchCheck [
      {
        label = "deterministic launch records guest write policy";
        needle = "guest_write_policy=copy-on-write-overlay";
      }
      {
        label = "deterministic launch records guest core content";
        needle = "guest_core_content=host-side-only";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes guest non-modification check";
        needle = "guestNonModification = import ./phase1-guest-non-modification.nix";
      }
      {
        label = "phase1 replay-oracle lists T-DET-21";
        needle = "\"T-DET-21\"";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/04-determinism-contract.md" determinismContract [
      {
        label = "T-DET-21 checklist complete";
        needle = "- [x] **T-DET-21**";
      }
      {
        label = "DET-15 host-side guest non-modification";
        needle = "content placed inside the guest";
      }
      {
        label = "DET-16 copy-on-write overlays";
        needle = "copy-on-write overlays";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/01-goals-nongoals-invariants.md" invariants [
      {
        label = "INV-5 guest non-modification";
        needle = "[INV-5] Guest non-modification.";
      }
      {
        label = "INV-5 copy-on-write overlays";
        needle = "copy-on-write overlays only";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/10-qemu-integration.md" qemuIntegration [
      {
        label = "QEMU-12 CoW disks";
        needle = "CoW disks.** Every guest disk MUST";
      }
      {
        label = "QEMU-12 byte-identical backing state";
        needle = "byte-identical backing state";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 guest non-modification check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-guest-non-modification";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
        pkgs.rust
        pkgs.sed
      ];

      phases = [
        {
          name = "unpack";
          script = ''
            cp -R "$src" source
            chmod -R u+w source
            cd source
          '';
        }
        {
          name = "configure";
          script = ''
            export CARGO_HOME="$TMPDIR/cargo"
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            mkdir -p "$CARGO_HOME" .cargo
            if [ -f "${cargoDeps}/.cargo/config.toml" ]; then
              sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
                > .cargo/config.toml
            else
              printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "${cargoDeps}"\n\n' \
                > .cargo/config.toml
            fi
          '';
        }
        {
          name = "run-guest-non-modification";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-non-modification-target" \
              -p crucible-qemu \
              --test deterministic_launch \
              launch_profile_enforces_guest_non_modification \
              -- --test-threads=1
          '';
        }
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=${attrPath}
            gate=gate:replay-oracle
            required_gates=gate:any-guest,gate:replay-oracle
            tasks=${builtins.concatStringsSep "," taskIds}
            rust_test=crucible-qemu::deterministic_launch::launch_profile_enforces_guest_non_modification
            scope=launch-contract-gate
            guest_writes=copy-on-write-overlay
            guest_backing_state=byte-identical-genesis
            guest_on_disk_mutation_policy=forbidden-by-launch-profile
            guest_core_content=host-side-only
            core_operation=host-side-only
            real_qemu_any_guest_gate=checks.crucible.phase2.gates.anyGuest
            RESULT
          '';
        }
      ];
    }
