{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuRealization",
  taskIds ? ["T-QEMU-6"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  qemuLib = builtins.readFile ../../crates/crucible-qemu/src/lib.rs;
  realizationLib = builtins.readFile ../../crates/crucible-qemu/src/realization.rs;
  qemuSpec = builtins.readFile ../../docs/rfcs/0010-crucible/10-qemu-integration.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/10-qemu-integration.md" qemuSpec [
      {
        label = "completion note names instantiate coordinator";
        needle = "QEMU VM realization coordinator";
      }
      {
        label = "completion note names start/resume/fork unification";
        needle = "`start`, `resume`, and `fork`";
      }
      {
        label = "completion note preserves replay follow-up";
        needle = "concrete shmem/QEMU quantum";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/lib.rs" qemuLib [
      {
        label = "realization module";
        needle = "mod realization;";
      }
      {
        label = "realization exports";
        needle = "pub use realization::{";
      }
      {
        label = "instantiate export";
        needle = "instantiate_qemu_vm";
      }
      {
        label = "start export";
        needle = "start_qemu_vm";
      }
      {
        label = "resume export";
        needle = "resume_qemu_vm";
      }
      {
        label = "fork export";
        needle = "fork_qemu_vm";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/realization.rs" realizationLib [
      {
        label = "module docs";
        needle = "QEMU VM realization branch coordination";
      }
      {
        label = "store trait";
        needle = "pub trait QemuVmRealizationStore";
      }
      {
        label = "executor trait";
        needle = "pub trait QemuVmRealizationExecutor";
      }
      {
        label = "loadvm admission policy trait";
        needle = "pub trait QemuVmLoadvmAdmissionPolicy";
      }
      {
        label = "bake executor trait";
        needle = "pub trait QemuVmBakeExecutor";
      }
      {
        label = "exact snapshot branch kind";
        needle = "ExactSnapshotLoadvm";
      }
      {
        label = "ancestor replay branch kind";
        needle = "AncestorReplay";
      }
      {
        label = "baked genesis branch kind";
        needle = "BakedGenesisLoad";
      }
      {
        label = "single instantiate API";
        needle = "pub fn instantiate_qemu_vm";
      }
      {
        label = "start wrapper";
        needle = "pub fn start_qemu_vm";
      }
      {
        label = "resume wrapper";
        needle = "pub fn resume_qemu_vm";
      }
      {
        label = "fork wrapper";
        needle = "pub fn fork_qemu_vm";
      }
      {
        label = "bake cold boot API";
        needle = "pub fn bake_qemu_genesis_vm";
      }
      {
        label = "start delegates to instantiate path";
        needle = "QemuVmRealizationOperation::Start";
      }
      {
        label = "resume delegates to instantiate path";
        needle = "QemuVmRealizationOperation::Resume";
      }
      {
        label = "fork computes prefix";
        needle = ".prefix(prefix_len)";
      }
      {
        label = "loadvm policy gate";
        needle = "policy.authorize_loadvm_runtime()";
      }
      {
        label = "loadvm QMP authorization token";
        needle = "QemuLoadvmCommandAuthorization";
      }
      {
        label = "loadvm replay oracle admission";
        needle = "accept_loadvm_realized_runtime";
      }
      {
        label = "loadvm policy rejection is fatal";
        needle = "QemuVmRealizationError::SavevmPolicy";
      }
      {
        label = "runtime admission content check";
        needle = "validate_runtime_matches_admission";
      }
      {
        label = "checkpoint/config identity validation";
        needle = "validate_checkpoint_matches_config";
      }
      {
        label = "baked genesis world validation";
        needle = "validate_baked_genesis_snapshot";
      }
      {
        label = "fork out-of-range guard";
        needle = "ForkPrefixOutOfRange";
      }
      {
        label = "nearest ancestor replay";
        needle = "store.nearest_cached_ancestor(&config)?";
      }
      {
        label = "baked genesis load";
        needle = "store.baked_genesis(world, &config.def)?";
      }
      {
        label = "per-decision replay";
        needle = "executor.replay_one_quantum";
      }
      {
        label = "only bake exposes cold boot";
        needle = "cold_boot_to_ready_and_savevm(world)";
      }
      {
        label = "shared instantiate test";
        needle = "qemu_start_resume_and_fork_share_instantiate_path";
      }
      {
        label = "ancestor replay test";
        needle = "qemu_instantiate_replays_from_nearest_cached_ancestor";
      }
      {
        label = "baked genesis no cold boot test";
        needle = "qemu_instantiate_loads_baked_genesis_for_genesis_without_cold_boot";
      }
      {
        label = "default exact snapshot test";
        needle = "qemu_exact_snapshot_loadvm_is_the_default_complete_realization_path";
      }
      {
        label = "loadvm admitted branch test";
        needle = "qemu_exact_snapshot_loadvm_requires_replay_oracle_admission";
      }
      {
        label = "wrong config exact snapshot test";
        needle = "qemu_exact_snapshot_rejects_wrong_configuration_checkpoint";
      }
      {
        label = "runtime mismatch test";
        needle = "qemu_loadvm_runtime_must_match_replay_oracle_admission";
      }
      {
        label = "missing oracle validation test";
        needle = "qemu_exact_snapshot_rejects_unvalidated_loadvm_runtime";
      }
      {
        label = "replay oracle mismatch test";
        needle = "qemu_exact_snapshot_rejects_mismatched_replay_oracle";
      }
      {
        label = "ancestor checkpoint mismatch test";
        needle = "qemu_instantiate_rejects_cached_ancestor_checkpoint_mismatch";
      }
      {
        label = "stale baked genesis world test";
        needle = "qemu_instantiate_rejects_stale_baked_genesis_world";
      }
      {
        label = "thin baked genesis checkpoint test";
        needle = "qemu_instantiate_rejects_thin_baked_genesis_checkpoint";
      }
      {
        label = "same world baked genesis sharing test";
        needle = "qemu_baked_genesis_snapshot_is_shared_across_same_world_scenarios";
      }
      {
        label = "fork prefix bounds test";
        needle = "qemu_fork_accepts_tip_and_rejects_out_of_range_prefixes";
      }
      {
        label = "bake cold boot test";
        needle = "qemu_bake_is_the_only_cold_boot_entry_point";
      }
      {
        label = "invalid ancestor test";
        needle = "qemu_instantiate_rejects_non_prefix_cached_ancestor";
      }
    ]
    ++ forbiddenFor "crates/crucible-qemu/src/realization.rs" realizationLib [
      {
        label = "production unwrap";
        needle = ".unwrap()";
      }
      {
        label = "production expect";
        needle = ".expect(";
      }
      {
        label = "hard-coded host shell";
        needle = "/bin/sh";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes qemu realization check";
        needle = "qemuRealization = import ./phase2-qemu-realization.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 qemu realization check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-realization";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
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
          name = "run-qemu-realization";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-qemu-realization-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu \
              --lib \
              realization::tests \
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
            tasks=${taskList}
            check_scope=task-level
            related_gates=gate:replay-oracle,gate:content-address
            rust_test=crucible-qemu::realization::tests
            instantiate_branches=exact-snapshot-loadvm,ancestor-replay,baked-genesis-load
            loadvm_runtime_policy=enabled-with-replay-oracle-admission
            cold_boot_entrypoint=bake-only
            lifecycle_ops=start-resume-fork-share-instantiate
            RESULT
          '';
        }
      ];
    }
