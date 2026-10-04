{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuNodeFactory",
  taskIds ? ["T-QEMU-3" "T-QEMU-6" "T-QEMU-7" "T-QEMU-12"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  nodeFactory = builtins.readFile ../../crates/crucible-qemu/src/node_factory.rs;
  restorePlan = builtins.readFile ../../crates/crucible-qemu/src/node_factory/restore_plan.rs;
  realization = builtins.readFile ../../crates/crucible-qemu/src/realization.rs;
  bakedReplay = builtins.readFile ../../crates/crucible-daemon/src/qemu_baked_genesis.rs;

  inherit (import ./_lib.nix {inherit lib;}) failuresFor forbiddenFor;

  currentSources = nodeFactory + restorePlan + realization + bakedReplay;
  failures =
    failuresFor "crates/crucible-qemu/src/node_factory/restore_plan.rs" restorePlan [
      {
        label = "complete exact restore plan";
        needle = "pub(crate) struct QemuNodeRestorePlan<'a>";
      }
      {
        label = "required host-I/O continuation";
        needle = "pub(super) host_io_checkpoint: &'a QemuHostIoCheckpoint,";
      }
      {
        label = "required node continuation";
        needle = "pub(super) node_continuation: &'a QemuNodeContinuationCheckpoint,";
      }
      {
        label = "operation-specific exact constructor";
        needle = "pub(crate) fn exact_checkpoint(";
      }
      {
        label = "snapshot owns continuation inputs";
        needle = "host_io_checkpoint: snapshot.host_io(),";
      }
      {
        label = "immutable descriptor validation";
        needle = "pub(crate) fn validate_immutable_descriptors(&self)";
      }
      {
        label = "unsealed descriptor rejection";
        needle = "fn descriptor_validation_rejects_unsealed_device_state()";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/node_factory.rs" nodeFactory [
      {
        label = "restored checkpoint factory";
        needle = "pub(crate) fn build_qemu_node_from_restored_checkpoint<";
      }
      {
        label = "factory validates immutable descriptors";
        needle = "restore.validate_immutable_descriptors()";
      }
      {
        label = "factory performs exact QMP restore";
        needle = ".restore_exact_checkpoint(exact_checkpoint.request)";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/realization.rs" realization [
      {
        label = "crate-private baked admission";
        needle = "pub(crate) struct QemuBakedGenesisRestoreAdmission<'a>";
      }
      {
        label = "baked admission validates snapshot and World";
        needle = "validate_baked_genesis_snapshot(snapshot, world)?;";
      }
    ]
    ++ failuresFor "crates/crucible-daemon/src/qemu_baked_genesis.rs" bakedReplay [
      {
        label = "operation-specific baked replay catalog";
        needle = "pub struct ProductionBakedGenesisReplayCatalogFactory<R>";
      }
      {
        label = "typed replay admission consumption";
        needle = ".into_replay_admission(";
      }
    ]
    ++ forbiddenFor "current node factory and baked replay sources" (nodeFactory + restorePlan + bakedReplay) [
      {
        label = "deleted generic exact basis attachment";
        needle = "with_exact_checkpoint";
      }
      {
        label = "deleted restore admission enum";
        needle = "QemuNodeRestoreAdmission";
      }
      {
        label = "discarded baked World identity";
        needle = "let _world_id";
      }
      {
        label = "optional host-I/O continuation";
        needle = "host_io_checkpoint: Option<";
      }
      {
        label = "optional node continuation";
        needle = "node_continuation: Option<";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 QEMU node factory check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-node-factory";
      version = "0";
      src = crucibleSrc;
      buildDeps = [pkgs.rust pkgs.sed];

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
            mkdir -p "$CARGO_HOME" .cargo
            sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" > .cargo/config.toml
          '';
        }
        {
          name = "run-node-factory-tests";
          script = ''
            cargo test --frozen --offline \
              --target-dir "$TMPDIR/qemu-node-factory-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu --lib node_factory -- --test-threads=1
          '';
        }
        {
          name = "write-result";
          script = ''
            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=${attrPath}
            tasks=${builtins.concatStringsSep "," taskIds}
            exact_plan=required-host-io-and-node-continuations
            exact_constructor=QemuNodeRestorePlan::exact_checkpoint
            descriptor_policy=immutable-sealed-inputs
            baked_replay=typed-operation-specific-admission
            generic_restore_admission=absent
            RESULT
          '';
        }
      ];

      meta.description = "Crucible Phase 2 exact QEMU node factory gate";
    }
