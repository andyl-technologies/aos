{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuNodeFactory",
  taskIds ? ["T-QEMU-3" "T-QEMU-6" "T-QEMU-7" "T-QEMU-12"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  qemuLib = builtins.readFile ../../crates/crucible-qemu/src/lib.rs;
  nodeFactory = builtins.readFile ../../crates/crucible-qemu/src/node_factory.rs;
  nodeFactoryTests = builtins.readFile ../../crates/crucible-qemu/src/node_factory/tests.rs;
  savevmPolicy = builtins.readFile ../../crates/crucible-qemu/src/savevm_policy.rs;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  hasInfix = needle: haystack: let
    needleLen = builtins.stringLength needle;
    haystackLen = builtins.stringLength haystack;
    maxStart = haystackLen - needleLen;
    indexes =
      if needleLen == 0
      then [0]
      else if maxStart < 0
      then []
      else builtins.genList (index: index) (maxStart + 1);
  in
    builtins.any (index:
      builtins.substring index needleLen haystack == needle)
    indexes;

  failuresFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (!(hasInfix requirement.needle content)) [
          "${fileLabel}: missing ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  forbiddenFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (hasInfix requirement.needle content) [
          "${fileLabel}: forbidden ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  failures =
    failuresFor "crates/crucible-qemu/src/lib.rs" qemuLib [
      {
        label = "node factory module map";
        needle = "`node_factory` owns";
      }
      {
        label = "linux node factory module";
        needle = "mod node_factory;";
      }
      {
        label = "node factory exports";
        needle = "pub use node_factory::{";
      }
      {
        label = "completed setup factory export";
        needle = "build_qemu_node_from_completed_setup";
      }
      {
        label = "restored checkpoint factory export";
        needle = "build_qemu_node_from_restored_checkpoint";
      }
      {
        label = "restore admission export";
        needle = "QemuNodeRestoreAdmission";
      }
      {
        label = "baked genesis restore admission export";
        needle = "QemuBakedGenesisRestoreAdmission";
      }
      {
        label = "shutdown-only QMP adapter export";
        needle = "QemuQmpShutdownOnlyControlChannel";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/node_factory.rs" nodeFactory [
      {
        label = "linux factory module docs";
        needle = "Linux factory for already-spawned QEMU nodes";
      }
      {
        label = "shutdown-only QMP adapter";
        needle = "pub struct QemuQmpShutdownOnlyControlChannel";
      }
      {
        label = "generic save checkpoint rejection";
        needle = "generic QEMU node checkpointing requires explicit VMState policy authorization";
      }
      {
        label = "generic restore checkpoint rejection";
        needle = "generic QEMU node restore requires explicit VMState policy authorization";
      }
      {
        label = "QMP quit delegation";
        needle = "self.vmstate.quit().map(|_complete| ())";
      }
      {
        label = "prepared setup token";
        needle = "struct PreparedQemuNodeSetup";
      }
      {
        label = "completed setup factory";
        needle = "pub fn build_qemu_node_from_completed_setup";
      }
      {
        label = "warm restore factory";
        needle = "pub fn build_qemu_node_from_restored_checkpoint";
      }
      {
        label = "restore admission enum";
        needle = "pub enum QemuNodeRestoreAdmission";
      }
      {
        label = "baked genesis restore admission";
        needle = "QemuNodeRestoreAdmission::BakedGenesis {\n                world_id: admission.world_id(),\n            }";
      }
      {
        label = "exact replay-oracle restore admission";
        needle = "QemuNodeRestoreAdmission::ReplayOracle(admission)";
      }
      {
        label = "baked genesis plan uses validated admission";
        needle = "pub fn baked_genesis(admission: QemuBakedGenesisRestoreAdmission";
      }
      {
        label = "baked genesis plan uses admitted checkpoint";
        needle = "checkpoint: admission.checkpoint()";
      }
      {
        label = "exact runtime admission proof consumed";
        needle = "let _admitted_runtime_hash = admission.runtime_hash();";
      }
      {
        label = "runtime authorization check before restore";
        needle = "validate_runtime_restore_authorization(authorization, admission)?;\n    let prepared_setup = prepare_qemu_node_setup";
      }
      {
        label = "local setup prepared before restore";
        needle = "let prepared_setup = prepare_qemu_node_setup(setup, shmem_config, send_authorizer)?;\n    qmp.restore_checkpoint_vmstate";
      }
      {
        label = "authorized VMState restore";
        needle = "qmp.restore_checkpoint_vmstate(checkpoint, authorization)";
      }
      {
        label = "runtime purpose enforcement";
        needle = "QemuLoadvmCommandPurpose::RuntimeRealization";
      }
      {
        label = "baked genesis purpose enforcement";
        needle = "QemuLoadvmCommandPurpose::BakedGenesisRealization";
      }
      {
        label = "baked genesis world proof consumed";
        needle = "let _admitted_world_id = world_id;";
      }
      {
        label = "setup slot validation";
        needle = "validate_setup_slot_matches_config";
      }
      {
        label = "mapped hot-path binding";
        needle = "QemuMappedQuantumShmemHotPath::new";
      }
      {
        label = "node channels assembled from prepared setup";
        needle = "QemuNodeChannels::new";
      }
      {
        label = "external test module";
        needle = "mod tests;";
      }
    ]
    ++ forbiddenFor "crates/crucible-qemu/src/node_factory.rs" nodeFactory [
      {
        label = "public QMP unwrap escape hatch";
        needle = "pub fn into_inner";
      }
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
    ++ failuresFor "crates/crucible-qemu/src/node_factory/tests.rs" nodeFactoryTests [
      {
        label = "shutdown-only rejection test";
        needle = "qmp_shutdown_only_rejects_generic_snapshot_restore_but_quits";
      }
      {
        label = "completed setup assembly test";
        needle = "factory_assembles_node_from_completed_setup_with_shutdown_only_qmp";
      }
      {
        label = "warm restore assembly test";
        needle = "factory_restores_vmstate_before_reducing_qmp_to_shutdown_only";
      }
      {
        label = "probe authorization rejection test";
        needle = "factory_rejects_probe_authorization_before_vmstate_restore";
      }
      {
        label = "baked genesis restore test";
        needle = "factory_restores_baked_genesis_without_oracle_admission";
      }
      {
        label = "baked restore test uses validated admission";
        needle = "QemuBakedGenesisRestoreAdmission::new";
      }
      {
        label = "baked restore test uses baked node blob";
        needle = "NodeBlobRef::baked";
      }
      {
        label = "baked auth exact restore rejection test";
        needle = "factory_rejects_baked_authorization_for_replay_oracle_restore";
      }
      {
        label = "slot mismatch before restore test";
        needle = "factory_rejects_restore_slot_mismatch_before_vmstate_restore";
      }
      {
        label = "setup slot mismatch test";
        needle = "factory_rejects_setup_slot_mismatch_before_binding_hot_path";
      }
      {
        label = "restore fails closed after assembly";
        needle = "Backend::restore(&mut node, &checkpoint)";
      }
      {
        label = "QMP load command order assertion";
        needle = "Some(QMP_SNAPSHOT_LOAD_COMMAND)";
      }
      {
        label = "capabilities-only rejection assertion";
        needle = "assert_qmp_wrote_only_capabilities";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/savevm_policy.rs" savevmPolicy [
      {
        label = "private admission field block";
        needle = "pub struct QemuLoadvmRealizationAdmission {\n    /// Shared runtime fingerprint proven by fat/thin replay-oracle equality.\n    runtime_hash: ContentHash,\n}";
      }
      {
        label = "public admission accessor";
        needle = "pub const fn runtime_hash(self) -> ContentHash";
      }
      {
        label = "cfg-test-only admission constructor";
        needle = "    #[cfg(test)]\n    pub(crate) const fn for_test";
      }
      {
        label = "baked genesis load authorization";
        needle = "pub const fn authorize_baked_genesis_runtime";
      }
      {
        label = "baked genesis load purpose";
        needle = "QemuLoadvmCommandPurpose::BakedGenesisRealization";
      }
    ]
    ++ forbiddenFor "crates/crucible-qemu/src/savevm_policy.rs" savevmPolicy [
      {
        label = "public admission field";
        needle = "pub runtime_hash: ContentHash";
      }
      {
        label = "public admission test constructor";
        needle = "pub const fn for_test";
      }
      {
        label = "public standalone admission validator";
        needle = "pub fn validate_loadvm_realized_runtime";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes qemu node factory check";
        needle = "qemuNodeFactory = import ./phase2-qemu-node-factory.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 qemu node factory check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-node-factory";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.rust
        pkgs.sed
      ];

      cargoDeps = cargoDeps;

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
          name = "run-qemu-node-factory";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-qemu-node-factory-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu \
              --lib \
              node_factory \
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
            check_scope=linux-post-setup-node-composition
            rust_test=crucible-qemu::node_factory
            completed_setup_factory=maps-setup-region-and-binds-shmem-hotpath
            warm_restore_factory=prepares-setup-before-authorized-loadvm
            qmp_after_assembly=shutdown-only
            generic_snapshot_restore=fail-closed
            admission_boundary=opaque-replay-oracle-proof-or-baked-genesis
            RESULT
          '';
        }
      ];

      meta = {
        description = "Crucible Phase 2 QEMU node factory composition gate";
      };
    }
