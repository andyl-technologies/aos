{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuSavevmFallback",
  taskIds ? ["T-QEMU-5"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  qemuLib = builtins.readFile ../../crates/crucible-qemu/src/lib.rs;
  qemuRealization = builtins.readFile ../../crates/crucible-qemu/src/realization.rs;
  savevmPolicy = builtins.readFile ../../crates/crucible-qemu/src/savevm_policy.rs;
  savevmTest = builtins.readFile ../../crates/crucible-qemu/tests/savevm_fallback.rs;
  qemuSpec = builtins.readFile ../../docs/rfcs/0010-crucible/10-qemu-integration.md;
  riskDoc = builtins.readFile ../../docs/rfcs/0010-crucible/30-risks-spikes.md;
  decisionDoc = builtins.readFile ../../docs/rfcs/0010-crucible/31-decision-register.md;
  phase0S3 = builtins.readFile ./phase0-s3.nix;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;



  failures =
    failuresFor "docs/rfcs/0010-crucible/10-qemu-integration.md" qemuSpec [
      {
        label = "T-QEMU-5 checklist complete";
        needle = "- [x] **T-QEMU-5**";
      }
      {
        label = "QEMU-21 fallback requirement";
        needle = "thin-checkpoint (replay) fallback";
      }
      {
        label = "QEMU-22 oracle validation requirement";
        needle = "When `loadvm` is used as the realization branch, the host MUST";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/30-risks-spikes.md" riskDoc [
      {
        label = "fallback risk resolved";
        needle = "**RISK-8 / RISK-9** are resolved by `T-RISK-4` with the thin/replay fallback";
      }
      {
        label = "full fat incompleteness retained";
        needle = "`full_fat_checkpoint_complete=false`";
      }
      {
        label = "loadvm branch disabled";
        needle = "`loadvm_branch_enabled=false`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/31-decision-register.md" decisionDoc [
      {
        label = "pass with fallback status";
        needle = "**Status:** PASS WITH FALLBACK";
      }
      {
        label = "thin checkpoint default";
        needle = "`thin_checkpoint_default=true`";
      }
      {
        label = "fat snapshot default disabled";
        needle = "`fat_snapshot_default=false`";
      }
      {
        label = "loadvm disabled until later full S3";
        needle = "fat-snapshot `loadvm` branch remains disabled until a later S3 rerun";
      }
    ]
    ++ failuresFor "tests/crucible/phase0-s3.nix" phase0S3 [
      {
        label = "thin default result";
        needle = "echo thin_checkpoint_default=true";
      }
      {
        label = "fat default disabled result";
        needle = "echo fat_snapshot_default=false";
      }
      {
        label = "loadvm disabled result";
        needle = "echo loadvm_branch_enabled=false";
      }
      {
        label = "fallback marker result";
        needle = "echo fallback_adopted=thin_replay_until_full_s3";
      }
      {
        label = "full fat incompleteness result";
        needle = "echo full_fat_checkpoint_complete=false";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/lib.rs" qemuLib [
      {
        label = "savevm policy module";
        needle = "mod savevm_policy;";
      }
      {
        label = "policy export";
        needle = "QemuSavevmCompletenessPolicy";
      }
      {
        label = "admission proof export";
        needle = "QemuLoadvmRealizationAdmission";
      }
      {
        label = "loadvm command authorization export";
        needle = "QemuLoadvmCommandAuthorization";
      }
    ]
    ++ forbiddenFor "crates/crucible-qemu/src/lib.rs" qemuLib [
      {
        label = "standalone validation export";
        needle = "validate_loadvm_realized_runtime";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/realization.rs" qemuRealization [
      {
        label = "replay oracle probe entry point";
        needle = "pub fn check_qemu_replay_oracle";
      }
      {
        label = "fat probe load path";
        needle = "load_exact_snapshot_for_replay_oracle_probe";
      }
      {
        label = "probe-only loadvm authorization";
        needle = "policy.authorize_loadvm_probe(),";
      }
      {
        label = "thin replay comparison path";
        needle = "realize_qemu_replay_oracle_thin_path";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/savevm_policy.rs" savevmPolicy [
      {
        label = "phase0 check constant";
        needle = "QEMU_SAVEVM_PHASE0_S3_CHECK";
      }
      {
        label = "fallback marker constant";
        needle = "QEMU_SAVEVM_FALLBACK_MARKER";
      }
      {
        label = "policy struct";
        needle = "pub struct QemuSavevmCompletenessPolicy";
      }
      {
        label = "phase0 fallback constructor";
        needle = "pub const fn phase0_fallback";
      }
      {
        label = "pass with fallback status";
        needle = "PassWithFallback";
      }
      {
        label = "thin replay default branch";
        needle = "QemuVmRealizationBranch::ThinReplay";
      }
      {
        label = "disabled loadvm branch field";
        needle = "loadvm_branch_enabled: false";
      }
      {
        label = "fat completeness disabled field";
        needle = "full_fat_checkpoint_complete: false";
      }
      {
        label = "oracle validation required field";
        needle = "oracle_validation_required_for_loadvm: true";
      }
      {
        label = "disabled branch error";
        needle = "LoadvmBranchDisabled";
      }
      {
        label = "oracle validation required error";
        needle = "ReplayOracleValidationRequired";
      }
      {
        label = "oracle mismatch error";
        needle = "ReplayOracleMismatch";
      }
      {
        label = "crate-private validation guard";
        needle = "pub(crate) fn validate_loadvm_realized_runtime";
      }
      {
        label = "policy admission guard";
        needle = "pub fn accept_loadvm_realized_runtime";
      }
      {
        label = "probe command authorization";
        needle = "pub const fn authorize_loadvm_probe";
      }
      {
        label = "runtime command authorization";
        needle = "pub fn authorize_loadvm_runtime";
      }
      {
        label = "loadvm authorization token";
        needle = "pub struct QemuLoadvmCommandAuthorization";
      }
      {
        label = "snapshot probe purpose";
        needle = "SnapshotCompletenessProbe";
      }
      {
        label = "runtime realization purpose";
        needle = "RuntimeRealization";
      }
      {
        label = "oracle required unit test";
        needle = "loadvm_runtime_requires_replay_oracle_validation";
      }
      {
        label = "oracle mismatch unit test";
        needle = "loadvm_runtime_rejects_replay_oracle_mismatch";
      }
      {
        label = "oracle match unit test";
        needle = "loadvm_runtime_accepts_matching_replay_oracle_evidence";
      }
    ]
    ++ forbiddenFor "crates/crucible-qemu/src/savevm_policy.rs" savevmPolicy [
      {
        label = "enabled default loadvm branch";
        needle = "loadvm_branch_enabled: true";
      }
      {
        label = "enabled full fat default";
        needle = "full_fat_checkpoint_complete: true";
      }
      {
        label = "fat snapshot default";
        needle = "fat_snapshot_default: true";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/tests/savevm_fallback.rs" savevmTest [
      {
        label = "phase0 fallback test";
        needle = "phase0_s3_policy_defaults_to_thin_replay_fallback";
      }
      {
        label = "loadvm disabled test";
        needle = "default_policy_rejects_loadvm_even_with_matching_oracle_evidence";
      }
      {
        label = "probe-only loadvm authorization test";
        needle = "phase0_policy_authorizes_only_probe_loadvm_commands";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes savevm fallback check";
        needle = "qemuSavevmFallback = import ./phase2-qemu-savevm-fallback.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 qemu savevm fallback check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-savevm-fallback";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.grep
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
          name = "run-qemu-savevm-fallback";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-qemu-savevm-fallback-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu \
              --test savevm_fallback \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-qemu-savevm-fallback-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu \
              savevm_policy \
              -- --test-threads=1
            if grep -R -n '\.loadvm[[:space:]]*(' crates/*/src \
              | grep -v '^crates/crucible-qemu/src/qmp.rs:' \
              | grep -v '^crates/crucible-qemu/src/qmp/vmstate_control.rs:' \
              | grep -v '^crates/crucible-qemu/src/savevm_policy.rs:' \
              > "$TMPDIR/production-loadvm-calls.txt"; then
              cat "$TMPDIR/production-loadvm-calls.txt" >&2
              echo "unexpected production loadvm call while fallback policy disables the branch" >&2
              exit 1
            fi
            if grep -R -n -E 'QmpClient::loadvm[[:space:]]*\(|QMP_SNAPSHOT_LOAD_COMMAND|snapshot-load' \
              crates/*/src \
              | grep -v '^crates/crucible-qemu/src/node_factory/tests.rs:' \
              | grep -v '^crates/crucible-qemu/src/qmp.rs:' \
              | grep -v '^crates/crucible-qemu/src/lib.rs:' \
              | grep -vE '^crates/crucible-api/src/vm_resume.rs:[0-9]+:.*"exact-snapshot-loadvm"' \
              > "$TMPDIR/production-loadvm-calls.txt"; then
              cat "$TMPDIR/production-loadvm-calls.txt" >&2
              echo "unexpected production loadvm bypass while fallback policy disables the branch" >&2
              exit 1
            fi
            if grep -R -n 'authorize_loadvm_probe' crates/*/src crates/*/tests \
              | grep -v '^crates/crucible-qemu/src/node_factory/tests.rs:' \
              | grep -v '^crates/crucible-qemu/src/savevm_policy.rs:' \
              | grep -v '^crates/crucible-qemu/src/realization.rs:' \
              | grep -v '^crates/crucible-qemu/tests/qmp.rs:' \
              | grep -v '^crates/crucible-qemu/tests/qmp_vmstate_control.rs:' \
              | grep -v '^crates/crucible-qemu/tests/savevm_fallback.rs:' \
              > "$TMPDIR/loadvm-probe-authorization-uses.txt"; then
              cat "$TMPDIR/loadvm-probe-authorization-uses.txt" >&2
              echo "unexpected loadvm probe authorization outside the QMP probe tests" >&2
              exit 1
            fi
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
            check_scope=task-level-pass-with-fallback
            related_gates=gate:replay-oracle
            upstream_spike=checks.crucible.phase0.s3SavevmLoadvm
            rust_test=crucible-qemu::savevm_fallback,crucible-qemu::savevm_policy
            s3_status=pass-with-fallback
            thin_checkpoint_default=true
            fat_snapshot_default=false
            loadvm_branch_enabled=false
            full_fat_checkpoint_complete=false
            fallback_adopted=thin_replay_until_full_s3
            runtime_loadvm_acceptance=none
            runtime_loadvm_command_authorization=disabled
            probe_loadvm_command_authorization=snapshot-completeness-only
            production_loadvm_runtime_calls=none
            production_loadvm_probe_authorization_uses=replay-oracle-only
            loadvm_requires_replay_oracle_validation=true
            RESULT
          '';
        }
      ];
    }
