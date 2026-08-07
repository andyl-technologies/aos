{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuExactSnapshotRestore",
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
  savevmTest = builtins.readFile ../../crates/crucible-qemu/tests/savevm_completeness.rs;
  defaultChecks = builtins.readFile ./default.nix;
  taskList = builtins.concatStringsSep "," taskIds;
  inherit (import ./_lib.nix {inherit lib;}) failuresFor forbiddenFor;
  failures =
    failuresFor "crates/crucible-qemu/src/lib.rs" qemuLib [
      {label = "savevm policy module"; needle = "mod savevm_policy;";}
      {label = "completeness gate export"; needle = "QEMU_SAVEVM_COMPLETENESS_CHECK";}
      {label = "admission proof export"; needle = "QemuLoadvmRealizationAdmission";}
    ]
    ++ failuresFor "crates/crucible-qemu/src/realization.rs" qemuRealization [
      {label = "replay oracle probe entry point"; needle = "pub fn check_qemu_replay_oracle";}
      {label = "exact snapshot load path"; needle = "load_exact_snapshot(";}
      {label = "runtime authorization"; needle = "policy.authorize_loadvm_runtime()";}
      {label = "oracle admission"; needle = "accept_loadvm_realized_runtime";}
    ]
    ++ failuresFor "crates/crucible-qemu/src/savevm_policy.rs" savevmPolicy [
      {label = "exact restore gate"; needle = "checks.crucible.phase2.qemuExactSnapshotRestore";}
      {label = "complete policy constructor"; needle = "pub const fn complete";}
      {label = "runtime command authorization"; needle = "pub const fn authorize_loadvm_runtime";}
      {label = "oracle required error"; needle = "ReplayOracleValidationRequired";}
      {label = "oracle mismatch error"; needle = "ReplayOracleMismatch";}
    ]
    ++ forbiddenFor "crates/crucible-qemu/src/savevm_policy.rs" savevmPolicy [
      {label = "legacy fallback API"; needle = "Fallback";}
      {label = "disabled loadvm branch"; needle = "LoadvmBranchDisabled";}
      {label = "phase-zero policy"; needle = "phase0";}
    ]
    ++ failuresFor "crates/crucible-qemu/tests/savevm_completeness.rs" savevmTest [
      {label = "probe and runtime authorization test"; needle = "complete_policy_authorizes_probe_and_runtime_loadvm";}
      {label = "oracle evidence test"; needle = "complete_policy_requires_matching_replay_oracle_evidence";}
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {label = "phase2 exposes exact snapshot check"; needle = "qemuExactSnapshotRestore = import ./phase2-qemu-exact-snapshot-restore.nix";}
    ];
in
  if failures != []
  then throw "crucible phase2 QEMU exact snapshot restore check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-exact-snapshot-restore";
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
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then cd source; fi
            mkdir -p "$CARGO_HOME" .cargo
            sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" > .cargo/config.toml
          '';
        }
        {
          name = "run-qemu-exact-snapshot-policy";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then cd source; fi
            cargo test --frozen --offline \
              --target-dir "$TMPDIR/crucible-qemu-exact-snapshot-target" \
              --manifest-path crates/Cargo.toml -p crucible-qemu \
              --test savevm_completeness -- --test-threads=1
            cargo test --frozen --offline \
              --target-dir "$TMPDIR/crucible-qemu-exact-snapshot-target" \
              --manifest-path crates/Cargo.toml -p crucible-qemu \
              savevm_policy -- --test-threads=1
          '';
        }
        {
          name = "write-result";
          script = ''
            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=${attrPath}
            tasks=${taskList}
            runtime_loadvm_command_authorization=enabled
            loadvm_requires_replay_oracle_validation=true
            legacy_fallback_paths=absent
            RESULT
          '';
        }
      ];
    }
