{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.executionStartResumeFork",
  taskIds ? ["T-EXEC-7" "T-PAT-9"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  qemuLib = builtins.readFile ../../crates/crucible-qemu/src/lib.rs;
  realization = builtins.readFile ../../crates/crucible-qemu/src/realization.rs;
  defaultChecks = builtins.readFile ./default.nix;
  rfc = builtins.readFile ../../docs/rfcs/0010-crucible/05-execution-model.md;
  patternsAndSketches = builtins.readFile ../../docs/rfcs/0010-crucible/29-patterns-and-sketches.md;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/05-execution-model.md" rfc [
      {
        label = "T-EXEC-7 completion note";
        needle = "Completed by `crates/crucible-qemu/src/realization.rs`";
      }
      {
        label = "completion note names start/resume/fork";
        needle = "`start_qemu_vm`,";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/lib.rs" qemuLib [
      {
        label = "realization module";
        needle = "mod realization;";
      }
      {
        label = "lifecycle export bake";
        needle = "bake_qemu_genesis_vm,";
      }
      {
        label = "lifecycle export replay oracle";
        needle = "check_qemu_replay_oracle,";
      }
      {
        label = "lifecycle export fork";
        needle = "fork_qemu_vm,";
      }
      {
        label = "lifecycle export instantiate";
        needle = "instantiate_qemu_vm,";
      }
      {
        label = "lifecycle export resume";
        needle = "resume_qemu_vm,";
      }
      {
        label = "lifecycle export start";
        needle = "start_qemu_vm,";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/realization.rs" realization [
      {
        label = "module docs name lifecycle unification";
        needle = "`resume`, and `fork` are all calls to one `instantiate` path";
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
        label = "single instantiate API";
        needle = "pub fn instantiate_qemu_vm";
      }
      {
        label = "shared wrapper helper";
        needle = "fn instantiate_qemu_vm_for_operation";
      }
      {
        label = "start delegates to shared instantiate helper";
        needle = "QemuVmRealizationOperation::Start";
      }
      {
        label = "resume delegates to shared instantiate helper";
        needle = "QemuVmRealizationOperation::Resume";
      }
      {
        label = "fork delegates to shared instantiate helper";
        needle = "QemuVmRealizationOperation::Fork { prefix_len }";
      }
      {
        label = "fork prefix construction";
        needle = ".prefix(prefix_len)";
      }
      {
        label = "direct instantiate equivalence test";
        needle = "qemu_lifecycle_wrappers_match_direct_instantiate";
      }
      {
        label = "shared instantiate path test";
        needle = "qemu_start_resume_and_fork_share_instantiate_path";
      }
      {
        label = "fork prefix bound test";
        needle = "qemu_fork_accepts_tip_and_rejects_out_of_range_prefixes";
      }
      {
        label = "bake-only cold boot API";
        needle = "pub fn bake_qemu_genesis_vm";
      }
      {
        label = "bake executor is the only cold boot path";
        needle = "cold_boot_to_ready_and_savevm(world)";
      }
      {
        label = "hot lifecycle avoids cold boot test";
        needle = "RealizationCall::ColdBootBake(_)";
      }
    ]
    ++ forbiddenFor "crates/crucible-qemu/src/realization.rs" realization [
      {
        label = "separate boot lifecycle API";
        needle = "pub fn boot_qemu_vm";
      }
      {
        label = "separate start realization helper";
        needle = "fn start_qemu_vm_inner";
      }
      {
        label = "separate resume realization helper";
        needle = "fn resume_qemu_vm_inner";
      }
      {
        label = "separate fork realization helper";
        needle = "fn fork_qemu_vm_inner";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes start/resume/fork execution check";
        needle = "executionStartResumeFork = import ./phase1-execution-start-resume-fork.nix";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/29-patterns-and-sketches.md" patternsAndSketches [
      {
        label = "T-PAT-9 completion names shared QEMU instantiate";
        needle = "`crucible_qemu::instantiate_qemu_vm`";
      }
      {
        label = "T-PAT-9 completion names lifecycle wrappers";
        needle = "`crucible_qemu::start_qemu_vm`, `crucible_qemu::resume_qemu_vm`,";
      }
      {
        label = "T-PAT-9 completion names execution start/resume/fork gate";
        needle = "`checks.crucible.phase1.executionStartResumeFork`";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 execution start/resume/fork check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-execution-start-resume-fork";
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
          name = "run-execution-start-resume-fork";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-execution-start-resume-fork-target" \
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
            tasks=${builtins.concatStringsSep "," taskIds}
            lifecycle_ops=start,resume,fork
            shared_entrypoint=instantiate_qemu_vm
            pattern_PAT_11=start-resume-fork-share-instantiate
            hot_lifecycle_cold_boot=false
            RESULT
          '';
        }
      ];
    }
