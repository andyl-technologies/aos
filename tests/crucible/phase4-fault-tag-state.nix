{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.faultTagState",
  taskIds ? ["T-FAULT-12"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoVendor {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-fWBTuyTXJ+/0BiVbB5WAtCqVwufg04NH4BJdocT+moU=";
  };

  model = import ./_crucible-model-source.nix {inherit lib;};
  canonical = builtins.readFile ../../crates/crucible/src/model/canonical.rs;
  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  tagTest = builtins.readFile ../../crates/crucible/tests/fault_tag_state.rs;
  faultDoc = builtins.readFile ../../docs/rfcs/0010-crucible/17-fault-injection.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/17-fault-injection.md" faultDoc [
      {
        label = "T-FAULT-12 completion note";
        needle = "Completed by `checks.crucible.phase4.faultTagState`";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "materialized active fault tags";
        needle = "pub active_fault_tags: BTreeMap<FaultTag, MembershipFault>";
      }
      {
        label = "empty active fault tag set";
        needle = "active_fault_tags: BTreeMap::new()";
      }
      {
        label = "symmetry material includes active fault tags";
        needle = "scheduler.active_fault_tags={}";
      }
    ]
    ++ failuresFor "crates/crucible/src/model/canonical.rs" canonical [
      {
        label = "active fault tag hash length";
        needle = "state.active_fault_tags.len()";
      }
      {
        label = "active fault tag hash material";
        needle = "super::membership_fault_material(fault)";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "same-tag activation replacement";
        needle = "state.active_faults.insert(tag.clone(), fault.clone())";
      }
      {
        label = "unknown heal no-op removal";
        needle = "state.active_faults.remove(tag)";
      }
      {
        label = "materialized scheduler state captures trigger tags";
        needle = "pub fn materialized_scheduler_state";
      }
    ]
    ++ failuresFor "crates/crucible/tests/fault_tag_state.rs" tagTest [
      {
        label = "replace-on-retag test";
        needle = "reinjecting_same_tag_replaces_prior_fault_and_materializes_binding";
      }
      {
        label = "heal-by-tag isolation test";
        needle = "heal_by_tag_removes_only_the_named_active_fault";
      }
      {
        label = "declarative vs imperative unknown heal test";
        needle = "declarative_unknown_heal_is_rejected_but_imperative_unknown_heal_noops";
      }
      {
        label = "active tag materialized hash test";
        needle = "materialized_active_fault_tags_hash_tag_and_replacement_fault";
      }
      {
        label = "declarative trigger active tag materialization test";
        needle = "materialized_scheduler_state_captures_declarative_trigger_tags";
      }
      {
        label = "production checkpoint active tag materialization test";
        needle = "fat_checkpoint_materialization_populates_active_tags_from_schedule";
      }
    ]
    ++ failuresFor "tests/crucible/phase4-fault-tag-state.nix" (builtins.readFile ./phase4-fault-tag-state.nix) [
      {
        label = "qemu runtime-state shape coverage";
        needle = "-p crucible-qemu";
      }
      {
        label = "qemu loadvm active tag preservation test";
        needle = "qemu_loadvm_preserves_materialized_scheduler_active_tags";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 fault tag state import";
        needle = "faultTagState = import ./phase4-fault-tag-state.nix";
      }
      {
        label = "phase4 fault tag state attr path";
        needle = "attrPath = \"checks.crucible.phase4.faultTagState\"";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/fault_tag_state.rs" tagTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "unfinished todo";
        needle = "todo!";
      }
      {
        label = "unfinished unimplemented";
        needle = "unimplemented!";
      }
    ];
in
  if failures != []
  then throw "crucible phase4 fault-tag-state check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-fault-tag-state";
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
            sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
                > .cargo/config.toml
          '';
        }
        {
          name = "run-fault-tag-state";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo check \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-fault-tag-state-target" \
              -p crucible \
              -p crucible-qemu
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-fault-tag-state-target" \
              -p crucible-qemu \
              qemu_loadvm_preserves_materialized_scheduler_active_tags
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-fault-tag-state-target" \
              -p crucible \
              --test fault_tag_state \
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
            tags=heal-by-tag replace-on-retag
            materialized=active-fault-tags
            RESULT
          '';
        }
      ];
    }
