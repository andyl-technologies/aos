{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase6.checkpointMaterialization",
  taskIds ? ["T-ADV-6"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };
  graphSource = import ./_crucible-model-source.nix {inherit lib;};
  gateTest = builtins.readFile ../../crates/crucible/tests/gate_checkpoint_materialization.rs;
  defaultChecks = builtins.readFile ./default.nix;
  taskList = builtins.concatStringsSep "," taskIds;
  inherit (import ./_lib.nix {inherit lib;}) failuresFor forbiddenFor;
  failures =
    failuresFor "crates/crucible model" graphSource [
      {label = "ordinary materialization policy"; needle = "pub struct MaterializationPolicy";}
      {label = "exact checkpoint materialization"; needle = "pub fn materialize_checkpoint(";}
      {label = "thin reconstruction cache"; needle = "pub fn record_thin_checkpoint(";}
    ]
    ++ forbiddenFor "crates/crucible model" graphSource [
      {label = "savevm hedge type"; needle = "SavevmCompletenessHedge";}
      {label = "savevm hedge method"; needle = "savevm_hedge";}
      {label = "S3 fallback constructor"; needle = "thin_replay_until_full_s3";}
    ]
    ++ failuresFor "crates/crucible/tests/gate_checkpoint_materialization.rs" gateTest [
      {label = "fat persistence gate"; needle = "gate_checkpoint_materialization_persists_exact_fat_checkpoint_by_configuration";}
      {label = "content-address closure assertion"; needle = "store.exists(&key)?";}
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {label = "phase6 checkpoint gate"; needle = "checkpointMaterialization = greenBeforeAdvance";}
      {label = "phase6 checkpoint import"; needle = "gate = import ./phase6-checkpoint-materialization.nix";}
    ];
in
  if failures != []
  then throw "crucible phase6 checkpoint materialization check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase6-checkpoint-materialization";
      version = "0";
      src = crucibleSrc;
      buildDeps = [pkgs.rust pkgs.sed];
      DEPENDENCIES = builtins.concatStringsSep ":" dependencies;
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
            : "$DEPENDENCIES"
            export CARGO_HOME="$TMPDIR/cargo-home"
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then cd source; fi
            mkdir -p "$CARGO_HOME" .cargo
            sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" > .cargo/config.toml
          '';
        }
        {
          name = "run-checkpoint-materialization";
          script = ''
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then cd source; fi
            cargo test --frozen --offline \
              --target-dir "$TMPDIR/crucible-checkpoint-materialization-target" \
              --manifest-path crates/Cargo.toml -p crucible \
              --test gate_checkpoint_materialization -- --test-threads=1
          '';
        }
        {
          name = "write-result";
          script = ''
            mkdir -p "$out"
            cat > "$out/result" <<RESULT
            PASS
            check=${attrPath}
            tasks=${taskList}
            exact_fat_checkpoint=content-addressed-and-complete
            thin_checkpoint=advisory-reconstruction-cache
            legacy_savevm_hedge=absent
            RESULT
          '';
        }
      ];
    }
