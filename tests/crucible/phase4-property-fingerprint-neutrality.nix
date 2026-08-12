{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.propertyFingerprintNeutrality",
  taskIds ? ["T-ASRT-2"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  model = import ./_crucible-model-source.nix {inherit lib;};
  neutralityTest = builtins.readFile ../../crates/crucible/tests/property_fingerprint_neutrality.rs;
  assertionDoc = builtins.readFile ../../docs/rfcs/0010-crucible/18-assertions-properties.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/18-assertions-properties.md" assertionDoc [
      {
        label = "T-ASRT-2 completion note";
        needle = "Completed by `checks.crucible.phase4.propertyFingerprintNeutrality`";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "scenario material helper";
        needle = "fn scenario_world_plan_properties_seed_material";
      }
      {
        label = "scenario material includes properties ref";
        needle = "properties_ref={}";
      }
      {
        label = "scenario identity uses world plan properties seed material";
        needle = "let material = scenario_world_plan_properties_seed_material(self, plan, properties, seed);";
      }
      {
        label = "scenario identity domain";
        needle = "\"crucible.model.world-plan-properties-seed-scenario.v1\"";
      }
      {
        label = "scenario form exposes properties component";
        needle = "pub fn properties(&self) -> &Properties";
      }
      {
        label = "scenario form exposes seed component";
        needle = "pub fn seed(&self) -> Seed";
      }
    ]
    ++ failuresFor "crates/crucible/tests/property_fingerprint_neutrality.rs" neutralityTest [
      {
        label = "identity and neutrality test";
        needle = "property_changes_move_scenario_identity_without_moving_run_material";
      }
      {
        label = "property declaration moves scenario hash";
        needle = "property declaration must move the scenario hash";
      }
      {
        label = "property amendment moves scenario hash";
        needle = "property amendment must move the scenario hash";
      }
      {
        label = "property removal moves scenario hash";
        needle = "property removal must move the scenario hash";
      }
      {
        label = "canonical material checks properties ref";
        needle = "properties_ref={}";
      }
      {
        label = "decision recorder uses scenario seed";
        needle = "DecisionRecorder::new(Configuration::genesis(form.scenario_def()))";
      }
      {
        label = "schedule neutrality assertion";
        needle = "declaring properties must not perturb seed-derived schedule decisions or node fingerprints";
      }
      {
        label = "amendment neutrality assertion";
        needle = "amending properties must not perturb seed-derived schedule decisions or node fingerprints";
      }
      {
        label = "seed stream neutrality assertion";
        needle = "property changes must not change seed-derived decision streams";
      }
      {
        label = "scenario-backed node fingerprint helper";
        needle = "fn run_node_to_fingerprint(form: &ScenarioDefForm, run: NodeRun) -> ExecutionFingerprint";
      }
      {
        label = "sim backend runtime witness";
        needle = "let mut backend = SimBackend::new();";
      }
      {
        label = "backend trait input delivery";
        needle = ".deliver_input(BackendInput";
      }
      {
        label = "backend trait horizon advance";
        needle = "backend.advance_to_horizon(ExecutionHorizon";
      }
      {
        label = "backend trait fingerprint read";
        needle = ".fingerprint()";
      }
      {
        label = "payload drift negative control";
        needle = "the node fingerprint witness must change when delivered input changes";
      }
      {
        label = "horizon drift negative control";
        needle = "the node fingerprint witness must change when the instruction horizon changes";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 property fingerprint neutrality check import";
        needle = "propertyFingerprintNeutrality = import ./phase4-property-fingerprint-neutrality.nix";
      }
      {
        label = "phase4 property fingerprint neutrality attr path";
        needle = "attrPath = \"checks.crucible.phase4.propertyFingerprintNeutrality\"";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/property_fingerprint_neutrality.rs" neutralityTest [
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
  then throw "crucible phase4 property-fingerprint-neutrality check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-property-fingerprint-neutrality";
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
          name = "run-property-fingerprint-neutrality";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-property-fingerprint-neutrality-target" \
              --features test-double \
              -p crucible \
              --test property_fingerprint_neutrality \
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
            scenario_hash_includes_properties=true
            run_fingerprint_neutral=true
            RESULT
          '';
        }
      ];
    }
