{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.spatialPropertiesComponent",
  taskIds ? ["T-SPAT-13"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  model = import ./_crucible-model-source.nix {inherit lib;};
  crateRoot = import ./_crucible-tests-source.nix {inherit lib;};
  propertiesTest = builtins.readFile ../../crates/crucible/tests/property_fingerprint_neutrality.rs;
  coverageTest = builtins.readFile ../../crates/crucible/tests/coverage_condition_leaf.rs;
  defaultChecks = builtins.readFile ./default.nix;
  spatialGraph = builtins.readFile ../../docs/rfcs/0010-crucible/06-spatial-graph.md;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/06-spatial-graph.md" spatialGraph [
      {
        label = "T-SPAT-13 completion names independent properties hash";
        needle = "`Properties` now carries an";
      }
      {
        label = "T-SPAT-13 completion names scenario composition";
        needle = "`World::scenario_def_with_plan_and_properties`";
      }
      {
        label = "T-SPAT-13 completion names gate";
        needle = "`checks.crucible.phase1.spatialPropertiesComponent`";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "properties type";
        needle = "pub struct Properties";
      }
      {
        label = "private properties identity field";
        needle = "pub(super) id: ContentHash,";
      }
      {
        label = "properties content hash accessor";
        needle = "pub fn content_hash(&self) -> ContentHash";
      }
      {
        label = "properties hash domain";
        needle = "\"crucible.model.properties.v1\"";
      }
      {
        label = "property quantifier enum";
        needle = "pub enum Property";
      }
      {
        label = "always quantifier";
        needle = "Always {";
      }
      {
        label = "eventually quantifier";
        needle = "Eventually {";
      }
      {
        label = "reachable expectation carries disposition only for reachable";
        needle = "on_unreached: ReachableDisposition,";
      }
      {
        label = "predicate vocabulary";
        needle = "pub enum Predicate";
      }
      {
        label = "properties canonical assertion helper";
        needle = "fn canonical_assertions(assertions: &[AssertionDef]) -> Vec<AssertionDef>";
      }
      {
        label = "properties world validation helper";
        needle = "fn validate_properties_for_world";
      }
      {
        label = "predicate validation helper";
        needle = "fn validate_property_predicate_for_world";
      }
      {
        label = "predicate unknown node error";
        needle = "PropertyPredicateUnknownNode";
      }
      {
        label = "world-plan-properties scenario helper";
        needle = "pub fn scenario_def_with_plan_and_properties";
      }
      {
        label = "scenario world-plan-properties domain";
        needle = "\"crucible.model.world-plan-properties-seed-scenario.v1\"";
      }
      {
        label = "scenario component material";
        needle = "fn scenario_world_plan_properties_seed_material";
      }
      {
        label = "scenario includes properties component hash";
        needle = "content_hash_hex(properties.content_hash())";
      }
      {
        label = "world validates properties before scenario composition";
        needle = "properties.validate_for_world(self)?;";
      }
    ]
    ++ lib.optionals (hasInfix ''
        pub struct Properties {
            /// The independently content-addressed properties identity.
        pub id: ContentHash,
      ''
      model) [
      "crates/crucible/src/model.rs: properties identity field must not be public"
    ]
    ++ failuresFor "crates/crucible/tests/property_fingerprint_neutrality.rs" propertiesTest [
      {
        label = "properties content-address test";
        needle = "fn property_changes_move_scenario_identity_without_moving_run_material()";
      }
      {
        label = "test checks properties identity changes";
        needle = "removed.properties().content_hash(),";
      }
      {
        label = "test checks scenario properties sensitivity";
        needle = "property declaration must move the scenario hash";
      }
      {
        label = "test checks properties do not move run components";
        needle = "assert_same_run_components(&removed, &declared);";
      }
      {
        label = "test checks properties ref in scenario material";
        needle = "assert_scenario_material_points_at_properties(&amended);";
      }
    ]
    ++ failuresFor "crates/crucible/tests/coverage_condition_leaf.rs" coverageTest [
      {
        label = "test rejects undeclared property predicate node";
        needle = "Err(EngineError::PropertyPredicateUnknownNode";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes spatial properties component check";
        needle = "spatialPropertiesComponent = import ./phase1-spatial-properties-component.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 spatial properties component check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-spatial-properties-component";
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
          name = "run-spatial-properties-component";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-spatial-properties-component-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --features test-double \
              --test property_fingerprint_neutrality \
              property_changes_move_scenario_identity_without_moving_run_material \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-spatial-properties-component-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test coverage_condition_leaf \
              coverage_point_properties_validate_referenced_nodes \
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
            related_gates=gate:content-address
            spatial_graph_task=orthogonal-properties-component
            component=properties
            canonical_order=assertion-id
            scenario_identity=world-ref-plus-plan-ref-plus-properties-ref
            RESULT
          '';
        }
      ];
    }
