{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.spatialPropertiesComponent",
  taskIds ? ["T-SPAT-13"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  model = import ./_crucible-model-source.nix {inherit lib;};
  crateRoot = builtins.readFile ../../crates/crucible/src/lib.rs;
  defaultChecks = builtins.readFile ./default.nix;
  spatialGraph = builtins.readFile ../../docs/rfcs/0010-crucible/06-spatial-graph.md;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;


  failures =
    failuresFor "docs/rfcs/0010-crucible/06-spatial-graph.md" spatialGraph [
      {
        label = "T-SPAT-13 checked off";
        needle = "- [x] **T-SPAT-13**";
      }
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
        needle = ''
          pub struct Properties {
              /// The independently content-addressed properties identity.
              id: ContentHash,
        '';
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
    ++ failuresFor "crates/crucible/src/lib.rs" crateRoot [
      {
        label = "properties content-address test";
        needle = "properties_content_address_is_orthogonal_and_validated";
      }
      {
        label = "test checks authoring order";
        needle = "let authored_order = vec![";
      }
      {
        label = "test checks canonical assertions";
        needle = "assert_eq!(properties.assertions(), same_properties.assertions());";
      }
      {
        label = "test checks properties reuse across compatible worlds";
        needle = "same_properties_changed_world.content_hash()";
      }
      {
        label = "test checks scenario properties sensitivity";
        needle = "properties should affect scenario identity";
      }
      {
        label = "test rejects incompatible world";
        needle = "incompatible_world.scenario_def_with_plan_and_properties";
      }
      {
        label = "test rejects incompatible plan in combined path";
        needle = "no_link_world.scenario_def_with_plan_and_properties";
      }
      {
        label = "test rejects undeclared predicate node";
        needle = "PropertyPredicateUnknownNode";
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
              --lib \
              properties_content_address \
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
