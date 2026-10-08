{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.spatialComponentAddressing",
  taskIds ? ["T-SPAT-3"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  model = import ./_crucible-model-source.nix {inherit lib;};
  crateRoot = import ./_crucible-tests-source.nix {inherit lib;};
  planTest = builtins.readFile ../../crates/crucible/tests/event_graph_serialization.rs;
  propertiesTest = builtins.readFile ../../crates/crucible/tests/property_fingerprint_neutrality.rs;
  defaultChecks = builtins.readFile ./default.nix;
  spatialGraph = builtins.readFile ../../docs/rfcs/0010-crucible/06-spatial-graph.md;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/06-spatial-graph.md" spatialGraph [
      {
        label = "T-SPAT-3 completion names test";
        needle = "`spatial_components_have_independent_content_addresses_and_cross_reuse`";
      }
      {
        label = "T-SPAT-3 completion names gate";
        needle = "`checks.crucible.phase1.spatialComponentAddressing`";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "world content address accessor";
        needle = "pub fn id(&self) -> ContentHash";
      }
      {
        label = "world content address domain";
        needle = "\"crucible.model.world.v4\"";
      }
      {
        label = "world canonical bytes";
        needle = "pub fn canonical_bytes(&self) -> Vec<u8>";
      }
      {
        label = "plan content hash accessor";
        needle = "pub fn content_hash(&self) -> ContentHash";
      }
      {
        label = "plan content address domain";
        needle = "\"crucible.model.plan.v5\"";
      }
      {
        label = "plan event graph accessor";
        needle = "pub const fn event_graph(&self) -> &EventGraph";
      }
      {
        label = "properties content hash accessor";
        needle = "pub fn content_hash(&self) -> ContentHash";
      }
      {
        label = "properties content address domain";
        needle = "\"crucible.model.properties.v1\"";
      }
      {
        label = "properties assertions accessor";
        needle = "pub fn assertions(&self) -> &[AssertionDef]";
      }
      {
        label = "scenario tuple uses world ref";
        needle = "world_ref={}";
      }
      {
        label = "scenario tuple uses plan ref";
        needle = "plan_ref={}";
      }
      {
        label = "scenario tuple uses properties ref";
        needle = "properties_ref={}";
      }
    ]
    ++ failuresFor "crates/crucible/tests/event_graph_serialization.rs" planTest [
      {
        label = "focused plan component addressing test";
        needle = "fn graph_plan_is_the_scenario_plan_component()";
      }
      {
        label = "test checks world BLAKE3 domain";
        needle = "compatible_changed_world()";
      }
      {
        label = "test checks plan BLAKE3 domain";
        needle = "\"crucible.model.plan.v5\"";
      }
      {
        label = "test reuses plan across compatible worlds";
        needle = "compatible_changed_world";
      }
      {
        label = "test preserves plan address across compatible worlds";
        needle = "assert_eq!(changed_world_plan.content_hash(), plan.content_hash())";
      }
    ]
    ++ failuresFor "crates/crucible/tests/property_fingerprint_neutrality.rs" propertiesTest [
      {
        label = "focused properties component addressing test";
        needle = "fn property_changes_move_scenario_identity_without_moving_run_material()";
      }
      {
        label = "properties change moves only scenario identity";
        needle = "assert_same_run_components(&removed, &declared);";
      }
      {
        label = "properties hash changes independently";
        needle = "removed.properties().content_hash(),";
      }
      {
        label = "scenario material commits to properties ref";
        needle = "assert_scenario_material_points_at_properties(&declared);";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes spatial component addressing check";
        needle = "spatialComponentAddressing = import ./phase1-spatial-component-addressing.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 spatial component addressing check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-spatial-component-addressing";
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
          name = "run-spatial-component-addressing";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-spatial-component-addressing-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test event_graph_serialization \
              graph_plan_is_the_scenario_plan_component \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-spatial-component-addressing-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --features test-double \
              --test property_fingerprint_neutrality \
              property_changes_move_scenario_identity_without_moving_run_material \
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
            component=spatial-component-addressing
            addressed_components=World,Plan,Properties
            cross_reuse=true
            RESULT
          '';
        }
      ];
    }
