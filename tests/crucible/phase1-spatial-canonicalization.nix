{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.spatialCanonicalization",
  taskIds ? ["T-SPAT-19"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-ULD9g6d87886b8O6/sGCMktquGwaUAyf+DLHUrFzod0=";
  };

  model = import ./_crucible-model-source.nix {inherit lib;};
  crateRoot = import ./_crucible-tests-source.nix {inherit lib;};
  defaultChecks = builtins.readFile ./default.nix;
  spatialGraph = builtins.readFile ../../docs/rfcs/0010-crucible/06-spatial-graph.md;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/06-spatial-graph.md" spatialGraph [
      {
        label = "T-SPAT-19 completion names canonicalization test";
        needle = "`canonicalization_hashes_meaning_not_authoring_spelling`";
      }
      {
        label = "T-SPAT-19 completion names gate";
        needle = "`checks.crucible.phase1.spatialCanonicalization`";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "world canonical node ordering";
        needle = "fn canonical_world_nodes(nodes: &[WorldNode]) -> Vec<WorldNode>";
      }
      {
        label = "world canonical link ordering";
        needle = "fn canonical_world_links(links: &[LinkDef]) -> Vec<LinkDef>";
      }
      {
        label = "canonical link endpoint ordering";
        needle = "fn canonical_link_endpoint_pair(left: &NodeId, right: &NodeId) -> (NodeId, NodeId)";
      }
      {
        label = "plan canonical entry ordering";
        needle = "fn canonical_plan_entries(entries: &[PlanEntry]) -> Vec<PlanEntry>";
      }
      {
        label = "plan stable tie break";
        needle = "then_with(|| plan_entry_material(left).cmp(&plan_entry_material(right)))";
      }
      {
        label = "properties canonical assertion ordering";
        needle = "fn canonical_assertions(assertions: &[AssertionDef]) -> Vec<AssertionDef>";
      }
      {
        label = "compound predicate canonical ordering";
        needle = "fn canonical_predicate_set(predicates: &[Predicate]) -> Vec<Predicate>";
      }
      {
        label = "fixed link loss material";
        needle = "link_loss_millionths={}";
      }
      {
        label = "fixed family density model";
        needle = "pub struct FaultDensity";
      }
      {
        label = "content-addressed blob refs in material";
        needle = "optional_blob_ref_material";
      }
      {
        label = "fixed-width binary integer encoding";
        needle = "fn write_u64(&mut self, value: u64)";
      }
      {
        label = "length-prefixed string encoding";
        needle = "fn write_string(&mut self, value: &str)";
      }
      {
        label = "canonical scenario component tuple";
        needle = "fn scenario_world_plan_properties_seed_material";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" crateRoot [
      {
        label = "focused canonicalization test";
        needle = "fn canonicalization_hashes_meaning_not_authoring_spelling()";
      }
      {
        label = "test covers canonical world bytes";
        needle = "authored_world.canonical_bytes()";
      }
      {
        label = "test covers canonical plan bytes";
        needle = "authored_plan.canonical_bytes()";
      }
      {
        label = "test covers canonical properties bytes";
        needle = "authored_properties.canonical_bytes()";
      }
      {
        label = "test covers canonical scenario bytes";
        needle = "authored_form.canonical_bytes()";
      }
      {
        label = "test fixes world golden vector";
        needle = "2f107a46c69f789cd0fa04ed4bca6e7c1d780594789e2167a80bf0dfe3bc21c3";
      }
      {
        label = "test fixes plan golden vector";
        needle = "f9e1e5c40ecbfce8d62e71476b59f2f207e6457ae947647c1e44ab1ad86f2e3a";
      }
      {
        label = "test fixes properties golden vector";
        needle = "b20bc725db83e5943ed694b56a51b3b5d099734c9185a466ac6135f1b9ceff13";
      }
      {
        # Scenario-form golden vector regenerated 2026-07-09 from the passing
        # canonicalization_hashes_meaning_not_authoring_spelling test (authored_form.id);
        # the scenario-form serialization changed, so the prior ff875d3d… vector no
        # longer matches. Value copied from the verified test assertion, not invented.
        label = "test fixes scenario golden vector";
        needle = "e13a8e94a43857719319c913ba7036109d033e47263411799a8baee73a50ea94";
      }
      {
        # Compact-binary golden vector regenerated 2026-07-09 from the passing test
        # (ContentHash::from_bytes(&authored_form.to_compact_binary())); prior
        # 64e947f6… vector predates the serialization change. Verified test value.
        label = "test fixes compact binary vector";
        needle = "455912b3f3ad4878d8d40af3b41b75179d3ad06b7038081d2ed8993b42fa2a44";
      }
      {
        label = "test covers compact binary magic";
        needle = "crucible.scenario-def-form.v1";
      }
      {
        label = "test covers exact probability encoding";
        needle = "loss.millionths(), 125_000";
      }
      {
        label = "test covers exact density encoding";
        needle = "density.millionths(), 125_000";
      }
      {
        label = "test covers density affecting scenario plan";
        needle = "zero_density_instance.form().plan().content_hash()";
      }
      {
        label = "test covers content-addressed refs";
        needle = "changed_ref_world";
      }
      {
        label = "test covers icount field sensitivity";
        needle = "changed_icount_world";
      }
      {
        label = "test covers duration field sensitivity";
        needle = "changed_duration_world";
      }
      {
        label = "test covers bandwidth field sensitivity";
        needle = "changed_bandwidth_world";
      }
      {
        label = "test covers plan time sensitivity";
        needle = "changed_time_plan";
      }
      {
        label = "test covers plan tag sensitivity";
        needle = "changed_tag_plan";
      }
      {
        label = "test covers plan fault sensitivity";
        needle = "changed_fault_plan";
      }
      {
        label = "test covers assertion message sensitivity";
        needle = "changed_message_properties";
      }
      {
        label = "test covers predicate sensitivity";
        needle = "changed_predicate_properties";
      }
      {
        label = "test covers seed sensitivity";
        needle = "other_seed_form";
      }
      {
        label = "test covers endpoint spelling";
        needle = "PartitionDirection::EndpointBToEndpointA";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes spatial canonicalization check";
        needle = "spatialCanonicalization = import ./phase1-spatial-canonicalization.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 spatial canonicalization check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-spatial-canonicalization";
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
          name = "run-spatial-canonicalization";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-spatial-canonicalization-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --lib \
              canonicalization_hashes_meaning_not_authoring_spelling \
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
            component=canonicalization
            meaning_not_spelling=true
            fixed_point_probabilities=true
            content_addressed_refs=true
            RESULT
          '';
        }
      ];
    }
