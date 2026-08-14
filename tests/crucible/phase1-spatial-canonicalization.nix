{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.spatialCanonicalization",
  taskIds ? ["T-SPAT-19"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  model = import ./_crucible-model-source.nix {inherit lib;};
  crateRoot = import ./_crucible-tests-source.nix {inherit lib;};
  defaultChecks = builtins.readFile ./default.nix;
  spatialGraph = builtins.readFile ../../docs/rfcs/0010-crucible/06-spatial-graph.md;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/06-spatial-graph.md" spatialGraph [
      {
        label = "T-SPAT-19 completion names world canonicalization test";
        needle = "`world_topology_hashes_nodes_and_links_canonically`";
      }
      {
        label = "T-SPAT-19 completion names signal canonicalization test";
        needle = "`authored_order_does_not_change_identity`";
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
        needle = "let (endpoint_a, endpoint_b) = if left <= right";
      }
      {
        label = "signal-program canonical ordering";
        needle = "programs.sort_by_key(SignalProgram::id)";
      }
      {
        label = "fault-binding canonical ordering";
        needle = "bindings.sort_by(|left, right| left.id().cmp(right.id()))";
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
        label = "fixed probability signal model";
        needle = "ProbabilityMillionths(u32)";
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
        label = "focused world canonicalization test";
        needle = "fn world_topology_hashes_nodes_and_links_canonically()";
      }
      {
        label = "test covers canonical world bytes";
        needle = "base_world.canonical_bytes()";
      }
      {
        label = "test covers canonical endpoint spelling";
        needle = "vec![link(\"b\", \"a\")]";
      }
      {
        label = "test covers canonical link identity";
        needle = "assert_eq!(canonical.id, reordered.id)";
      }
      {
        label = "test covers exact probability encoding";
        needle = "base.links()[0].loss().millionths(), 250_000";
      }
      {
        label = "test covers probability identity sensitivity";
        needle = "assert_ne!(base.id, changed_loss.id)";
      }
      {
        label = "test covers bandwidth identity sensitivity";
        needle = "assert_ne!(base.id, changed_bandwidth.id)";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "signal authoring order identity test";
        needle = "fn authored_order_does_not_change_identity()";
      }
      {
        label = "signal authoring order identity assertion";
        needle = "assert_eq!(first.id(), second.id())";
      }
      {
        label = "outer plan commits to signal layer";
        needle = "fn outer_plan_identity_commits_to_the_complete_fault_layer()";
      }
      {
        label = "outer plan identity changes with signal layer";
        needle = "assert_ne!(plan.content_hash(), baseline.content_hash())";
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
            for test_name in \
              world_topology_hashes_nodes_and_links_canonically \
              world_link_transport_material_affects_world_identity \
              authored_order_does_not_change_identity \
              outer_plan_identity_commits_to_the_complete_fault_layer
            do
              cargo test \
                --frozen \
                --offline \
                --target-dir "$TMPDIR/crucible-spatial-canonicalization-target" \
                --manifest-path crates/Cargo.toml \
                -p crucible \
                --lib \
                "$test_name" \
                -- --test-threads=1
            done
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
            signal_authoring_order=true
            signal_plan_identity=true
            content_addressed_refs=true
            RESULT
          '';
        }
      ];
    }
