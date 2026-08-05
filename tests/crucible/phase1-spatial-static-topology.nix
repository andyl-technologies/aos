{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.spatialStaticTopology",
  taskIds ? ["T-SPAT-10"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoVendor {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-fWBTuyTXJ+/0BiVbB5WAtCqVwufg04NH4BJdocT+moU=";
  };

  model = import ./_crucible-model-source.nix {inherit lib;};
  crateRoot = import ./_crucible-tests-source.nix {inherit lib;};
  qemuCargo = builtins.readFile ../../crates/crucible-qemu/Cargo.toml;
  qemuRealization = builtins.readFile ../../crates/crucible-qemu/src/realization.rs;
  defaultChecks = builtins.readFile ./default.nix;
  spatialGraph = builtins.readFile ../../docs/rfcs/0010-crucible/06-spatial-graph.md;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/06-spatial-graph.md" spatialGraph [
      {
        label = "T-SPAT-10 completion names immutable accessors";
        needle = "`World` now stores nodes and";
      }
      {
        label = "T-SPAT-10 completion names static topology API";
        needle = "`World::static_topology()`";
      }
      {
        label = "T-SPAT-10 completion names gate";
        needle = "`checks.crucible.phase1.spatialStaticTopology`";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "world id accessor";
        needle = "pub fn id(&self) -> ContentHash";
      }
      {
        label = "world node accessor";
        needle = "pub fn nodes(&self) -> &[WorldNodeDef]";
      }
      {
        label = "world link accessor";
        needle = "pub fn links(&self) -> &[LinkDef]";
      }
      {
        label = "static topology API";
        needle = "pub fn static_topology(&self) -> WorldStaticTopology";
      }
      {
        label = "static topology type";
        needle = "pub struct WorldStaticTopology";
      }
      {
        label = "lookahead edge type";
        needle = "pub struct WorldLookaheadEdge";
      }
      {
        label = "participant derivation";
        needle = "fn world_participants(world: &World) -> Vec<NodeId>";
      }
      {
        label = "RNG stream derivation";
        needle = "fn world_rng_streams(world: &World) -> Vec<RngStreamId>";
      }
      {
        label = "lookahead graph derivation";
        needle = "fn world_lookahead_edges(world: &World) -> Vec<WorldLookaheadEdge>";
      }
      {
        label = "bake node derivation";
        needle = "fn world_bake_nodes(world: &World) -> Vec<NodeId>";
      }
      {
        label = "link-scoped RNG stream";
        needle = "RngStreamId::for_link(world_link_stream_name(&link))";
      }
      {
        label = "directed lookahead minimum latency";
        needle = "minimum_latency: link_minimum_latency(&link)";
      }
      {
        label = "jitter-reduced minimum latency helper";
        needle = "fn link_minimum_latency(link: &LinkDef) -> SimDuration";
      }
      {
        label = "collision-free link RNG stream material";
        needle = "link_endpoint_a_len={}";
      }
      {
        label = "validated recorded world compatibility path";
        needle = "pub fn from_recorded_parts(";
      }
    ]
    ++ forbiddenFor "crates/crucible/src/model.rs" model [
      {
        label = "public mutable node vector";
        needle = "pub nodes: Vec<WorldNode>";
      }
      {
        label = "public mutable link vector";
        needle = "pub links: Vec<LinkDef>";
      }
      {
        label = "mutable node accessor";
        needle = "nodes_mut";
      }
      {
        label = "mutable link accessor";
        needle = "links_mut";
      }
      {
        label = "runtime add-node operation";
        needle = "add_node";
      }
      {
        label = "runtime remove-node operation";
        needle = "remove_node";
      }
      {
        label = "runtime create-link operation";
        needle = "create_link";
      }
      {
        label = "runtime destroy-link operation";
        needle = "destroy_link";
      }
      {
        label = "unchecked world constructor";
        needle = "from_unchecked_recorded_parts";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" crateRoot [
      {
        label = "static topology type exported";
        needle = "WorldStaticTopology";
      }
      {
        label = "lookahead edge type exported";
        needle = "WorldLookaheadEdge";
      }
      {
        label = "static topology test";
        needle = "world_static_topology_is_derived_from_world_only";
      }
      {
        label = "link RNG stream collision test";
        needle = "world_static_topology_link_rng_streams_are_collision_free";
      }
      {
        label = "test checks schedule independence";
        needle = "assert_ne!(genesis.schedule, scheduled.schedule);";
      }
      {
        label = "test checks jitter-reduced lookahead";
        needle = "minimum_latency: SimDuration { nanos: 8 }";
      }
      {
        label = "test checks physical layout invariance";
        needle = "compact_world.static_topology()";
      }
    ]
    ++ forbiddenFor "crates/crucible-qemu/Cargo.toml" qemuCargo [
      {
        label = "production QEMU enables unchecked world feature";
        needle = "crucible = { path = \"../crucible\", features = [\"qemu-backend\"] }";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/realization.rs" qemuRealization [
      {
        label = "QEMU reads world nodes immutably";
        needle = "for node in world.vm_nodes()";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes spatial static topology check";
        needle = "spatialStaticTopology = import ./phase1-spatial-static-topology.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 spatial static topology check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-spatial-static-topology";
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
          name = "run-spatial-static-topology";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-spatial-static-topology-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --lib \
              world_static_topology \
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
            related_gates=gate:content-address,gate:e2e-determinism
            spatial_graph_task=static-world-topology
            topology_api=immutable-accessors
            derived_sets=participants,rng-streams,lookahead-graph,bake-nodes
            RESULT
          '';
        }
      ];
    }
