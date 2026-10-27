{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.spatialStaticTopology",
  taskIds ? ["T-SPAT-10"],
}: let
  inherit (import ./_test-gate.nix {inherit pkgs lib;}) mkCrucibleTestGate;

  model = import ./_crucible-model-source.nix {inherit lib;};
  crateRoot = import ./_crucible-tests-source.nix {inherit lib;};
  qemuCargo = builtins.readFile ../../crates/crucible/crucible-qemu-host/Cargo.toml;
  qemuRealization = builtins.readFile ../../crates/crucible/crucible-qemu-host/src/realization.rs;
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
    ++ failuresFor "crates/crucible/crucible-engine/src/model.rs" model [
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
        label = "validated recorded-world construction";
        needle = "pub fn from_recorded_parts(";
      }
    ]
    ++ forbiddenFor "crates/crucible/crucible-engine/src/model.rs" model [
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
    ++ failuresFor "crates/crucible/crucible-engine/src/lib.rs" crateRoot [
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
    ++ forbiddenFor "crates/crucible/crucible-qemu-host/Cargo.toml" qemuCargo [
      {
        label = "production QEMU enables unchecked world feature";
        needle = "crucible = { path = \"../crucible\", features = [\"qemu-backend\"] }";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-qemu-host/src/realization.rs" qemuRealization [
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
    mkCrucibleTestGate {
      pname = "crucible-phase1-spatial-static-topology";

      runtimeDeps = [pkgs.sqlite];

      buildDeps = [
        pkgs.sqlite
        pkgs.coreutils
        pkgs.sed
      ];

      phases = [
        {
          name = "run-spatial-static-topology";
          script = ''
            set -eu
            crucible-cargo test \
              -p crucible-engine \
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
