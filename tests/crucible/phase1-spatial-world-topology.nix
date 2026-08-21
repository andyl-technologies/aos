{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.spatialWorldTopology",
  taskIds ? ["T-SPAT-4" "T-SPAT-7"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = import ../../pkgs/tools/crucible/_cargo-deps-hash.nix;
  };

  model = import ./_crucible-model-source.nix {inherit lib;};
  crateRoot = import ./_crucible-tests-source.nix {inherit lib;};
  defaultChecks = builtins.readFile ./default.nix;
  spatialGraph = builtins.readFile ../../docs/rfcs/0010-crucible/06-spatial-graph.md;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/06-spatial-graph.md" spatialGraph [
      {
        label = "T-SPAT-4 completion names world links";
        needle = "`nodes` and `links`, `World::from_nodes_and_links`";
      }
      {
        label = "T-SPAT-7 completion names endpoint validation";
        needle = "endpoint order and rejects self-loops";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "world link accessor";
        needle = "pub fn links(&self) -> &[LinkDef]";
      }
      {
        label = "link definition";
        needle = "pub struct LinkDef";
      }
      {
        label = "canonical link constructor";
        needle = "pub fn new(left: NodeId, right: NodeId) -> Result<Self, EngineError>";
      }
      {
        label = "link endpoint accessor";
        needle = "pub fn endpoints(&self) -> (&NodeId, &NodeId)";
      }
      {
        label = "world topology constructor";
        needle = "pub fn from_nodes_and_links(";
      }
      {
        label = "topology validator";
        needle = "pub fn validate_topology(&self) -> Result<(), EngineError>";
      }
      {
        label = "canonical link ordering";
        needle = "fn canonical_world_links(links: &[LinkDef]) -> Vec<LinkDef>";
      }
      {
        label = "world link validation";
        needle = "fn validate_world_links_for_node_defs(";
      }
      {
        label = "link material included";
        needle = "fn world_links_material(links: &[LinkDef]) -> String";
      }
      {
        label = "link material records endpoints";
        needle = "fn world_link_material(link: &LinkDef) -> String";
      }
      {
        label = "self-loop error";
        needle = "WorldLinkSelfLoop";
      }
      {
        label = "unknown endpoint error";
        needle = "WorldLinkUnknownNode";
      }
      {
        label = "duplicate link error";
        needle = "DuplicateWorldLink";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" crateRoot [
      {
        label = "Icount exported";
        needle = "Icount,";
      }
      {
        label = "IrqVector exported";
        needle = "IrqVector,";
      }
      {
        label = "LinkDef exported";
        needle = "LinkDef,";
      }
      {
        label = "canonical topology test";
        needle = "world_topology_hashes_nodes_and_links_canonically";
      }
      {
        label = "invalid topology test";
        needle = "world_topology_rejects_invalid_links";
      }
      {
        label = "topology helper";
        needle = "world_from_nodes_and_links";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes spatial topology check";
        needle = "spatialWorldTopology = import ./phase1-spatial-world-topology.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 spatial world topology check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-spatial-world-topology";
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
          name = "run-spatial-world-topology";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-spatial-world-topology-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --lib \
              world_topology \
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
            spatial_graph_task=world-node-link-topology
            world_shape=nodes-and-links
            node_ids=unique
            link_endpoints=canonical-and-declared
            RESULT
          '';
        }
      ];
    }
