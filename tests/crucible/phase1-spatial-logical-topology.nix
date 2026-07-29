{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.spatialLogicalTopology",
  taskIds ? ["T-SPAT-9"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  model = import ./_crucible-model-source.nix {inherit lib;};
  deviceSubnode = builtins.readFile ../../crates/crucible/src/device_subnode.rs;
  worldDevices = builtins.readFile ../../crates/crucible/tests/world_devices.rs;
  crateRoot = builtins.readFile ../../crates/crucible/src/lib.rs;
  shmemRoot = builtins.readFile ../../crates/crucible-shmem/src/lib.rs;
  defaultChecks = builtins.readFile ./default.nix;
  spatialGraph = builtins.readFile ../../docs/rfcs/0010-crucible/06-spatial-graph.md;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;



  failures =
    failuresFor "docs/rfcs/0010-crucible/06-spatial-graph.md" spatialGraph [
      {
        label = "T-SPAT-9 checked off after physical-layout invariance proof";
        needle = "- [x] **T-SPAT-9**";
      }
      {
        label = "T-SPAT-9 completion names logical-only world";
        needle = "`World::nodes` is the one\n    heterogeneous logical VM/block/9p collection";
      }
      {
        label = "T-SPAT-9 completion names physical layout invariance";
        needle = "vary real shmem layout and host\n    memory geometry";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "world shape";
        needle = "pub struct World";
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
        label = "logical link transport fields";
        needle = "bandwidth_bps: Option<u64>";
      }
      {
        label = "scenario id derives from world component identity";
        needle = "content_hash_hex(canonical_world_identity(world))";
      }
      {
        label = "non-empty world identity is recomputed from logical material";
        needle = "fn canonical_world_identity(world: &World) -> ContentHash";
      }
      {
        label = "opaque world compatibility path is explicit";
        needle = "return world.id;";
      }
      {
        label = "world material is nodes and links";
        needle = "fn world_material(nodes: &[WorldNodeDef], links: &[LinkDef]) -> String";
      }
    ]
    ++ failuresFor "crates/crucible/src/device_subnode.rs" deviceSubnode [
      {
        label = "instantiation-time physical layout policy";
        needle = "pub struct WorldIoLayoutPolicy";
      }
      {
        label = "deterministic logical-to-physical derivation";
        needle = "pub struct WorldIoInstantiationLayout";
      }
      {
        label = "physical source id outside World";
        needle = "pub source_node: u32";
      }
      {
        label = "physical request capacity outside World";
        needle = "pub inbox_capacity: u64";
      }
      {
        label = "physical response capacity outside World";
        needle = "pub outbox_capacity: u64";
      }
    ]
    ++ failuresFor "crates/crucible/tests/world_devices.rs" worldDevices [
      {
        label = "physical layout identity regression";
        needle = "transport_layout_is_derived_and_cannot_change_world_or_device_identity";
      }
      {
        label = "serialized World excludes source ids";
        needle = "assert!(!toml.contains(\"source_node\"))";
      }
      {
        label = "serialized World excludes request capacity";
        needle = "assert!(!toml.contains(\"inbox_capacity\"))";
      }
      {
        label = "serialized World excludes response capacity";
        needle = "assert!(!toml.contains(\"outbox_capacity\"))";
      }
    ]
    ++ forbiddenFor "crates/crucible/src/model.rs" model [
      {
        label = "shared-memory region config in engine model";
        needle = "RegionConfig";
      }
      {
        label = "shared-memory region layout in engine model";
        needle = "RegionLayout";
      }
      {
        label = "queue capacity in engine model";
        needle = "queue_capacity";
      }
      {
        label = "node slot offset in engine model";
        needle = "node_slots_off";
      }
      {
        label = "shared-memory fd in engine model";
        needle = "shmem_fd";
      }
      {
        label = "shared-memory crate import in engine model";
        needle = "crucible_shmem";
      }
      {
        label = "region size in engine model";
        needle = "region_size";
      }
      {
        label = "ring count in engine model";
        needle = "ring_count";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" crateRoot [
      {
        label = "logical topology physical-layout invariance test";
        needle = "world_logical_topology_ignores_physical_transport_layout";
      }
      {
        label = "test uses actual shmem region config";
        needle = "crucible_shmem::RegionConfig::new";
      }
      {
        label = "test uses actual shmem region layout";
        needle = "crucible_shmem::RegionLayout::for_config";
      }
      {
        label = "test poisons world id with physical layout";
        needle = "world_with_physical_layout_id";
      }
      {
        label = "test proves physical ids differ";
        needle = "assert_ne!(compact_world.id, expanded_world.id);";
      }
      {
        label = "test scenario identity invariance";
        needle = "assert_eq!(compact_world.scenario_def(), expanded_world.scenario_def());";
      }
      {
        label = "test bake identity invariance";
        needle = "assert_eq!(compact_baked.checkpoint.id, expanded_baked.checkpoint.id);";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/src/lib.rs" shmemRoot [
      {
        label = "physical layout isolated in shmem crate";
        needle = "pub struct RegionLayout";
      }
      {
        label = "region config isolated in shmem crate";
        needle = "pub struct RegionConfig";
      }
      {
        label = "queue capacity isolated in shmem crate";
        needle = "pub queue_capacity: u32";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes spatial logical topology check";
        needle = "spatialLogicalTopology = import ./phase1-spatial-logical-topology.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 spatial logical topology check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-spatial-logical-topology";
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
          name = "run-spatial-logical-topology";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --features test-double \
              --target-dir "$TMPDIR/crucible-spatial-logical-topology-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --lib \
              world_logical_topology \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --features test-double \
              --target-dir "$TMPDIR/crucible-spatial-logical-topology-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test world_devices \
              transport_layout_is_derived_and_cannot_change_world_or_device_identity \
              -- --exact --test-threads=1
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
            spatial_graph_task=logical-topology-no-physical-layout
            world_identity=independent-of-transport-layout
            physical_layout_home=crucible-shmem
            engine_world_schema=nodes-and-links-only
            RESULT
          '';
        }
      ];
    }
