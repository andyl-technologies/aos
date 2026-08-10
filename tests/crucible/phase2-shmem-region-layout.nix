{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.shmemRegionLayout",
  taskIds ? ["T-SHM-1" "T-SHM-2" "T-SHM-4" "T-SHM-5" "T-SHM-12"],
}: let
  root = ../..;
  cratesDir = root + "/crates";
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-ULD9g6d87886b8O6/sGCMktquGwaUAyf+DLHUrFzod0=";
  };

  shmemContract = builtins.concatStringsSep "\n" [
    (import ./_crucible-shmem-source.nix {inherit lib;})
    (builtins.readFile ../../crates/crucible-shmem/src/shmem/frame_node.rs)
    (builtins.readFile ../../crates/crucible-shmem/src/shmem/frame_node/frame_entry.rs)
    (builtins.readFile ../../crates/crucible-shmem/src/shmem/region.rs)
    (builtins.readFile ../../crates/crucible-shmem/src/shmem/ring_coverage.rs)
  ];
  regionTest = builtins.readFile ../../crates/crucible-shmem/tests/region_layout.rs;
  shmemSpec = builtins.readFile ../../docs/rfcs/0010-crucible/13-shmem-abi.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  rustSources = dir: displayPrefix: let
    entries =
      if builtins.pathExists dir
      then builtins.readDir dir
      else {};
  in
    lib.concatMap (
      name: let
        path = dir + "/${name}";
        display =
          if displayPrefix == ""
          then name
          else "${displayPrefix}/${name}";
        kind = entries.${name};
      in
        if kind == "directory"
        then rustSources path display
        else if kind == "regular" && lib.hasSuffix ".rs" name
        then [
          {
            inherit path display;
          }
        ]
        else []
    ) (lib.sort builtins.lessThan (builtins.attrNames entries));

  crateEntries = builtins.readDir cratesDir;
  packages =
    lib.filter (package: crateEntries.${package} == "directory")
    (builtins.attrNames crateEntries);
  nonShmemSources =
    lib.concatMap (
      package:
        if package == "crucible-shmem"
        then []
        else
          map (
            source:
              source
              // {
                inherit package;
              }
          ) (rustSources (cratesDir + "/${package}") "")
    )
    packages;

  maxNodesEscapeFailures =
    lib.concatMap (
      source:
        lib.optionals (hasInfix "MAX_NODES" (builtins.readFile source.path)) [
          "crates/${source.package}/${source.display}: MAX_NODES escaped crucible-shmem"
        ]
    )
    nonShmemSources;

  failures =
    failuresFor "crates/crucible-shmem source modules" shmemContract [
      {
        label = "region magic";
        needle = "pub const REGION_MAGIC: u64 = u64::from_le_bytes(*b\"CRUCSHM1\");";
      }
      {
        label = "ABI version";
        needle = "pub const ABI_VERSION: u32 = 10;";
      }
      {
        label = "physical slot capacity";
        needle = "pub const MAX_NODES: usize = 32;";
      }
      {
        label = "reserved slot count";
        needle = "pub const RESERVED_SLOTS: usize = 3;";
      }
      {
        label = "maximum VM node count";
        needle = "pub const MAX_VM_NODES: usize = MAX_NODES - RESERVED_SLOTS;";
      }
      {
        label = "network router slot";
        needle = "pub const SLOT_NET_ROUTER: usize = MAX_NODES - 1;";
      }
      {
        label = "block I/O slot";
        needle = "pub const SLOT_BLK_IO: usize = MAX_NODES - 2;";
      }
      {
        label = "9p I/O slot";
        needle = "pub const SLOT_9P_IO: usize = MAX_NODES - 3;";
      }
      {
        label = "region header ABI";
        needle = "pub struct RegionHeader";
      }
      {
        label = "node slot ABI";
        needle = "pub struct NodeSlot";
      }
      {
        label = "ring header ABI";
        needle = "pub struct RingHeader";
      }
      {
        label = "frame entry ABI";
        needle = "pub struct FrameEntry";
      }
      {
        label = "coverage entry ABI";
        needle = "pub struct CoverageEntry";
      }
      {
        label = "coverage queue cardinality";
        needle = "pub const COVERAGE_QUEUE_CAPACITY: u32 = 65_536;";
      }
      {
        label = "region header size";
        needle = "pub const REGION_HEADER_SIZE";
      }
      {
        label = "region header magic offset";
        needle = "REGION_HEADER_MAGIC_OFFSET == 0";
      }
      {
        label = "region header shutdown offset";
        needle = "REGION_HEADER_SHUTDOWN_REQUESTED_OFFSET == 61";
      }
      {
        label = "region header reserved offset";
        needle = "REGION_HEADER_RESERVED_OFFSET == 62";
      }
      {
        label = "node slot size";
        needle = "pub const NODE_SLOT_SIZE";
      }
      {
        label = "node slot pad offset";
        needle = "NODE_SLOT_PAD0_OFFSET == 39";
      }
      {
        label = "node slot logical-time raw offset";
        needle = "NODE_SLOT_LOGICAL_TIME_RAW_ICOUNT_OFFSET == 104";
      }
      {
        label = "ring header size";
        needle = "pub const RING_HEADER_SIZE";
      }
      {
        label = "ring header read padding offset";
        needle = "RING_HEADER_PAD_READ_OFFSET == 8";
      }
      {
        label = "ring header write padding offset";
        needle = "RING_HEADER_PAD_WRITE_OFFSET == 72";
      }
      {
        label = "frame entry size";
        needle = "pub const FRAME_ENTRY_SIZE";
      }
      {
        label = "frame entry padding offset";
        needle = "FRAME_ENTRY_PAD_OFFSET == 18";
      }
      {
        label = "pinned layout target";
        needle = "pub const LAYOUT_TARGET_TRIPLE: &str = \"x86_64-unknown-linux-gnu\";";
      }
      {
        label = "target validator";
        needle = "pub fn validate_layout_target";
      }
      {
        label = "GNU target environment pin";
        needle = "target_env = \"gnu\"";
      }
      {
        label = "64-bit target pointer width pin";
        needle = "target_pointer_width = \"64\"";
      }
      {
        label = "default target ABI pin";
        needle = "target_abi = \"\"";
      }
      {
        label = "unsupported target error";
        needle = "UnsupportedTarget";
      }
      {
        label = "region config";
        needle = "pub struct RegionConfig";
      }
      {
        label = "region layout";
        needle = "pub struct RegionLayout";
      }
      {
        label = "region allocation";
        needle = "pub struct RegionAllocation";
      }
      {
        label = "per-VM coverage ring geometry";
        needle = "pub coverage_ring_count: u32";
      }
      {
        label = "coverage storage extent";
        needle = "pub fn coverage_entry_count(&self) -> u64";
      }
      {
        label = "layout geometry computation";
        needle = "pub fn for_config(config: RegionConfig)";
      }
      {
        label = "header initialization from layout";
        needle = "pub fn new(layout: RegionLayout) -> Self";
      }
      {
        label = "owned region allocation";
        needle = "pub fn new(config: RegionConfig) -> Result<Self, RegionLayoutError>";
      }
      {
        label = "directed ring map";
        needle = "pub struct DirectedRing";
      }
      {
        label = "reserved executor slot enum";
        needle = "pub enum ReservedExecutorSlot";
      }
      {
        label = "VM-to-executor ring allocation";
        needle = "src_slot: vm_slot";
      }
      {
        label = "executor-to-VM ring allocation";
        needle = "src_slot: executor_slot";
      }
      {
        label = "header reserved zero check";
        needle = "pub fn reserved_bytes_are_zero(&self) -> bool";
      }
      {
        label = "node reserved zero check";
        needle = "&& self._reserved.iter().all(|byte| *byte == 0)";
      }
      {
        label = "ring padding zero check";
        needle = "pub fn padding_bytes_are_zero(&self) -> bool";
      }
    ]
    ++ forbiddenFor "crates/crucible-shmem source modules" shmemContract [
      {
        label = "public raw header magic";
        needle = "pub magic: AtomicU64";
      }
      {
        label = "public raw node count";
        needle = "pub node_count: AtomicU32";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/tests/region_layout.rs" regionTest [
      {
        label = "header layout test";
        needle = "region_header_layout_matches_wire_contract";
      }
      {
        label = "computed geometry test";
        needle = "region_layout_computes_offsets_and_directed_rings";
      }
      {
        label = "coverage entry layout assertions";
        needle = "assert_eq!(COVERAGE_ENTRY_SIZE, 64);";
      }
      {
        label = "header records geometry test";
        needle = "region_header_records_computed_geometry";
      }
      {
        label = "invalid shape rejection test";
        needle = "region_layout_rejects_invalid_shapes";
      }
      {
        label = "unsupported target rejection test";
        needle = "region_allocation_rejects_unpinned_developer_targets";
      }
      {
        label = "Linux allocation initialization test";
        needle = "region_allocation_initializes_slots_rings_and_storage";
      }
      {
        label = "reserved executor slot stability test";
        needle = "reserved_executor_slot_constants_are_stable";
      }
    ]
    ++ forbiddenFor "crates/crucible-shmem/tests/region_layout.rs" regionTest [
      {
        label = "ignored region layout test";
        needle = "#[ignore";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/13-shmem-abi.md" shmemSpec [
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes shmem region layout check";
        needle = "shmemRegionLayout = import ./phase2-shmem-region-layout.nix";
      }
    ]
    ++ maxNodesEscapeFailures;
in
  if failures != []
  then throw "crucible phase2 shmem region layout check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-shmem-region-layout";
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
          name = "run-shmem-region-layout";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-shmem-region-layout-target" \
              -p crucible-shmem \
              --test region_layout \
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
            gate=gate:abi-conformance
            gate=gate:layer1-injection
            rust_tests=crucible-shmem::region_layout
            layout_target=x86_64-unknown-linux-gnu
            max_nodes_escape=false
            region_header=true
            region_allocation=true
            directed_rings=vm_to_reserved_executors
            coverage_rings=one_per_vm_capacity_65536
            RESULT
          '';
        }
      ];
    }
