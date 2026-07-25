{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.simDouble",
  taskIds ? ["T-HARN-3"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  simBackend = builtins.readFile ../../crates/crucible/src/sim_backend.rs;
  crateRoot = builtins.readFile ../../crates/crucible/src/lib.rs;
  cargoManifest = builtins.readFile ../../crates/crucible/Cargo.toml;
  shmem = builtins.concatStringsSep "\n" [
    (builtins.readFile ../../crates/crucible-shmem/src/lib.rs)
    (builtins.readFile ../../crates/crucible-shmem/src/shmem/frame_node.rs)
    (builtins.readFile ../../crates/crucible-shmem/src/shmem/region.rs)
    (builtins.readFile ../../crates/crucible-shmem/src/shmem/ring_coverage.rs)
  ];
  protocol = builtins.readFile ../../crates/crucible-protocol/src/lib.rs;
  defaultChecks = builtins.readFile ./default.nix;
  harnessTesting = builtins.readFile ../../docs/rfcs/0010-crucible/24-determinism-harness-testing.md;

  hasInfix = needle: haystack: let
    needleLen = builtins.stringLength needle;
    haystackLen = builtins.stringLength haystack;
    maxStart = haystackLen - needleLen;
    indexes =
      if needleLen == 0
      then [0]
      else if maxStart < 0
      then []
      else builtins.genList (index: index) (maxStart + 1);
  in
    builtins.any (index:
      builtins.substring index needleLen haystack == needle)
    indexes;

  failuresFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (!(hasInfix requirement.needle content)) [
          "${fileLabel}: missing ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  forbiddenFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (hasInfix requirement.needle content) [
          "${fileLabel}: forbidden ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  failures =
    failuresFor "docs/rfcs/0010-crucible/24-determinism-harness-testing.md" harnessTesting [
      {
        label = "T-HARN-3 checked off";
        needle = "- [x] **T-HARN-3**";
      }
      {
        label = "T-HARN-3 completion note";
        needle = "Completed by `crucible::SimDouble`";
      }
    ]
    ++ failuresFor "crates/crucible/Cargo.toml" cargoManifest [
      {
        label = "shared shmem dependency";
        needle = ''crucible-shmem = { path = "../crucible-shmem", optional = true }'';
      }
      {
        label = "shared protocol dependency";
        needle = ''crucible-protocol = { path = "../crucible-protocol" }'';
      }
      {
        label = "test-double feature dependencies";
        needle = ''test-double = ["dep:crucible-shmem"]'';
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" crateRoot [
      {
        label = "SimDouble export";
        needle = "SimDouble";
      }
      {
        label = "SimDouble config export";
        needle = "SimDoubleConfig";
      }
      {
        label = "SimDouble script export";
        needle = "SimInstructionScript";
      }
    ]
    ++ failuresFor "crates/crucible/src/sim_backend.rs" simBackend [
      {
        label = "SimDouble type";
        needle = "pub struct SimDouble";
      }
      {
        label = "plugin-side shared memory model";
        needle = "struct SimDoubleShmem";
      }
      {
        label = "canonical shmem allocation";
        needle = "RegionAllocation::new_model(config)?";
      }
      {
        label = "real shmem allocation access errors";
        needle = "RegionAllocationAccessError";
      }
      {
        label = "real directed SPSC enqueue";
        needle = ".enqueue_directed_frame(src_slot, dst_slot, frame)";
      }
      {
        label = "real directed SPSC dequeue";
        needle = ".dequeue_directed_frame(src_slot, dst_slot)";
      }
      {
        label = "real directed SPSC peek";
        needle = ".peek_directed_frame(src_slot, dst_slot)";
      }
      {
        label = "shared protocol lifecycle";
        needle = "ControlLifecycle::new()";
      }
      {
        label = "real protocol decode";
        needle = "control_decode_host_msg(frame)?";
      }
      {
        label = "shared handshake validation";
        needle = "plugin_validate_handshake_ack";
      }
      {
        label = "real setup header validation";
        needle = "validate_setup_region_header(self.shmem.header_snapshot(), region_len)?";
      }
      {
        label = "real protocol encode";
        needle = "control_encode_plugin_msg(&PluginMsg::Hello";
      }
      {
        label = "lookahead delivery ceiling";
        needle = "authorize_sim_double_delivery_ceiling";
      }
      {
        label = "instruction-budget script";
        needle = "pub struct SimInstructionScript";
      }
      {
        label = "scripted quantum advance";
        needle = "advance_scripted_quantum";
      }
      {
        label = "synthetic fingerprint";
        needle = "synthetic_fingerprint";
      }
      {
        label = "synthetic register file";
        needle = "synthetic_register_file";
      }
      {
        label = "synthetic memory region";
        needle = "synthetic_memory_region";
      }
      {
        label = "sequence-bearing inbound API";
        needle = "enqueue_inbound_frame_with_sequence";
      }
      {
        label = "canonical delivery key";
        needle = "FrameDeliveryKey";
      }
      {
        label = "no host wall clock";
        needle = "StableHasher::new()";
      }
      {
        label = "SPSC test coverage";
        needle = "sim_double_runs_script_through_real_spsc_ring_and_fingerprint";
      }
      {
        label = "protocol lifecycle test coverage";
        needle = "sim_double_speaks_real_control_protocol_lifecycle";
      }
      {
        label = "out-of-order lifecycle test coverage";
        needle = "sim_double_rejects_out_of_order_control_lifecycle";
      }
      {
        label = "lookahead test coverage";
        needle = "sim_double_does_not_advance_past_pending_inbound_delivery";
      }
      {
        label = "canonical inbound order test coverage";
        needle = "sim_double_delivers_inbound_frames_by_canonical_key";
      }
    ]
    ++ failuresFor "crates/crucible-shmem split modules" shmem [
      {
        label = "shmem ABI region";
        needle = "pub struct RegionHeader";
      }
      {
        label = "SPSC queue implementation";
        needle = "pub struct RingHeader";
      }
      {
        label = "SPSC frame peek";
        needle = "pub fn peek(&self, entries: &[FrameEntry])";
      }
      {
        label = "frame entry ABI";
        needle = "pub struct FrameEntry";
      }
      {
        label = "canonical typed allocation";
        needle = "pub struct RegionAllocation";
      }
      {
        label = "developer-host shmem model allocation";
        needle = "pub fn new_model(config: RegionConfig)";
      }
      {
        label = "typed directed-ring access";
        needle = "pub enum RegionAllocationAccessError";
      }
    ]
    ++ failuresFor "crates/crucible-protocol/src/lib.rs" protocol [
      {
        label = "host/plugin codec";
        needle = "pub fn control_decode_host_msg";
      }
      {
        label = "plugin encoder";
        needle = "pub fn control_encode_plugin_msg";
      }
      {
        label = "control messages";
        needle = "pub enum PluginMsg";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes SimDouble check";
        needle = "simDouble = import ./phase1-sim-double.nix";
      }
    ]
    ++ forbiddenFor "crates/crucible/src/sim_backend.rs" simBackend [
      {
        label = "wall-clock dependency";
        needle = "SystemTime";
      }
      {
        label = "thread RNG dependency";
        needle = "thread_rng";
      }
      {
        label = "unordered hash map";
        needle = "HashMap";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 SimDouble check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-sim-double";
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
          name = "run-sim-double";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-sim-double-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --features test-double \
              sim_double_ \
              -- --test-threads=1

            mkdir -p "$out"
            cat > "$out/result" <<RESULT
            PASS
            check=${attrPath}
            tasks=${builtins.concatStringsSep "," taskIds}
            gate=gate:sim-double
            sim_double=crucible::SimDouble
            shared_shmem_abi=true
            shared_spsc_queue=true
            shared_protocol_codec=true
            shared_protocol_lifecycle=true
            canonical_shmem_allocation=true
            canonical_inbound_order=true
            lookahead_delivery_ceiling=true
            instruction_budget_script=true
            synthetic_fingerprint=true
            deterministic_no_wall_clock_rng_or_hashmap=true
            RESULT
          '';
        }
      ];
    }
