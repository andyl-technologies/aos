{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuPluginNetworkTx",
  taskIds ? ["T-PLUG-10"],
  openTaskIds ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  pluginLib = builtins.readFile ../../crates/crucible-qemu-plugin/src/lib.rs;
  pluginNetworkTx = builtins.readFile ../../crates/crucible-qemu-plugin/src/network_tx.rs;
  pluginSpec = builtins.readFile ../../docs/rfcs/0010-crucible/12-qemu-plugin.md;
  shmemLib = builtins.readFile ../../crates/crucible-shmem/src/lib.rs;
  shmemFrameNode = builtins.readFile ../../crates/crucible-shmem/src/shmem/frame_node.rs;
  shmemRingCoverage = builtins.readFile ../../crates/crucible-shmem/src/shmem/ring_coverage.rs;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;
  openTaskList = builtins.concatStringsSep "," openTaskIds;

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

  forbiddenCallbackApis = [
    "Instant::now"
    "SystemTime::now"
    "std::time::Instant"
    "std::time::SystemTime"
    "thread::sleep"
    "park_timeout"
    "clock_gettime"
    "gettimeofday"
    "CLOCK_REALTIME"
    "CLOCK_MONOTONIC"
    "thread_rng"
    "rand::random"
    "Mutex"
    "RwLock"
    ".lock()"
  ];

  forbiddenCallbackFailures =
    lib.concatMap (
      api:
        lib.optionals (hasInfix api pluginNetworkTx) [
          "crates/crucible-qemu-plugin/src/network_tx.rs: forbidden host-time, entropy, or lock API in network TX callback path: `${api}`"
        ]
    )
    forbiddenCallbackApis;

  failures =
    failuresFor "docs/rfcs/0010-crucible/12-qemu-plugin.md" pluginSpec [
      {
        label = "T-PLUG-10 is closed by live QEMU callback integration";
        needle = "- [x] **T-PLUG-10**";
      }
      {
        label = "network TX wording";
        needle = "Implement the network TX interception callback";
      }
      {
        label = "oversize/full-ring wording";
        needle = "rejecting oversize frames and full rings loudly";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/lib.rs" pluginLib [
      {
        label = "network TX module exported";
        needle = "pub mod network_tx;";
      }
      {
        label = "network TX state exported";
        needle = "PluginNetworkTx";
      }
      {
        label = "network TX ring exported";
        needle = "NetworkTxRing";
      }
      {
        label = "network TX error exported";
        needle = "NetworkTxError";
      }
      {
        label = "network TX safe callback body exported";
        needle = "handle_network_tx_callback";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/network_tx.rs" pluginNetworkTx [
      {
        label = "network TX state";
        needle = "pub struct PluginNetworkTx";
      }
      {
        label = "registration-time directed ring binding";
        needle = "pub fn from_directed_ring";
      }
      {
        label = "reserved router slot";
        needle = "SLOT_NET_ROUTER";
      }
      {
        label = "fixed outbound ring mismatch";
        needle = "WrongOutboundRing";
      }
      {
        label = "callback enqueue method";
        needle = "pub fn enqueue_guest_frame";
      }
      {
        label = "safe callback body";
        needle = "pub fn handle_network_tx_callback";
      }
      {
        label = "emit icount stamp";
        needle = "FrameEntry::new(emit_icount, self.src_slot, seq, payload)";
      }
      {
        label = "per-ring sequence counter";
        needle = "next_seq: Cell<u32>";
      }
      {
        label = "sequence overflow guard";
        needle = "checked_add(1)";
      }
      {
        label = "sequence advances after success";
        needle = "self.next_seq.set(next_seq)";
      }
      {
        label = "SPSC enqueue";
        needle = "PluginShmemOrdering::enqueue_outbound_frame";
      }
      {
        label = "ring operation error";
        needle = "RingOperation";
      }
      {
        label = "oversized payload error";
        needle = "PayloadTooLarge";
      }
      {
        label = "full ring test uses SPSC full error";
        needle = "SpscRingError::QueueFull";
      }
      {
        label = "stamp test";
        needle = "network_tx_enqueue_stamps_emit_icount_source_sequence_and_payload";
      }
      {
        label = "wrong ring test";
        needle = "network_tx_rejects_wrong_ring_without_enqueuing_or_advancing_sequence";
      }
      {
        label = "safe callback body test";
        needle = "network_tx_safe_callback_body_delegates_to_fixed_enqueue_state";
      }
      {
        label = "wrong producer test";
        needle = "wrong_producer_ring";
      }
      {
        label = "oversize test";
        needle = "network_tx_rejects_oversized_payload_without_truncation_or_sequence_advance";
      }
      {
        label = "full ring test";
        needle = "network_tx_rejects_full_ring_loudly_without_dropping_or_sequence_advance";
      }
      {
        label = "full ring preserves queued frames";
        needle = "first_before";
      }
      {
        label = "reentrant idle path test";
        needle = "network_tx_idle_reentrant_path_uses_fixed_state_without_locks";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/src/lib.rs" shmemLib [
      {
        label = "router slot constant";
        needle = "pub const SLOT_NET_ROUTER";
      }
      {
        label = "frame payload capacity";
        needle = "pub const MAX_FRAME_DATA";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/src/shmem/frame_node.rs" shmemFrameNode [
      {
        label = "frame constructor";
        needle = "pub fn new(";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/src/shmem/ring_coverage.rs" shmemRingCoverage [
      {
        label = "SPSC enqueue";
        needle = "pub fn enqueue(";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes plugin network TX check";
        needle = "qemuPluginNetworkTx = import ./phase2-plugin-network-tx.nix";
      }
    ]
    ++ forbiddenCallbackFailures;
in
  if failures != []
  then throw "crucible phase2 plugin network-TX check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-plugin-network-tx";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
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
          name = "run-plugin-network-tx";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-plugin-network-tx-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              network_tx \
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
            open_tasks=${openTaskList}
            status=complete
            live_gate=checks.crucible.phase2.qemuLiveNetworkIo
            network_tx_ring=vm-slot-to-net-router
            emit_icount=stamped-in-delivery-icount
            sequence=per-ring-monotonic
            reentrant_state=registration-fixed-no-locks
            oversize_payload=loud-error-no-truncation
            full_ring=loud-error-no-drop
            callback_host_time_apis=forbidden
            RESULT
          '';
        }
      ];
    }
