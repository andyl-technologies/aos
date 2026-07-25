{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuPluginBlockIo",
  taskIds ? [],
  openTaskIds ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  pluginLib = builtins.readFile ../../crates/crucible-qemu-plugin/src/lib.rs;
  pluginBlockIo = builtins.readFile ../../crates/crucible-qemu-plugin/src/block_io.rs;
  pluginSpec = builtins.readFile ../../docs/rfcs/0010-crucible/12-qemu-plugin.md;
  shmemSources = builtins.concatStringsSep "\n" (map builtins.readFile [
    ../../crates/crucible-shmem/src/lib.rs
    ../../crates/crucible-shmem/src/shmem/frame_node.rs
    ../../crates/crucible-shmem/src/shmem/region.rs
    ../../crates/crucible-shmem/src/shmem/ring_coverage.rs
  ]);
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
        lib.optionals (hasInfix api pluginBlockIo) [
          "crates/crucible-qemu-plugin/src/block_io.rs: forbidden host-time, entropy, or lock API in block callback path: `${api}`"
        ]
    )
    forbiddenCallbackApis;

  failures =
    failuresFor "docs/rfcs/0010-crucible/12-qemu-plugin.md" pluginSpec [
      {
        label = "T-PLUG-12 completed by live QEMU callback integration";
        needle = "- [x] **T-PLUG-12**";
      }
      {
        label = "T-PLUG-12 live completion evidence";
        needle = "Completed by `checks.crucible.phase2.qemuLiveBlockIo`";
      }
      {
        label = "block callback wording";
        needle = "Implement the block submit/poll callbacks against the";
      }
      {
        label = "delivery icount wording";
        needle = "validating the response's";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/lib.rs" pluginLib [
      {
        label = "block I/O module exported";
        needle = "pub mod block_io;";
      }
      {
        label = "block I/O state exported";
        needle = "PluginBlockIo";
      }
      {
        label = "block outbound ring exported";
        needle = "BlockOutboundRing";
      }
      {
        label = "block inbound ring exported";
        needle = "BlockInboundRing";
      }
      {
        label = "block request exported";
        needle = "BlockRequest";
      }
      {
        label = "block response exported";
        needle = "BlockResponse";
      }
      {
        label = "block error exported";
        needle = "BlockIoError";
      }
      {
        label = "block submit callback exported";
        needle = "handle_block_submit_callback";
      }
      {
        label = "block poll callback exported";
        needle = "handle_block_poll_callback";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/block_io.rs" pluginBlockIo [
      {
        label = "block state";
        needle = "pub struct PluginBlockIo";
      }
      {
        label = "registration-time directed ring binding";
        needle = "pub fn from_directed_rings";
      }
      {
        label = "reserved block executor slot";
        needle = "SLOT_BLK_IO";
      }
      {
        label = "outbound block ring view";
        needle = "pub struct BlockOutboundRing";
      }
      {
        label = "inbound block ring view";
        needle = "pub struct BlockInboundRing";
      }
      {
        label = "submit path";
        needle = "pub fn submit_request";
      }
      {
        label = "poll path";
        needle = "pub fn poll_response";
      }
      {
        label = "safe submit callback body";
        needle = "pub fn handle_block_submit_callback";
      }
      {
        label = "safe poll callback body";
        needle = "pub fn handle_block_poll_callback";
      }
      {
        label = "block operation wire types";
        needle = "pub enum BlockOperation";
      }
      {
        label = "read operation";
        needle = "Read";
      }
      {
        label = "write operation";
        needle = "Write";
      }
      {
        label = "flush operation";
        needle = "Flush";
      }
      {
        label = "get-length operation";
        needle = "GetLength";
      }
      {
        label = "wire version";
        needle = "BLOCK_WIRE_VERSION";
      }
      {
        label = "little-endian request encoding";
        needle = "request_id.to_le_bytes()";
      }
      {
        label = "little-endian response decoding";
        needle = "u32::from_le_bytes";
      }
      {
        label = "reserved response field validation";
        needle = "NonZeroReserved";
      }
      {
        label = "exact response count validation";
        needle = "ResponseCountPayloadMismatch";
      }
      {
        label = "request frame stamp";
        needle = "FrameEntry::new(submit_icount, self.vm_slot, request_id, &payload)";
      }
      {
        label = "freeze before publish";
        needle = "freeze\n            .begin_independent_submit(slot, submit_icount)";
      }
      {
        label = "SPSC enqueue";
        needle = "PluginShmemOrdering::enqueue_outbound_frame";
      }
      {
        label = "enqueue failure releases freeze token";
        needle = ".fail_request(slot, device_token)";
      }
      {
        label = "request id sequence advances after success";
        needle = "self.next_request_id.set(next_request_id)";
      }
      {
        label = "response head preview";
        needle = "fn peek_head_frame";
      }
      {
        label = "delivery icount preview";
        needle = "PluginShmemOrdering::peek_inbound_delivery_icount";
      }
      {
        label = "future delivery gate";
        needle = "head.delivery_icount > current_icount";
      }
      {
        label = "request id match";
        needle = "response.request_id() != token.request_id";
      }
      {
        label = "response source match";
        needle = "head.src_node != self.block_slot";
      }
      {
        label = "malformed response fails token";
        needle = "BlockIoError::MalformedResponse";
      }
      {
        label = "unexpected source fails token";
        needle = "UnexpectedSource";
      }
      {
        label = "SPSC dequeue after validation";
        needle = "PluginShmemOrdering::dequeue_inbound_frame";
      }
      {
        label = "guest completion";
        needle = "complete_block_response";
      }
      {
        label = "freeze completion before guest completion";
        needle = "freeze\n            .complete_request(slot, token.device_token)";
      }
      {
        label = "freeze token failure helper";
        needle = "fn fail_polled_request";
      }
      {
        label = "wrong outbound ring error";
        needle = "WrongOutboundRing";
      }
      {
        label = "wrong inbound ring error";
        needle = "WrongInboundRing";
      }
      {
        label = "request id overflow error";
        needle = "RequestIdOverflow";
      }
      {
        label = "enqueue failure error";
        needle = "RingEnqueueFailed";
      }
      {
        label = "unexpected response error";
        needle = "UnexpectedResponse";
      }
      {
        label = "state binding test";
        needle = "block_io_state_binds_reserved_block_rings";
      }
      {
        label = "submit encode/freeze test";
        needle = "block_submit_encodes_request_stamps_icount_and_freezes_time";
      }
      {
        label = "wrong ring test";
        needle = "block_submit_wrong_ring_does_not_freeze_or_enqueue";
      }
      {
        label = "full ring fail-release test";
        needle = "block_submit_full_ring_releases_freeze_token_loudly";
      }
      {
        label = "poll delivery gate test";
        needle = "block_poll_returns_not_ready_until_delivery_icount_is_reached";
      }
      {
        label = "request id mismatch test";
        needle = "block_poll_rejects_wrong_request_id_and_releases_freeze_token";
      }
      {
        label = "wrong response source test";
        needle = "block_poll_rejects_wrong_response_source_and_releases_freeze_token";
      }
      {
        label = "guest completion failure releases test";
        needle = "block_poll_guest_completion_failure_still_releases_freeze_token";
      }
      {
        label = "response wire validation test";
        needle = "block_response_decode_rejects_nonzero_reserved_and_trailing_payload";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/src/{lib.rs,shmem/*.rs}" shmemSources [
      {
        label = "block slot constant";
        needle = "pub const SLOT_BLK_IO";
      }
      {
        label = "directed ring type";
        needle = "pub struct DirectedRing";
      }
      {
        label = "frame constructor";
        needle = "pub fn new(";
      }
      {
        label = "SPSC enqueue";
        needle = "pub fn enqueue(";
      }
      {
        label = "SPSC dequeue";
        needle = "pub fn dequeue";
      }
      {
        label = "delivery icount peek";
        needle = "pub fn peek_delivery_icount";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes plugin block I/O check";
        needle = "qemuPluginBlockIo = import ./phase2-plugin-block-io.nix";
      }
    ]
    ++ forbiddenCallbackFailures;
in
  if failures != []
  then throw "crucible phase2 plugin block-I/O check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-plugin-block-io";
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
          name = "run-plugin-block-io";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-plugin-block-io-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              block_ \
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
            block_rings=vm-slot-to-block-io-and-return
            submit_icount=stamped-in-request-frame
            device_io_freeze=begin-submit-before-enqueue
            enqueue_failure=fail-request-token
            delivery_gate=response-icount-before-guest-completion
            request_pairing=token-request-id-must-match-response
            reentrant_state=registration-fixed-no-locks
            callback_host_time_apis=forbidden
            RESULT
          '';
        }
      ];
    }
