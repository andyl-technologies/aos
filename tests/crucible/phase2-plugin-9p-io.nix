{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuPluginNinePIo",
  taskIds ? [],
  openTaskIds ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  pluginLib = builtins.readFile ../../crates/crucible-qemu-plugin/src/lib.rs;
  pluginNinePIo = builtins.readFile ../../crates/crucible-qemu-plugin/src/ninep_io.rs;
  pluginSpec = builtins.readFile ../../docs/rfcs/0010-crucible/12-qemu-plugin.md;
  shmemSources =
    builtins.concatStringsSep "\n"
    (map builtins.readFile [
      ../../crates/crucible-shmem/src/lib.rs
      ../../crates/crucible-shmem/src/shmem/frame_node.rs
      ../../crates/crucible-shmem/src/shmem/region.rs
      ../../crates/crucible-shmem/src/shmem/ring_coverage.rs
    ]);
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;
  openTaskList = builtins.concatStringsSep "," openTaskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

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
        lib.optionals (hasInfix api pluginNinePIo) [
          "crates/crucible-qemu-plugin/src/ninep_io.rs: forbidden host-time, entropy, or lock API in 9p callback path: `${api}`"
        ]
    )
    forbiddenCallbackApis;

  failures =
    failuresFor "docs/rfcs/0010-crucible/12-qemu-plugin.md" pluginSpec [
      {
        label = "T-PLUG-13 cites its live completion gate";
        needle = "Completed by `checks.crucible.phase2.qemuLive9pIo`";
      }
      {
        label = "9p callback wording";
        needle = "Implement the 9p submit/poll/burst-done callbacks against the";
      }
      {
        label = "whole burst wording";
        needle = "holding the freeze for the whole burst";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/lib.rs" pluginLib [
      {
        label = "9p module exported";
        needle = "pub mod ninep_io;";
      }
      {
        label = "9p state exported";
        needle = "PluginNinePIo";
      }
      {
        label = "9p outbound ring exported";
        needle = "NinePOutboundRing";
      }
      {
        label = "9p inbound ring exported";
        needle = "NinePInboundRing";
      }
      {
        label = "9p request exported";
        needle = "NinePRequest";
      }
      {
        label = "9p response exported";
        needle = "NinePResponse";
      }
      {
        label = "9p error exported";
        needle = "NinePIoError";
      }
      {
        label = "9p submit callback exported";
        needle = "handle_9p_submit_callback";
      }
      {
        label = "9p poll callback exported";
        needle = "handle_9p_poll_callback";
      }
      {
        label = "9p burst-done callback exported";
        needle = "handle_9p_burst_done_callback";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/ninep_io.rs" pluginNinePIo [
      {
        label = "9p state";
        needle = "pub struct PluginNinePIo";
      }
      {
        label = "registration-time directed ring binding";
        needle = "pub fn from_directed_rings";
      }
      {
        label = "reserved 9p executor slot";
        needle = "SLOT_9P_IO";
      }
      {
        label = "outbound 9p ring view";
        needle = "pub struct NinePOutboundRing";
      }
      {
        label = "inbound 9p ring view";
        needle = "pub struct NinePInboundRing";
      }
      {
        label = "burst start path";
        needle = "pub fn begin_burst";
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
        label = "burst done path";
        needle = "pub fn burst_done";
      }
      {
        label = "safe burst-start callback body";
        needle = "pub fn handle_9p_burst_start_callback";
      }
      {
        label = "safe submit callback body";
        needle = "pub fn handle_9p_submit_callback";
      }
      {
        label = "safe poll callback body";
        needle = "pub fn handle_9p_poll_callback";
      }
      {
        label = "safe burst-done callback body";
        needle = "pub fn handle_9p_burst_done_callback";
      }
      {
        label = "active burst required";
        needle = "if !freeze.burst_active()";
      }
      {
        label = "raw request frame stamp";
        needle = "FrameEntry::new(submit_icount, self.vm_slot, request_id, request.payload())";
      }
      {
        label = "SPSC enqueue";
        needle = "PluginShmemOrdering::enqueue_outbound_frame";
      }
      {
        label = "enqueue failure releases token";
        needle = ".fail_request(slot, device_token)";
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
        label = "response source match";
        needle = "head.src_node != self.ninep_slot";
      }
      {
        label = "request id match";
        needle = "head.seq != token.request_id";
      }
      {
        label = "fixed pending request table";
        needle = "struct PendingNinePRequests";
      }
      {
        label = "pending request insert";
        needle = "self.pending_request_ids.insert(request_id)";
      }
      {
        label = "out-of-order pending response is not ready";
        needle = "self.pending_request_ids.contains(head.seq)";
      }
      {
        label = "pending request removal";
        needle = "self.pending_request_ids.remove(request_id)";
      }
      {
        label = "freeze completion before guest completion";
        needle = "freeze\n            .complete_request(slot, token.device_token)";
      }
      {
        label = "burst-done freeze release";
        needle = ".burst_done(slot)";
      }
      {
        label = "request failure helper";
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
        label = "submit outside burst error";
        needle = "SubmitOutsideBurst";
      }
      {
        label = "pending request capacity error";
        needle = "PendingRequestCapacityExceeded";
      }
      {
        label = "unexpected source error";
        needle = "UnexpectedSource";
      }
      {
        label = "unexpected response error";
        needle = "UnexpectedResponse";
      }
      {
        label = "state binding test";
        needle = "ninep_io_state_binds_reserved_9p_rings";
      }
      {
        label = "burst required test";
        needle = "ninep_submit_requires_active_burst";
      }
      {
        label = "submit stamp test";
        needle = "ninep_submit_encodes_raw_message_stamps_icount_and_holds_burst";
      }
      {
        label = "whole burst hold test";
        needle = "ninep_poll_holds_burst_until_burst_done_after_all_requests_complete";
      }
      {
        label = "out-of-order multi-request burst test";
        needle = "ninep_poll_allows_out_of_order_due_response_for_another_pending_token";
      }
      {
        label = "poll delivery gate test";
        needle = "ninep_poll_returns_not_ready_until_delivery_icount_is_reached";
      }
      {
        label = "unknown request id test";
        needle = "ninep_poll_rejects_unknown_request_id_and_releases_request_token";
      }
      {
        label = "wrong response source test";
        needle = "ninep_poll_rejects_wrong_response_source_and_releases_request_token";
      }
      {
        label = "guest completion failure releases test";
        needle = "ninep_poll_guest_completion_failure_still_releases_request_token";
      }
      {
        label = "full ring release test";
        needle = "ninep_submit_full_ring_releases_request_token_and_pending_id";
      }
      {
        label = "request id overflow test";
        needle = "ninep_submit_rejects_request_id_overflow_before_freezing";
      }
      {
        label = "pending burst-done rejection test";
        needle = "ninep_burst_done_rejects_pending_requests_and_keeps_hold_active";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/src source tree" shmemSources [
      {
        label = "9p slot constant";
        needle = "pub const SLOT_9P_IO";
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
        label = "phase2 exposes plugin 9p I/O check";
        needle = "qemuPluginNinePIo = import ./phase2-plugin-9p-io.nix";
      }
    ]
    ++ forbiddenCallbackFailures;
in
  if failures != []
  then throw "crucible phase2 plugin 9p-I/O check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-plugin-9p-io";
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
          name = "run-plugin-9p-io";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-plugin-9p-io-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              ninep_ \
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
            status=partial
            ninep_rings=vm-slot-to-9p-io-and-return
            submit_icount=stamped-in-request-frame
            request_payload=raw-9p-message
            delivery_gate=response-icount-before-guest-completion
            burst_hold=active-from-burst-start-through-burst-done
            request_pairing=token-request-id-must-match-response
            reentrant_state=registration-fixed-no-locks
            callback_host_time_apis=forbidden
            RESULT
          '';
        }
      ];
    }
