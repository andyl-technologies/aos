{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuPluginFailLoud",
  taskIds ? [],
  openTaskIds ? ["T-PLUG-22"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  pluginAbi = builtins.concatStringsSep "\n" [
    (builtins.readFile ../../crates/crucible-qemu-plugin/src/abi.rs)
    (builtins.readFile ../../crates/crucible-qemu-plugin/src/abi/tests.rs)
  ];
  pluginSetup = import ./_qemu-plugin-setup-source.nix {inherit lib;};
  pluginHandshake = builtins.readFile ../../crates/crucible-qemu-plugin/src/handshake.rs;
  pluginRegistration = import ./_qemu-plugin-registration-source.nix {inherit lib;};
  pluginDeadline = builtins.readFile ../../crates/crucible-qemu-plugin/src/deadline.rs;
  pluginTimeControl = import ./_qemu-plugin-time-control-source.nix {inherit lib;};
  pluginInbound = builtins.readFile ../../crates/crucible-qemu-plugin/src/inbound.rs;
  pluginIdleLoop = builtins.readFile ../../crates/crucible-qemu-plugin/src/idle_loop.rs;
  pluginNetworkTx = builtins.readFile ../../crates/crucible-qemu-plugin/src/network_tx.rs;
  pluginNetworkRx = builtins.readFile ../../crates/crucible-qemu-plugin/src/network_rx.rs;
  pluginBlockIo = builtins.readFile ../../crates/crucible-qemu-plugin/src/block_io.rs;
  pluginNinePIo = builtins.readFile ../../crates/crucible-qemu-plugin/src/ninep_io.rs;
  pluginWhitebox = builtins.concatStringsSep "\n" [
    (builtins.readFile ../../crates/crucible-qemu-plugin/src/whitebox_doorbell.rs)
    (builtins.readFile ../../crates/crucible-qemu-plugin/src/whitebox_doorbell/tests.rs)
  ];
  pluginCoverage = builtins.concatStringsSep "\n" [
    (builtins.readFile ../../crates/crucible-qemu-plugin/src/coverage.rs)
    (builtins.readFile ../../crates/crucible-qemu-plugin/src/coverage/tests.rs)
  ];
  pluginSpec = builtins.readFile ../../docs/rfcs/0010-crucible/12-qemu-plugin.md;
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

  forbiddenFallbackApis = [
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
  ];

  failLoudSources = [
    {
      label = "crates/crucible-qemu-plugin/src/abi.rs";
      content = pluginAbi;
    }
    {
      label = "crates/crucible-qemu-plugin/src/setup.rs";
      content = pluginSetup;
    }
    {
      label = "crates/crucible-qemu-plugin/src/handshake.rs";
      content = pluginHandshake;
    }
    {
      label = "crates/crucible-qemu-plugin/src/registration.rs";
      content = pluginRegistration;
    }
    {
      label = "crates/crucible-qemu-plugin/src/deadline.rs";
      content = pluginDeadline;
    }
    {
      label = "crates/crucible-qemu-plugin/src/time_control.rs";
      content = pluginTimeControl;
    }
    {
      label = "crates/crucible-qemu-plugin/src/idle_loop.rs";
      content = pluginIdleLoop;
    }
    {
      label = "crates/crucible-qemu-plugin/src/inbound.rs";
      content = pluginInbound;
    }
    {
      label = "crates/crucible-qemu-plugin/src/network_rx.rs";
      content = pluginNetworkRx;
    }
    {
      label = "crates/crucible-qemu-plugin/src/network_tx.rs";
      content = pluginNetworkTx;
    }
    {
      label = "crates/crucible-qemu-plugin/src/block_io.rs";
      content = pluginBlockIo;
    }
    {
      label = "crates/crucible-qemu-plugin/src/ninep_io.rs";
      content = pluginNinePIo;
    }
    {
      label = "crates/crucible-qemu-plugin/src/whitebox_doorbell.rs";
      content = pluginWhitebox;
    }
    {
      label = "crates/crucible-qemu-plugin/src/coverage.rs";
      content = pluginCoverage;
    }
  ];

  forbiddenFallbackFailures =
    lib.concatMap (
      source:
        lib.concatMap (
          api:
            lib.optionals (hasInfix api source.content) [
              "${source.label}: forbidden wall-clock, timeout, or entropy fallback API in fail-loud path: `${api}`"
            ]
        )
        forbiddenFallbackApis
    )
    failLoudSources;

  failures =
    failuresFor "docs/rfcs/0010-crucible/12-qemu-plugin.md" pluginSpec [
      {
        label = "T-PLUG-22 remains open until live QEMU callback integration";
        needle = "- [ ] **T-PLUG-22**";
      }
      {
        label = "PLUG-48 wording";
        needle = "Any failure of the determinism-critical machinery MUST fail loud";
      }
      {
        label = "diagnosable divergence wording";
        needle = "distinct, diagnosable failure";
      }
      {
        label = "no wall-clock fallback wording";
        needle = "wall-clock-dependent fallback";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/abi.rs" pluginAbi [
      {
        label = "negative argc diagnostic";
        needle = "NegativeArgc";
      }
      {
        label = "missing argv diagnostic";
        needle = "MissingArgv";
      }
      {
        label = "missing info diagnostic";
        needle = "MissingInfo";
      }
      {
        label = "ABI range diagnostic";
        needle = "UnsupportedPluginApi";
      }
      {
        label = "exact deadline ABI capability diagnostic";
        needle = "ExactDeadlineCapability";
      }
      {
        label = "queued advance ABI capability diagnostic";
        needle = "QueuedIdleAdvanceCapability";
      }
      {
        label = "ABI missing-capability entrypoint test";
        needle = "abi_install_entrypoint_fails_closed_without_exact_deadline_or_queued_advance_symbols";
      }
      {
        label = "ABI unsupported model test";
        needle = "abi_qemu_install_path_validates_execution_model_before_success";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/handshake.rs" pluginHandshake [
      {
        label = "protocol IPC failure wrapper";
        needle = "PluginHandshakeError::Protocol";
      }
      {
        label = "slot out-of-range diagnostic";
        needle = "LaunchSlotOutOfRange";
      }
      {
        label = "slot mismatch diagnostic";
        needle = "LaunchSlotMismatch";
      }
      {
        label = "protocol failure preservation test";
        needle = "plugin_handshake_preserves_protocol_failures";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/setup.rs" pluginSetup [
      {
        label = "setup receive failure";
        needle = "PluginSetupError::ReceiveSetup";
      }
      {
        label = "nonzero setup failure ack";
        needle = "plugin_send_setup_ack(writer, SETUP_ACK_STATUS_SETUP_FAILED)";
      }
      {
        label = "failure ack stage diagnostic";
        needle = "PluginSetupFailureStage";
      }
      {
        label = "failure ack send diagnostic";
        needle = "SendFailureAck";
      }
      {
        label = "wrong descriptor count test";
        needle = "receive_setup_sends_nonzero_ack_when_descriptor_count_is_wrong";
      }
      {
        label = "region validation failure test";
        needle = "prepare_setup_sends_nonzero_ack_when_region_validation_fails";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/registration.rs" pluginRegistration [
      {
        label = "step-scoped failure record";
        needle = "pub struct PluginRegistrationFailure";
      }
      {
        label = "diagnostic accessor";
        needle = "pub fn diagnostic(&self) -> &str";
      }
      {
        label = "fail-step API";
        needle = "pub fn fail_step";
      }
      {
        label = "after-failure block";
        needle = "AfterFailure";
      }
      {
        label = "control handshake failure mapping";
        needle = "fail_control_handshake";
      }
      {
        label = "setup receive failure mapping";
        needle = "fail_setup_receive";
      }
      {
        label = "setup preparation failure mapping";
        needle = "fail_setup_preparation";
      }
      {
        label = "exact deadline failure mapping";
        needle = "fail_exact_deadline_capability";
      }
      {
        label = "queued advance failure mapping";
        needle = "fail_queued_idle_advance_capability";
      }
      {
        label = "coverage failure mapping";
        needle = "fail_coverage_capability";
      }
      {
        label = "closed socket diagnostic test";
        needle = "registration_order_aborts_without_later_steps_after_failure";
      }
      {
        label = "exact deadline missing test";
        needle = "registration_order_fails_loud_when_exact_deadline_capability_missing";
      }
      {
        label = "queued advance missing test";
        needle = "registration_order_fails_loud_when_queued_idle_advance_missing";
      }
      {
        label = "coverage missing test";
        needle = "registration_coverage_on_requires_basic_block_callback_capability";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/deadline.rs" pluginDeadline [
      {
        label = "exact deadline missing capability";
        needle = "CapabilityUnavailable";
      }
      {
        label = "overshoot fallback rejected";
        needle = "OvershootFallbackForbidden";
      }
      {
        label = "exact deadline capability test";
        needle = "exact_deadline_fails_when_capability_is_missing";
      }
      {
        label = "overshoot fallback test";
        needle = "exact_deadline_rejects_overshoot_and_correct_fallback";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/time_control.rs" pluginTimeControl [
      {
        label = "queued advance capability error";
        needle = "QueuedIdleAdvanceError::CapabilityUnavailable";
      }
      {
        label = "direct advance range diagnostic";
        needle = "VirtualTimeOutOfRange";
      }
      {
        label = "queued advance missing test";
        needle = "queued_idle_advance_requires_qemu_enqueue_symbol";
      }
      {
        label = "queued advance range test";
        needle = "queued_idle_advance_rejects_targets_outside_qemu_signed_range";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/inbound.rs" pluginInbound [
      {
        label = "inbound late delivery diagnostic";
        needle = "DeliveryAlreadyPassed";
      }
      {
        label = "inbound ring operation diagnostic";
        needle = "RingOperation";
      }
      {
        label = "late head test";
        needle = "inbound_frame_drain_rejects_late_head_without_consuming";
      }
      {
        label = "late candidate test";
        needle = "inbound_frame_select_rejects_late_candidate_frame";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/idle_loop.rs" pluginIdleLoop [
      {
        label = "idle exact deadline failure";
        needle = "IdleHotLoopError::ReadExactDeadline";
      }
      {
        label = "idle queued advance failure";
        needle = "IdleHotLoopError::QueuedIdleAdvance";
      }
      {
        label = "idle inbound failure";
        needle = "IdleHotLoopError::InboundFrames";
      }
      {
        label = "idle RX failure";
        needle = "IdleHotLoopError::NetworkRxInjection";
      }
      {
        label = "idle queue failure no commit test";
        needle = "idle_loop_rx_queue_failure_does_not_commit_inbound_ring_reads";
      }
      {
        label = "idle passed delivery tests";
        needle = "idle_loop_rejects_late_inbound_ring_before_direct_advance";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/network_rx.rs" pluginNetworkRx [
      {
        label = "network RX missing capability";
        needle = "NetworkRxError::CapabilityUnavailable";
      }
      {
        label = "network RX late delivery";
        needle = "DeliveryAlreadyPassed";
      }
      {
        label = "network RX queue failure";
        needle = "NetworkRxError::Queue";
      }
      {
        label = "network RX flush failure";
        needle = "NetworkRxError::Flush";
      }
      {
        label = "network RX capability test";
        needle = "network_rx_requires_qemu_net_send_and_flush_symbols";
      }
      {
        label = "network RX queue failure test";
        needle = "network_rx_queue_failure_is_loud_without_flush";
      }
      {
        label = "network RX flush failure test";
        needle = "network_rx_flush_failure_is_loud_after_queueing";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/network_tx.rs" pluginNetworkTx [
      {
        label = "network TX enqueue failure";
        needle = "RingOperation";
      }
      {
        label = "network TX queue full test";
        needle = "network_tx_rejects_full_ring_loudly_without_dropping_or_sequence_advance";
      }
      {
        label = "network TX queue full error";
        needle = "SpscRingError::QueueFull";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/block_io.rs" pluginBlockIo [
      {
        label = "block enqueue failure";
        needle = "RingEnqueueFailed";
      }
      {
        label = "block dequeue failure";
        needle = "RingDequeue";
      }
      {
        label = "block malformed response";
        needle = "MalformedResponse";
      }
      {
        label = "block queue full test";
        needle = "block_submit_full_ring_releases_freeze_token_loudly";
      }
      {
        label = "block guest completion failure test";
        needle = "block_poll_guest_completion_failure_still_releases_freeze_token";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/ninep_io.rs" pluginNinePIo [
      {
        label = "9p enqueue failure";
        needle = "RingEnqueueFailed";
      }
      {
        label = "9p dequeue failure";
        needle = "RingDequeue";
      }
      {
        label = "9p malformed response";
        needle = "MalformedResponse";
      }
      {
        label = "9p queue full test";
        needle = "ninep_submit_full_ring_releases_request_token_and_pending_id";
      }
      {
        label = "9p guest completion failure test";
        needle = "ninep_poll_guest_completion_failure_still_releases_request_token";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/whitebox_doorbell.rs" pluginWhitebox [
      {
        label = "whitebox missing capability";
        needle = "WhiteboxDoorbellError::CapabilityUnavailable";
      }
      {
        label = "whitebox late input";
        needle = "InputDeliveryAlreadyPassed";
      }
      {
        label = "whitebox late input test";
        needle = "whitebox_guest_input_rejects_late_delivery";
      }
      {
        label = "whitebox guest memory failure";
        needle = "GuestMemoryRead";
      }
      {
        label = "whitebox capability test";
        needle = "whitebox_guest_input_requires_qemu_guest_memory_write_capability";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/coverage.rs" pluginCoverage [
      {
        label = "coverage missing capability";
        needle = "CoverageError::CapabilityUnavailable";
      }
      {
        label = "coverage capability test";
        needle = "coverage_registration_on_mode_requires_basic_block_callback_capability";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes plugin fail-loud check";
        needle = "qemuPluginFailLoud = import ./phase2-plugin-fail-loud.nix";
      }
    ]
    ++ forbiddenFallbackFailures;
in
  if failures != []
  then throw "crucible phase2 plugin fail-loud check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-plugin-fail-loud";
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
          name = "run-plugin-fail-loud";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi

            target_dir="$TMPDIR/crucible-plugin-fail-loud-target"
            for filter in \
              abi_install_entrypoint_fails_closed_without_exact_deadline_or_queued_advance_symbols \
              abi_qemu_install_path_validates_execution_model_before_success \
              plugin_handshake_preserves_protocol_failures \
              receive_setup_sends_nonzero_ack_when_descriptor_count_is_wrong \
              prepare_setup_sends_nonzero_ack_when_region_validation_fails \
              registration_order_aborts_without_later_steps_after_failure \
              registration_order_fails_loud_when_exact_deadline_capability_missing \
              registration_order_fails_loud_when_queued_idle_advance_missing \
              registration_coverage_on_requires_basic_block_callback_capability \
              exact_deadline_fails_when_capability_is_missing \
              exact_deadline_rejects_overshoot_and_correct_fallback \
              queued_idle_advance_requires_qemu_enqueue_symbol \
              queued_idle_advance_rejects_targets_outside_qemu_signed_range \
              inbound_frame_drain_rejects_late_head_without_consuming \
              inbound_frame_select_rejects_late_candidate_frame \
              idle_loop_rejects_late_inbound_ring_before_direct_advance \
              idle_loop_rx_queue_failure_does_not_commit_inbound_ring_reads \
              network_rx_requires_qemu_net_send_and_flush_symbols \
              network_rx_rejects_late_frame_before_queue_or_flush \
              network_rx_queue_failure_is_loud_without_flush \
              network_rx_flush_failure_is_loud_after_queueing \
              network_tx_rejects_full_ring_loudly_without_dropping_or_sequence_advance \
              block_submit_full_ring_releases_freeze_token_loudly \
              block_poll_guest_completion_failure_still_releases_freeze_token \
              ninep_submit_full_ring_releases_request_token_and_pending_id \
              ninep_poll_guest_completion_failure_still_releases_request_token \
              whitebox_guest_input_requires_qemu_guest_memory_write_capability \
              whitebox_guest_input_rejects_late_delivery \
              coverage_registration_on_mode_requires_basic_block_callback_capability
            do
              cargo test \
                --frozen \
                --offline \
                --target-dir "$target_dir" \
                --manifest-path crates/Cargo.toml \
                -p crucible-qemu-plugin \
                "$filter" \
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
            tasks=${taskList}
            open_tasks=${openTaskList}
            status=partial
            broken_ipc=step-scoped-diagnostic
            missing_capability=distinct-errors
            abi_mismatch=unsupported-api-diagnostic
            full_ring=queuefull-preserved
            passed_delivery_icount=fail-loud-no-consume
            wall_clock_fallback=forbidden
            RESULT
          '';
        }
      ];
    }
