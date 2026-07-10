{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.hostObservableSchedule",
  taskIds ? [],
  openTaskIds ? ["T-HARN-4"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  simBackend = builtins.readFile ../../crates/crucible/src/sim_backend.rs;
  crateRoot = builtins.readFile ../../crates/crucible/src/lib.rs;
  pluginManifest = builtins.readFile ../../crates/crucible-qemu-plugin/Cargo.toml;
  pluginNetworkRx = builtins.readFile ../../crates/crucible-qemu-plugin/src/network_rx.rs;
  pluginNetworkTx = builtins.readFile ../../crates/crucible-qemu-plugin/src/network_tx.rs;
  pluginTimeControl = import ./_qemu-plugin-time-control-source.nix {inherit lib;};
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

  failures =
    failuresFor "docs/rfcs/0010-crucible/24-determinism-harness-testing.md" harnessTesting [
      {
        label = "T-HARN-4 remains open";
        needle = "- [ ] **T-HARN-4**";
      }
      {
        label = "T-HARN-4 partial-evidence note";
        needle = "Partial callback-core evidence is provided by";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" crateRoot [
      {
        label = "host schedule event export";
        needle = "SimDoubleHostScheduleEvent";
      }
    ]
    ++ failuresFor "crates/crucible/src/sim_backend.rs" simBackend [
      {
        label = "host schedule event type";
        needle = "pub enum SimDoubleHostScheduleEvent";
      }
      {
        label = "horizon event";
        needle = "HorizonAdvance";
      }
      {
        label = "frame delivery event";
        needle = "FrameDelivery";
      }
      {
        label = "frame emission event";
        needle = "FrameEmission";
      }
      {
        label = "I/O completion event";
        needle = "IoCompletion";
      }
      {
        label = "snapshot event";
        needle = "Snapshot";
      }
      {
        label = "schedule storage";
        needle = "host_observable_schedule: Vec<SimDoubleHostScheduleEvent>";
      }
      {
        label = "schedule accessor";
        needle = "pub fn host_observable_schedule(&self) -> &[SimDoubleHostScheduleEvent]";
      }
      {
        label = "horizon recording";
        needle = "SimDoubleHostScheduleEvent::HorizonAdvance";
      }
      {
        label = "delivery recording";
        needle = "SimDoubleHostScheduleEvent::FrameDelivery";
      }
      {
        label = "emission recording";
        needle = "SimDoubleHostScheduleEvent::FrameEmission";
      }
      {
        label = "real plugin sequence overflow parity";
        needle = "OutboundSequenceOverflow";
      }
      {
        label = "fail-before-commit outbound sequence";
        needle = "checked_add(1)";
      }
      {
        label = "sequence overflow regression";
        needle = "sim_double_rejects_outbound_sequence_overflow_like_real_plugin_tx";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/Cargo.toml" pluginManifest [
      {
        label = "test-only layer exception comment";
        needle = "Test-only HARN-16 cross-check: production plugin dependencies stay L1-only.";
      }
      {
        label = "test-only crucible dependency";
        needle = "crucible = { path = \"../crucible\", features = [\"test-double\", \"test-support\"] }";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/network_rx.rs" pluginNetworkRx [
      {
        label = "focused HARN-16 cross-check test";
        needle = "host_observable_schedule_cross_checks_sim_double_against_plugin_projection";
      }
      {
        label = "double schedule source";
        needle = "double.host_observable_schedule()";
      }
      {
        label = "double quantum driver";
        needle = "double.advance_scripted_quantum(horizon, &ALLOW_ALL_SENDS)";
      }
      {
        label = "plugin callback model schedule projection";
        needle = "plugin_projection_host_observable_schedule";
      }
      {
        label = "plugin projection clock";
        needle = "PluginVirtualClock";
      }
      {
        label = "plugin projection clock source assertion";
        needle = "PluginClockAdvanceSource::GuestInstructions";
      }
      {
        label = "plugin projection idle hot-loop";
        needle = "PluginIdleHotLoop";
      }
      {
        label = "plugin projection inbound ring surface";
        needle = "InboundFrameRing::new";
      }
      {
        label = "idle begin path";
        needle = "begin_idle_with_inbound_rings";
      }
      {
        label = "idle completion RX path";
        needle = "complete_after_scheduler_wake_from_inbound_rings_with_rx_injection";
      }
      {
        label = "idle wake cause assertion";
        needle = "IdleWakeCause::InboundFrame";
      }
      {
        label = "idle jump source assertion";
        needle = "PluginClockAdvanceSource::SchedulerAuthorizedIdleJump";
      }
      {
        label = "plugin projection RX callback";
        needle = "handle_network_rx_idle_callback";
      }
      {
        label = "plugin projection RX state";
        needle = "PluginNetworkRx::new()";
      }
      {
        label = "plugin projection TX callback";
        needle = "handle_network_tx_callback";
      }
      {
        label = "plugin projection TX state";
        needle = "PluginNetworkTx::new";
      }
      {
        label = "shared schedule event type";
        needle = "SimDoubleHostScheduleEvent";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/network_tx.rs" pluginNetworkTx [
      {
        label = "safe TX callback body";
        needle = "pub fn handle_network_tx_callback";
      }
      {
        label = "TX enqueue metadata";
        needle = "pub struct NetworkTxEnqueue";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/time_control.rs" pluginTimeControl [
      {
        label = "plugin virtual clock";
        needle = "pub struct PluginVirtualClock";
      }
      {
        label = "guest instruction advance";
        needle = "pub fn advance_guest_instructions";
      }
      {
        label = "clock advance metadata";
        needle = "pub struct PluginClockAdvance";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes host schedule check";
        needle = "hostObservableSchedule = import ./phase1-host-observable-schedule.nix";
      }
      {
        label = "phase1 gates expose host schedule check";
        needle = "attrPath = \"checks.crucible.phase1.gates.hostObservableSchedule\"";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 host-observable schedule check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-host-observable-schedule";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
        pkgs.rust
        pkgs.sed
      ] ++ dependencies;

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
          name = "run-host-observable-schedule";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-host-observable-schedule-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              --lib \
              host_observable_schedule_cross_checks_sim_double_against_plugin_projection \
              -- --test-threads=1

            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-host-observable-schedule-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --features test-double \
              --lib \
              sim_double_ \
              -- --test-threads=1

            mkdir -p "$out"
            cat > "$out/result" <<RESULT
            PASS
            check=${attrPath}
            tasks=${builtins.concatStringsSep "," taskIds}
            open_tasks=${builtins.concatStringsSep "," openTaskIds}
            status=partial
            evidence_scope=callback-core-model-not-installed-production-plugin
            sim_double_schedule_trace=true
            plugin_projection_clock_cross_check=true
            plugin_projection_rx_cross_check=true
            plugin_projection_tx_cross_check=true
            host_observable_schedule_identical=true
            RESULT
          '';
        }
      ];
    }
