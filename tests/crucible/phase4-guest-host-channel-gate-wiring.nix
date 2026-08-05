{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.guestHostChannelGateWiring",
  taskIds ? ["T-GHC-15"],
  openTaskIds ? [],
  qemuLiveWhiteboxDoorbell ? import ./phase2-qemu-live-whitebox-doorbell.nix {inherit pkgs lib;},
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoVendor {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-fWBTuyTXJ+/0BiVbB5WAtCqVwufg04NH4BJdocT+moU=";
  };

  phase2SingleVmFingerprintDefinition = import ./phase1-single-vm-fingerprint-gate.nix {
    inherit pkgs lib;
    attrPath = "checks.crucible.phase2.gates.singleVmFingerprint";
    taskIds = [];
  };
  phase2AnyGuestDefinition = import ./phase2-any-guest.nix {
    inherit pkgs lib;
    attrPath = "checks.crucible.phase2.gates.anyGuest";
    taskIds = ["T-DET-22" "T-HARN-16"];
    dependencies = [phase2SingleVmFingerprintDefinition];
  };
  phase4ChannelDeterminismDefinition = import ./phase4-guest-host-channel-determinism.nix {
    inherit pkgs lib;
    attrPath = "checks.crucible.phase4.guestHostChannelDeterminism";
    taskIds = [];
    openTaskIds = ["T-GHC-12"];
  };
  phase4EmitterAbsenceDefinition = import ./phase4-guest-host-emitter-absence.nix {
    inherit pkgs lib;
    attrPath = "checks.crucible.phase4.guestHostEmitterAbsence";
    taskIds = ["T-GHC-11"];
  };

  anyGuestTest = builtins.readFile ../../crates/crucible-qemu/tests/gate_any_guest.rs;
  channelDeterminismTest = builtins.readFile ../../crates/crucible/tests/guest_host_channel_determinism.rs;
  blackBoxSurfaceGate = builtins.readFile ./phase4-guest-host-black-box-surface.nix;
  singleVmGate = builtins.readFile ./phase1-single-vm-fingerprint-gate.nix;
  anyGuestGate = builtins.readFile ./phase2-any-guest.nix;
  channelGate = builtins.readFile ./phase4-guest-host-channel-determinism.nix;
  emitterAbsenceGate = builtins.readFile ./phase4-guest-host-emitter-absence.nix;
  liveWhiteboxGate = builtins.readFile ./phase2-qemu-live-whitebox-doorbell.nix;
  phaseGate = builtins.readFile ./phase4-guest-host-channel-gate-wiring.nix;
  guestHostDoc = builtins.readFile ../../docs/rfcs/0010-crucible/16-guest-host-channel.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  openTaskList = builtins.concatStringsSep "," openTaskIds;
  canonicalGate = "checks.crucible.phase4.guestHostChannelGateWiring";
  failures =
    failuresFor "docs/rfcs/0010-crucible/16-guest-host-channel.md" guestHostDoc [
      {
        label = "T-GHC-15 completion note";
        needle = "Completed by";
      }
      {
        label = "canonical channel wiring no longer deferred";
        needle = "gate definition files in lazy passthru";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/tests/gate_any_guest.rs" anyGuestTest [
      {
        label = "black-box host-side launch profile";
        needle = "gate_any_guest_launch_profile_requires_host_side_guest_operation";
      }
      {
        label = "no in-guest Crucible content rejection";
        needle = "GuestCoreContentMode::GuestInjectedContent";
      }
      {
        label = "white-box switch is host plugin config";
        needle = "gate_any_guest_whitebox_switch_is_host_plugin_configuration_without_agent_content";
      }
      {
        label = "single VM fingerprint driver covers off/on";
        needle = "run_single_vm_fingerprint_gate";
      }
      {
        label = "white-box off plugin argument";
        needle = "whitebox=off";
      }
      {
        label = "white-box on plugin argument";
        needle = "whitebox=on";
      }
      {
        label = "fingerprint stream comparison";
        needle = "compare_single_vm_fingerprint_streams";
      }
      {
        label = "launch hash unchanged by white-box switch";
        needle = "gate_any_guest_launch_command_keeps_whitebox_as_host_plugin_configuration";
      }
      {
        label = "launch material equality";
        needle = "black_box.vm_launch_hash_material()";
      }
    ]
    ++ failuresFor "crates/crucible/tests/guest_host_channel_determinism.rs" channelDeterminismTest [
      {
        label = "white-box on/off fingerprint equality";
        needle = "whitebox_channel_fingerprints_are_identical_with_markers_on_vs_off";
      }
      {
        label = "disabled policy witness";
        needle = "WhiteBoxPolicy::Disabled";
      }
      {
        label = "enabled policy witness";
        needle = "WhiteBoxPolicy::Enabled";
      }
      {
        label = "black-box event floor in channel run";
        needle = "black_box_events()";
      }
      {
        label = "opt-in marker events";
        needle = "marker_events()";
      }
      {
        label = "causal event-log fingerprint equality";
        needle = "markers_off.causal_event_log_fingerprint";
      }
      {
        label = "backend fingerprint equality";
        needle = "markers_on.backend_fingerprint";
      }
      {
        label = "determinism comparison ignores marker additivity";
        needle = "compare_event_log_determinism(&markers_off.event_log, &markers_on.event_log)";
      }
    ]
    ++ failuresFor "tests/crucible/phase4-guest-host-black-box-surface.nix" blackBoxSurfaceGate [
      {
        label = "required black-box surface result";
        needle = "surface=network,disk-9p,console-serial,qmp-state,run-outcome,crash-hang,basic-block-coverage";
      }
      {
        label = "black-box observations are observational";
        needle = "determinism_class=observational";
      }
    ]
    ++ failuresFor "tests/crucible/phase1-single-vm-fingerprint-gate.nix" singleVmGate [
      {
        label = "single VM fingerprint gate result";
        needle = "gate=gate:single-vm-fingerprint";
      }
      {
        label = "real QEMU source result";
        needle = "real_qemu_source=checks.crucible.phase0.s1Fingerprint";
      }
      {
        label = "black-box execution fingerprint";
        needle = "execution_fingerprint=icount-registers-ram";
      }
      {
        label = "read-only observation mode";
        needle = "observation_mode=plugin-read-only";
      }
      {
        label = "mismatch remains failing";
        needle = "mismatch_policy=first-mismatch-is-failure";
      }
    ]
    ++ failuresFor "tests/crucible/phase2-any-guest.nix" anyGuestGate [
      {
        label = "any-guest gate result";
        needle = "gate=gate:any-guest";
      }
      {
        label = "diskless black-box fingerprints match";
        needle = "diskless_black_box_fingerprints_match=true";
      }
      {
        label = "no in-guest agent required";
        needle = "in_guest_crucible_agent_required=false";
      }
      {
        label = "no in-guest content required";
        needle = "in_guest_crucible_content_required=false";
      }
      {
        label = "white-box consumed separately";
        needle = "whitebox_contract_consumed=separate-host-plugin-doorbell-gate";
      }
      {
        label = "any-guest live run remains black-box";
        needle = "whitebox_real_qemu_any_guest_enabled=false";
      }
      {
        label = "host-side black-box trace plugin";
        needle = "trace_plugin=host-side-black-box-fingerprint";
      }
    ]
    ++ failuresFor "tests/crucible/phase4-guest-host-channel-determinism.nix" channelGate [
      {
        label = "scheduler marker fingerprint equality";
        needle = "marker_fingerprint=scheduler-witness-identical-with-markers-on-vs-off";
      }
      {
        label = "canonical gate wiring pointer";
        needle = "canonical_gate_wiring=${canonicalGate}";
      }
    ]
    ++ failuresFor "tests/crucible/phase4-guest-host-emitter-absence.nix" emitterAbsenceGate [
      {
        label = "emitter absence preserves black-box function";
        needle = "preserved=determinism,faults,coverage,observable-io,backend-fingerprint";
      }
      {
        label = "canonical gate wiring pointer";
        needle = "canonical_gate_wiring=${canonicalGate}";
      }
    ]
    ++ failuresFor "tests/crucible/phase2-qemu-live-whitebox-doorbell.nix" liveWhiteboxGate [
      {
        label = "live white-box off/on modes";
        needle = "run_mode off off";
      }
      {
        label = "live white-box marker mode";
        needle = "run_mode on on";
      }
      {
        label = "live off/on fingerprint equality";
        needle = "test \"$off_fingerprint\" = \"$on_fingerprint\"";
      }
      {
        label = "live marker host event-log admission";
        needle = "marker_event_log_admission=true";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 channel gate wiring import";
        needle = "guestHostChannelGateWiring = import ./phase4-guest-host-channel-gate-wiring.nix";
      }
      {
        label = "phase4 channel gate wiring attr path";
        needle = "checks.crucible.phase4.guestHostChannelGateWiring";
      }
      {
        label = "phase4 channel gate wiring task id";
        needle = "taskIds = [\"T-GHC-15\"]";
      }
      {
        label = "phase4 channel gate consumes live white-box result";
        needle = "qemuLiveWhiteboxDoorbell = phase2.qemuLiveWhiteboxDoorbell;";
      }
      {
        label = "phase2 single-VM fingerprint canonical gate attr";
        needle = "attrPath = \"checks.crucible.phase2.gates.singleVmFingerprint\";";
      }
      {
        label = "phase2 qemu-inert canonical gate attr";
        needle = "attrPath = \"checks.crucible.phase2.gates.qemuInert\";";
      }
      {
        label = "phase2 any-guest canonical gate attr";
        needle = "attrPath = \"checks.crucible.phase2.gates.anyGuest\";";
      }
      {
        label = "phase2 qemu-inert depends on patch microtests";
        needle = "dependencies = [patchMicrotests.rawGate];";
      }
      {
        label = "phase2 single-VM fingerprint depends on qemu-inert";
        needle = "dependencies = [qemuInert.rawGate];";
      }
      {
        label = "phase2 any-guest depends on single-VM fingerprint";
        needle = "dependencies = [singleVmFingerprint.rawGate];";
      }
    ]
    ++ forbiddenFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 gate forcing any-guest during eval";
        needle = "anyGuest = phase2.gates.anyGuest.rawGate;";
      }
      {
        label = "phase4 gate forcing single-VM fingerprint during eval";
        needle = "singleVmFingerprint = phase2.gates.singleVmFingerprint.rawGate;";
      }
    ]
    ++ failuresFor "tests/crucible/phase4-guest-host-channel-gate-wiring.nix" phaseGate [
      {
        label = "phase gate keeps gate definitions lazy";
        needle = "passthru.lazyGateDefinitions = {";
      }
      {
        label = "phase gate owns lazy any-guest definition";
        needle = "phase2AnyGuestDefinition = import ./phase2-any-guest.nix";
      }
      {
        label = "phase gate owns lazy single-VM fingerprint definition";
        needle = "phase2SingleVmFingerprintDefinition = import ./phase1-single-vm-fingerprint-gate.nix";
      }
      {
        label = "phase gate owns lazy channel determinism definition";
        needle = "phase4ChannelDeterminismDefinition = import ./phase4-guest-host-channel-determinism.nix";
      }
      {
        label = "phase gate owns lazy emitter absence definition";
        needle = "phase4EmitterAbsenceDefinition = import ./phase4-guest-host-emitter-absence.nix";
      }
      {
        label = "phase gate passthru binds lazy any-guest definition";
        needle = "anyGuest = phase2AnyGuestDefinition;";
      }
      {
        label = "phase gate passthru binds lazy single-VM fingerprint definition";
        needle = "singleVmFingerprint = phase2SingleVmFingerprintDefinition;";
      }
      {
        label = "phase gate passthru binds lazy channel determinism definition";
        needle = "channelDeterminism = phase4ChannelDeterminismDefinition;";
      }
      {
        label = "phase gate passthru binds lazy emitter absence definition";
        needle = "emitterAbsence = phase4EmitterAbsenceDefinition;";
      }
      {
        label = "phase gate records lazy passthru definitions";
        needle = "lazy_gate_definitions=passthru.lazyGateDefinitions.anyGuest";
      }
      {
        label = "phase gate reruns any-guest off/on test target";
        needle = "--test gate_any_guest";
      }
      {
        label = "phase gate reruns channel determinism target";
        needle = "--test guest_host_channel_determinism";
      }
      {
        label = "phase gate reruns white-box on/off fingerprint proof";
        needle = "whitebox_channel_fingerprints_are_identical_with_markers_on_vs_off";
      }
    ]
    ++ forbiddenFor "tests/crucible/phase4-guest-host-channel-determinism.nix" channelGate [
      {
        label = "deferred channel gate wiring";
        needle = "canonical_gate_wiring_deferred=T-GHC-15";
      }
    ]
    ++ forbiddenFor "tests/crucible/phase4-guest-host-emitter-absence.nix" emitterAbsenceGate [
      {
        label = "deferred emitter absence gate wiring";
        needle = "canonical_gate_wiring_deferred=T-GHC-15";
      }
    ]
    ++ forbiddenFor "crates/crucible-qemu/tests/gate_any_guest.rs" anyGuestTest [
      {
        label = "ignored any-guest test";
        needle = "#[ignore";
      }
      {
        label = "unfinished todo";
        needle = "todo!";
      }
      {
        label = "unfinished unimplemented";
        needle = "unimplemented!";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/guest_host_channel_determinism.rs" channelDeterminismTest [
      {
        label = "ignored channel determinism test";
        needle = "#[ignore";
      }
      {
        label = "unfinished todo";
        needle = "todo!";
      }
      {
        label = "unfinished unimplemented";
        needle = "unimplemented!";
      }
    ];
in
  if failures != []
  then
    throw ''
      crucible phase4 guest-host channel gate wiring check failed:
      ${builtins.concatStringsSep "\n" failures}
    ''
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-guest-host-channel-gate-wiring";
      version = "0";
      src = crucibleSrc;
      buildDeps = [
        pkgs.coreutils
        pkgs.rust
        pkgs.sed
        qemuLiveWhiteboxDoorbell
      ];
      passthru.lazyGateDefinitions = {
        anyGuest = phase2AnyGuestDefinition;
        singleVmFingerprint = phase2SingleVmFingerprintDefinition;
        channelDeterminism = phase4ChannelDeterminismDefinition;
        emitterAbsence = phase4EmitterAbsenceDefinition;
      };
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
            set -eu
            export CARGO_HOME="$TMPDIR/cargo-home"
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            mkdir -p "$CARGO_HOME" .cargo
            sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
                > .cargo/config.toml
          '';
        }
        {
          name = "run-guest-host-channel-gate-wiring";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi

            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-channel-gate-wiring-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu \
              --test gate_any_guest \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-channel-gate-wiring-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --features test-double \
              --test guest_host_channel_determinism \
              whitebox_channel_fingerprints_are_identical_with_markers_on_vs_off \
              -- --test-threads=1

            grep -Fxq PASS ${qemuLiveWhiteboxDoorbell}/result
            grep -Fxq 'whitebox_modes=off,on' ${qemuLiveWhiteboxDoorbell}/result
            grep -Fxq 'marker_event_log_admission=true' ${qemuLiveWhiteboxDoorbell}/result
            grep -Fxq 'off_on_fingerprint_equal=true' ${qemuLiveWhiteboxDoorbell}/result
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
            evidence_scope=canonical-gate-binding-with-live-whitebox-run
            gate=gate:any-guest,gate:single-vm-fingerprint
            black_box_sufficiency=gate:any-guest:no-agent-no-content
            opt_in_additivity=whitebox-host-plugin-switch-no-guest-content
            real_qemu_black_box_sufficiency=gate:any-guest
            real_qemu_fingerprint_axis=gate:single-vm-fingerprint:icount-registers-ram
            real_qemu_whitebox_off_on_fingerprint=byte-identical
            real_qemu_whitebox_marker_event_log_admission=true
            fingerprint_equality=host-plugin-off-on-gate-target-and-scheduler-marker-neutral
            canonical_gate_wiring=complete
            lazy_gate_definitions=passthru.lazyGateDefinitions.anyGuest,passthru.lazyGateDefinitions.singleVmFingerprint,passthru.lazyGateDefinitions.channelDeterminism,passthru.lazyGateDefinitions.emitterAbsence
            source_gates=checks.crucible.phase2.gates.anyGuest,checks.crucible.phase2.gates.singleVmFingerprint,checks.crucible.phase2.qemuLiveWhiteboxDoorbell,checks.crucible.phase4.guestHostChannelDeterminism,checks.crucible.phase4.guestHostEmitterAbsence
            RESULT
          '';
        }
      ];
    }
