{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.protocolInertness",
  taskIds ? ["T-PROTO-11"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  qemuLib = builtins.readFile ../../crates/crucible-qemu/src/lib.rs;
  inertnessLib = builtins.readFile ../../crates/crucible-qemu/src/inertness.rs;
  inertnessTest = builtins.readFile ../../crates/crucible-qemu/tests/protocol_inertness.rs;
  protocolSpec = builtins.readFile ../../docs/rfcs/0010-crucible/14-protocol.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;


  failures =
    failuresFor "crates/crucible-qemu/src/lib.rs" qemuLib [
      {
        label = "inertness module";
        needle = "mod inertness;";
      }
      {
        label = "inertness assertion export";
        needle = "assert_qemu_control_plane_inert";
      }
      {
        label = "observation export";
        needle = "QemuControlPlaneObservation";
      }
      {
        label = "simulation mode export";
        needle = "QemuSimulationMode";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/inertness.rs" inertnessLib [
      {
        label = "sim mode enum";
        needle = "pub enum QemuSimulationMode";
      }
      {
        label = "control-plane observation";
        needle = "pub struct QemuControlPlaneObservation";
      }
      {
        label = "sim-off constructor";
        needle = "pub fn sim_off(profile: &DeterministicLaunchProfile) -> Self";
      }
      {
        label = "sim-off stock TCG launch arguments";
        needle = "profile.canonical_sim_off_qemu_args()";
      }
      {
        label = "sim-on protocol constructor";
        needle = "pub fn sim_on_protocol_contract() -> Self";
      }
      {
        label = "inertness assertion function";
        needle = "pub fn assert_qemu_control_plane_inert";
      }
      {
        label = "sim-off control socket rejection";
        needle = "ControlSocketCreatedWhenSimulationOff";
      }
      {
        label = "sim-off control frame rejection";
        needle = "ControlFrameSentWhenSimulationOff";
      }
      {
        label = "sim-off plugin argument rejection";
        needle = "SIM_OFF_FORBIDDEN_ARG_FRAGMENTS";
      }
      {
        label = "protocol runtime data-plane contract";
        needle = "RUNTIME_DATA_PLANE_CONTRACT";
      }
      {
        label = "runtime frames forbidden";
        needle = "control_channel_carries_runtime_frames";
      }
      {
        label = "delivery icounts forbidden";
        needle = "control_channel_carries_delivery_icounts";
      }
      {
        label = "run silence required";
        needle = "control_channel_silent_between_setup_ack_and_quit";
      }
      {
        label = "run control frame rejection";
        needle = "ControlFrameObservedDuringRun";
      }
      {
        label = "timing significant payload rejection";
        needle = "TimingSignificantControlPayloads";
      }
      {
        label = "lifecycle class table";
        needle = "SIM_ON_CONTROL_FRAME_CLASSES";
      }
      {
        label = "lifecycle frames are not timing significant";
        needle = "timing_significant: false";
      }
      {
        label = "lifecycle frames are not allowed during run";
        needle = "allowed_during_run: false";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/tests/protocol_inertness.rs" inertnessTest [
      {
        label = "sim-off inertness test";
        needle = "sim_mode_off_creates_no_control_socket_and_sends_no_frames";
      }
      {
        label = "sim-off rejection test";
        needle = "sim_mode_off_rejects_control_plane_activation";
      }
      {
        label = "sim-on timing neutrality test";
        needle = "sim_mode_on_control_channel_is_timing_neutral_and_silent_during_run";
      }
      {
        label = "sim-on rejection test";
        needle = "sim_mode_on_rejects_timing_significant_or_run_phase_control_traffic";
      }
      {
        label = "canonical launch profile proof";
        needle = "DeterministicLaunchProfile::conservative_default()";
      }
      {
        label = "sim-off stock TCG assertion";
        needle = ''window == ["-accel", "tcg,thread=single"]'';
      }
      {
        label = "sim-off sim accelerator rejection assertion";
        needle = ''String::from("sim,thread=single")'';
      }
      {
        label = "runtime shared memory proof";
        needle = "RuntimeDataPlane::SharedMemory";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/14-protocol.md" protocolSpec [
      {
        label = "T-PROTO-11 checklist complete";
        needle = "- [x] **T-PROTO-11**";
      }
      {
        label = "gate qemu inert reference";
        needle = "`gate:qemu-inert`";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes protocol inertness check";
        needle = "protocolInertness = import ./phase2-protocol-inertness.nix";
      }
      {
        label = "full qemu inert gate implemented";
        needle = "qemuInert = import ./phase2-qemu-inert.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 protocol inertness check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-protocol-inertness";
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
          name = "run-protocol-inertness";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-protocol-inertness-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu \
              --test protocol_inertness \
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
            gate=gate:qemu-inert,gate:abi-conformance
            rust_test=crucible-qemu::protocol_inertness
            sim_off=stock-tcg-thread-single,no-control-socket,no-control-frames,no-plugin-args,no-sim-accelerator
            sim_on=shared-memory-runtime,no-runtime-control-frames,no-delivery-icounts,run-silent
            full_qemu_inert_gate=checks.crucible.phase2.gates.qemuInert
            RESULT
          '';
        }
      ];
    }
