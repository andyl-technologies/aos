{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.guestHostDoorbell",
  taskIds ? ["T-GHC-4"],
  openTaskIds ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  pluginLib = builtins.readFile ../../crates/crucible-qemu-plugin/src/lib.rs;
  pluginWhiteboxDoorbell = builtins.readFile ../../crates/crucible-qemu-plugin/src/whitebox_doorbell.rs;
  pluginWhiteboxDoorbellWithTests =
    pluginWhiteboxDoorbell
    + builtins.readFile ../../crates/crucible-qemu-plugin/src/whitebox_doorbell/tests.rs;
  guestHostDoc = builtins.readFile ../../docs/rfcs/0010-crucible/16-guest-host-channel.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;



  taskList = builtins.concatStringsSep "," taskIds;
  openTaskList = builtins.concatStringsSep "," openTaskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/16-guest-host-channel.md" guestHostDoc [
      {
        label = "T-GHC-4 completed";
        needle = "- [x] **T-GHC-4**";
      }
      {
        label = "T-GHC-4 completion note";
        needle = "Completed by";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "guest-host phase4 task range";
        needle = "Guest↔host channel + optional agent";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/lib.rs" pluginLib [
      {
        label = "payload source export";
        needle = "WhiteboxDoorbellPayloadSource";
      }
      {
        label = "doorbell callback export";
        needle = "handle_whitebox_doorbell_callback";
      }
      {
        label = "doorbell event export";
        needle = "WhiteboxDoorbellTrapEvent";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/whitebox_doorbell.rs and tests.rs" pluginWhiteboxDoorbellWithTests [
      {
        label = "white-box state";
        needle = "pub struct PluginWhiteboxDoorbell";
      }
      {
        label = "registration plan";
        needle = "pub fn registration_plan";
      }
      {
        label = "disabled mode installs no trap";
        needle = "WhiteboxDoorbellRegistrationPlan::Disabled";
      }
      {
        label = "reserved trap install";
        needle = "PluginDeviceCallbackKind::WhiteboxDoorbell";
      }
      {
        label = "synchronous callback body";
        needle = "pub fn handle_whitebox_doorbell_callback";
      }
      {
        label = "service trap method";
        needle = "pub fn service_trap";
      }
      {
        label = "trap event exact icount";
        needle = "pub struct WhiteboxDoorbellTrapEvent";
      }
      {
        label = "current icount accessor";
        needle = "pub const fn current_icount";
      }
      {
        label = "guest memory reader";
        needle = "pub trait GuestMemoryReader";
      }
      {
        label = "guest memory read gets current icount";
        needle = "event.current_icount()";
      }
      {
        label = "marker stamped at event icount";
        needle = "marker_icount: event.current_icount()";
      }
      {
        label = "payload source enum";
        needle = "pub enum WhiteboxDoorbellPayloadSource";
      }
      {
        label = "shared page source";
        needle = "SharedPage";
      }
      {
        label = "register pointer source";
        needle = "RegisterPointerLength";
      }
      {
        label = "payload source accessor";
        needle = "pub const fn payload_source";
      }
      {
        label = "x86 trap surface";
        needle = "X86PortIo";
      }
      {
        label = "aarch64 trap surface";
        needle = "Aarch64Hlt";
      }
      {
        label = "disabled trap error";
        needle = "TrapWhileDisabled";
      }
      {
        label = "guest memory range";
        needle = "pub struct GuestMemoryRange";
      }
      {
        label = "physical payload address space";
        needle = "GuestMemoryAddressSpace::Physical";
      }
      {
        label = "virtual payload address space";
        needle = "GuestMemoryAddressSpace::Virtual";
      }
      {
        label = "read and stamp test";
        needle = "whitebox_doorbell_reads_guest_memory_via_api_and_stamps_current_icount";
      }
      {
        label = "payload source test";
        needle = "whitebox_doorbell_payload_source_is_shared_page_or_register_pointer_length";
      }
      {
        label = "disabled trap test";
        needle = "whitebox_doorbell_trap_while_disabled_is_loud";
      }
      {
        label = "off mode test";
        needle = "whitebox_registration_off_mode_installs_no_trap_and_preserves_black_box";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 doorbell import";
        needle = "guestHostDoorbell = import ./phase4-guest-host-doorbell.nix";
      }
      {
        label = "phase4 doorbell attr path";
        needle = "checks.crucible.phase4.guestHostDoorbell";
      }
      {
        label = "phase4 doorbell task id";
        needle = "taskIds = [\"T-GHC-4\"]";
      }
    ]
    ++ forbiddenFor "crates/crucible-qemu-plugin/src/whitebox_doorbell.rs" pluginWhiteboxDoorbell [
      {
        label = "virtio serial channel";
        needle = "VirtioSerial";
      }
      {
        label = "virtio serial snake-case channel";
        needle = "virtio_serial";
      }
      {
        label = "device queue channel";
        needle = "DeviceQueue";
      }
      {
        label = "device queue snake-case channel";
        needle = "device_queue";
      }
      {
        label = "virtqueue channel";
        needle = "virtqueue";
      }
      {
        label = "guest dev-node channel";
        needle = "/dev/virtio-ports";
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
      crucible phase4 guest-host doorbell check failed:
      ${builtins.concatStringsSep "\n" failures}
    ''
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-guest-host-doorbell";
      version = "0";
      src = crucibleSrc;
      buildDeps = [pkgs.coreutils pkgs.rust pkgs.sed];
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
          name = "run-guest-host-doorbell";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-doorbell-target" \
              -p crucible-qemu-plugin \
              --lib whitebox_doorbell \
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
            evidence_scope=doorbell-callback-core-model
            doorbell=synchronous-trapped-instruction
            payload_sources=shared-page,register-pointer-length
            marker_stamp=exact-retirement-icount
            device_channel=forbidden
            RESULT
          '';
        }
      ];
    }
