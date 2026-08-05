{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuPluginWhiteboxDoorbell",
  taskIds ? ["T-PLUG-14"],
  openTaskIds ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoVendor {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-fWBTuyTXJ+/0BiVbB5WAtCqVwufg04NH4BJdocT+moU=";
  };

  pluginLib = builtins.readFile ../../crates/crucible-qemu-plugin/src/lib.rs;
  pluginWhiteboxDoorbell = builtins.readFile ../../crates/crucible-qemu-plugin/src/whitebox_doorbell.rs;
  pluginWhiteboxDoorbellTests = builtins.readFile ../../crates/crucible-qemu-plugin/src/whitebox_doorbell/tests.rs;
  pluginSpec = builtins.readFile ../../docs/rfcs/0010-crucible/12-qemu-plugin.md;
  shmemLib = import ./_crucible-shmem-source.nix {inherit lib;};
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
        lib.optionals (hasInfix api pluginWhiteboxDoorbell) [
          "crates/crucible-qemu-plugin/src/whitebox_doorbell.rs: forbidden host-time, entropy, or lock API in white-box doorbell path: `${api}`"
        ]
    )
    forbiddenCallbackApis;

  failures =
    failuresFor "docs/rfcs/0010-crucible/12-qemu-plugin.md" pluginSpec [
      {
        label = "white-box doorbell wording";
        needle = "Implement the optional white-box doorbell trap";
      }
      {
        label = "delivery contract wording";
        needle = "route white-box inputs through the injection contract";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/lib.rs" pluginLib [
      {
        label = "white-box doorbell module exported";
        needle = "pub mod whitebox_doorbell;";
      }
      {
        label = "white-box state exported";
        needle = "PluginWhiteboxDoorbell";
      }
      {
        label = "registration plan exported";
        needle = "WhiteboxDoorbellRegistrationPlan";
      }
      {
        label = "guest memory reader exported";
        needle = "GuestMemoryReader";
      }
      {
        label = "marker exported";
        needle = "WhiteboxMarker";
      }
      {
        label = "guest input exported";
        needle = "WhiteboxGuestInput";
      }
      {
        label = "guest input capability exported";
        needle = "WhiteboxGuestInputCapability";
      }
      {
        label = "doorbell callback exported";
        needle = "handle_whitebox_doorbell_callback";
      }
      {
        label = "guest input callback exported";
        needle = "handle_whitebox_guest_input_callback";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/whitebox_doorbell.rs" pluginWhiteboxDoorbell [
      {
        label = "white-box state";
        needle = "pub struct PluginWhiteboxDoorbell";
      }
      {
        label = "registration plan";
        needle = "pub fn registration_plan";
      }
      {
        label = "off-mode disabled plan";
        needle = "WhiteboxDoorbellRegistrationPlan::Disabled";
      }
      {
        label = "off-mode checked before validation";
        needle = "if !self.mode.is_on()";
      }
      {
        label = "black-box functional method";
        needle = "black_box_remains_functional";
      }
      {
        label = "trap capability";
        needle = "QEMU_PLUGIN_REGISTER_DOORBELL_TRAP_SYMBOL";
      }
      {
        label = "guest memory read capability";
        needle = "QEMU_PLUGIN_GUEST_MEMORY_READ_SYMBOL";
      }
      {
        label = "guest memory write capability";
        needle = "QEMU_PLUGIN_GUEST_MEMORY_WRITE_SYMBOL";
      }
      {
        label = "x86 doorbell trap";
        needle = "X86PortIo";
      }
      {
        label = "aarch64 doorbell trap";
        needle = "Aarch64Hlt";
      }
      {
        label = "guest memory range";
        needle = "pub struct GuestMemoryRange";
      }
      {
        label = "physical guest memory";
        needle = "Physical";
      }
      {
        label = "virtual guest memory";
        needle = "Virtual";
      }
      {
        label = "guest memory reader trait";
        needle = "pub trait GuestMemoryReader";
      }
      {
        label = "guest memory read API method";
        needle = "read_guest_memory";
      }
      {
        label = "guest memory read gets exact icount";
        needle = "event.current_icount()";
      }
      {
        label = "safe doorbell callback body";
        needle = "pub fn handle_whitebox_doorbell_callback";
      }
      {
        label = "trap event";
        needle = "pub struct WhiteboxDoorbellTrapEvent";
      }
      {
        label = "exact current icount";
        needle = "current_icount";
      }
      {
        label = "marker stamp";
        needle = "marker_icount";
      }
      {
        label = "marker sink";
        needle = "pub trait WhiteboxMarkerSink";
      }
      {
        label = "payload bound";
        needle = "MAX_FRAME_DATA";
      }
      {
        label = "host-to-guest input";
        needle = "pub struct WhiteboxGuestInput";
      }
      {
        label = "host-to-guest input capability";
        needle = "pub struct WhiteboxGuestInputCapability";
      }
      {
        label = "guest input capability requirement";
        needle = "pub fn require_guest_input_capability";
      }
      {
        label = "delivery icount";
        needle = "delivery_icount";
      }
      {
        label = "guest input writer trait";
        needle = "pub trait WhiteboxGuestInputWriter";
      }
      {
        label = "guest input not-ready outcome";
        needle = "WhiteboxGuestInputOutcome::NotReady";
      }
      {
        label = "late input failure";
        needle = "InputDeliveryAlreadyPassed";
      }
      {
        label = "safe guest input callback body";
        needle = "pub fn handle_whitebox_guest_input_callback";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/whitebox_doorbell/tests.rs" pluginWhiteboxDoorbellTests [
      {
        label = "off-mode test";
        needle = "whitebox_registration_off_mode_installs_no_trap_and_preserves_black_box";
      }
      {
        label = "off-mode invalid config bypass test";
        needle = "whitebox_registration_off_mode_bypasses_whitebox_payload_validation";
      }
      {
        label = "on-mode capability test";
        needle = "whitebox_registration_on_mode_requires_trap_and_memory_read_capabilities";
      }
      {
        label = "guest memory read and stamp test";
        needle = "whitebox_doorbell_reads_guest_memory_via_api_and_stamps_current_icount";
      }
      {
        label = "oversize payload test";
        needle = "whitebox_doorbell_rejects_oversized_payload_before_guest_memory_read";
      }
      {
        label = "disabled trap test";
        needle = "whitebox_doorbell_trap_while_disabled_is_loud";
      }
      {
        label = "input not-ready test";
        needle = "whitebox_guest_input_is_not_visible_before_delivery_icount";
      }
      {
        label = "input exact delivery test";
        needle = "whitebox_guest_input_writes_at_exact_delivery_icount_only";
      }
      {
        label = "input late rejection test";
        needle = "whitebox_guest_input_rejects_late_delivery";
      }
      {
        label = "guest input write capability test";
        needle = "whitebox_guest_input_requires_qemu_guest_memory_write_capability";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/src/lib.rs" shmemLib [
      {
        label = "shared max frame payload bound";
        needle = "pub const MAX_FRAME_DATA";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes plugin white-box doorbell check";
        needle = "qemuPluginWhiteboxDoorbell = import ./phase2-plugin-whitebox-doorbell.nix";
      }
    ]
    ++ forbiddenCallbackFailures;
in
  if failures != []
  then throw "crucible phase2 plugin white-box doorbell check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-plugin-whitebox-doorbell";
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
            sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
                > .cargo/config.toml
          '';
        }
        {
          name = "run-plugin-whitebox-doorbell";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-plugin-whitebox-doorbell-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              whitebox_ \
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
            off_mode=disabled-plan-installs-no-trap
            black_box_remains_functional=true
            guest_memory=read-through-qemu-plugin-api-trait
            marker_stamp=exact-current-icount
            host_to_guest_input=explicit-delivery-icount-gate
            callback_host_time_apis=forbidden
            RESULT
          '';
        }
      ];
    }
