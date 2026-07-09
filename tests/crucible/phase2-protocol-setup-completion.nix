{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.protocolSetupCompletion",
  taskIds ? ["T-PROTO-5"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  protocolLib = builtins.readFile ../../crates/crucible-protocol/src/lib.rs;
  protocolTest = builtins.readFile ../../crates/crucible-protocol/tests/setup_completion.rs;
  # The setup-region mmap surface was split out of lib.rs into
  # mapped_setup_region.rs; scan both so the needles survive file moves.
  shmemLib =
    builtins.readFile ../../crates/crucible-shmem/src/lib.rs
    + builtins.readFile ../../crates/crucible-shmem/src/mapped_setup_region.rs;
  shmemTest = builtins.readFile ../../crates/crucible-shmem/tests/setup_validation.rs;
  pluginCargo = builtins.readFile ../../crates/crucible-qemu-plugin/Cargo.toml;
  pluginLib = builtins.readFile ../../crates/crucible-qemu-plugin/src/lib.rs;
  pluginSetup = builtins.readFile ../../crates/crucible-qemu-plugin/src/setup.rs;
  pluginTimeControl = builtins.readFile ../../crates/crucible-qemu-plugin/src/time_control.rs;
  protocolSpec = builtins.readFile ../../docs/rfcs/0010-crucible/14-protocol.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

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
    failuresFor "crates/crucible-protocol/src/lib.rs" protocolLib [
      {
        label = "ready setup-ack status constant";
        needle = "pub const SETUP_ACK_STATUS_READY: u8 = 0;";
      }
      {
        label = "generic setup failure status constant";
        needle = "pub const SETUP_ACK_STATUS_SETUP_FAILED: u8 = 1;";
      }
      {
        label = "schedulable setup token";
        needle = "pub struct SchedulableNodeSetup";
      }
      {
        label = "setup completion error type";
        needle = "pub enum SetupCompletionError";
      }
      {
        label = "nonzero setup-ack refusal";
        needle = "NonZeroSetupAck";
      }
      {
        label = "plugin setup ack sender";
        needle = "pub fn plugin_send_setup_ack";
      }
      {
        label = "host setup ack reader";
        needle = "pub fn host_accept_setup_ack";
      }
      {
        label = "host pure setup ack validator";
        needle = "pub fn host_validate_setup_ack";
      }
      {
        label = "setup ack write flush path";
        needle = "write_control_frame(writer, &ack)";
      }
      {
        label = "setup ack read path";
        needle = "read_control_frame(reader)";
      }
      {
        label = "host scheduling token grants scheduling";
        needle = "pub const fn can_schedule";
      }
    ]
    ++ failuresFor "crates/crucible-protocol/tests/setup_completion.rs" protocolTest [
      {
        label = "plugin sends flushed setup ack";
        needle = "plugin_sends_setup_ack_status_and_flushes";
      }
      {
        label = "zero setup ack schedules";
        needle = "host_accepts_zero_setup_ack_as_schedulable";
      }
      {
        label = "nonzero setup ack refusal";
        needle = "host_refuses_nonzero_setup_ack_before_scheduling";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/src/lib.rs" shmemLib [
      {
        label = "setup mmap wrapper";
        needle = "pub fn mmap_setup_region";
      }
      {
        label = "mmap syscall";
        needle = "libc::mmap";
      }
      {
        label = "mapped setup region type";
        needle = "pub struct MappedSetupRegion";
      }
      {
        label = "setup region header validator";
        needle = "pub fn validate_setup_region_header";
      }
      {
        label = "validated setup region token";
        needle = "pub struct ValidatedSetupRegion";
      }
      {
        label = "region magic validation";
        needle = "snapshot.magic != REGION_MAGIC";
      }
      {
        label = "ABI marker validation";
        needle = "snapshot.abi_version != ABI_VERSION";
      }
      {
        label = "region_len/header length mismatch";
        needle = "RegionLengthMismatch";
      }
      {
        label = "short region refusal";
        needle = "RegionTooSmall";
      }
      {
        label = "setup geometry validation";
        needle = "validate_setup_region_header";
      }
      {
        label = "computed layout length validation";
        needle = "LayoutRegionLengthMismatch";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/tests/setup_validation.rs" shmemTest [
      {
        label = "valid setup header test";
        needle = "setup_region_header_validation_accepts_magic_abi_and_region_len";
      }
      {
        label = "invalid ABI marker test";
        needle = "setup_region_header_validation_rejects_invalid_abi_marker";
      }
      {
        label = "wrong region length test";
        needle = "setup_region_header_validation_rejects_wrong_region_len";
      }
      {
        label = "invalid geometry test";
        needle = "setup_region_header_validation_rejects_invalid_geometry";
      }
      {
        label = "mmap exact length test";
        needle = "mmap_setup_region_maps_exact_region_len_before_header_validation";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/Cargo.toml" pluginCargo [
      {
        label = "plugin depends on protocol";
        needle = "crucible-protocol = { path = \"../crucible-protocol\" }";
      }
      {
        label = "plugin depends on shmem";
        needle = "crucible-shmem = { path = \"../crucible-shmem\" }";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/lib.rs" pluginLib [
      {
        label = "plugin exposes setup module";
        needle = "pub mod setup;";
      }
      {
        label = "plugin exports setup completion";
        needle = "prepare_setup_completion";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/setup.rs" pluginSetup [
      {
        label = "coupled setup preparation function";
        needle = "pub fn prepare_setup_completion";
      }
      {
        label = "separate ready ack sender";
        needle = "pub fn send_ready_setup_ack";
      }
      {
        label = "typed plugin setup completion";
        needle = "pub struct PluginSetupCompletion";
      }
      {
        label = "maps setup region length";
        needle = "mmap_setup_region(shmem_fd.as_fd(), region_len)";
      }
      {
        label = "validates mapped header";
        needle = "PluginShmemOrdering::validate_setup_header(&mapped_region)";
      }
      {
        label = "wake fd arming token";
        needle = "pub struct ArmedWakeFd";
      }
      {
        label = "wake fd arming function";
        needle = "pub fn arm";
      }
      {
        label = "wake fd nonblocking fcntl";
        needle = "libc::O_NONBLOCK";
      }
      {
        label = "completion token returned before ready ack";
        needle = "Ok(PluginSetupCompletion {\n        mapped_region,\n        validated_region,\n        wake_fd,\n        registered_wake_fd,\n    })";
      }
      {
        label = "ready setup ack";
        needle = "plugin_send_setup_ack(writer, SETUP_ACK_STATUS_READY)";
      }
      {
        label = "failure setup ack";
        needle = "plugin_send_setup_ack(writer, SETUP_ACK_STATUS_SETUP_FAILED)";
      }
      {
        label = "valid complete setup test";
        needle = "prepare_setup_maps_validates_and_arms_wake_fd_before_ready_ack";
      }
      {
        label = "no ready ack before callbacks test assertion";
        needle = "assert!(io.written().is_empty());";
      }
      {
        label = "validation failure nonzero ack test";
        needle = "prepare_setup_sends_nonzero_ack_when_region_validation_fails";
      }
      {
        label = "wake fd arming descriptor test";
        needle = "wake_fd_arm_sets_nonblocking_on_descriptor";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/time_control.rs" pluginTimeControl [
      {
        label = "wake fd arming registration step";
        needle = "PluginRegistrationStep::ArmWakeFd";
      }
      {
        label = "mapping before wake fd arming";
        needle = "PluginRegistrationStep::MapSharedMemory,\n            PluginRegistrationStep::ArmWakeFd";
      }
      {
        label = "wake fd arming before setup ack";
        needle = "PluginRegistrationStep::ArmWakeFd,\n            PluginRegistrationStep::SendSetupAck";
      }
      {
        label = "setup ack before wake fd arm rejection";
        needle = "time_control_registration_order_rejects_setup_ack_before_wake_fd_arm";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/14-protocol.md" protocolSpec [
      {
        label = "T-PROTO-5 checklist complete";
        needle = "- [x] **T-PROTO-5**";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes protocol setup-completion check";
        needle = "protocolSetupCompletion = import ./phase2-protocol-setup-completion.nix";
      }
      {
        label = "canonical ABI conformance gate is implemented";
        needle = "abiConformance = import ./phase2-abi-conformance.nix";
      }
      {
        label = "canonical ABI conformance task list";
        needle = "taskIds = [\"T-PLAN-3\" \"T-HARN-17\" \"T-API-11\" \"T-API-12\" \"T-PAT-8\"]";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 protocol setup-completion check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-protocol-setup-completion";
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
          name = "run-protocol-setup-completion";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-protocol-setup-completion-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-protocol \
              --test setup_completion \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-protocol-setup-completion-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-shmem \
              --test setup_validation \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-protocol-setup-completion-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              --lib setup \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-protocol-setup-completion-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              --lib time_control \
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
            gates=gate:abi-conformance,gate:control-responsive
            rust_tests=crucible-protocol::setup_completion,crucible-shmem::setup_validation,crucible-qemu-plugin::setup,crucible-qemu-plugin::time_control
            setup_region=mmap-region_len
            setup_header_validation=REGION_MAGIC+ABI_VERSION+region_size
            wake_fd_order=armed-before-SetupAck
            scheduling_refusal=nonzero-SetupAck
            RESULT
          '';
        }
      ];
    }
