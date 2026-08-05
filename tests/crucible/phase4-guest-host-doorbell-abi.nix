{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.guestHostDoorbellAbi",
  taskIds ? ["T-GHC-5"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoVendor {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-fWBTuyTXJ+/0BiVbB5WAtCqVwufg04NH4BJdocT+moU=";
  };

  pluginLib = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-qemu-plugin/src/lib.rs;
  };
  pluginWhiteboxDoorbell = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-qemu-plugin/src/whitebox_doorbell.rs;
  };
  protocolLib = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-protocol/src/lib.rs;
  };
  protocolDoorbellAbi = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-protocol/src/doorbell_abi.rs;
  };
  guestCargo = builtins.readFile ../../crates/crucible-guest/Cargo.toml;
  guestLib = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-guest/src/lib.rs;
  };
  gateAbiConformance = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-qemu-plugin/tests/gate_abi_conformance.rs;
  };
  guestHostDoc = builtins.readFile ../../docs/rfcs/0010-crucible/16-guest-host-channel.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/16-guest-host-channel.md" guestHostDoc [
      {
        label = "T-GHC-5 completion note";
        needle = "Completed by `checks.crucible.phase4.guestHostDoorbellAbi`";
      }
      {
        label = "single-source ABI table";
        needle = "WHITEBOX_DOORBELL_ABIS";
      }
      {
        label = "x86 bytes documented";
        needle = "x86_64   out 0xe7,al";
      }
      {
        label = "aarch64 bytes documented";
        needle = "aarch64  hlt #0x04c1";
      }
      {
        label = "aarch64 instruction word";
        needle = "0xd4409820";
      }
    ]
    ++ failuresFor "crates/crucible-protocol/src/lib.rs" protocolLib [
      {
        label = "doorbell ABI module";
        needle = "mod doorbell_abi;";
      }
      {
        label = "doorbell ABI exports";
        needle = "WhiteboxDoorbellTrapAbi";
      }
    ]
    ++ failuresFor "crates/crucible-protocol/src/doorbell_abi.rs" protocolDoorbellAbi [
      {
        label = "instruction ABI version";
        needle = "pub const WHITEBOX_DOORBELL_INSTRUCTION_ABI_VERSION: u16 = 3;";
      }
      {
        label = "x86 reserved port";
        needle = "pub const WHITEBOX_DOORBELL_X86_64_RESERVED_PORT: u16 = 0x00e7;";
      }
      {
        label = "aarch64 reserved immediate";
        needle = "pub const WHITEBOX_DOORBELL_AARCH64_RESERVED_IMMEDIATE: u16 = 0x04c1;";
      }
      {
        label = "x86 bytes";
        needle = "pub const WHITEBOX_DOORBELL_X86_64_OUT_IMM8_AL_BYTES: [u8; 2]";
      }
      {
        label = "aarch64 bytes";
        needle = "pub const WHITEBOX_DOORBELL_AARCH64_HLT_BYTES: [u8; 4]";
      }
      {
        label = "ABI table";
        needle = "pub const WHITEBOX_DOORBELL_ABIS: &[WhiteboxDoorbellAbi]";
      }
      {
        label = "shared trap ABI";
        needle = "pub enum WhiteboxDoorbellTrapAbi";
      }
      {
        label = "exact aarch64 hlt trap";
        needle = "Aarch64Hlt";
      }
      {
        label = "x86 encoder re-export";
        needle = "encode_x86_64_out_imm8_al_instruction";
      }
      {
        label = "aarch64 encoder re-export";
        needle = "encode_aarch64_hlt_instruction";
      }
      {
        label = "protocol x86 golden test";
        needle = "doorbell_abi_x86_64_vector_freezes_out_imm8_al";
      }
      {
        label = "protocol aarch64 golden test";
        needle = "doorbell_abi_aarch64_vector_freezes_hlt_immediate";
      }
    ]
    ++ failuresFor "crates/crucible-guest/Cargo.toml" guestCargo [
      {
        label = "guest depends on protocol ABI";
        needle = "crucible-protocol = { path = \"../crucible-protocol\" }";
      }
    ]
    ++ failuresFor "crates/crucible-guest/src/lib.rs" guestLib [
      {
        label = "guest ABI re-export";
        needle = "WHITEBOX_DOORBELL_ABIS";
      }
      {
        label = "guest trap ABI re-export";
        needle = "WhiteboxDoorbellTrapAbi";
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
        label = "ABI table export";
        needle = "WHITEBOX_DOORBELL_ABIS";
      }
      {
        label = "x86 byte vector export";
        needle = "WHITEBOX_DOORBELL_X86_64_OUT_IMM8_AL_BYTES";
      }
      {
        label = "aarch64 byte vector export";
        needle = "WHITEBOX_DOORBELL_AARCH64_HLT_BYTES";
      }
      {
        label = "ABI type export";
        needle = "WhiteboxDoorbellAbi";
      }
      {
        label = "ABI lookup export";
        needle = "whitebox_doorbell_abi_for_architecture";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/whitebox_doorbell.rs" pluginWhiteboxDoorbell [
      {
        label = "plugin re-exports protocol ABI";
        needle = "pub use crucible_protocol";
      }
      {
        label = "x86 trap value";
        needle = "WhiteboxDoorbellTrap::X86PortIo";
      }
      {
        label = "exact aarch64 trap value";
        needle = "WhiteboxDoorbellTrap::Aarch64Hlt";
      }
      {
        label = "plugin trap conversion";
        needle = "pub const fn from_abi(trap: WhiteboxDoorbellTrapAbi) -> Self";
      }
      {
        label = "single-source constructor";
        needle = "pub const fn from_abi";
      }
      {
        label = "x86 literal vector test";
        needle = "whitebox_doorbell_x86_64_golden_vector_freezes_out_imm8_al";
      }
      {
        label = "aarch64 literal vector test";
        needle = "whitebox_doorbell_aarch64_golden_vector_freezes_hlt_immediate";
      }
      {
        label = "single-source registration test";
        needle = "whitebox_doorbell_registration_uses_single_source_abi_trap";
      }
    ]
    ++ forbiddenFor "crates/crucible-qemu-plugin/src/whitebox_doorbell.rs" pluginWhiteboxDoorbell [
      {
        label = "public arbitrary doorbell constructor";
        needle = "pub const fn new(\n        mode: PluginSwitch";
      }
      {
        label = "generic aarch64 reserved trap";
        needle = "Aarch64ReservedInstruction";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/tests/gate_abi_conformance.rs" gateAbiConformance [
      {
        label = "canonical ABI gate covers doorbell ABI";
        needle = "gate_abi_conformance_covers_whitebox_doorbell_instruction_abi";
      }
      {
        label = "canonical ABI gate runs protocol doorbell ABI tests";
        needle = "run_doorbell_abi_unit_targets";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 doorbell ABI import";
        needle = "guestHostDoorbellAbi = import ./phase4-guest-host-doorbell-abi.nix";
      }
      {
        label = "phase4 doorbell ABI attr path";
        needle = "checks.crucible.phase4.guestHostDoorbellAbi";
      }
      {
        label = "phase4 doorbell ABI task id";
        needle = "taskIds = [\"T-GHC-5\"]";
      }
    ];
in
  if failures != []
  then throw "crucible phase4 guest-host doorbell ABI check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-guest-host-doorbell-abi";
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
          name = "run-guest-host-doorbell-abi";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-doorbell-abi-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-protocol \
              doorbell_abi \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-doorbell-abi-target" \
              --manifest-path crates/Cargo.toml \
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
            gate=gate:abi-conformance
            instruction_abi_version=3
            x86_64_doorbell_bytes=e6-e7
            aarch64_doorbell_bytes=209840d4
            abi_source=crucible-protocol::doorbell_abi::WHITEBOX_DOORBELL_ABIS
            RESULT
          '';
        }
      ];
    }
