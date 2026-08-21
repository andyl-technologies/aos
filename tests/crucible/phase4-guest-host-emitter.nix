{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.guestHostEmitter",
  taskIds ? ["T-GHC-10"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = import ../../pkgs/tools/crucible/_cargo-deps-hash.nix;
  };

  guestCargo = builtins.readFile ../../crates/crucible-guest/Cargo.toml;
  guestLib = builtins.readFile ../../crates/crucible-guest/src/lib.rs;
  guestMain = builtins.readFile ../../crates/crucible-guest/src/main.rs;
  guestGate = builtins.readFile ../../crates/crucible-guest/tests/gate_abi_conformance.rs;
  guestPackage = builtins.readFile ../../pkgs/tools/crucible-guest.nix;
  gateTargets = builtins.readFile ../../crates/crucible-harness/src/gate_targets.rs;
  guestHostDoc = builtins.readFile ../../docs/rfcs/0010-crucible/16-guest-host-channel.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  phaseGate = builtins.readFile ./phase4-guest-host-emitter.nix;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/16-guest-host-channel.md" guestHostDoc [
      {
        label = "T-GHC-10 completion note";
        needle = "Completed by `checks.crucible.phase4.guestHostEmitter`";
      }
      {
        label = "guest emitter implementation note";
        needle = "`crucible-guest::GuestCommand`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "guest-host phase4 task range";
        needle = "Guest↔host channel + optional agent";
      }
    ]
    ++ failuresFor "crates/crucible-guest/Cargo.toml" guestCargo [
      {
        label = "guest binary name";
        needle = "name = \"crucible-guest\"";
      }
      {
        label = "guest binary entry";
        needle = "path = \"src/main.rs\"";
      }
      {
        label = "guest protocol dependency";
        needle = "crucible-protocol = { path = \"../crucible-protocol\" }";
      }
    ]
    ++ forbiddenFor "crates/crucible-guest/Cargo.toml" guestCargo [
      {
        label = "CLI parser dependency";
        needle = "clap";
      }
    ]
    ++ failuresFor "crates/crucible-guest/src/lib.rs" guestLib [
      {
        label = "guest command type";
        needle = "pub struct GuestCommand";
      }
      {
        label = "doorbell transport trait";
        needle = "pub trait DoorbellTransport";
      }
      {
        label = "native instruction transport";
        needle = "pub struct InstructionDoorbellTransport";
      }
      {
        label = "emit command helper";
        needle = "pub fn emit_command";
      }
      {
        label = "CLI parser";
        needle = "pub fn parse_cli_args";
      }
      {
        label = "static rustflags contract";
        needle = "CRUCIBLE_GUEST_STATIC_RUSTFLAGS";
      }
      {
        label = "supported architectures";
        needle = "CRUCIBLE_GUEST_SUPPORTED_ARCHITECTURES";
      }
      {
        label = "shared ABI table";
        needle = "WHITEBOX_DOORBELL_ABIS";
      }
      {
        label = "shared frame encoder";
        needle = "encode_whitebox_marker_frame";
      }
      {
        label = "x86 trap instruction";
        needle = "\"out 0xe7, al\"";
      }
      {
        label = "x86 port permission request";
        needle = "libc::ioperm";
      }
      {
        label = "aarch64 inert instruction";
        needle = "\"hint #0x4c\"";
      }
      {
        label = "app-random reply buffer";
        needle = "frame[..width].to_vec()";
      }
    ]
    ++ failuresFor "crates/crucible-guest/src/main.rs" guestMain [
      {
        label = "main uses native transport";
        needle = "InstructionDoorbellTransport::native()";
      }
      {
        label = "main parses CLI";
        needle = "parse_cli_args";
      }
      {
        label = "main emits command";
        needle = "emit_command";
      }
      {
        label = "main prints random reply";
        needle = "hex_lower(&reply)";
      }
    ]
    ++ failuresFor "crates/crucible-guest/tests/gate_abi_conformance.rs" guestGate [
      {
        label = "CLI marker verb coverage";
        needle = "guest_cli_verbs_encode_shared_marker_payloads";
      }
      {
        label = "single-source ABI test";
        needle = "guest_emitter_uses_single_source_doorbell_abi_table";
      }
      {
        label = "random reply test";
        needle = "guest_get_random_round_trip_reads_reply_from_payload_range";
      }
      {
        label = "static package test";
        needle = "guest_static_build_contract_is_declared_for_aos_package";
      }
      {
        label = "recording transport test double";
        needle = "struct RecordingDoorbellTransport";
      }
    ]
    ++ failuresFor "pkgs/tools/crucible-guest.nix" guestPackage [
      {
        label = "dedicated AOS guest package";
        needle = "pname = \"crucible-guest\"";
      }
      {
        label = "static rustflags";
        needle = "target-feature=+crt-static";
      }
      {
        label = "target-specific rustflags";
        needle = "CARGO_TARGET_";
      }
      {
        label = "guest binary cargo flags";
        needle = "-p crucible-guest --bin crucible-guest";
      }
      {
        label = "static interpreter check";
        needle = "patchelf --print-interpreter";
      }
      {
        label = "packaged guest system";
        needle = "packaged_guest_system=" + "$" + "{lib.system}";
      }
      {
        label = "instruction ABI architectures";
        needle = "instruction_abi_architectures=x86_64,aarch64";
      }
      {
        label = "instruction ABI version";
        needle = "doorbell_instruction_abi_version=4";
      }
      {
        label = "single-source ABI source";
        needle = "abi_source=crucible-protocol::doorbell_abi::WHITEBOX_DOORBELL_ABIS";
      }
    ]
    ++ failuresFor "tests/crucible/phase4-guest-host-emitter.nix" phaseGate [
      {
        label = "phase gate inspects built package";
        needle = "\${pkgs.crucible-guest}/bin/crucible-guest";
      }
      {
        label = "phase gate inspects package build info";
        needle = "\${pkgs.crucible-guest}/nix-support/crucible-guest-build-info";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/gate_targets.rs" gateTargets [
      {
        label = "guest ABI conformance target";
        needle = "package: \"crucible-guest\"";
      }
      {
        label = "guest ABI conformance test target";
        needle = "test_target: \"gate_abi_conformance\"";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 guest emitter import";
        needle = "guestHostEmitter = import ./phase4-guest-host-emitter.nix";
      }
      {
        label = "phase4 guest emitter attr path";
        needle = "checks.crucible.phase4.guestHostEmitter";
      }
      {
        label = "phase4 guest emitter task id";
        needle = "taskIds = [\"T-GHC-10\"]";
      }
    ];
in
  if failures != []
  then
    throw ''
      crucible phase4 guest-host emitter check failed:
      ${builtins.concatStringsSep "\n" failures}
    ''
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-guest-host-emitter";
      version = "0";
      src = crucibleSrc;
      buildDeps = [pkgs.coreutils pkgs.rust pkgs.sed pkgs.patchelf pkgs.crucible-guest];
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
          name = "run-guest-host-emitter";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-emitter-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-guest \
              --test gate_abi_conformance \
              -- --test-threads=1
            cargo build \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-emitter-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-guest \
              --bin crucible-guest
            test -x "${pkgs.crucible-guest}/bin/crucible-guest"
            build_info="${pkgs.crucible-guest}/nix-support/crucible-guest-build-info"
            test -f "$build_info"
            build_info_content="$(cat "$build_info")"
            case "$build_info_content" in
              *"rustflags=-C target-feature=+crt-static"*) ;;
              *) echo "crucible-guest package missing static Rust flags" >&2; exit 1 ;;
            esac
            case "$build_info_content" in
              *"abi_source=crucible-protocol::doorbell_abi::WHITEBOX_DOORBELL_ABIS"*) ;;
              *) echo "crucible-guest package missing ABI source proof" >&2; exit 1 ;;
            esac
            case "$build_info_content" in
              *"doorbell_instruction_abi_version=4"*) ;;
              *) echo "crucible-guest package missing instruction ABI version" >&2; exit 1 ;;
            esac
            if patchelf --print-interpreter "${pkgs.crucible-guest}/bin/crucible-guest" \
              > "$TMPDIR/crucible-guest-package.interpreter" 2>/dev/null; then
              printf 'crucible-guest package unexpectedly has ELF interpreter: ' >&2
              cat "$TMPDIR/crucible-guest-package.interpreter" >&2
              exit 1
            fi
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
            package=crucible-guest
            binary=crucible-guest
            static_contract=target-feature=+crt-static
            packaged_guest_system=${lib.system}
            instruction_abi_architectures=x86_64,aarch64
            abi_source=crucible-protocol::doorbell_abi::WHITEBOX_DOORBELL_ABIS
            marker_source=crucible-protocol::doorbell_marker
            RESULT
          '';
        }
      ];
    }
