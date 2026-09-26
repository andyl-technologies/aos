{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase6.canonicalDebugBreakpoint",
  taskIds ? ["T-DBG-3"],
  openTaskIds ? [],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  debugDoc = builtins.readFile ../../docs/rfcs/0010-crucible/36-time-travel-debugging.md;
  temporalGraph = import ./_crucible-model-source.nix {inherit lib;};
  engineLib = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible/src/lib.rs;
  };
  gatewayLib = builtins.readFile ../../crates/crucible-debug-gateway/src/lib.rs;
  gatewayMain = builtins.readFile ../../crates/crucible-debug-gateway/src/main.rs;
  gatewayTest = builtins.readFile ../../crates/crucible-debug-gateway/src/main/tests.rs;
  relayPolicy = builtins.readFile ../../crates/crucible-api/src/debug_relay.rs;
  relayTest = builtins.readFile ../../crates/crucible-api/src/debug_relay/tests.rs;
  breakpointTest = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible/tests/gate_canonical_debug_breakpoint.rs;
  };
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;
  openTaskList = builtins.concatStringsSep "," openTaskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  forbiddenFailuresFor = fileLabel: content: forbidden:
    lib.concatMap (
      requirement:
        lib.optionals (hasInfix requirement.needle content) [
          "${fileLabel}: forbidden ${requirement.label}: `${requirement.needle}`"
        ]
    )
    forbidden;

  failures =
    failuresFor "docs/rfcs/0010-crucible/36-time-travel-debugging.md" debugDoc [
      {
        label = "T-DBG-3 partial-evidence note";
        needle = "Completed under `checks.crucible.phase6.canonicalDebugBreakpoint`";
      }
      {
        label = "hardware/out-of-band spec";
        needle = "Canonical breakpoints are hardware/out-of-band";
      }
      {
        label = "allow mutate guidance";
        needle = "--allow-mutate";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" temporalGraph [
      {
        label = "canonical breakpoint API";
        needle = "pub fn canonical_debug_breakpoint";
      }
      {
        label = "breakpoint request type";
        needle = "pub struct DebugBreakpointRequest";
      }
      {
        label = "breakpoint report type";
        needle = "pub struct DebugBreakpointReport";
      }
      {
        label = "breakpoint target type";
        needle = "pub enum DebugBreakpointTarget";
      }
      {
        label = "breakpoint mechanism type";
        needle = "pub enum DebugBreakpointMechanism";
      }
      {
        label = "software request helper";
        needle = "pub fn software_guest_address";
      }
      {
        label = "memory-patch-only helper";
        needle = "software_memory_patch_only_guest_address";
      }
      {
        label = "memory-patch-only target";
        needle = "GuestMemoryPatchOnly";
      }
      {
        label = "QEMU hardware mechanism";
        needle = "DebugBreakpointMechanism::QemuHardwareBreakpoint";
      }
      {
        label = "engine condition mechanism";
        needle = "DebugBreakpointMechanism::EngineCondition";
      }
      {
        label = "typed allow-mutate error";
        needle = "DebugBreakpointRequiresAllowMutate";
      }
      {
        label = "no guest memory mutation report";
        needle = "mutates_guest_memory: false";
      }
      {
        label = "no memory patch report";
        needle = "memory_patch_used: false";
      }
      {
        label = "canonical helper";
        needle = "is_canonical_out_of_band";
      }
      {
        label = "software transparency helper";
        needle = "transparently_satisfies_software_request";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" engineLib [
      {
        label = "breakpoint request export";
        needle = "DebugBreakpointRequest";
      }
      {
        label = "breakpoint report export";
        needle = "DebugBreakpointReport";
      }
      {
        label = "breakpoint mechanism export";
        needle = "DebugBreakpointMechanism";
      }
      {
        label = "breakpoint target export";
        needle = "DebugBreakpointTarget";
      }
    ]
    ++ failuresFor "crates/crucible-debug-gateway/src/lib.rs" gatewayLib [
      {
        label = "canonical software breakpoint admission";
        needle = "packet.starts_with(b\"Z0,\")";
      }
      {
        label = "canonical hardware breakpoint admission";
        needle = "packet.starts_with(b\"Z1,\")";
      }
      {
        label = "guest write rejection";
        needle = "RspDisposition::RejectReadOnly";
      }
    ]
    ++ failuresFor "crates/crucible-debug-gateway/src/main.rs" gatewayMain [
      {
        label = "software breakpoint hardware translation";
        needle = "fn canonical_breakpoint_packet";
      }
      {
        label = "Z0 to Z1 translation";
        needle = "b\"Z1,\".as_slice()";
      }
      {
        label = "z0 to z1 translation";
        needle = "b\"z1,\".as_slice()";
      }
    ]
    ++ failuresFor "crates/crucible-debug-gateway/src/main/tests.rs" gatewayTest [
      {
        label = "QEMU receives hardware breakpoint only";
        needle = "canonical_software_breakpoint_reaches_qemu_only_as_hardware";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/debug_relay.rs" relayPolicy [
      {
        label = "read-only relay admits canonical software requests";
        needle = "payload.starts_with(b\"Z0,\")";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/debug_relay/tests.rs" relayTest [
      {
        label = "read-only relay breakpoint admission test";
        needle = "read_only_relay_allows_queries_breakpoints_and_transport_acknowledgements";
      }
      {
        label = "read-only relay guest write denial test";
        needle = "read_only_relay_rejects_every_state_changing_command_family";
      }
    ]
    ++ failuresFor "crates/crucible/tests/gate_canonical_debug_breakpoint.rs" breakpointTest [
      {
        label = "canonical out-of-band gate";
        needle = "canonical_debug_breakpoint_uses_out_of_band_mechanisms";
      }
      {
        label = "memory patch refusal gate";
        needle = "canonical_debug_breakpoint_refuses_memory_patch_only_breakpoint";
      }
      {
        label = "software request satisfied by hardware";
        needle = "transparently_satisfies_software_request";
      }
      {
        label = "allow mutate error assertion";
        needle = "DebugBreakpointRequiresAllowMutate";
      }
      {
        label = "allow mutate display assertion";
        needle = "contains(\"--allow-mutate\")";
      }
      {
        label = "no mutation assertion";
        needle = "!software_report.mutates_guest_memory";
      }
      {
        label = "no memory patch assertion";
        needle = "!software_report.memory_patch_used";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "green canonical debug breakpoint gate";
        needle = "canonicalDebugBreakpoint = greenBeforeAdvance";
      }
      {
        label = "explicit task id";
        needle = "taskIds = [\"T-DBG-3\"]";
      }
      {
        label = "read-only debug raw dependency";
        needle = "phase6.readOnlyDebugInspection.rawGate";
      }
      {
        label = "read-only debug blocker dependency";
        needle = "phase6.readOnlyDebugInspection";
      }
    ]
    ++ forbiddenFailuresFor "crates/crucible/tests/gate_canonical_debug_breakpoint.rs" breakpointTest [
      {
        label = "ignored red placeholder";
        needle = "#[ignore";
      }
      {
        label = "pending implementation panic";
        needle = "implementation is pending";
      }
      {
        label = "memory patch success assertion";
        needle = "memory_patch_used: true";
      }
    ]
    ++ forbiddenFailuresFor "crates/crucible/src/model.rs" temporalGraph [
      {
        label = "caller-asserted mechanism set";
        needle = "available_mechanisms";
      }
    ];
in
  if failures != []
  then throw "crucible phase6 canonical-debug-breakpoint check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase6-canonical-debug-breakpoint";
      version = "0";
      LIBSQLITE3_SYS_USE_PKG_CONFIG = "1";
      runtimeDeps = [pkgs.sqlite];
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
        pkgs.rust
        pkgs.sed

        pkgs.pkg-config
        pkgs.sqlite
      ];

      DEPENDENCIES = builtins.concatStringsSep ":" dependencies;

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
            : "$DEPENDENCIES"
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
          name = "run-canonical-debug-breakpoint";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-canonical-debug-breakpoint-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test gate_canonical_debug_breakpoint \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-canonical-debug-breakpoint-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-debug-gateway \
              canonical_software_breakpoint_reaches_qemu_only_as_hardware \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-canonical-debug-breakpoint-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-api \
              --lib \
              debug_relay::tests \
              -- --test-threads=1
          '';
        }
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out"
            cat > "$out/result" <<RESULT
            PASS
            check=${attrPath}
            tasks=${taskList}
            open_tasks=${openTaskList}
            status=complete
            evidence_scope=canonical-breakpoint-model-and-gateway
            gate=gate:canonical-debug-breakpoint
            breakpoint=out-of-band
            software_request=transparent-hardware-or-refused
            memory_patch=refused
            RESULT
          '';
        }
      ];
    }
