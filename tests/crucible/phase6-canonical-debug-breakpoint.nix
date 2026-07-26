{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase6.canonicalDebugBreakpoint",
  taskIds ? ["T-DBG-3"],
  openTaskIds ? [],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  debugDoc = builtins.readFile ../../docs/rfcs/0010-crucible/36-time-travel-debugging.md;
  temporalGraph = import ./_crucible-model-source.nix {inherit lib;};
  engineLib = builtins.readFile ../../crates/crucible/src/lib.rs;
  qemuProxy = builtins.readFile ../../crates/crucible-qemu/src/gdbstub_proxy.rs;
  qemuLib = builtins.readFile ../../crates/crucible-qemu/src/lib.rs;
  breakpointTest = builtins.readFile ../../crates/crucible/tests/gate_canonical_debug_breakpoint.rs;
  qemuTest = builtins.readFile ../../crates/crucible-qemu/tests/debug_gdbstub.rs;
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
        label = "T-DBG-3 checklist complete";
        needle = "- [x] **T-DBG-3**";
      }
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
    ++ failuresFor "crates/crucible-qemu/src/gdbstub_proxy.rs" qemuProxy [
      {
        label = "gdbstub breakpoint policy";
        needle = "pub struct QemuGdbstubBreakpointPolicy";
      }
      {
        label = "hardware policy";
        needle = "canonical_hardware_breakpoints";
      }
      {
        label = "no hardware policy";
        needle = "canonical_without_hardware_breakpoints";
      }
      {
        label = "operator packet parser";
        needle = "process_operator_gdbstub_bytes";
      }
      {
        label = "software breakpoint detector";
        needle = "is_software_breakpoint_packet";
      }
      {
        label = "Z0 to Z1 rewrite";
        needle = "hardware_breakpoint_packet";
      }
      {
        label = "local refusal response";
        needle = "GDB_ERROR_MEMORY_PATCH_REFUSED";
      }
      {
        label = "lowercase z0 removal detector";
        needle = "payload.starts_with(b\"z0,\")";
      }
      {
        label = "local refusal ack write";
        needle = "write_all(b\"+\")";
      }
      {
        label = "local response ack accounting";
        needle = "local_response_acks_consumed";
      }
      {
        label = "translated count";
        needle = "software_breakpoints_translated";
      }
      {
        label = "refused count";
        needle = "software_breakpoints_refused";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/lib.rs" qemuLib [
      {
        label = "qemu policy export";
        needle = "QemuGdbstubBreakpointPolicy";
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
    ++ failuresFor "crates/crucible-qemu/tests/debug_gdbstub.rs" qemuTest [
      {
        label = "Z0 translation test";
        needle = "debug_gdbstub_proxy_translates_software_breakpoint_to_hardware_packet";
      }
      {
        label = "Z0 refusal test";
        needle = "debug_gdbstub_proxy_refuses_software_breakpoint_without_hardware_support";
      }
      {
        label = "operator sends Z0";
        needle = "gdb_packet(b\"Z0,401000,1\")";
      }
      {
        label = "qemu receives Z1";
        needle = "gdb_packet(b\"Z1,401000,1\")";
      }
      {
        label = "operator sends z0";
        needle = "gdb_packet(b\"z0,401000,1\")";
      }
      {
        label = "qemu receives z1";
        needle = "gdb_packet(b\"z1,401000,1\")";
      }
      {
        label = "local refusal packet";
        needle = "gdb_packet(b\"E22\")";
      }
      {
        label = "operator acks local refusal";
        needle = "write_all(b\"+\")";
      }
      {
        label = "local refusal ack assertion";
        needle = "report.local_response_acks_consumed";
      }
      {
        label = "qemu receives nothing on refusal";
        needle = "assert!(request.is_empty())";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "red canonical debug breakpoint gate";
        needle = "canonicalDebugBreakpoint = redBeforeAdvance";
      }
      {
        label = "explicit task id";
        needle = "openTaskIds = [\"T-DBG-3\"]";
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
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
        pkgs.rust
        pkgs.sed
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
              -p crucible-qemu \
              --test debug_gdbstub \
              debug_gdbstub_proxy \
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
            evidence_scope=canonical-breakpoint-model-and-proxy
            gate=gate:canonical-debug-breakpoint
            breakpoint=out-of-band
            software_request=transparent-hardware-or-refused
            memory_patch=refused
            RESULT
          '';
        }
      ];
    }
