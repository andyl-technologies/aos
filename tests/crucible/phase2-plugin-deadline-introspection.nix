{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuPluginDeadlineIntrospection",
  taskIds ? ["T-PLUG-6"],
  openTaskIds ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  pluginLib = builtins.readFile ../../crates/crucible-qemu-plugin/src/lib.rs;
  pluginAbi = builtins.readFile ../../crates/crucible-qemu-plugin/src/abi.rs;
  pluginAbiTests = builtins.readFile ../../crates/crucible-qemu-plugin/src/abi/tests.rs;
  pluginDeadline = builtins.readFile ../../crates/crucible-qemu-plugin/src/deadline.rs;
  pluginRegistration = import ./_qemu-plugin-registration-source.nix {inherit lib;};
  pluginIdleLoop = builtins.readFile ../../crates/crucible-qemu-plugin/src/idle_loop.rs;
  pluginSpec = builtins.readFile ../../docs/rfcs/0010-crucible/12-qemu-plugin.md;
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

  deadlinePathForbiddenApis = [
    "Instant::now"
    "SystemTime::now"
    "std::time"
    "thread::sleep"
    "clock_gettime"
    "gettimeofday"
    "CLOCK_REALTIME"
    "CLOCK_MONOTONIC"
    "thread_rng"
    "rand::random"
  ];

  deadlinePathForbiddenFailures =
    lib.concatMap (
      api:
        lib.optionals (hasInfix api pluginDeadline) [
          "crates/crucible-qemu-plugin/src/deadline.rs: forbidden host-time, timeout, or entropy API in exact-deadline path: `${api}`"
        ]
    )
    deadlinePathForbiddenApis;

  failures =
    failuresFor "docs/rfcs/0010-crucible/12-qemu-plugin.md" pluginSpec [
      {
        label = "T-PLUG-6 completed by the live plugin quantum gate";
        needle = "- [x] **T-PLUG-6**";
      }
      {
        label = "T-PLUG-6 live completion evidence";
        needle = "Completed by `checks.crucible.phase2.qemuLivePluginQuantum`";
      }
      {
        label = "required plugin export wording";
        needle = "required plugin export";
      }
      {
        label = "registration-time fail-loud wording";
        needle = "fail loudly during callback";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/lib.rs" pluginLib [
      {
        label = "deadline reader exported";
        needle = "ExactDeadlineReader";
      }
      {
        label = "deadline function pointer exported";
        needle = "QemuClockDeadlineFn";
      }
      {
        label = "deadline symbol exported";
        needle = "QEMU_PLUGIN_CLOCK_DEADLINE_SYMBOL";
      }
      {
        label = "required deadline install helper exported";
        needle = "install_required_deadline_scaffold_from_qemu_info";
      }
      {
        label = "deadline symbol resolver exported";
        needle = "resolve_qemu_clock_deadline_symbol";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/abi.rs" pluginAbi [
      {
        label = "deadline dlsym symbol bytes";
        needle = "QEMU_PLUGIN_CLOCK_DEADLINE_SYMBOL_C";
      }
      {
        label = "QEMU deadline symbol resolver";
        needle = "pub fn resolve_qemu_clock_deadline_symbol";
      }
      {
        label = "process symbol lookup";
        needle = "libc::dlsym";
      }
      {
        label = "required deadline install helper";
        needle = "pub fn install_required_deadline_scaffold";
      }
      {
        label = "required deadline QEMU-info install helper";
        needle = "pub fn install_required_deadline_scaffold_from_qemu_info";
      }
      {
        # The deadline scaffold now rides through the generalized runtime-api
        # boundary scaffold, which resolves the clock-deadline symbol as a
        # required capability.
        label = "install boundary requires deadline";
        needle = "let clock_deadline_ns = resolve_qemu_clock_deadline_symbol();";
      }
      {
        label = "qemu install uses required deadline path";
        needle = "let runtime = install_owned_boundary(id, boundary, &mut reservation)?;";
      }
      {
        label = "ABI error carries deadline failure";
        needle = "ExactDeadlineCapability";
      }
      {
        label = "state stores resolved deadline reader";
        needle = "exact_deadline_reader: Some(exact_deadline_reader)";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/abi/tests.rs" pluginAbiTests [
      {
        label = "install path missing symbol test";
        needle = "abi_install_entrypoint_fails_closed_without_exact_deadline_or_queued_advance_symbols";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/deadline.rs" pluginDeadline [
      {
        label = "deadline symbol constant";
        needle = "qemu_plugin_clock_deadline_ns";
      }
      {
        label = "QEMU deadline function pointer";
        needle = "pub type QemuClockDeadlineFn = extern \"C\" fn() -> i64;";
      }
      {
        label = "required reader type";
        needle = "pub struct ExactDeadlineReader";
      }
      {
        label = "required capability constructor";
        needle = "pub fn require";
      }
      {
        label = "optional symbol rejected";
        needle = "Option<QemuClockDeadlineFn>";
      }
      {
        label = "missing capability error";
        needle = "CapabilityUnavailable";
      }
      {
        label = "required virtual-clock policy";
        needle = "ExactDeadlineIntrospection::required()";
      }
      {
        label = "raw QEMU deadline read";
        needle = "(self.clock_deadline_ns)()";
      }
      {
        label = "next deadline reader";
        needle = "pub fn read_next_deadline";
      }
      {
        label = "overshoot fallback forbidden";
        needle = "OvershootFallbackForbidden";
      }
      {
        label = "no armed timer sentinel mapping";
        needle = "ExactDeadlineReport::NoArmedTimer";
      }
      {
        label = "symbol-required test";
        needle = "exact_deadline_reader_requires_qemu_clock_deadline_symbol";
      }
      {
        label = "reader no-fallback test";
        needle = "exact_deadline_reader_reads_virtual_deadline_without_fallback";
      }
      {
        label = "multi-vCPU minimum aggregation";
        needle = "aggregate_multi_vcpu_deadline";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/registration.rs" pluginRegistration [
      {
        label = "registration helper requires deadline";
        needle = "pub fn register_callbacks_with_exact_deadline";
      }
      {
        label = "registration invokes deadline require";
        needle = "ExactDeadlineReader::require";
      }
      {
        label = "private callback milestone recorder";
        needle = "record_step_unchecked";
      }
      {
        label = "registration callback milestone";
        needle = "PluginRegistrationStep::RegisterCallbacks";
      }
      {
        label = "registration fail step";
        needle = "fail_exact_deadline_capability";
      }
      {
        label = "registration failure diagnostic";
        needle = "exact deadline introspection failed";
      }
      {
        label = "registration success test";
        needle = "registration_order_records_callbacks_after_exact_deadline_capability_check";
      }
      {
        label = "registration missing capability test";
        needle = "registration_order_fails_loud_when_exact_deadline_capability_missing";
      }
      {
        label = "registration bypass rejection test";
        needle = "registration_order_rejects_callback_registration_without_exact_deadline_capability";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/idle_loop.rs" pluginIdleLoop [
      {
        label = "idle path takes required deadline reader";
        needle = "exact_deadline_reader: &ExactDeadlineReader";
      }
      {
        label = "idle path reads QEMU deadline";
        needle = ".read_next_deadline()";
      }
      {
        label = "idle path maps deadline read errors";
        needle = "ReadExactDeadline";
      }
      {
        label = "deadline ceil conversion";
        needle = "pub fn timer_deadline_icount";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes plugin deadline introspection check";
        needle = "qemuPluginDeadlineIntrospection = import ./phase2-plugin-deadline-introspection.nix";
      }
    ]
    ++ deadlinePathForbiddenFailures;
in
  if failures != []
  then throw "crucible phase2 plugin deadline-introspection check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-plugin-deadline-introspection";
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
          name = "run-plugin-deadline-introspection";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-plugin-deadline-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              exact_deadline \
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
            deadline_symbol=qemu_plugin_clock_deadline_ns
            clock_source=QEMU_CLOCK_VIRTUAL
            required_export=true
            missing_capability_fails_registration=true
            overshoot_and_correct_fallback=false
            no_armed_timer_sentinel=true
            multi_vcpu_deadline=min
            idle_deadline_to_icount=ceil
            RESULT
          '';
        }
      ];
    }
