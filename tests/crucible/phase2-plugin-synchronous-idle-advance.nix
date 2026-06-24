{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuPluginSynchronousIdleAdvance",
  taskIds ? ["T-PLUG-7"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-7PIlTjQ6Cnb2k2+Qn4A49maDZSffD20krhCcwJ7od8Y=";
  };

  pluginLib = builtins.readFile ../../crates/crucible-qemu-plugin/src/lib.rs;
  pluginAbi = builtins.readFile ../../crates/crucible-qemu-plugin/src/abi.rs;
  pluginRegistration = builtins.readFile ../../crates/crucible-qemu-plugin/src/registration.rs;
  pluginIdleLoop = builtins.readFile ../../crates/crucible-qemu-plugin/src/idle_loop.rs;
  pluginTimeControl = builtins.readFile ../../crates/crucible-qemu-plugin/src/time_control.rs;
  pluginSpec = builtins.readFile ../../docs/rfcs/0010-crucible/12-qemu-plugin.md;
  qemuPatchSpec = builtins.readFile ../../docs/rfcs/0010-crucible/11-qemu-patches.md;
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

  forbiddenTimePathApis = [
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
  ];

  timePathSources = [
    {
      label = "crates/crucible-qemu-plugin/src/idle_loop.rs";
      content = pluginIdleLoop;
    }
    {
      label = "crates/crucible-qemu-plugin/src/time_control.rs";
      content = pluginTimeControl;
    }
  ];

  forbiddenTimePathFailures =
    lib.concatMap (
      source:
        lib.concatMap (
          api:
            lib.optionals (hasInfix api source.content) [
              "${source.label}: forbidden host-time, timeout, or entropy API in synchronous idle path: `${api}`"
            ]
        )
        forbiddenTimePathApis
    )
    timePathSources;

  failures =
    failuresFor "docs/rfcs/0010-crucible/12-qemu-plugin.md" pluginSpec [
      {
        label = "T-PLUG-7 checklist complete";
        needle = "- [x] **T-PLUG-7**";
      }
      {
        label = "direct advance wording";
        needle = "required direct-advance export";
      }
      {
        label = "bottom-half drain wording";
        needle = "bottom-halves from the idle context";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/11-qemu-patches.md" qemuPatchSpec [
      {
        label = "direct advance export spec";
        needle = "qemu_plugin_advance_virtual_time_direct(ns)";
      }
      {
        label = "inline virtual timer run spec";
        needle = "qemu_clock_run_timers(QEMU_CLOCK_VIRTUAL)";
      }
      {
        label = "bottom-half drain spec";
        needle = "pending main-loop bottom halves";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/lib.rs" pluginLib [
      {
        label = "direct advance function pointer exported";
        needle = "QemuAdvanceVirtualTimeDirectFn";
      }
      {
        label = "synchronous idle advance exported";
        needle = "SynchronousIdleAdvance";
      }
      {
        label = "synchronous idle drain exported";
        needle = "SynchronousIdleDrain";
      }
      {
        label = "direct advance resolver exported";
        needle = "resolve_qemu_advance_virtual_time_direct_symbol";
      }
      {
        label = "time-capability install helper exported";
        needle = "install_required_time_capability_scaffold_from_qemu_info";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/time_control.rs" pluginTimeControl [
      {
        label = "direct advance symbol constant";
        needle = "QEMU_PLUGIN_ADVANCE_VIRTUAL_TIME_DIRECT_SYMBOL";
      }
      {
        label = "direct advance function pointer";
        needle = "pub type QemuAdvanceVirtualTimeDirectFn = extern \"C\" fn(i64);";
      }
      {
        label = "required direct advance handle";
        needle = "pub struct SynchronousIdleAdvance";
      }
      {
        label = "direct advance require constructor";
        needle = "pub fn require";
      }
      {
        label = "optional direct advance rejected";
        needle = "Option<QemuAdvanceVirtualTimeDirectFn>";
      }
      {
        label = "advance and drain method";
        needle = "pub fn advance_and_drain";
      }
      {
        label = "QEMU direct advance call";
        needle = "(self.advance_virtual_time_direct)(qemu_target_ns)";
      }
      {
        label = "bottom-half drain evidence";
        needle = "drained_bottom_halves: true";
      }
      {
        label = "signed QEMU range guard";
        needle = "VirtualTimeOutOfRange";
      }
      {
        label = "authorized target projection";
        needle = "pub fn target_virtual_ns";
      }
      {
        label = "direct advance missing-symbol test";
        needle = "synchronous_idle_advance_requires_qemu_direct_advance_symbol";
      }
      {
        label = "direct advance call test";
        needle = "synchronous_idle_advance_calls_qemu_and_reports_bottom_half_drain";
      }
      {
        label = "direct advance range test";
        needle = "synchronous_idle_advance_rejects_targets_outside_qemu_signed_range";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/registration.rs" pluginRegistration [
      {
        label = "callback capabilities type";
        needle = "pub struct PluginCallbackCapabilities";
      }
      {
        label = "registration requires direct advance function";
        needle = "QemuAdvanceVirtualTimeDirectFn";
      }
      {
        label = "registration invokes direct advance require";
        needle = "SynchronousIdleAdvance::require";
      }
      {
        label = "direct callback bypass diagnostic";
        needle = "exact deadline and synchronous idle-advance capabilities";
      }
      {
        label = "missing direct advance registration test";
        needle = "registration_order_fails_loud_when_synchronous_idle_advance_missing";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/idle_loop.rs" pluginIdleLoop [
      {
        label = "completion takes synchronous advance capability";
        needle = "synchronous_idle_advance: &SynchronousIdleAdvance";
      }
      {
        label = "idle completion projects authorized target";
        needle = ".target_virtual_ns(clock.icount_shift())";
      }
      {
        label = "idle completion calls advance and drain";
        needle = ".advance_and_drain(target_virtual_ns)";
      }
      {
        label = "idle result carries drain evidence";
        needle = "pub const fn synchronous_drain";
      }
      {
        label = "idle completion maps direct advance errors";
        needle = "IdleHotLoopError::SynchronousIdleAdvance";
      }
      {
        label = "idle direct advance test assertion";
        needle = "LAST_DIRECT_ADVANCE_NS.load(Ordering::SeqCst)";
      }
      {
        label = "idle range failure test";
        needle = "idle_loop_direct_advance_range_failure_leaves_clock_and_slot_unchanged";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/abi.rs" pluginAbi [
      {
        label = "direct advance dlsym bytes";
        needle = "QEMU_PLUGIN_ADVANCE_VIRTUAL_TIME_DIRECT_SYMBOL_C";
      }
      {
        label = "direct advance resolver";
        needle = "pub fn resolve_qemu_advance_virtual_time_direct_symbol";
      }
      {
        label = "direct advance process lookup";
        needle = "libc::dlsym";
      }
      {
        label = "time capability install helper";
        needle = "pub fn install_required_time_capability_scaffold";
      }
      {
        label = "time capability QEMU-info install helper";
        needle = "pub fn install_required_time_capability_scaffold_from_qemu_info";
      }
      {
        label = "install boundary resolves direct advance";
        needle = "resolve_qemu_advance_virtual_time_direct_symbol()";
      }
      {
        label = "ABI error carries direct advance failure";
        needle = "SynchronousIdleAdvanceCapability";
      }
      {
        label = "state stores direct advance handle";
        needle = "synchronous_idle_advance: Some(synchronous_idle_advance)";
      }
      {
        label = "install missing direct advance test";
        needle = "abi_install_requires_synchronous_idle_advance_symbol";
      }
      {
        label = "entrypoint missing direct advance test";
        needle = "abi_install_entrypoint_requires_direct_advance_after_deadline_resolution";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes plugin synchronous idle advance check";
        needle = "qemuPluginSynchronousIdleAdvance = import ./phase2-plugin-synchronous-idle-advance.nix";
      }
    ]
    ++ forbiddenTimePathFailures;
in
  if failures != []
  then throw "crucible phase2 plugin synchronous-idle-advance check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-plugin-synchronous-idle-advance";
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
          name = "run-plugin-synchronous-idle-advance";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-plugin-synchronous-idle-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              synchronous_idle \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-plugin-synchronous-idle-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              abi_install_entrypoint_requires_direct_advance_after_deadline_resolution \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-plugin-synchronous-idle-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              idle_loop_release_advances_injects_due_frames_and_republishes_running \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-plugin-synchronous-idle-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              idle_loop_direct_advance_range_failure_leaves_clock_and_slot_unchanged \
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
            direct_advance_symbol=qemu_plugin_advance_virtual_time_direct
            fires_due_timers_inline=true
            drains_bottom_halves=true
            callback_registration_requires_direct_advance=true
            qemu_install_requires_direct_advance=true
            host_time_apis_on_synchronous_idle_path=forbidden
            RESULT
          '';
        }
      ];
    }
