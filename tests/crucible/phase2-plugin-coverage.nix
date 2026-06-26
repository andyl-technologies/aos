{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuPluginCoverage",
  taskIds ? ["T-PLUG-15"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  pluginLib = builtins.readFile ../../crates/crucible-qemu-plugin/src/lib.rs;
  pluginArgs = builtins.readFile ../../crates/crucible-qemu-plugin/src/args.rs;
  pluginCoverage = builtins.readFile ../../crates/crucible-qemu-plugin/src/coverage.rs;
  pluginRegistration = builtins.readFile ../../crates/crucible-qemu-plugin/src/registration.rs;
  pluginSpec = builtins.readFile ../../docs/rfcs/0010-crucible/12-qemu-plugin.md;
  patchSpec = builtins.readFile ../../docs/rfcs/0010-crucible/11-qemu-patches.md;
  advancedSpec = builtins.readFile ../../docs/rfcs/0010-crucible/22-advanced-features.md;
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
        lib.optionals (hasInfix api pluginCoverage) [
          "crates/crucible-qemu-plugin/src/coverage.rs: forbidden host-time, entropy, or lock API in coverage callback path: `${api}`"
        ]
    )
    forbiddenCallbackApis;

  failures =
    failuresFor "docs/rfcs/0010-crucible/12-qemu-plugin.md" pluginSpec [
      {
        label = "T-PLUG-15 checklist complete";
        needle = "- [x] **T-PLUG-15**";
      }
      {
        label = "coverage hook wording";
        needle = "Implement the optional coverage hook";
      }
      {
        label = "zero cost wording";
        needle = "zero cost when off";
      }
      {
        label = "observational wording";
        needle = "emit coverage as observational output";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/11-qemu-patches.md" patchSpec [
      {
        label = "TCG-exec callback export spec";
        needle = "qemu_plugin_register_tcg_exec_cb";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/22-advanced-features.md" advancedSpec [
      {
        label = "basic-block coverage spec";
        needle = "TCG-execution hook";
      }
      {
        label = "coverage feedback only spec";
        needle = "Coverage MUST feed the search and fuzzer as feedback only";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/lib.rs" pluginLib [
      {
        label = "coverage module exported";
        needle = "pub mod coverage;";
      }
      {
        label = "coverage state exported";
        needle = "PluginCoverage";
      }
      {
        label = "coverage map exported";
        needle = "CoverageMap";
      }
      {
        label = "coverage registration plan exported";
        needle = "CoverageRegistrationPlan";
      }
      {
        label = "coverage callback token exported";
        needle = "CoverageCallback";
      }
      {
        label = "coverage sink exported";
        needle = "CoverageSink";
      }
      {
        label = "coverage callback exported";
        needle = "handle_coverage_exec_callback";
      }
      {
        label = "TCG exec symbol exported";
        needle = "QEMU_PLUGIN_REGISTER_TCG_EXEC_CB_SYMBOL";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/args.rs" pluginArgs [
      {
        label = "coverage launch argument key";
        needle = "PLUGIN_ARG_COVERAGE";
      }
      {
        label = "coverage switch parsed from args";
        needle = "let coverage = parse_optional_switch";
      }
      {
        label = "coverage switch accessor";
        needle = "pub const fn coverage(&self) -> PluginSwitch";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/coverage.rs" pluginCoverage [
      {
        label = "coverage state";
        needle = "pub struct PluginCoverage";
      }
      {
        label = "registration plan";
        needle = "pub fn registration_plan";
      }
      {
        label = "off-mode disabled plan";
        needle = "CoverageRegistrationPlan::Disabled";
      }
      {
        label = "off-mode checked before validation";
        needle = "if !self.mode.is_on()";
      }
      {
        label = "hot path zero overhead method";
        needle = "hot_path_has_zero_coverage_overhead";
      }
      {
        label = "callback proof token";
        needle = "pub struct CoverageCallback";
      }
      {
        label = "enabled plan callback token";
        needle = "pub const fn require_callback";
      }
      {
        label = "TCG-exec callback capability";
        needle = "QEMU_PLUGIN_REGISTER_TCG_EXEC_CB_SYMBOL";
      }
      {
        label = "TCG-exec symbol spelling";
        needle = "\"qemu_plugin_register_tcg_exec_cb\"";
      }
      {
        label = "coverage map";
        needle = "pub struct CoverageMap";
      }
      {
        label = "fixed map default";
        needle = "DEFAULT_COVERAGE_MAP_ENTRIES";
      }
      {
        label = "basic block event";
        needle = "pub struct CoverageBlockEvent";
      }
      {
        label = "guest pc";
        needle = "guest_pc";
      }
      {
        label = "deterministic pc fold";
        needle = "pub fn fold_basic_block_pc";
      }
      {
        label = "map update";
        needle = "map.mark(map_index)";
      }
      {
        label = "saturating counter";
        needle = "saturating_add";
      }
      {
        label = "coverage observation";
        needle = "pub struct CoverageObservation";
      }
      {
        label = "coverage sink";
        needle = "pub trait CoverageSink";
      }
      {
        label = "observational record method";
        needle = "record_coverage";
      }
      {
        label = "safe coverage callback body";
        needle = "pub fn handle_coverage_exec_callback";
      }
      {
        label = "callback avoids deterministic-state side effects";
        needle = "No scheduler, virtual-time, injection state";
      }
      {
        label = "disabled callback failure";
        needle = "CallbackWhileDisabled";
      }
      {
        label = "off-mode test";
        needle = "coverage_registration_off_mode_installs_no_callback_and_ignores_map_config";
      }
      {
        label = "on-mode capability test";
        needle = "coverage_registration_on_mode_requires_tcg_exec_capability";
      }
      {
        label = "basic-block fold test";
        needle = "coverage_exec_callback_folds_basic_block_pc_and_records_observation";
      }
      {
        label = "repeat counter test";
        needle = "coverage_exec_callback_uses_saturating_counters_without_new_signal_on_repeat";
      }
      {
        label = "disabled plan callback token test";
        needle = "coverage_disabled_plan_cannot_build_hot_callback_and_does_not_touch_map";
      }
      {
        label = "map mismatch test";
        needle = "coverage_exec_callback_rejects_wrong_map_size_before_recording";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/registration.rs" pluginRegistration [
      {
        label = "registration consumes parsed coverage switch";
        needle = "PluginCoverage::with_default_map(args.coverage())";
      }
      {
        label = "registration accepts coverage capabilities";
        needle = "coverage_capabilities: CoverageCapabilities";
      }
      {
        label = "registration returns coverage plan";
        needle = "coverage_registration_plan";
      }
      {
        label = "registration returns coverage callback token";
        needle = "coverage_callback";
      }
      {
        label = "registration fails on missing TCG-exec callback";
        needle = "fail_coverage_capability";
      }
      {
        label = "registration off coverage test";
        needle = "registration_coverage_off_installs_no_callback_without_capability";
      }
      {
        label = "registration on missing capability test";
        needle = "registration_coverage_on_requires_tcg_exec_callback_capability";
      }
      {
        label = "registration on callback token test";
        needle = "registration_coverage_on_installs_tcg_exec_callback_token";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes plugin coverage check";
        needle = "qemuPluginCoverage = import ./phase2-plugin-coverage.nix";
      }
    ]
    ++ forbiddenCallbackFailures;
in
  if failures != []
  then throw "crucible phase2 plugin coverage check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-plugin-coverage";
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
          name = "run-plugin-coverage";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-plugin-coverage-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              coverage_ \
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
            off_mode=disabled-plan-installs-no-tcg-exec-callback
            coverage_signal=guest-pc-folded-into-fixed-map
            output=observational-coverage-entry
            hot_path_when_off=no-registered-callback
            callback_host_time_apis=forbidden
            RESULT
          '';
        }
      ];
    }
