##! Repeated storage/campaign compilation with complete untimed case validation.
{
  trial,
  system ? builtins.currentSystem,
  modes ? ["cargo-incremental" "cargo-nonincremental-accache" "bazel-server"],
}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
  family = import ../../../tests/build/_bazel-store.nix {inherit pkgs;};
  packages = {
    crucible-store = "crates/crucible/storage/crucible-store";
    crucible-campaign = "crates/crucible/engine/crucible-campaign";
  };
  inventory = builtins.fromJSON (builtins.readFile ../metadata/store-inventory.json);
  targets = map (target: target.label) (builtins.filter
    (target:
      target.kind
      == "rust_test"
      && target.features == []
      && builtins.elem (builtins.head (pkgs.lib.splitString ":" target.label))
      (map (path: "//${path}") (builtins.attrValues packages)))
    inventory.configured_targets);
  compilerCache = pkgs.mkAccacheEnvironment {
    compilers = {"${builtins.unsafeDiscardStringContext (toString pkgs.rust)}/bin/rustc" = "rust";};
    roots = [pkgs.rust pkgs.cc pkgs.sqlite];
    cacheDir = "/unused-performance-cache";
    stateDir = "/unused-performance-state";
  };
  configuration = pkgs.writeTextFile {
    name = "aos-bazel-store-measurement.json";
    text = builtins.toJSON {
      inherit trial packages targets modes;
      jobs = 4;
      # Untimed case validation can outlast the ordinary development idle
      # timeout. Keep this private JVM for warm samples; the harness shuts it
      # down in its finally block and verifies reuse from recorded PIDs.
      server_idle_seconds = 3600;
      scope = "connected storage/campaign default-feature libtest compilation";
      compiler_profile_scope = "Four selected test-artifact settings are matched; dependency, execution-tool, and incremental code-generation defaults may differ. Cargo compiler commands and Bazel execution events retain actual arguments.";
      require_matched_profiles = true;
      edits = {
        implementation-edit = "${packages.crucible-campaign}/src/lib.rs";
        public-api-edit = "${packages.crucible-store}/src/lib.rs";
      };
      bazel_compilation_profile = {
        opt_level = "s";
        debug = 0;
        debug_assertions = true;
        overflow_checks = true;
      };
      bazel_source = toString family.workspace.source;
      bazel_config = toString family.workspace.configuration;
      prepared_lock = "${family.workspace.preparedLock}/MODULE.bazel.lock";
      cargo_source = toString (import ../../../pkgs/tools/crucible/_cargo-source.nix {inherit (pkgs) lib;});
      vendor = toString pkgs.aos.passthru.cargoDeps;
      parity = "${family.oracle}/parity.json";
      launcher = "${../launcher.py}";
      case_runner = "${../testing/runner.py}";
      test_policy = "${../testing/policy.json}";
      cargo = "${pkgs.rust}/bin/cargo";
      rustc = "${pkgs.rust}/bin/rustc";
      accache = "${pkgs.accache}/bin/accache";
      accache_manifest = compilerCache.ACCACHE_MANIFEST;
      versions = {
        rust = pkgs.rust.version;
        bazel = pkgs.bazel.version;
      };
      native_inputs = {
        cargo_sqlite = toString pkgs.sqlite;
        bazel = toString pkgs.aosBazelStoreLibraries;
        cargo_zstd = "zstd-sys builds its pinned bundled upstream C source";
        bazel_zstd = "prepared AOS threaded zstd archive; dependency preparation is excluded";
      };
    };
  };
in
  assert builtins.isString trial && trial != "";
  assert builtins.isList modes && modes != []; {
    inherit configuration;
    measurement =
      pkgs.runCommand "aos-bazel-store-performance" {
        buildDeps = [pkgs.rust pkgs.accache pkgs.python3 pkgs.pkg-config];
        runtimeDeps = [pkgs.sqlite];
        measurementTrial = trial;
      } ''
        mkdir tools
        cp ${./measure_family.py} tools/measure_family.py
        cp ${./measure_pilot.py} tools/measure_pilot.py
        cp ${../metadata/export_packages.py} tools/export_packages.py
        cp ${../tests/verify_cache.py} tools/verify_cache.py
        cp ${../tests/family_libtest.py} tools/family_libtest.py
        ${pkgs.python3}/bin/python3 tools/measure_family.py \
          --configuration ${configuration} --scratch "$TMPDIR/performance" \
          --output "$out" --repetitions 3 \
          ${pkgs.lib.escapeShellArgs (pkgs.lib.concatMap (mode: ["--mode" mode]) modes)}
      '';
  }
