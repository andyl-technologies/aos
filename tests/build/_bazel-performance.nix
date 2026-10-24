##! Temporary matched-source compile baselines before the boot family's cutover.
{
  pkgs,
  trial,
}: let
  workspace = pkgs.mkAosBazelWorkspace {
    root = ../..;
    sourceInventory = ../../tools/bazel/metadata/boot-pilot-inventory.json;
    analysisTargets = ["//crates/boot/aos-boot-identity:package"];
  };
  cargoSource = import ../../pkgs/tools/crucible/_cargo-source.nix {inherit (pkgs) lib;};
  compilerCache = pkgs.mkAccacheEnvironment {
    compilers = {"${builtins.unsafeDiscardStringContext (toString pkgs.rust)}/bin/rustc" = "rust";};
    roots = [pkgs.rust pkgs.cc];
    # Each repetition supplies its own disk directories. Only this immutable
    # realized compiler manifest is shared between measurement series.
    cacheDir = "/unused-performance-cache";
    stateDir = "/unused-performance-state";
  };
  configuration = pkgs.writeTextFile {
    name = "aos-bazel-pilot-measurement.json";
    text = builtins.toJSON {
      inherit trial;
      jobs = 4;
      bazel_source = toString workspace.source;
      bazel_config = toString workspace.configuration;
      prepared_lock = "${workspace.preparedLock}/MODULE.bazel.lock";
      cargo_source = toString cargoSource;
      vendor = toString pkgs.aos.passthru.cargoDeps;
      launcher = "${../../tools/bazel/launcher.py}";
      cargo = "${pkgs.rust}/bin/cargo";
      rustc = "${pkgs.rust}/bin/rustc";
      accache = "${pkgs.accache}/bin/accache";
      accache_manifest = compilerCache.ACCACHE_MANIFEST;
      versions = {
        rust = pkgs.rust.version;
        bazel = pkgs.bazel.version;
      };
      profiles = {
        cargo-incremental = "Cargo dev defaults, incremental, no compiler wrapper";
        cargo-nonincremental-accache = "Cargo dev defaults, nonincremental, local accache";
        cargo-incremental-debug0 = "Cargo dev with debug=0, incremental, no compiler wrapper";
        bazel = "Bazel fastbuild defaults, local disk action cache, private output base";
        bazel-server = "Bazel fastbuild, private persistent JVM, 2 GiB heap limit, 60-second idle limit, explicit shutdown";
      };
    };
  };
in
  assert builtins.isString trial && trial != "";
    pkgs.mkDerivation {
      pname = "aos-bazel-pilot-performance";
      version = "1";
      src = null;
      measurementTrial = trial;
      sharedBuildCache = false;
      buildDeps = [pkgs.rust pkgs.accache pkgs.python3];
      dontStrip = true;
      dontPatchELF = true;
      dontNukeRefs = true;
      phases = [
        {
          name = "measure";
          script = ''
            mkdir "$TMPDIR/performance-tools"
            cp ${../../tools/bazel/bench/measure_pilot.py} "$TMPDIR/performance-tools/measure_pilot.py"
            cp ${../../tools/bazel/metadata/export_packages.py} "$TMPDIR/performance-tools/export_packages.py"
            cp ${../../tools/bazel/tests/verify_cache.py} "$TMPDIR/performance-tools/verify_cache.py"
            ${pkgs.python3}/bin/python3 "$TMPDIR/performance-tools/measure_pilot.py" \
              --configuration ${configuration} --scratch "$TMPDIR/performance" --output "$out" \
              --repetitions 3
          '';
        }
      ];
    }
