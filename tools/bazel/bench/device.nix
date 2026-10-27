##! Device-family test compilation, independent of production builders.
{
  trial,
  system ? builtins.currentSystem,
  modes ? ["cargo-incremental" "cargo-nonincremental-accache" "cargo-incremental-debug0" "bazel-server"],
}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
  family = import ../../../tests/build/_bazel-device.nix {inherit pkgs;};
  packages = {
    crucible-determinism = "crates/crucible/crucible-determinism";
    crucible-device = "crates/crucible/crucible-device";
    crucible-qemu-protocol = "crates/crucible/crucible-qemu-protocol";
    crucible-qemu-shmem = "crates/crucible/crucible-qemu-shmem";
  };
  inventory = builtins.fromJSON (builtins.readFile ../metadata/device-inventory.json);
  targets = map (target: target.label) (builtins.filter
    (target:
      target.kind
      == "rust_test"
      && builtins.elem (builtins.head (pkgs.lib.splitString ":" target.label))
      (map (path: "//${path}") (builtins.attrValues packages)))
    inventory.configured_targets);
  compilerCache = pkgs.mkAccacheEnvironment {
    compilers = {"${builtins.unsafeDiscardStringContext (toString pkgs.rust)}/bin/rustc" = "rust";};
    roots = [pkgs.rust pkgs.cc];
    cacheDir = "/unused-performance-cache";
    stateDir = "/unused-performance-state";
  };
  configuration = pkgs.writeTextFile {
    name = "aos-bazel-device-measurement.json";
    text = builtins.toJSON {
      inherit trial packages targets modes;
      jobs = 4;
      bazel_source = toString family.workspace.source;
      bazel_config = toString family.workspace.configuration;
      prepared_lock = "${family.workspace.preparedLock}/MODULE.bazel.lock";
      cargo_source = toString (import ../../../pkgs/tools/crucible/_cargo-source.nix {inherit (pkgs) lib;});
      vendor = toString pkgs.aos.passthru.cargoDeps;
      parity = "${family.oracle}/parity.json";
      launcher = "${../launcher.py}";
      cargo = "${pkgs.rust}/bin/cargo";
      rustc = "${pkgs.rust}/bin/rustc";
      accache = "${pkgs.accache}/bin/accache";
      accache_manifest = compilerCache.ACCACHE_MANIFEST;
      versions = {
        rust = pkgs.rust.version;
        bazel = pkgs.bazel.version;
      };
    };
  };
in
  assert builtins.isString trial && trial != "";
  assert builtins.isList modes && modes != [];
    pkgs.runCommand "aos-bazel-device-performance" {
      buildDeps = [pkgs.rust pkgs.accache pkgs.python3];
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
    ''
