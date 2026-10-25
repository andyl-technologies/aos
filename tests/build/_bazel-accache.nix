##! Qualifies the standalone compiler cache without making it a Bazel bootstrap input.
{
  pkgs,
  sourceInventory ? ../../tools/bazel/metadata/accache-inventory.json,
}: let
  packages = {
    accache = "crates/accache/accache";
    accache-frontend = "crates/accache/accache-frontend";
  };
  cargoPackage = pkgs.accache.passthru.withBuildDriver "cargo";
  productionPackage = pkgs.accache.passthru.withBuildDriver "bazel";
  # The ordinary Cargo linker resolves the bootstrap GCC unwinder statically.
  # Import that archive explicitly instead of acquiring the shared GCC runtime.
  unwinder = assert !pkgs.stdenv.isCross;
    pkgs.mkAosBazelNativeLibraries {
      libraries.unwinder = {
        # Bootstrap derivations predate the package platform annotations.
        package = pkgs.gccUnwrapped // {targetSystem = pkgs.stdenv.hostPlatform.system;};
        headerPackage = pkgs.stdenv.glibc.dev // {targetSystem = pkgs.stdenv.hostPlatform.system;};
        libraryFile = "lib/gcc/${pkgs.stdenv.hostPlatform.config}/${pkgs.gccUnwrapped.version}/libgcc.a";
        linkage = "static";
      };
    };
  repositories = pkgs.aosBazelRepositories // pkgs.aosBazelRustRepositories.accache // {aos_native = unwinder;};
  rustcFlags = ["-Copt-level=3" "-Cdebuginfo=0" "-Cdebug-assertions=no" "-Coverflow-checks=no" "-Cstrip=symbols"];
  prefix = "//crates/accache/accache:";
  vendorConfig = pkgs.writeTextFile {
    name = "accache-cargo-vendor-config";
    text = ''
      [source.crates-io]
      replace-with = "vendored-sources"
      [source.vendored-sources]
      directory = "@vendor@"
    '';
  };
  family = import ./_bazel-rust-family.nix {
    inherit pkgs packages sourceInventory repositories rustcFlags;
    execRustcFlags = ["-Copt-level=0" "-Cdebuginfo=0" "-Cdebug-assertions=no" "-Coverflow-checks=no" "-Cstrip=symbols"];
    # The editor oracle's global flags also apply to its native macro tools.
    editorExecRustcFlags = rustcFlags;
    editorCfgFlags = rustcFlags;
    pname = "aos-bazel-accache";
    dependencyProfile = "accache";
    packageTargets = {
      accache = {
        root = "accache";
        unit = "bin_accache";
        doctest = null;
      };
      accache-frontend = {
        root = "lib";
        unit = "unit";
        doctest = "doc";
      };
    };
    cargoManifest = "crates/accache/Cargo.toml";
    cargoVendor = cargoPackage.passthru.cargoDeps;
    cargoVendorConfig = vendorConfig;
    cargoFlags = ["--release"];
    captureCompilerArguments = true;
    # The models enumerate different numbers of successfully inferred expressions.
    # Retain both statistics and compare diagnostics in the two package sources.
    editorComparisonScope = "selected-packages";
    editorRustcFlags = rustcFlags;
  };
  productionTargets = map (name: prefix + name) ["accache" "package" "production_license_closure"];
  parityTools = builtins.path {
    path = ../../tools/bazel/tests;
    name = "aos-accache-production-parity-tools";
    filter = path: type:
      type == "regular" && builtins.elem (builtins.baseNameOf path) ["verify_protocol.py" "verify_pilot.py"];
  };
in
  family
  // rec {
    inherit packages;
    production = productionPackage.passthru.bazelBuild;
    production-parity = pkgs.runCommand "aos-bazel-accache-production-parity" {buildDeps = [pkgs.python3];} ''
      mkdir -p "$out"
      ${pkgs.python3}/bin/python3 ${parityTools}/verify_protocol.py \
        --tests ${production}/evidence/tests --inventory ${production}/inventory.json \
        --messages ${family.cargo}/cargo-messages.jsonl --cargo-log ${family.cargo}/cargo-tests.log \
        --package-path accache=crates/accache/accache \
        --package-path accache-frontend=crates/accache/accache-frontend \
        --output "$out/parity.json"
    '';
    driver-selection = assert cargoPackage.passthru.buildDriver == "cargo";
    assert productionPackage.passthru.buildDriver == "bazel";
    assert productionPackage.passthru.cargoFallback.drvPath == cargoPackage.drvPath;
    assert (productionPackage.passthru.withBuildDriver "cargo").drvPath == cargoPackage.drvPath;
    assert productionPackage.platformSupport == cargoPackage.platformSupport;
    assert productionPackage.platformSupport.role == "build-input";
    assert !(builtins.tryEval ((cargoPackage.passthru.withBuildDriver "unknown").drvPath)).success;
      pkgs.runCommand "aos-bazel-accache-driver-selection" {} ''
        mkdir -p "$out"
        printf '%s\n' ${pkgs.lib.escapeShellArg (builtins.toJSON {
          status = "PASS";
          default_driver = pkgs.accache.passthru.buildDriver;
          bazel = toString productionPackage;
          cargo = toString cargoPackage;
          platform_support = productionPackage.platformSupport;
        })} > "$out/selection.json"
      '';
    execution-profiles = import ./_bazel-accache-execution-profiles.nix {
      inherit pkgs production;
      inherit (family) editorWorkspace cargo;
      editorCargoOracle = family.editor-cargo-oracle;
    };
    editor-builtin-cfg = import ./_bazel-editor-builtin-cfg.nix {
      inherit pkgs;
      inherit (family) editor;
      pname = "aos-bazel-accache-editor-builtin-cfg";
      cargo = family.editor-cargo-oracle;
      workspace = family.editorWorkspace;
      flags = rustcFlags;
    };
    development-editor = import ./_bazel-accache-development-editor.nix {
      inherit pkgs;
      executionProfiles = execution-profiles;
      editorBuiltinCfg = editor-builtin-cfg;
    };
    package = productionPackage;
    installation = let
      closureInfo = pkgs.lib.build.closureInfo {inherit pkgs;};
      bazelClosure = closureInfo {
        pname = "aos-bazel-accache-runtime-closure";
        rootPaths = [package];
      };
      cargoClosure = closureInfo {
        pname = "aos-cargo-accache-runtime-closure";
        rootPaths = [cargoPackage];
      };
    in
      pkgs.runCommand "aos-bazel-accache-installation" {buildDeps = [pkgs.python3];} ''
        mkdir -p "$out"
        ${pkgs.python3}/bin/python3 - "$out/installation.json" <<'PYTHON'
        import hashlib
        import json
        from pathlib import Path
        import re
        import subprocess
        import sys

        def inspect(root, closure):
            executable = Path(root) / "bin/accache"

            def elf(option):
                return subprocess.check_output([
                    "${pkgs.patchelf}/bin/patchelf", option, str(executable),
                ], text=True).strip()

            needed = sorted(elf("--print-needed").splitlines())
            rpath = elf("--print-rpath").split(":")
            interpreter = elf("--print-interpreter")
            paths = Path(closure).read_text().splitlines()
            if not Path(interpreter).is_file() or any(not Path(entry).is_dir() for entry in rpath):
                raise ValueError("accache has an invalid loader or runtime path")

            resolved = subprocess.check_output([interpreter, "--list", str(executable)], env={}, text=True)
            libraries = dict(re.findall(r"^\s*(\S+) => (/nix/store/\S+) \(", resolved, re.MULTILINE))
            # The loader reports itself without the soname-to-path arrow.
            for path in re.findall(r"^\s*(/nix/store/\S+) \(", resolved, re.MULTILINE):
                libraries[Path(path).name] = path
            if not set(needed) <= libraries.keys():
                raise ValueError(f"the loader did not resolve every declared accache library: {needed!r}, {libraries!r}")
            help_output = subprocess.check_output([str(executable), "--help"], env={}, text=True)
            return {
                "executable": str(executable), "sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
                "needed": needed, "rpath": rpath, "interpreter": interpreter,
                "libraries": {name: str(Path(path).resolve()) for name, path in libraries.items()},
                "closure": paths, "runtime_dependencies": sorted(set(paths) - {root}),
                "help": help_output,
            }

        bazel = inspect("${package}", "${bazelClosure}/store-paths")
        cargo = inspect("${cargoPackage}", "${cargoClosure}/store-paths")
        compared = ["needed", "interpreter", "libraries", "runtime_dependencies", "help"]
        for field in compared:
            if bazel[field] != cargo[field]:
                raise ValueError("installed Bazel/Cargo accache runtime differs: " + field)
        Path(sys.argv[1]).write_text(json.dumps({
            "status": "PASS", "bazel": bazel, "cargo": cargo,
            "compared": compared,
        }, indent=2, sort_keys=True) + "\n")
        PYTHON
      '';
    integration = import ./accache.nix {
      inherit pkgs;
      inherit (pkgs) lib;
      accache = package;
      pname = "aos-bazel-accache-integration";
    };
    inventory = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-accache-inventory";
      workspace = family.workspace;
      inventoryOnly = true;
      targets =
        pkgs.lib.concatMap (path:
          map (name: "//${path}:" + name) ["license_closure" "clippy" "documentation" "format"])
        (builtins.attrValues packages)
        ++ ["${prefix}bin_accache" "//crates/accache/accache-frontend:unit" "//crates/accache/accache-frontend:doc"]
        ++ productionTargets;
    };
    all =
      pkgs.runCommand "aos-bazel-accache-checks" {
        buildDeps = [family.all family.editor-parity package installation integration driver-selection production-parity execution-profiles editor-builtin-cfg development-editor];
      } ''
        mkdir -p "$out"
        ln -s ${family.all} "$out/tests"
        ln -s ${family.editor-parity} "$out/editor"
        ln -s ${package} "$out/package"
        ln -s ${installation} "$out/installation"
        ln -s ${integration} "$out/integration"
        ln -s ${driver-selection} "$out/driver-selection"
        ln -s ${production-parity} "$out/production-parity"
        ln -s ${execution-profiles} "$out/execution-profiles"
        ln -s ${editor-builtin-cfg} "$out/editor-builtin-cfg"
        ln -s ${development-editor} "$out/development-editor"
      '';
  }
