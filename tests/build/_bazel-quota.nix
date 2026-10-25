##! Qualifies the Linux quota library; enforcement runs only inside its VM flight.
{
  pkgs,
  sourceInventory ? ../../tools/bazel/metadata/quota-inventory.json,
}: let
  label = "//crates/linux/aos-linux-project-quota";
  family = import ./_bazel-rust-family.nix {
    inherit pkgs sourceInventory;
    pname = "aos-bazel-quota";
    packages.aos-linux-project-quota = "crates/linux/aos-linux-project-quota";
    dependencyProfile = "quota";
    repositories = pkgs.aosBazelRepositories // pkgs.aosBazelRustRepositories.quota;
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    execRustcFlags = ["-Copt-level=0" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    # Native analyzer cfg queries are optimized independently of test targets.
    editorTargetRustcFlags = [];
    retainTestActionGraph = true;
    captureCompilerArguments = true;
  };
  execution-profiles = import ./_bazel-rust-test-profiles.nix {
    inherit pkgs;
    inherit (family) tests cargo;
    pname = "aos-bazel-quota-execution-profiles";
    firstPartyTests = {"${label}:unit_binary" = "aos_linux_project_quota";};
    proceduralMacros = ["thiserror_impl"];
  };
  flightBuild = pkgs.mkAosBazelBuild {
    pname = "aos-bazel-project-quota-flight";
    workspace = family.workspace;
    targets = ["${label}:flight_package"];
  };
in
  family
  // rec {
    inherit execution-profiles;
    inventory = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-quota-inventory";
      workspace = family.workspace;
      inventoryOnly = true;
      targets = map (name: "${label}:${name}") ["lib" "unit" "unit_binary" "project-quota-flight" "flight_package" "doc" "clippy" "format" "documentation" "license_closure"];
    };
    flight = pkgs.mkAosBazelPackage {
      pname = "aos-linux-project-quota";
      version = "0.1.0";
      build = flightBuild;
      packageLabel = "${label}:flight_package";
      runtimeDeps = [pkgs.gcc-libs];
    };
    installation = let
      closure = (pkgs.lib.build.closureInfo {inherit pkgs;}) {
        pname = "aos-bazel-quota-flight-runtime-closure";
        rootPaths = [flight];
      };
    in
      pkgs.runCommand "aos-bazel-quota-flight-installation" {buildDeps = [pkgs.python3];} ''
        mkdir -p "$out"
        ${pkgs.python3}/bin/python3 - "$out" <<'PYTHON'
        import hashlib
        import json
        from pathlib import Path
        import subprocess
        import sys

        executable = Path("${flight}/bin/project-quota-flight")

        def inspect(option):
            return subprocess.check_output(["${pkgs.patchelf}/bin/patchelf", option, str(executable)], text=True).strip()

        needed = inspect("--print-needed").splitlines()
        rpath = inspect("--print-rpath").split(":")
        interpreter = inspect("--print-interpreter")
        closure = Path("${closure}/store-paths").read_text().splitlines()
        if "libgcc_s.so.1" not in needed or "${pkgs.gcc-libs}/lib" not in rpath:
            raise ValueError("installed flight lost its declared unwinder runtime")
        if "${pkgs.gcc-libs}" not in closure:
            raise ValueError("flight closure omits its unwinder runtime")
        if not Path(interpreter).is_file() or any(not Path(entry).is_dir() for entry in rpath):
            raise ValueError("installed flight contains an invalid interpreter or runtime path")

        report = {
            "executable": str(executable), "sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
            "needed": needed, "rpath": rpath, "interpreter": interpreter,
            "gcc_runtime": "${pkgs.gcc-libs}", "gcc_runtime_in_closure": True,
        }
        (Path(sys.argv[1]) / "installation.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        PYTHON
      '';
    vm = import ../crucible/phase4-project-quota-vm.nix {
      inherit pkgs;
      inherit (pkgs) lib;
      bazelProbe = flight;
    };
    all = pkgs.runCommand "aos-bazel-quota-qualified-checks" {buildDeps = [family.all family.editor-parity flight installation execution-profiles];} ''
      mkdir -p "$out/editor"
      cp -r ${family.all}/evidence "$out/evidence"
      cp ${family.all}/inventory.json ${family.all}/parity.json "$out/"
      cp ${family.editor-parity}/parity.json "$out/editor-parity.json"
      cp -r ${family.editor} "$out/editor/bazel"
      cp -r ${family.editor-cargo-oracle} "$out/editor/cargo"
      cp ${flight}/nix-support/bazel-package.json "$out/flight-package.json"
      cp ${installation}/installation.json "$out/installation.json"
      cp ${execution-profiles}/evidence.json "$out/execution-profiles.json"
    '';
  }
