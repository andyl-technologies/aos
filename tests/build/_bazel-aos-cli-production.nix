##! Builds the complete fifteen-program CLI suite before production cutover.
{
  pkgs,
  sourceInventory ? null,
  toolchains ? pkgs.aosBazelToolchains,
}: let
  declarations = import ./_bazel-aos-cli.nix {inherit pkgs;};
  prefix = "//crates/cli/aos-cli:";
  targets = map (name: prefix + name) ["production_binaries" "production_suite_license_closure"];
  workspace = pkgs.mkAosBazelWorkspace {
    root = ../..;
    inherit sourceInventory toolchains;
    dependencyProfile = "aos-cli-production";
    sourceDirectories = pkgs.lib.optionals (sourceInventory == null) (
      ["tools/bazel" "third_party/rust" "api/proto"]
      ++ builtins.attrValues declarations.packages
      ++ builtins.attrValues declarations.dependencyPackages
    );
    repositories =
      pkgs.aosBazelRepositories
      // pkgs.aosBazelRustRepositories.aos-cli-production
      // {
        aos_native = pkgs.aosBazelHubServiceLibraries;
        aos_codegen = pkgs.aosBazelCodegenTools;
        aos_console_assets = pkgs.aosBazelConsoleAssets;
        aos_cli_runtime = pkgs.aosBazelCrucibleCliRuntime;
      };
    rustcFlags = ["-Copt-level=3" "-Cdebuginfo=0" "-Cdebug-assertions=no" "-Coverflow-checks=no"];
    # The retained release Cargo artifacts use unoptimized execution tools with
    # assertions and overflow checks disabled, independently of target code.
    execRustcFlags = ["-Copt-level=0" "-Cdebuginfo=0" "-Cdebug-assertions=no" "-Coverflow-checks=no"];
    analysisTargets = targets;
  };
in rec {
  inherit workspace;
  build = pkgs.mkAosBazelBuild {
    pname = "aos-bazel-aos-cli-production";
    inherit workspace targets;
    retainActionGraph = true;
  };
  installed = pkgs.mkAosBazelPackage {
    pname = "aos-cli";
    version = "0.1.0";
    inherit build;
    runtimeDeps = [pkgs.gcc-libs pkgs.openssl pkgs.sqlite pkgs.libssh2 pkgs.zlib];
    packageLabel = "${prefix}production_binaries";
  };
  runtime-smoke = pkgs.runCommand "aos-bazel-aos-cli-production-runtime-smoke" {buildDeps = [pkgs.python3];} ''
    mkdir -p "$out"
    ${pkgs.python3}/bin/python3 - "$out" <<'PYTHON'
    import json
    from pathlib import Path
    import subprocess
    import sys

    directory = Path("${installed}/bin")
    expected = {
        "aos", "apr", "apm", "aos-package-runtime", "aos-boot-configuration",
        "aos-provisioning-configuration-evaluator", "aos-release-fleet-fixture",
        "aos-ability-interruption-audit", "aos-ability-authority-audit",
        "aos-deployment-check", "aos-image-rollout-boot", "aos-image-rollout-observer",
        "aos-image-rollout-provider", "aos-package-attestation-provider", "aos-image-metadata",
    }
    assert {path.name for path in directory.iterdir()} == expected
    commands = {}
    for name in sorted(expected):
        # The loader resolves every imported library without entering service
        # helpers, whose ordinary entry points can perform privileged effects.
        result = subprocess.run(
            ["${pkgs.glibc}/lib/${pkgs.stdenv.hostPlatform.dynamicLinker}", "--list", str(directory / name)],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode or "not found" in result.stdout:
            raise ValueError(f"installed {name} failed to load: {result.stdout}{result.stderr}")
        libraries = [line.split(" => ", 1)[1].split()[0] for line in result.stdout.splitlines() if " => /" in line]
        assert libraries and all(path.startswith("/nix/store/") for path in libraries), result.stdout
        commands[name] = {"loader_exit_code": result.returncode, "libraries": libraries}
        if name in {"aos", "apr", "apm"}:
            help_result = subprocess.run([str(directory / name), "--help"], capture_output=True, text=True, timeout=15)
            if help_result.returncode:
                raise ValueError(f"installed {name} failed: {help_result.stdout}{help_result.stderr}")
            commands[name]["help_exit_code"] = help_result.returncode
    Path(sys.argv[1], "report.json").write_text(json.dumps({
        "schema_version": 1, "installed": "${installed}", "commands": commands,
    }, indent=2, sort_keys=True) + "\n")
    PYTHON
  '';
  developer-build = pkgs.mkAosBazelBuild {
    pname = "aos-bazel-aos-cli-production-clippy";
    inherit workspace;
    targets = ["${prefix}production_clippy"];
  };
  inventory = pkgs.mkAosBazelBuild {
    pname = "aos-bazel-aos-cli-production-inventory";
    inherit workspace;
    targets = targets ++ ["${prefix}production_clippy"];
    inventoryOnly = true;
  };
}
