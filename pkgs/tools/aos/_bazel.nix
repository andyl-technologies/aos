##! Builds the CLI programs with Bazel and preserves their production installation.
{
  packageArguments,
  cargoFallback,
  mkDerivation,
  mkAosBazelWorkspace,
  mkAosBazelToolchains,
  mkAosBazelBuild,
  mkAosBazelPackage,
  aosBazelRepositories,
  aosBazelRustRepositories,
  aosBazelHubServiceLibraries,
  aosBazelCodegenTools,
  aosBazelConsoleAssets,
  aosBazelCrucibleCliRuntime,
  gccUnwrapped,
  openssl,
  sqlite,
  libssh2,
  zlib,
  rust,
  python3,
  remove-references-to,
  stdenv,
}: let
  prefix = "//crates/cli/aos-cli:";
  targets = map (name: prefix + name) ["production_binaries" "production_suite_license_closure"];
  repositories =
    aosBazelRepositories
    // aosBazelRustRepositories.aos-cli-production
    // {
      aos_native = aosBazelHubServiceLibraries;
      aos_codegen = aosBazelCodegenTools;
      aos_console_assets = aosBazelConsoleAssets;
      aos_cli_runtime = aosBazelCrucibleCliRuntime;
    };
  workspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceInventory = ../../../tools/bazel/metadata/aos-cli-inventory.json;
    dependencyProfile = "aos-cli-production";
    cargoProfile = "release";
    inherit repositories;
    # Match the ordinary compiler's static unwinder search, as in the boot
    # package, without introducing a shared libgcc_s runtime dependency.
    toolchains = mkAosBazelToolchains {gccRuntime = gccUnwrapped;};
    rustcFlags = ["-Copt-level=3" "-Cdebuginfo=0" "-Cdebug-assertions=no" "-Coverflow-checks=no"];
    execRustcFlags = ["-Copt-level=0" "-Cdebuginfo=0" "-Cdebug-assertions=no" "-Coverflow-checks=no"];
    analysisTargets = targets;
  };
  build = mkAosBazelBuild {
    pname = "aos-bazel-cli-production-programs";
    inherit workspace targets;
    retainActionGraph = true;
  };
  programs = mkAosBazelPackage {
    pname = "aos-cli";
    version = packageArguments.version;
    inherit build;
    runtimeDeps = [openssl sqlite libssh2 zlib];
    packageLabel = "${prefix}production_binaries";
  };
  bundleRecipe = ../../../docs/rfcs/0012-hub-surface-topology/hub-topology-cutover-bundle-generation-v1.fixture.json;
in
  assert !stdenv.isCross && stdenv.hostPlatform.isLinux;
    mkDerivation {
      inherit
        (packageArguments)
        pname
        version
        platformSupport
        qualification
        outputs
        outputPackages
        module
        moduleDeps
        outputChecks
        runtimeDeps
        nukeRefsKeep
        NIX_LDFLAGS
        postInstall
        checks
        meta
        ;
      src = null;
      buildDeps = [programs remove-references-to python3];
      # Replace Cargo's source/vendor exclusions with this driver's build
      # inputs. The existing per-output runtime exclusions remain in force.
      disallowedReferences = [build programs workspace.source rust];
      phases = [
        {
          name = "install";
          script = ''
            mkdir -p "$out/bin"
            install -m 755 ${programs}/bin/* "$out/bin/"

            # Bazel stages shared imports through _solib. Installed programs
            # use immutable AOS library paths, never the deleted action tree.
            ${python3}/bin/python3 - "$out/bin" <<'PYTHON'
            from pathlib import Path
            import subprocess
            import sys

            for program in sorted(Path(sys.argv[1]).iterdir()):
                rpath = subprocess.check_output(["patchelf", "--print-rpath", str(program)], text=True).strip()
                retained = []
                for directory in rpath.split(":"):
                    if directory.startswith("$ORIGIN/../../../_solib_"):
                        continue
                    if not directory.startswith("/nix/store/"):
                        raise ValueError("unexpected CLI library search path: " + directory)
                    retained.append(directory)
                subprocess.run(["patchelf", "--set-rpath", ":".join(retained), str(program)], check=True)
                subprocess.run(["patchelf", "--shrink-rpath", str(program)], check=True)
            PYTHON

            # The retained production hook tests the installed wrapper's
            # verifier bytes using this explicit recipe, without Cargo sources.
            recipe_directory="$NIX_BUILD_TOP/source/docs/rfcs/0012-hub-surface-topology"
            mkdir -p "$recipe_directory"
            cp ${bundleRecipe} "$recipe_directory/${baseNameOf bundleRecipe}"
          '';
        }
      ];
      passthru =
        (builtins.removeAttrs packageArguments.passthru [
          "cargoArtifacts"
          "cargoDeps"
          "cargoEnv"
          "cargoArtifactContract"
          "integrationSource"
          "testTargets"
          "tests"
          "evidenceSources"
        ])
        // {
          buildDriver = "bazel";
          inherit cargoFallback;
          bazelBuild = build;
          bazelWorkspace = workspace;
          bazelPrograms = programs;
          evidenceSources = [workspace.source] ++ builtins.attrValues repositories;
        };
    }
