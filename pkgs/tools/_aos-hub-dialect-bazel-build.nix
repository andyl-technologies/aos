##! Compiles the required live SQL contract without executing it outside its VM.
{
  mkDerivation,
  rust,
  mkAosBazelWorkspace,
  mkAosBazelBuild,
  mkAosBazelToolchains,
  gccUnwrapped,
  aosBazelRepositories,
  aosBazelRustRepositories,
  aosBazelHubServiceLibraries,
  aosBazelCodegenTools,
  aosBazelRegistryTestTools,
  aosBazelCrucibleCliRuntime,
  sourceInventory ? ../../tools/bazel/metadata/hub-dialect-inventory.json,
}: let
  targets = map (name: "//crates/hub/aos-hub-native:" + name) ["dialect_package" "dialect_license_closure"];
  # This test package supplies no browser assets to Cargo. Run the unchanged
  # generator to retain its actual fallback bytes without copying constants.
  consoleAssets = mkDerivation {
    pname = "aos-bazel-hub-dialect-console-assets";
    version = "1";
    src = null;
    buildDeps = [rust];
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out"
          rustc --edition=2021 ${../../crates/hub/aos-hub-service/build.rs} -o console-assets
          unset AOS_HUB_CONSOLE_JS AOS_HUB_CONSOLE_WASM AOS_HUB_CONSOLE_CSS
          OUT_DIR="$out" ./console-assets
          cat > "$out/BUILD.bazel" <<'BUILD'
          package(default_visibility = ["//visibility:public"])
          filegroup(name = "javascript", srcs = ["hub-console.js"], tags = ["aos-license:apache-host"])
          filegroup(name = "wasm", srcs = ["hub-console_bg.wasm"], tags = ["aos-license:apache-host"])
          filegroup(name = "stylesheet", srcs = ["hub-console.css"], tags = ["aos-license:apache-host"])
          BUILD
          touch "$out/REPO.bazel"
        '';
      }
    ];
  };
  workspace = mkAosBazelWorkspace {
    root = ../..;
    inherit sourceInventory;
    # Bazel evaluates this fixture glob while loading the model package even
    # though its separate retained-control test is outside this target graph.
    extraFiles = ["crates/hub/aos-hub-model/tests/fixtures"];
    sourceDirectories =
      if sourceInventory == null
      then ["crates" "api/proto" "tests/vm" "tools/bazel" "third_party/rust"]
      else [];
    dependencyProfile = "hub-native-dialects";
    cargoProfile = "release";
    toolchains = mkAosBazelToolchains {gccRuntime = gccUnwrapped;};
    rustcFlags = [
      "-Copt-level=3"
      "-Cdebuginfo=0"
      "-Cdebug-assertions=no"
      "-Coverflow-checks=no"
      # Cargo's installed harness retains these declared native imports even
      # though its SQL cases do not call the Hub's Git/TLS entry points.
      # Preserve that ELF contract through the linker, using the same native
      # providers and search paths already declared by the dependency graph.
      "-Clink-arg=-Xlinker"
      "-Clink-arg=--push-state"
      "-Clink-arg=-Xlinker"
      "-Clink-arg=--no-as-needed"
      "-Clink-arg=-lssl"
      "-Clink-arg=-lcrypto"
      "-Clink-arg=-lssh2"
      "-Clink-arg=-Xlinker"
      "-Clink-arg=--pop-state"
    ];
    execRustcFlags = ["-Copt-level=0" "-Cdebuginfo=0" "-Cdebug-assertions=no" "-Coverflow-checks=no"];
    repositories =
      aosBazelRepositories
      // aosBazelRustRepositories.hub-native-tests
      // {
        aos_native = aosBazelHubServiceLibraries;
        aos_codegen = aosBazelCodegenTools;
        aos_console_assets = consoleAssets;
        aos_registry_runtime = aosBazelRegistryTestTools;
        aos_cli_runtime = aosBazelCrucibleCliRuntime;
      };
    analysisTargets = targets;
  };
in {
  inherit workspace consoleAssets;
  build = mkAosBazelBuild {
    pname = "aos-bazel-hub-dialect-production";
    inherit workspace targets;
    retainActionGraph = true;
  };
  inventory = mkAosBazelBuild {
    pname = "aos-bazel-hub-dialect-production-inventory";
    inherit workspace targets;
    inventoryOnly = true;
  };
}
