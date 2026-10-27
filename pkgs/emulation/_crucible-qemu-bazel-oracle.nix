##! Builds the independent Apache oracle consumed by GPL process tests.
{
  lib,
  mkAosBazelWorkspace,
  mkAosBazelBuild,
  mkAosBazelCheck,
  mkAosBazelPackage,
  mkDerivation,
  aosBazelRepositories,
  aosBazelRustRepositories,
  aosBazelStoreLibraries,
  jq,
  bash,
  sqlite,
  gcc-libs,
  sourceInventory ? ../../tools/bazel/metadata/qemu-test-oracle-host-inventory.json,
  release ? false,
}: let
  root = ../..;
  host = "//crates/crucible/crucible-control-server:";
  sourceDirectories = ["tools/bazel" "third_party/rust" "crates"];
  profileOptions = lib.optionalAttrs release {
    cargoProfile = "release";
    rustcFlags = ["-Copt-level=3" "-Cdebuginfo=0" "-Cdebug-assertions=no" "-Coverflow-checks=no"];
    execRustcFlags = ["-Copt-level=0" "-Cdebuginfo=0" "-Cdebug-assertions=no" "-Coverflow-checks=no"];
  };
  hostTargets = [
    "${host}qemu_test_oracle_artifact"
    "${host}qemu_test_oracle_license_closure"
  ];
  hostWorkspace = mkAosBazelWorkspace ({
      inherit root;
      inherit sourceInventory;
      sourceDirectories = lib.optionals (sourceInventory == null) sourceDirectories;
      dependencyProfile = "qemu-test-oracle-host";
      analysisTargets = hostTargets;
      repositories =
        aosBazelRepositories
        // aosBazelRustRepositories.qemu-test-oracle-host
        // {aos_native = aosBazelStoreLibraries;};
    }
    // profileOptions);
  testTools = mkDerivation {
    pname = "aos-bazel-qemu-process-test-tools";
    version = "1";
    src = null;
    sharedBuildCache = false;
    buildDeps = [jq];
    outputChecks.out = {};
    exportReferencesGraph.oracle = [hostPackage];
    dontStrip = true;
    dontPatchELF = true;
    dontNukeRefs = true;
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out"
          jq -cS '{schema: 1, closure: [.oracle[] | {path, narHash}] | sort_by(.path)}' \
            "$NIX_ATTRS_JSON_FILE" > "$out/closure.json"
          # Bazel hashes file contents after resolving symlinks. Bind the
          # helper's runtime closure even when its executable bytes are equal.
          printf '#!${bash}/bin/bash\n# Runtime closure: ' > "$out/oracle"
          cat "$out/closure.json" >> "$out/oracle"
          printf 'exec ${hostPackage}/bin/crucible-qemu-test-oracle "$@"\n' >> "$out/oracle"
          chmod +x "$out/oracle"
          cat > "$out/BUILD.bazel" <<'BUILD'
          exports_files(["oracle", "closure.json"], visibility = ["//visibility:public"])
          BUILD
          touch "$out/REPO.bazel"
        '';
      }
    ];
  };
  hostBuild = mkAosBazelBuild {
    pname = "aos-bazel-qemu-test-oracle-host";
    workspace = hostWorkspace;
    targets = hostTargets;
    retainActionGraph = true;
  };
  hostPackage = mkAosBazelPackage {
    pname = "crucible-control-server";
    version = "0.1.0";
    build = hostBuild;
    packageLabel = "${host}qemu_test_oracle_artifact";
    runtimeDeps = [sqlite gcc-libs];
  };
in {
  inherit hostBuild hostPackage hostWorkspace testTools;
  hostDevelopment = mkAosBazelBuild {
    pname = "aos-bazel-qemu-test-oracle-development";
    workspace = hostWorkspace;
    targets = ["${host}qemu_test_oracle_clippy"];
  };
  hostFormat = mkAosBazelCheck {
    pname = "aos-bazel-qemu-test-oracle-format";
    workspace = hostWorkspace;
    targets = ["${host}qemu_test_oracle_format"];
  };
  hostInventory = mkAosBazelBuild {
    pname = "aos-bazel-qemu-test-oracle-host-inventory";
    workspace = hostWorkspace;
    inventoryOnly = true;
    targets = hostTargets ++ ["${host}qemu_test_oracle_clippy" "${host}qemu_test_oracle_format"];
  };
}
