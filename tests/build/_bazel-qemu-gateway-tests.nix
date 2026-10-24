##! Qualifies GPL lifecycle tests using an independently linked Apache oracle.
{
  pkgs,
  hostSourceInventory ? ../../tools/bazel/metadata/qemu-test-oracle-host-inventory.json,
  testSourceInventory ? ../../tools/bazel/metadata/qemu-gateway-process-test-inventory.json,
}: let
  root = ../..;
  host = "//crates/crucible/control/crucible-control-server:";
  gateway = "//crates/crucible/qemu/crucible-qemu-debug-gateway:";
  protocol = "//crates/crucible/protocol/crucible-qemu-protocol:";
  hostPackages = {
    crucible-control-server = "crates/crucible/control/crucible-control-server";
    crucible-control-client = "crates/crucible/control/crucible-control-client";
    crucible-control-api = "crates/crucible/control/crucible-control-api";
    crucible-session = "crates/crucible/control/crucible-session";
    crucible-engine = "crates/crucible/engine/crucible-engine";
    crucible-determinism = "crates/crucible/engine/crucible-determinism";
    crucible-device = "crates/crucible/engine/crucible-device";
    crucible-campaign = "crates/crucible/engine/crucible-campaign";
    crucible-store = "crates/crucible/storage/crucible-store";
    crucible-qemu-protocol = "crates/crucible/protocol/crucible-qemu-protocol";
    crucible-qemu-shmem = "crates/crucible/protocol/crucible-qemu-shmem";
  };
  hostPackageOptions =
    pkgs.lib.concatMap
    (name: ["--package-path" "${name}=${hostPackages.${name}}"])
    (builtins.attrNames hostPackages);
  parityTools = builtins.path {
    path = root + "/tools/bazel/tests";
    name = "aos-qemu-process-parity-tools";
    filter = path: type: type == "directory" || pkgs.lib.hasSuffix ".py" path;
  };
  sourceDirectories = ["tools/bazel" "third_party/rust" "crates"];
  hostTargets = [
    "${host}qemu_test_oracle_artifact"
    "${host}qemu_test_oracle_license_closure"
  ];
  testTargets = [
    "${gateway}unit"
    "${gateway}bin_crucible-debug-gateway"
    "${gateway}process_lifecycle"
    "${gateway}test_license_closure"
    "${gateway}production_license_closure"
  ];
  hostWorkspace = pkgs.mkAosBazelWorkspace {
    inherit root;
    sourceInventory = hostSourceInventory;
    sourceDirectories = pkgs.lib.optionals (hostSourceInventory == null) sourceDirectories;
    dependencyProfile = "qemu-test-oracle-host";
    analysisTargets = hostTargets;
    repositories =
      pkgs.aosBazelRepositories
      // pkgs.aosBazelRustRepositories.qemu-test-oracle-host
      // {aos_native = pkgs.aosBazelStoreLibraries;};
  };
  testTools = pkgs.mkDerivation {
    pname = "aos-bazel-qemu-process-test-tools";
    version = "1";
    src = null;
    sharedBuildCache = false;
    buildDeps = [pkgs.jq];
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
          printf '#!${pkgs.bash}/bin/bash\n# Runtime closure: ' > "$out/oracle"
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
  testWorkspace = pkgs.mkAosBazelWorkspace {
    inherit root;
    sourceInventory = testSourceInventory;
    sourceDirectories = pkgs.lib.optionals (testSourceInventory == null) sourceDirectories;
    dependencyProfile = "qemu-gpl-tests";
    analysisTargets = testTargets;
    repositories =
      pkgs.aosBazelRepositories
      // pkgs.aosBazelRustRepositories.qemu-gpl-tests
      // {aos_qemu_test_tools = testTools;};
  };
  hostBuild = pkgs.mkAosBazelBuild {
    pname = "aos-bazel-qemu-test-oracle-host";
    workspace = hostWorkspace;
    targets = hostTargets;
    retainActionGraph = true;
  };
  hostPackage = pkgs.mkAosBazelPackage {
    pname = "crucible-control-server";
    version = "0.1.0";
    build = hostBuild;
    packageLabel = "${host}qemu_test_oracle_artifact";
    runtimeDeps = [pkgs.sqlite pkgs.gcc-libs];
  };
in rec {
  inherit hostBuild hostPackage hostWorkspace testWorkspace testTools hostPackageOptions;
  cargo = import ./_bazel-qemu-process-cargo.nix {inherit pkgs;};
  tests = pkgs.mkAosBazelCheck {
    pname = "aos-bazel-qemu-gateway-process-tests";
    workspace = testWorkspace;
    targets = testTargets;
    retainActionGraph = true;
  };
  codecTests = pkgs.mkAosBazelCheck {
    pname = "aos-bazel-qemu-test-oracle-codec-tests";
    workspace = testWorkspace;
    targets = ["${protocol}test_oracle_unit"];
  };
  hostDevelopment = pkgs.mkAosBazelBuild {
    pname = "aos-bazel-qemu-test-oracle-development";
    workspace = hostWorkspace;
    targets = ["${host}qemu_test_oracle_clippy"];
  };
  hostFormat = pkgs.mkAosBazelCheck {
    pname = "aos-bazel-qemu-test-oracle-format";
    workspace = hostWorkspace;
    targets = ["${host}qemu_test_oracle_format"];
  };
  testDevelopment = pkgs.mkAosBazelBuild {
    pname = "aos-bazel-qemu-gateway-test-development";
    workspace = testWorkspace;
    targets = ["${gateway}test_clippy"];
  };
  testFormat = pkgs.mkAosBazelCheck {
    pname = "aos-bazel-qemu-gateway-test-format";
    workspace = testWorkspace;
    targets = ["${gateway}test_format"];
  };
  hostInventory = pkgs.mkAosBazelBuild {
    pname = "aos-bazel-qemu-test-oracle-host-inventory";
    workspace = hostWorkspace;
    inventoryOnly = true;
    targets = hostTargets ++ ["${host}qemu_test_oracle_clippy" "${host}qemu_test_oracle_format"];
  };
  testInventory = pkgs.mkAosBazelBuild {
    pname = "aos-bazel-qemu-gateway-process-test-inventory";
    workspace = testWorkspace;
    inventoryOnly = true;
    targets = testTargets ++ ["${gateway}test_clippy" "${gateway}test_format" "${protocol}test_oracle_unit"];
  };
  parity = pkgs.runCommand "aos-bazel-qemu-gateway-process-parity" {buildDeps = [pkgs.python3];} ''
    mkdir -p "$out"
    export PYTHONDONTWRITEBYTECODE=1
    ${pkgs.python3}/bin/python3 ${parityTools}/verify_protocol.py \
      --features-only --inventory ${hostInventory}/inventory.json \
      --messages ${cargo}/host/cargo-messages.jsonl \
      ${pkgs.lib.escapeShellArgs hostPackageOptions} --output "$out/host-features.json"
    ${pkgs.python3}/bin/python3 ${parityTools}/verify_protocol.py \
      --tests ${tests}/evidence/tests --inventory ${testInventory}/inventory.json \
      --messages ${cargo}/gpl/cargo-messages.jsonl \
      --package-path crucible-qemu-debug-gateway=crates/crucible/qemu/crucible-qemu-debug-gateway \
      --dependency-package-path crucible-qemu-protocol=crates/crucible/protocol/crucible-qemu-protocol \
      --output "$out/tests.json"
    ${pkgs.python3}/bin/python3 ${parityTools}/verify_compiler_options.py \
      --build ${hostBuild} --cargo ${cargo}/host --output "$out/host-compiler.json"
    ${pkgs.python3}/bin/python3 ${parityTools}/verify_compiler_options.py \
      --build ${tests} --cargo ${cargo}/gpl --output "$out/gpl-compiler.json"
    printf '%s\n' ${pkgs.lib.escapeShellArg (builtins.toJSON {
      schema_version = 1;
      host_build = toString hostBuild;
      host_inventory = toString hostInventory;
      test_build = toString tests;
      test_inventory = toString testInventory;
      cargo = toString cargo;
      test_tools = toString testTools;
    })} > "$out/inputs.json"
  '';
  all = pkgs.runCommand "aos-bazel-qemu-gateway-process-checks" {} ''
    mkdir -p "$out"
    ln -s ${parity} "$out/parity"
    ln -s ${codecTests} "$out/codec-tests"
    ln -s ${hostDevelopment} "$out/host-development"
    ln -s ${hostFormat} "$out/host-format"
    ln -s ${testDevelopment} "$out/test-development"
    ln -s ${testFormat} "$out/test-format"
  '';
}
