##! Regression checks for reusable Cargo dependency artifacts.
{pkgs}: let
  isCargoBuildDirectory = import ../../pkgs/build-support/_cargo-build-directory.nix;
  buildDirectories = [
    "target"
    "target-debug"
    "member/target"
    "member/target-release"
  ];
  sourceDirectories = [
    "src/target"
    "member/src/target"
    "member/src/nested/target"
    "member/src/target-specific"
  ];
  cachePermissions = import ./cache-permissions.nix {inherit pkgs;};
  # This real module was previously mistaken for an output directory. Keep
  # the packaged daemon source identical to the file compiled by Cargo.
  workspaceSource = import ../../pkgs/tools/aos/_workspace-source.nix {
    lib = pkgs.lib;
    selectedCrates = ["crucible/crucible-daemon"];
  };
  resultModule = "crates/crucible/crucible-daemon/src/executor_worker/result/operations.rs";
  sourceA = builtins.path {
    path = ./source-a;
    name = "cargo-artifact-source-a";
  };
  sourceB = builtins.path {
    path = ./source-b;
    name = "cargo-artifact-source-b";
  };
  sourceManifestChange = builtins.path {
    path = ./source-manifest-change;
    name = "cargo-artifact-source-manifest-change";
  };
  dummyA = pkgs.mkCargoDummySource {
    srcRoot = sourceA;
    name = "cargo-artifact-fixture-dummy";
  };
  dummyB = pkgs.mkCargoDummySource {
    srcRoot = sourceB;
    name = "cargo-artifact-fixture-dummy";
  };
  dummyManifestChange = pkgs.mkCargoDummySource {
    srcRoot = sourceManifestChange;
    name = "cargo-artifact-fixture-dummy";
  };
  cargoDeps = pkgs.fetchCargoDeps {
    src = sourceA;
    # Cargo includes its format comment in .cargo-checksum.json; the locked
    # itoa archive and all vendored package bytes remain unchanged.
    hash = "sha256-O70O+WRN7Er7JDh1EVJFFqkPzQu5kmJ8DLX/gxCoavQ=";
  };
  contract = {family = "fixture-native-release";};
  artifacts = pkgs.mkCargoArtifacts {
    pname = "cargo-artifact-fixture-dependencies";
    version = "1";
    src = dummyA;
    inherit cargoDeps;
    cargoArtifactContract = contract;
  };
  consumer = pkgs.mkCargoPackage {
    pname = "cargo-artifact-fixture-consumer";
    version = "1";
    src = sourceB;
    inherit cargoDeps;
    cargoArtifacts = artifacts;
    cargoArtifactContract = contract;
    # This check exercises the immutable dependency seed. Development target
    # caches deliberately replace that seed and have their own permission gate.
    sharedBuildCache = false;
    doCheck = false;
  };
in
  assert builtins.all (relative: isCargoBuildDirectory "/workspace" "/workspace/${relative}") buildDirectories;
  assert builtins.all (relative: !isCargoBuildDirectory "/workspace" "/workspace/${relative}") sourceDirectories;
  assert builtins.pathExists "${workspaceSource}/${resultModule}";
  assert builtins.readFile "${workspaceSource}/${resultModule}" == builtins.readFile (../../. + "/${resultModule}");
  assert toString dummyA == toString dummyB;
  assert toString dummyA != toString dummyManifestChange;
    pkgs.mkDerivation {
      pname = "cargo-artifacts-check";
      version = "1";
      src = null;
      buildDeps = [consumer cachePermissions pkgs.jq];
      phases = [
        {
          name = "check";
          script = ''
            test -f ${dummyA}/src/target/phase.rs
            test -f ${dummyB}/src/target/phase.rs
            test -x ${consumer}/bin/artifact-fixture
            ${consumer}/bin/artifact-fixture | grep -qx 'answer=42'
            jq -e 'select(.reason == "compiler-artifact" and (.package_id | startswith("registry+") and contains("itoa@1.0.18")) and .fresh == true)' \
              ${consumer}/nix-support/cargo-build-messages.jsonl >/dev/null
            if grep -F '${cargoDeps}' ${consumer}/nix-support/cargo-build-messages.jsonl; then
              echo "runtime Cargo diagnostics retain the vendor store path" >&2
              exit 1
            fi
            grep -F '/nix/store/00000000000000000000000000000000-redacted/' \
              ${consumer}/nix-support/cargo-build-messages.jsonl >/dev/null
            mkdir -p "$out"
            echo PASS > "$out/result"
          '';
        }
      ];
      passthru = {inherit artifacts cachePermissions consumer dummyA dummyB dummyManifestChange;};
    }
