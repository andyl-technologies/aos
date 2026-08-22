##! Regression checks for reusable Cargo dependency artifacts.
{pkgs}: let
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
    hash = "sha256-8KYbFEUyYG3jH3ro0ZhRyqbdeWnj44reziNvTTdFd1Q=";
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
    doCheck = false;
  };
in
  assert toString dummyA == toString dummyB;
  assert toString dummyA != toString dummyManifestChange;
    pkgs.mkDerivation {
      pname = "cargo-artifacts-check";
      version = "1";
      src = null;
      buildDeps = [consumer pkgs.jq];
      phases = [
        {
          name = "check";
          script = ''
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
      passthru = {inherit artifacts consumer dummyA dummyB dummyManifestChange;};
    }
