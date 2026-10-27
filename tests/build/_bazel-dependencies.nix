##! Dependency resolution is an explicit update; ordinary targets export specs.
{pkgs}: let
  profiles = [
    "aos-cli-tests"
    "aos-cli-fleet-tests"
    "aos-cli-production"
    "hub-worker-tests"
    "hub-worker-all-features-tests"
    "hub-worker-wasm"
    "hub-worker-wasm-do-e2e"
    "hub-worker-wasm-all-features"
    "hub-native-postgres"
    "hub-native-tests"
    "hub-service"
    "hub-service-tests"
    "hub-service-all-features"
    "hub-service-all-features-tests"
    "accache"
    "registry-web"
    "registry-web-wasm"
    "hub-console"
    "hub-console-wasm"
    "hub-db"
    "hub-db-tests"
    "hub-db-all-features"
    "hub-db-all-features-tests"
    "package-manager"
    "package-manager-tests"
    "configuration-image"
    "configuration-image-tests"
    "systemd-provider"
    "configuration-files"
    "configuration-files-tests"
    "kernel-tunable"
    "kernel-tunable-tests"
    "preparation-provider"
    "preparation-provider-tests"
    "boot-preparation"
    "boot-preparation-minimal"
    "release-coordination"
    "registry-native"
    "registry-native-tests"
    "release-preparation"
    "hub-client"
    "hub-model"
    "hub-model-tests"
    "hub-portable"
    "deployment"
    "build-services"
    "cli-support"
    "activation-crucible"
    "activation-crucible-tests"
    "activation-systemd"
    "activation-storage"
    "activation-core"
    "activation-core-tests"
    "core"
    "device"
    "store"
    "guest"
    "engine"
    "quota"
    "session"
    "control"
    "qemu-host"
    "qemu-gpl-production"
    "qemu-gpl-tests"
    "qemu-gpl-plugin-tests"
    "qemu-test-oracle-host"
    "store-s3"
    "daemon"
    "crucible-cli"
    "native-foundation"
    "native-bindings"
    "native-foundation-tests"
    "native-foundation-minimal"
    "formats"
  ];

  publishedProfiles = builtins.attrNames (pkgs.lib.filterAttrs
    (name: type:
      type
      == "directory"
      && builtins.pathExists (../../third_party/rust + "/${name}/sources.json"))
    (builtins.readDir ../../third_party/rust));

  workspace = pkgs.mkAosBazelWorkspace {
    root = ../..;
    sourceDirectories = ["tools/bazel/toolchains" "tools/bazel/rules" "tools/bazel/metadata" "third_party/rust"];
    analysisTargets = ["//third_party/rust:core_specification_package"];
  };
in rec {
  build = pkgs.mkAosBazelBuild {
    pname = "aos-bazel-rust-specifications";
    inherit workspace;
    targets = ["//third_party/rust:core_specification_package"];
  };
  specifications = specification-packages.core;
  # Missing or duplicate exports must fail instead of silently dropping an SDK.
  specification-packages = assert builtins.length profiles == builtins.length (pkgs.lib.unique profiles);
  assert builtins.sort builtins.lessThan profiles == publishedProfiles;
    builtins.listToAttrs (map (family: {
        name = family;
        value = pkgs.mkAosBazelPackage {
          pname = "aos-rust-${family}-specifications";
          version = "1";
          build = pkgs.mkAosBazelBuild {
            pname = "aos-bazel-${family}-rust-specifications";
            inherit workspace;
            targets = ["//third_party/rust:${family}_specification_package"];
          };
          packageLabel = "//third_party/rust:${family}_specification_package";
        };
      })
      profiles);
  core = pkgs.mkAosBazelCheck {
    pname = "aos-bazel-external-rust-pilot";
    workspace = pkgs.mkAosBazelWorkspace {
      root = ../..;
      sourceDirectories = ["tools/bazel/toolchains" "tools/bazel/rules" "tools/bazel/metadata" "tools/bazel/testing" "third_party/rust" "crates/crucible/crucible-determinism"];
      repositories = pkgs.aosBazelRepositories // pkgs.aosBazelRustRepositories.core;
      analysisTargets = ["//crates/crucible/crucible-determinism:unit"];
    };
    targets = [
      "//crates/crucible/crucible-determinism:unit"
      "//crates/crucible/crucible-determinism:doc"
      "//crates/crucible/crucible-determinism:clippy"
      "//crates/crucible/crucible-determinism:format"
      "//crates/crucible/crucible-determinism:documentation"
    ];
  };
  all = pkgs.runCommand "aos-bazel-external-rust-checks" {buildDeps = [specifications core];} ''
    mkdir -p "$out"
    cp -r ${core}/evidence "$out/evidence"
    cp ${core}/inventory.json "$out/inventory.json"
  '';
}
