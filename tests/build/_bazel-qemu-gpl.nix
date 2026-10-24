##! Builds the GPL production components with checked QEMU compiler inputs.
{
  pkgs,
  sourceInventory ? ../../tools/bazel/metadata/qemu-gpl-production-inventory.json,
}: let
  packages = {
    crucible-qemu-plugin = "crates/crucible/qemu/crucible-qemu-plugin";
    crucible-qemu-debug-gateway = "crates/crucible/qemu/crucible-qemu-debug-gateway";
    crucible-qemu-protocol = "crates/crucible/protocol/crucible-qemu-protocol";
    crucible-qemu-shmem = "crates/crucible/protocol/crucible-qemu-shmem";
  };
  packageOptions =
    pkgs.lib.concatMap
    (name: ["--package-path" "${name}=${packages.${name}}"])
    (builtins.attrNames packages);
  parityTools = builtins.path {
    path = ../../tools/bazel/tests;
    name = "aos-qemu-gpl-parity-tools";
    filter = path: type: type == "directory" || pkgs.lib.hasSuffix ".py" path;
  };
  plugin = "//crates/crucible/qemu/crucible-qemu-plugin:";
  gateway = "//crates/crucible/qemu/crucible-qemu-debug-gateway:";
  productionTargets = [
    "${plugin}plugin"
    "${plugin}production_license_closure"
    "${plugin}compiler_artifact"
    "${gateway}lib"
    "${gateway}crucible-debug-gateway"
    "${gateway}production_license_closure"
    "${gateway}compiler_artifact"
  ];
  workspace = pkgs.mkAosBazelWorkspace {
    root = ../..;
    inherit sourceInventory;
    dependencyProfile = "qemu-gpl-production";
    repositories =
      pkgs.aosBazelRepositories
      // pkgs.aosBazelRustRepositories.qemu-gpl-production
      // {aos_qemu_plugin_abi = pkgs.aosBazelQemuPluginAbi;};
    rustcFlags = [
      "-Copt-level=3"
      "-Cdebuginfo=0"
      "-Cdebug-assertions=no"
      "-Coverflow-checks=no"
      "-Cstrip=debuginfo"
      # Match the ordinary AOS driver's libgcc linker script before the
      # shared C++ runtime search path supplied by the Bazel C toolchain.
      "-Lnative=${pkgs.gccUnwrapped}/lib/gcc/${pkgs.stdenv.hostPlatform.config}/${pkgs.gccUnwrapped.version}"
    ];
    sourceDirectories = pkgs.lib.optionals (sourceInventory == null) [
      "tools/bazel"
      "third_party/rust"
      "crates/crucible/qemu/crucible-qemu-plugin"
      "crates/crucible/qemu/crucible-qemu-debug-gateway"
      "crates/crucible/protocol/crucible-qemu-protocol"
      "crates/crucible/protocol/crucible-qemu-shmem"
    ];
    analysisTargets = productionTargets;
  };
in rec {
  inherit workspace productionTargets;
  build = pkgs.mkAosBazelBuild {
    pname = "aos-bazel-qemu-gpl-production";
    inherit workspace;
    targets = productionTargets;
    retainActionGraph = true;
  };
  developer-build = pkgs.mkAosBazelBuild {
    pname = "aos-bazel-qemu-gpl-production-developer";
    inherit workspace;
    targets = [
      "${plugin}clippy"
      "${plugin}documentation"
      "${gateway}clippy"
      "${gateway}documentation"
    ];
  };
  format = pkgs.mkAosBazelCheck {
    pname = "aos-bazel-qemu-gpl-production-format";
    inherit workspace;
    targets = ["${plugin}format" "${gateway}format"];
  };
  cargo = import ./_bazel-qemu-gpl-cargo.nix {inherit pkgs;};
  installed = import ./_bazel-qemu-gpl-installed.nix {inherit pkgs build;};
  live-whitebox = import ../crucible/phase2-qemu-live-whitebox-doorbell.nix {
    pkgs = pkgs // {crucible-qemu-plugin = installed.plugin;};
    inherit (pkgs) lib;
    attrPath = "checks.build.bazel.qemu-gpl.live-whitebox";
  };
  installed-inspection =
    pkgs.runCommand "aos-bazel-qemu-gpl-installed-inspection" {
      buildDeps = [pkgs.python3];
    } ''
      mkdir -p "$out"
      ${pkgs.python3}/bin/python3 ${parityTools}/verify_qemu_installed.py \
        --plugin ${installed.plugin} --gateway ${installed.gateway} --cargo ${cargo} \
        --abi ${pkgs.aosBazelQemuPluginAbi} --qemu ${pkgs.qemu-crucible} \
        --qemu-shmem-abi ${pkgs.lib.escapeShellArg pkgs.qemu-crucible.passthru.shmemAbi} \
        --readelf ${pkgs.binutils}/bin/readelf \
        --loader ${pkgs.glibc}/lib/${pkgs.stdenv.hostPlatform.dynamicLinker} \
        --gpl ${../../LICENSES/GPL-2.0-only.txt} --mit ${../../LICENSES/MIT.txt} \
        --metadata-installer ${../../tools/bazel/metadata/install_qemu_plugin_metadata.py} \
        --output "$out/report.json"
    '';
  parity =
    pkgs.runCommand "aos-bazel-qemu-gpl-production-parity" {
      buildDeps = [pkgs.python3];
    } ''
      mkdir -p "$out"
      printf '%s\n' ${pkgs.lib.escapeShellArg (builtins.toJSON {
        schema_version = 1;
        build = toString build;
        cargo = toString cargo;
        inventory = toString inventory;
        abi = toString pkgs.aosBazelQemuPluginAbi;
      })} > "$out/inputs.json"
      ${pkgs.python3}/bin/python3 ${parityTools}/verify_protocol.py \
        --features-only --inventory ${inventory}/inventory.json \
        --messages ${cargo}/cargo-messages.jsonl \
        ${pkgs.lib.escapeShellArgs packageOptions} --output "$out/features.json"
      ${pkgs.python3}/bin/python3 ${parityTools}/verify_compiler_options.py \
        --build ${build} --cargo ${cargo} --output "$out/compiler.json"
      ${pkgs.python3}/bin/python3 ${parityTools}/verify_qemu_gpl.py \
        --build ${build} --cargo ${cargo} --abi ${pkgs.aosBazelQemuPluginAbi} \
        --readelf ${pkgs.binutils}/bin/readelf --output "$out/elf.json"
    '';
  gateway-tests = import ./_bazel-qemu-gateway-tests.nix {inherit pkgs;};
  inventory = pkgs.mkAosBazelBuild {
    pname = "aos-bazel-qemu-gpl-production-inventory";
    inherit workspace;
    inventoryOnly = true;
    targets =
      productionTargets
      ++ [
        "${plugin}clippy"
        "${plugin}documentation"
        "${plugin}format"
        "${gateway}clippy"
        "${gateway}documentation"
        "${gateway}format"
      ];
  };
  all =
    pkgs.runCommand "aos-bazel-qemu-gpl-production-checks" {
      buildDeps = [parity developer-build format installed-inspection gateway-tests.all];
    } ''
      mkdir -p "$out"
      printf 'PASS: production compiler artifacts and developer tools\n' > "$out/result"
    '';
}
