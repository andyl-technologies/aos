##! Builds the GPL production components with checked QEMU compiler inputs.
{
  pkgs,
  sourceInventory ? ../../tools/bazel/metadata/qemu-gpl-production-inventory.json,
  cargoInstalled ? {
    plugin = pkgs.crucible-qemu-plugin;
    gateway = pkgs.crucible.passthru.cargoDebugGateway;
  },
}: let
  production = pkgs.callPackage ../../pkgs/emulation/_crucible-qemu-bazel.nix {
    inherit sourceInventory;
  };
  packages = {
    crucible-qemu-plugin = "crates/crucible/crucible-qemu-plugin";
    crucible-qemu-debug-gateway = "crates/crucible/crucible-qemu-debug-gateway";
    crucible-qemu-protocol = "crates/crucible/crucible-qemu-protocol";
    crucible-qemu-shmem = "crates/crucible/crucible-qemu-shmem";
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
  plugin = "//crates/crucible/crucible-qemu-plugin:";
  gateway = "//crates/crucible/crucible-qemu-debug-gateway:";
in rec {
  inherit (production) workspace productionTargets build installed;
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
  cargo-execution-trace = import ./_bazel-qemu-gpl-cargo.nix {
    inherit pkgs;
    retainExecutionTrace = true;
  };
  cargo-execution-inspection = import ./_bazel-compiler-execution.nix {
    inherit pkgs;
    cargo = cargo-execution-trace;
    pname = "aos-bazel-qemu-gpl-compiler-execution-inspection";
  };
  suite = pkgs.callPackage ../../pkgs/tools/crucible/crucible.nix {
    crucible-qemu-plugin = installed.plugin;
    debugGatewayPackage = installed.gateway;
  };
  suite-release-manifest = import ../crucible/phase7-crucible-release-manifest.nix {
    inherit pkgs;
    inherit (pkgs) lib;
    attrPath = "checks.build.bazel.qemu-gpl.suite-release-manifest";
    cruciblePackage = suite;
  };
  suite-source-retention = import ./_bazel-qemu-gpl-suite.nix {
    inherit pkgs suite installed;
  };
  suite-publication = import ./_bazel-qemu-gpl-publication.nix {
    inherit pkgs suite installed;
  };
  runtime-closure = import ./_bazel-runtime-closure-parity.nix {
    inherit pkgs;
    pname = "aos-bazel-qemu-gpl-runtime-closure-parity";
    packages =
      pkgs.lib.mapAttrs (name: package: {
        bazel = package;
        cargo = cargoInstalled.${name};
      })
      installed;
  };
  live-whitebox = import ../crucible/phase2-qemu-live-whitebox-doorbell.nix {
    pkgs = pkgs // {crucible-qemu-plugin = installed.plugin;};
    inherit (pkgs) lib;
    attrPath = "checks.build.bazel.qemu-gpl.live-whitebox";
  };
  production-plugin-flight = import ../crucible/phase7-production-rust-plugin-flight.nix {
    pkgs = pkgs // {crucible-qemu-plugin = installed.plugin;};
    inherit (pkgs) lib;
    attrPath = "checks.build.bazel.qemu-gpl.production-plugin-flight";
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
  gateway-release-tests = import ./_bazel-qemu-gateway-tests.nix {
    inherit pkgs;
    release = true;
  };
  plugin-tests = import ./_bazel-qemu-plugin-tests.nix {inherit pkgs;};
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
      buildDeps = [parity developer-build format installed-inspection runtime-closure gateway-tests.all plugin-tests.all];
    } ''
      mkdir -p "$out"
      printf 'PASS: production compiler artifacts and developer tools\n' > "$out/result"
    '';
}
