##! Qualifies the public GPL plugin selector and its mandatory release assertions.
{pkgs}: let
  ordinary = pkgs.crucible-qemu-plugin;
  candidate = ordinary.passthru.withBuildDriver "bazel";
  guarded = pkgs.callPackage ../../pkgs/emulation/crucible-qemu-plugin.nix {
    buildDriver = "bazel";
    mkCargoPackage = _: throw "Bazel plugin evaluated Cargo package";
    mkCargoArtifacts = _: throw "Bazel plugin evaluated Cargo artifacts";
    mkCargoDummySource = _: throw "Bazel plugin evaluated Cargo dummy source";
    aosWorkspaceVendor = throw "Bazel plugin evaluated Cargo vendor";
  };
  execution = pkgs.callPackage ../../pkgs/emulation/_crucible-qemu-bazel-plugin-tests.nix {release = true;};
  hostPackages = {
    crucible-control-server = "crates/crucible/crucible-control-server";
    crucible-control-client = "crates/crucible/crucible-control-client";
    crucible-control-api = "crates/crucible/crucible-control-api";
    crucible-session = "crates/crucible/crucible-session";
    crucible-engine = "crates/crucible/crucible-engine";
    crucible-determinism = "crates/crucible/crucible-determinism";
    crucible-device = "crates/crucible/crucible-device";
    crucible-campaign = "crates/crucible/crucible-campaign";
    crucible-store = "crates/crucible/crucible-store";
    crucible-qemu-protocol = "crates/crucible/crucible-qemu-protocol";
    crucible-qemu-shmem = "crates/crucible/crucible-qemu-shmem";
  };
  hostPackageOptions =
    pkgs.lib.concatMap
    (name: ["--package-path" "${name}=${hostPackages.${name}}"])
    (builtins.attrNames hostPackages);
  scripts = builtins.path {
    path = ../../tools/bazel/tests;
    name = "aos-bazel-qemu-plugin-package-verifiers";
    filter = path: type: type == "regular" && pkgs.lib.hasSuffix ".py" path;
  };
  identity = package: builtins.unsafeDiscardStringContext package.drvPath;
in rec {
  inherit ordinary candidate execution;
  release-cargo = import ./_bazel-qemu-plugin-tests-cargo.nix {
    inherit pkgs;
    release = true;
  };
  driver-selection = assert ordinary.passthru.buildDriver == "cargo";
  assert candidate.passthru.buildDriver == "bazel";
  assert candidate.passthru.cargoFallback.drvPath == ordinary.drvPath;
  assert (candidate.passthru.withBuildDriver "cargo").drvPath == ordinary.drvPath;
  assert !(builtins.tryEval (ordinary.passthru.withBuildDriver "invalid").drvPath).success;
  assert guarded.drvPath == candidate.drvPath;
  assert ordinary.platformSupport == candidate.platformSupport;
  assert ordinary.qualification == candidate.qualification;
  assert ordinary.runtimeDeps == candidate.runtimeDeps;
  assert ordinary.meta == candidate.meta;
    pkgs.runCommand "aos-bazel-qemu-plugin-public-driver-selection" {} ''
      mkdir -p "$out"
      cat > "$out/report.json" <<'JSON'
      ${builtins.toJSON {
        cargo = identity ordinary;
        bazel = identity candidate;
        fallback = identity candidate.passthru.cargoFallback;
        invalid_driver_rejected = true;
        cargo_constructors_and_vendor_not_evaluated = true;
        platform_runtime_metadata_and_qualification_contracts_preserved = true;
        release_tests = identity candidate.passthru.bazelTests;
        independent_apache_oracle = identity candidate.passthru.bazelOracle;
      }}
      JSON
      printf 'PASS\n' > "$out/result"
    '';
  parity =
    pkgs.runCommand "aos-bazel-qemu-plugin-public-package-parity" {
      buildDeps = [pkgs.python3 pkgs.binutils];
      outputChecks.out = {};
      exportReferencesGraph = {
        ordinary_out = [ordinary];
        bazel_out = [candidate];
      };
    } ''
      mkdir -p "$out"
      cat > packages.json <<'JSON'
      ${builtins.toJSON {
        ordinary.out = toString ordinary;
        bazel.out = toString candidate;
      }}
      JSON
      PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 ${scripts}/verify_qemu_plugin_package.py \
        --packages packages.json --closure-attributes "$NIX_ATTRS_JSON_FILE" \
        --build ${candidate.passthru.bazelBuild} --tests ${candidate.passthru.bazelTests} \
        --oracle-build ${candidate.passthru.bazelOracleBuild} \
        --workspace ${candidate.passthru.bazelWorkspace.source} \
        --test-workspace ${candidate.passthru.bazelTestWorkspace.source} \
        --oracle-workspace ${candidate.passthru.bazelOracleWorkspace.source} \
        --abi ${pkgs.aosBazelQemuPluginAbi} --qemu ${pkgs.qemu-crucible} \
        --qemu-shmem-abi ${pkgs.lib.escapeShellArg pkgs.qemu-crucible.passthru.shmemAbi} \
        --gpl ${../../LICENSES/GPL-2.0-only.txt} --mit ${../../LICENSES/MIT.txt} \
        --readelf ${pkgs.binutils}/bin/readelf \
        --loader ${pkgs.glibc}/lib/${pkgs.stdenv.hostPlatform.dynamicLinker} \
        --metadata-installer ${../../tools/bazel/metadata/install_qemu_plugin_metadata.py} \
        --output "$out/report.json"
      printf 'PASS\n' > "$out/result"
    '';
  release-parity = pkgs.runCommand "aos-bazel-qemu-plugin-release-test-parity" {buildDeps = [pkgs.python3];} ''
    mkdir -p "$out"
    export PYTHONDONTWRITEBYTECODE=1
    ${pkgs.python3}/bin/python3 ${scripts}/verify_protocol.py \
      --features-only --inventory ${execution.hostInventory}/inventory.json \
      --messages ${release-cargo}/host/cargo-messages.jsonl \
      ${pkgs.lib.escapeShellArgs hostPackageOptions} --output "$out/host-features.json"
    ${pkgs.python3}/bin/python3 ${scripts}/verify_protocol.py \
      --tests ${execution.tests}/evidence/tests --inventory ${execution.inventory}/inventory.json \
      --messages ${release-cargo}/gpl/cargo-messages.jsonl \
      --package-path crucible-qemu-plugin=crates/crucible/crucible-qemu-plugin \
      --dependency-package-path crucible-qemu-protocol=crates/crucible/crucible-qemu-protocol \
      --dependency-package-path crucible-qemu-shmem=crates/crucible/crucible-qemu-shmem \
      --output "$out/tests.json"
    ${pkgs.python3}/bin/python3 ${scripts}/verify_compiler_options.py \
      --build ${execution.hostBuild} --cargo ${release-cargo}/host --output "$out/host-compiler.json"
    ${pkgs.python3}/bin/python3 ${scripts}/verify_compiler_options.py \
      --build ${execution.tests} --cargo ${release-cargo}/gpl --output "$out/gpl-compiler.json"
    printf 'PASS\n' > "$out/result"
  '';
  live-whitebox = builtins.mapAttrs (driver: package:
    import ../crucible/phase2-qemu-live-whitebox-doorbell.nix {
      pkgs = pkgs // {crucible-qemu-plugin = package;};
      inherit (pkgs) lib;
      attrPath = "checks.build.bazel.qemu-plugin-production.live-whitebox.${driver}";
    }) {
    ordinary = ordinary;
    bazel = candidate;
  };
  abi-conformance = (import ./_bazel-abi-owners.nix {inherit pkgs;}).driver-comparison;
  license-boundary = import ../crucible/phase1-license-boundary.nix {
    inherit pkgs;
    inherit (pkgs) lib;
    attrPath = "checks.build.bazel.qemu-plugin-production.license-boundary";
  };
  all =
    pkgs.runCommand "aos-bazel-qemu-plugin-public-production-checks" {
      buildDeps = [driver-selection parity release-parity];
    } ''
      mkdir -p "$out"
      cp ${driver-selection}/report.json "$out/driver-selection.json"
      cp ${parity}/report.json "$out/report.json"
      cp -R ${release-parity} "$out/release-tests"
      printf 'PASS\n' > "$out/result"
    '';
}
