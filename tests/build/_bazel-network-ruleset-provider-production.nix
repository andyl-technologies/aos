##! Qualifies the static network-ruleset provider production selector.
{pkgs}: let
  ordinary = pkgs.aos-network-ruleset-provider;
  candidate = ordinary.passthru.withBuildDriver "bazel";
  compilation = pkgs.callPackage ../../pkgs/networking/_aos-network-ruleset-provider-bazel-build.nix {};
  guarded = pkgs.callPackage ../../pkgs/networking/aos-network-ruleset-provider.nix {
    buildDriver = "bazel";
    mkAosCargoPackage = _: throw "Bazel network-ruleset provider evaluated its Cargo constructor";
    mkCargoArtifacts = _: throw "Bazel network-ruleset provider evaluated Cargo artifacts";
    mkCargoDummySource = _: throw "Bazel network-ruleset provider evaluated Cargo dummy source";
    aosWorkspaceVendor = throw "Bazel network-ruleset provider evaluated its Cargo vendor";
  };
  triple = pkgs.stdenv.hostPlatform.config;
  flagsVariable = "CARGO_TARGET_${pkgs.lib.toUpper (builtins.replaceStrings ["-"] ["_"] triple)}_RUSTFLAGS";
  scripts = builtins.path {
    path = ../../tools/bazel/tests;
    name = "aos-bazel-network-ruleset-provider-production-verifiers";
    filter = path: type: type == "regular" && pkgs.lib.hasSuffix ".py" path;
  };
  identity = package: builtins.unsafeDiscardStringContext package.drvPath;
in rec {
  inherit candidate compilation;
  cargo = import ./_bazel-cargo-oracle.nix {
    inherit pkgs;
    pname = "aos-bazel-network-ruleset-provider-production-cargo-oracle";
    packages = ["aos-activation-nftables"];
    cargoFlags = ["--release"];
    captureCompilerArguments = true;
    cargoSetup = ''
      export AOS_NFT_EXECUTABLE=${pkgs.nftables}/sbin/nft
      export CARGO_BUILD_TARGET=${pkgs.lib.escapeShellArg triple}
      export ${flagsVariable}="-C target-feature=+crt-static -C relocation-model=static -L ${compilation.libraries}/static/lib"
    '';
  };
  driver-selection = assert ordinary.passthru.buildDriver == "cargo";
  assert candidate.passthru.buildDriver == "bazel";
  assert candidate.passthru.cargoFallback.drvPath == ordinary.drvPath;
  assert (candidate.passthru.withBuildDriver "cargo").drvPath == ordinary.drvPath;
  assert !(builtins.tryEval (ordinary.passthru.withBuildDriver "invalid").drvPath).success;
  assert guarded.drvPath == candidate.drvPath;
  assert candidate.platformSupport == ordinary.platformSupport;
  assert candidate.module == ordinary.module;
  assert candidate.moduleDeps == ordinary.moduleDeps;
  assert candidate ? checks && ordinary ? checks;
  assert candidate.runtimeDeps == ordinary.runtimeDeps;
  assert candidate.qualification == ordinary.qualification;
    pkgs.runCommand "aos-bazel-network-ruleset-provider-production-driver-selection" {} ''
      mkdir -p "$out"
      cat > "$out/report.json" <<'JSON'
      ${builtins.toJSON {
        ordinary = identity ordinary;
        bazel = identity candidate;
        fallback = identity candidate.passthru.cargoFallback;
        invalid_driver_rejected = true;
        cargo_constructor_artifacts_dummy_source_and_vendor_not_evaluated = true;
        module_runtime_and_qualification_declarations_preserved = true;
      }}
      JSON
      printf 'PASS\n' > "$out/result"
    '';
  execution-profiles = import ./_bazel-rust-test-profiles.nix {
    inherit pkgs cargo;
    pname = "aos-bazel-network-ruleset-provider-production-release-test-profiles";
    tests = compilation.tests;
    targetOptLevel = "3";
    debugAssertions = false;
    firstPartyTests = {
      "//crates/activation/aos-activation-nftables:static_unit_binary" = "aos_activation_nftables";
      "//crates/activation/aos-activation-nftables:static_bin_binary" = "aos_network_ruleset_provider";
    };
    proceduralMacros = ["ref_cast_impl" "schemars_derive" "serde_derive" "thiserror_impl"];
  };
  parity =
    pkgs.runCommand "aos-bazel-network-ruleset-provider-production-installed-parity" {
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
      PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 ${scripts}/verify_network_ruleset_provider.py \
        --packages packages.json --build ${compilation.build} --tests ${compilation.tests} \
        --oracle ${cargo} --workspace ${compilation.workspace.source} \
        --libraries ${compilation.libraries} --runtime ${compilation.runtime} \
        --nft-executable ${pkgs.nftables}/sbin/nft --package-version ${candidate.version} \
        --readelf ${pkgs.binutils}/bin/readelf \
        --closure-attributes "$NIX_ATTRS_JSON_FILE" --output "$out/report.json"
      printf 'PASS\n' > "$out/result"
    '';
  native-contracts = let
    evaluate = package:
      import ../../pkgs/networking/_aos-network-ruleset-provider/native-tests.nix {
        inherit (pkgs) lib;
        inherit package;
      };
    ordinaryContract = evaluate ordinary;
    bazelContract = evaluate candidate;
  in
    assert ordinaryContract == bazelContract;
      pkgs.runCommand "aos-bazel-network-ruleset-provider-native-contracts" {} ''
        mkdir -p "$out"
        cat > "$out/report.json" <<'JSON'
        ${builtins.toJSON {
          ordinary = ordinaryContract;
          bazel = bazelContract;
        }}
        JSON
        printf 'PASS\n' > "$out/result"
      '';
  vm-contracts = let
    testing = import ../../lib/testing {
      inherit pkgs;
      inherit (pkgs) lib;
    };
    check = package:
      (package.checks {
        inherit testing;
        self = package;
      }).native-contract;
  in {
    ordinary = check ordinary;
    bazel = check candidate;
  };
  runtime-negative = let
    # Reproduce an intermediate install that scrubs the compiled nft path.
    unretained = pkgs.mkAosBazelPackage {
      inherit (ordinary) pname version;
      build = compilation.build;
      packageLabel = "//crates/activation/aos-activation-nftables:static_package";
    };
  in
    pkgs.runCommand "aos-bazel-network-ruleset-provider-runtime-reference-negative" {
      buildDeps = [pkgs.python3 pkgs.binutils pkgs.grep];
      outputChecks.out = {};
      exportReferencesGraph = {
        ordinary_out = [ordinary];
        bazel_out = [unretained];
      };
    } ''
      mkdir -p "$out"
      cat > packages.json <<'JSON'
      ${builtins.toJSON {
        ordinary.out = toString ordinary;
        bazel.out = toString unretained;
      }}
      JSON
      if PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 ${scripts}/verify_network_ruleset_provider.py \
        --packages packages.json --build ${compilation.build} --tests ${compilation.tests} \
        --oracle ${cargo} --workspace ${compilation.workspace.source} \
        --libraries ${compilation.libraries} --runtime ${compilation.runtime} \
        --nft-executable ${pkgs.nftables}/sbin/nft --package-version ${candidate.version} \
        --readelf ${pkgs.binutils}/bin/readelf \
        --closure-attributes "$NIX_ATTRS_JSON_FILE" --output "$out/unexpected.json" \
        > "$out/rejection.log" 2>&1; then
        printf 'Qualification accepted a package with a scrubbed nft runtime reference\n' >&2
        exit 1
      fi
      ${pkgs.grep}/bin/grep -F \
        'installed network-ruleset package changed its required runtime closure' "$out/rejection.log"
      printf 'PASS\n' > "$out/result"
    '';
  all =
    pkgs.runCommand "aos-bazel-network-ruleset-provider-production-package-checks" {
      buildDeps = [driver-selection parity execution-profiles native-contracts runtime-negative] ++ builtins.attrValues vm-contracts;
    } ''
      mkdir -p "$out"
      cp ${driver-selection}/report.json "$out/driver-selection.json"
      cp ${parity}/report.json "$out/report.json"
      cp ${execution-profiles}/evidence.json "$out/execution-profiles.json"
      cp ${native-contracts}/report.json "$out/native-contracts.json"
      cp ${runtime-negative}/rejection.log "$out/runtime-reference-rejection.log"
      mkdir -p "$out/vm-ordinary" "$out/vm-bazel"
      cp ${vm-contracts.ordinary}/result ${vm-contracts.ordinary}/serial.log "$out/vm-ordinary/"
      cp ${vm-contracts.bazel}/result ${vm-contracts.bazel}/serial.log "$out/vm-bazel/"
      printf 'PASS\n' > "$out/result"
    '';
}
