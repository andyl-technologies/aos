##! Qualifies both complete BPF policy packages against their Cargo builders.
{pkgs}: let
  ordinary = {
    lsm = pkgs.aos-ebpf-lsm-policy;
    net = pkgs.aos-ebpf-net-policy;
  };
  candidate = builtins.mapAttrs (_: package: package.passthru.withBuildDriver "bazel") ordinary;
  compilation = pkgs.callPackage ../../pkgs/security/_aos-bpf-policy-bazel-build.nix {};
  guarded = family:
    pkgs.callPackage (../../pkgs/security + "/aos-ebpf-${family}-policy.nix") {
      buildDriver = "bazel";
      mkAosCargoPackage = _: throw "Bazel BPF provider evaluated its Cargo constructor";
      mkCargoArtifacts = _: throw "Bazel BPF provider evaluated Cargo artifacts";
      mkCargoDummySource = _: throw "Bazel BPF provider evaluated Cargo dummy source";
      aosWorkspaceVendor = throw "Bazel BPF provider evaluated its Cargo vendor";
    };
  triple = pkgs.stdenv.hostPlatform.config;
  flagsVariable = "CARGO_TARGET_${pkgs.lib.toUpper (builtins.replaceStrings ["-"] ["_"] triple)}_RUSTFLAGS";
  loaderName =
    if pkgs.stdenv.hostPlatform.isx86_64
    then "ld-linux-x86-64.so.2"
    else "ld-linux-aarch64.so.1";
  scripts = builtins.path {
    path = ../../tools/bazel/tests;
    name = "aos-bazel-bpf-provider-production-verifiers";
    filter = path: type: type == "regular" && pkgs.lib.hasSuffix ".py" path;
  };
  identity = package: builtins.unsafeDiscardStringContext package.drvPath;
in rec {
  inherit ordinary candidate compilation;
  cargo = import ./_bazel-cargo-oracle.nix {
    inherit pkgs;
    pname = "aos-bazel-bpf-provider-release-cargo-oracle";
    packages = ["aos-activation-bpf-lsm" "aos-activation-bpf-network"];
    cargoFlags = ["--release"];
    captureCompilerArguments = true;
    cargoSetup = ''
      export CARGO_BUILD_TARGET=${pkgs.lib.escapeShellArg triple}
      export ${flagsVariable}="-C target-feature=+crt-static -C relocation-model=static -L ${compilation.libraries}/static/lib"
    '';
  };
  driver-selection = let
    valid = family: let
      before = ordinary.${family};
      after = candidate.${family};
    in
      assert before.passthru.buildDriver == "cargo";
      assert after.passthru.buildDriver == "bazel";
      assert after.passthru.cargoFallback.drvPath == before.drvPath;
      assert (after.passthru.withBuildDriver "cargo").drvPath == before.drvPath;
      assert !(builtins.tryEval (before.passthru.withBuildDriver "invalid").drvPath).success;
      assert (guarded family).drvPath == after.drvPath;
      assert before.platformSupport == after.platformSupport;
      assert before.module == after.module && before.moduleDeps == after.moduleDeps;
      assert before.runtimeDeps == after.runtimeDeps;
      assert before.qualification == after.qualification;
      assert before ? checks && after ? checks; {
        cargo = identity before;
        bazel = identity after;
        fallback = identity after.passthru.cargoFallback;
        cargo_constructor_artifacts_dummy_source_and_vendor_not_evaluated = true;
        module_runtime_and_qualification_contracts_preserved = true;
      };
    report = builtins.mapAttrs (family: _: valid family) ordinary;
  in
    pkgs.runCommand "aos-bazel-bpf-provider-driver-selection" {} ''
      mkdir -p "$out"
      cat > "$out/report.json" <<'JSON'
      ${builtins.toJSON report}
      JSON
      printf 'PASS\n' > "$out/result"
    '';
  execution-profiles = import ./_bazel-rust-test-profiles.nix {
    inherit pkgs cargo;
    pname = "aos-bazel-bpf-provider-release-test-profiles";
    tests = compilation.tests;
    targetOptLevel = "3";
    debugAssertions = false;
    firstPartyTests = {
      "//crates/activation/aos-activation-bpf-lsm:static_unit_binary" = "aos_activation_bpf_lsm";
      "//crates/activation/aos-activation-bpf-lsm:static_bin_binary" = "aos_ebpf_lsm_provider";
      "//crates/activation/aos-activation-bpf-network:static_unit_binary" = "aos_activation_bpf_network";
      "//crates/activation/aos-activation-bpf-network:static_bin_binary" = "aos_ebpf_net_policy_provider";
    };
    proceduralMacros = ["ref_cast_impl" "schemars_derive" "serde_derive" "thiserror_impl"];
  };
  parity =
    pkgs.runCommand "aos-bazel-bpf-provider-installed-parity" {
      buildDeps = [pkgs.python3 pkgs.binutils];
      outputChecks.out = {};
      exportReferencesGraph = {
        lsm_ordinary_out = [ordinary.lsm];
        lsm_bazel_out = [candidate.lsm];
        net_ordinary_out = [ordinary.net];
        net_bazel_out = [candidate.net];
      };
    } ''
      mkdir -p "$out"
      cat > packages.json <<'JSON'
      ${builtins.toJSON (builtins.mapAttrs (family: before: {
          ordinary.out = toString before;
          bazel.out = toString candidate.${family};
        })
        ordinary)}
      JSON
      cat ${ordinary.lsm}/nix-support/cargo-build-messages.jsonl \
        ${ordinary.net}/nix-support/cargo-build-messages.jsonl > production-messages.jsonl
      PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 ${scripts}/verify_bpf_provider.py \
        --packages packages.json --build ${compilation.build} --tests ${compilation.tests} \
        --oracle ${cargo} --workspace ${compilation.workspace.source} \
        --libraries ${compilation.libraries} --compilers ${pkgs.aosBazelToolchains} \
        --tools ${pkgs.aosBazelBpfTools} --native ${pkgs.aosBazelBpfLibraries} \
        --readelf ${pkgs.binutils}/bin/readelf --loader ${pkgs.glibc}/lib/${loaderName} \
        --production-messages production-messages.jsonl \
        --closure-attributes "$NIX_ATTRS_JSON_FILE" --output "$out/report.json"
      printf 'PASS\n' > "$out/result"
    '';
  all =
    pkgs.runCommand "aos-bazel-bpf-provider-production-package-checks" {
      buildDeps = [driver-selection parity execution-profiles];
    } ''
      mkdir -p "$out"
      cp ${driver-selection}/report.json "$out/driver-selection.json"
      cp ${parity}/report.json "$out/report.json"
      cp ${execution-profiles}/evidence.json "$out/execution-profiles.json"
      printf 'PASS\n' > "$out/result"
    '';
}
