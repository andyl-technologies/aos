##! Qualifies the dynamic configuration provider production selector.
{pkgs}: let
  ordinary = pkgs.aos-configuration-provider;
  candidate = ordinary.passthru.withBuildDriver "bazel";
  compilation = pkgs.callPackage ../../pkgs/system/_aos-configuration-provider-bazel-build.nix {};
  guarded = pkgs.callPackage ../../pkgs/system/aos-configuration-provider.nix {
    buildDriver = "bazel";
    mkAosCargoPackage = _: throw "Bazel configuration provider evaluated its Cargo constructor";
    aosWorkspaceVendor = throw "Bazel configuration provider evaluated its Cargo vendor";
  };
  scripts = builtins.path {
    path = ../../tools/bazel/tests;
    name = "aos-bazel-configuration-provider-production-verifiers";
    filter = path: type: type == "regular" && pkgs.lib.hasSuffix ".py" path;
  };
  identity = package: builtins.unsafeDiscardStringContext package.drvPath;
in rec {
  inherit candidate compilation;
  baseline-helper = pkgs.runCommand "aos-configuration-provider-cargo-account-lookup" {} ''
    mkdir -p "$out/bin"
    cc -std=c11 -O2 -Wall -Wextra -Werror \
      ${../../pkgs/system/_aos-configuration-provider/account-lookup.c} \
      -o "$out/bin/aos-account-lookup"
  '';
  cargo = import ./_bazel-cargo-oracle.nix {
    inherit pkgs;
    pname = "aos-bazel-configuration-provider-production-cargo-oracle";
    packages = ["aos-activation-config-files"];
    cargoFlags = ["--release"];
    captureCompilerArguments = true;
    cargoSetup = ''
      export AOS_ACCOUNT_LOOKUP=${baseline-helper}/bin/aos-account-lookup
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
  assert candidate.runtimeDeps == ordinary.runtimeDeps;
  assert candidate.moduleDeps == ordinary.moduleDeps;
    pkgs.runCommand "aos-bazel-configuration-provider-production-driver-selection" {} ''
      mkdir -p "$out"
      cat > "$out/report.json" <<'JSON'
      ${builtins.toJSON {
        ordinary = identity ordinary;
        bazel = identity candidate;
        fallback = identity candidate.passthru.cargoFallback;
        invalid_driver_rejected = true;
        cargo_constructor_and_vendor_not_evaluated = true;
        module_dependencies_and_runtime_declarations_preserved = true;
      }}
      JSON
      printf 'PASS\n' > "$out/result"
    '';
  execution-profiles = import ./_bazel-rust-test-profiles.nix {
    inherit pkgs cargo;
    pname = "aos-bazel-configuration-provider-production-release-test-profiles";
    tests = compilation.tests;
    targetOptLevel = "3";
    debugAssertions = false;
    firstPartyTests = {
      "//crates/activation/aos-activation-config-files:unit_binary" = "aos_activation_config_files";
      "//crates/activation/aos-activation-config-files:bin_aos-configuration-provider_binary" = "aos_configuration_provider";
    };
    proceduralMacros = ["serde_derive"];
  };
  parity =
    pkgs.runCommand "aos-bazel-configuration-provider-production-installed-parity" {
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
      PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 ${scripts}/verify_configuration_provider.py \
        --packages packages.json --build ${compilation.build} --tests ${compilation.tests} \
        --oracle ${cargo} --workspace ${compilation.workspace.source} \
        --loader ${pkgs.glibc}/lib/${pkgs.stdenv.hostPlatform.dynamicLinker} \
        --readelf ${pkgs.binutils}/bin/readelf \
        --bash ${pkgs.bash}/bin/bash --python ${pkgs.python3}/bin/python3 \
        --closure-attributes "$NIX_ATTRS_JSON_FILE" --output "$out/report.json"
      printf 'PASS\n' > "$out/result"
    '';
  vm-effects = let
    testing = import ../../lib/testing {
      inherit pkgs;
      inherit (pkgs) lib;
    };
    script = pkgs.runCommand "aos-bazel-configuration-provider-vm-script" {} ''
      mkdir -p "$out"
      cp ${../../tools/bazel/tests/configuration_provider_vm.py} "$out/effects.py"
    '';
    check = package:
      testing.mkVMTest {
        name = "bazel-configuration-provider-effects";
        rootfsDeps = [package pkgs.python3 script];
        testScript = ''
          ${pkgs.python3}/bin/python3 ${script}/effects.py ${package}
        '';
      };
  in {
    ordinary = check ordinary;
    bazel = check candidate;
  };
  vm-parity = pkgs.runCommand "aos-bazel-configuration-provider-vm-effect-parity" {buildDeps = [pkgs.python3];} ''
    mkdir -p "$out"
    ${pkgs.python3}/bin/python3 - ${vm-effects.ordinary} ${vm-effects.bazel} "$out/report.json" <<'PYTHON'
    import json
    from pathlib import Path
    import sys

    reports = []
    prefix = "CONFIGURATION_PROVIDER_REPORT:"
    for output in map(Path, sys.argv[1:3]):
        assert (output / "result").read_text().strip() == "PASS"
        matches = [json.loads(line.removeprefix(prefix))
                   for line in (output / "serial.log").read_text().splitlines()
                   if line.startswith(prefix)]
        assert len(matches) == 1, matches
        report = matches[0]
        assert report["status"] == "PASS" and len(report["cases"]) == len(set(report["cases"])) == 7
        reports.append(report)
    assert reports[0] == reports[1], reports
    Path(sys.argv[3]).write_text(json.dumps(reports[0], indent=2, sort_keys=True) + "\n")
    PYTHON
  '';
  all =
    pkgs.runCommand "aos-bazel-configuration-provider-production-package-checks" {
      buildDeps = [driver-selection parity execution-profiles vm-parity];
    } ''
      mkdir -p "$out"
      cp ${driver-selection}/report.json "$out/driver-selection.json"
      cp ${parity}/report.json "$out/report.json"
      cp ${execution-profiles}/evidence.json "$out/execution-profiles.json"
      cp ${vm-parity}/report.json "$out/vm-effects.json"
      mkdir -p "$out/vm-ordinary" "$out/vm-bazel"
      cp ${vm-effects.ordinary}/result ${vm-effects.ordinary}/serial.log "$out/vm-ordinary/"
      cp ${vm-effects.bazel}/result ${vm-effects.bazel}/serial.log "$out/vm-bazel/"
      printf 'PASS\n' > "$out/result"
    '';
}
