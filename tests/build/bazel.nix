##! Qualification entry points for the first-party Bazel migration.
{
  pkgs,
  sharedBazelCacheDir ? null,
}: let
  workspace = pkgs.mkAosBazelWorkspace {
    root = ../..;
    sourceDirectories = ["tools/bazel/toolchains" "tools/bazel/rules" "tools/bazel/metadata" "tools/bazel/testing" "tools/bazel/tests/fixture"];
  };
in
  rec {
    source-selection = import ./_bazel-source-selection.nix {inherit pkgs;};
    pilot = import ./_bazel-pilot.nix {inherit pkgs;};
    license-boundary = import ./_bazel-license.nix {inherit pkgs workspace;};
    precise = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-precise-fixtures";
      workspace = pkgs.mkAosBazelWorkspace {
        root = ../..;
        sourceInventory = ../../tools/bazel/metadata/fixture-inventory.json;
      };
      targets = ["//tools/bazel/tests/fixture:package"];
    };
    precision-parity = pkgs.runCommand "aos-bazel-source-precision-parity" {} ''
      cmp ${fixtures}/packages/index.json ${precise}/packages/index.json
      for manifest in ${fixtures}/packages/*/manifest.json; do
        relative="''${manifest#${fixtures}/}"
        cmp "$manifest" "${precise}/$relative"
      done
      mkdir -p "$out"
      cp ${precise}/inventory.json "$out/inventory.json"
    '';
    toolchains = pkgs.aosBazelToolchains;
    fixtures = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-fixtures";
      inherit workspace;
      targets = ["//tools/bazel/tests/fixture:package"];
    };
    package = pkgs.mkAosBazelPackage {
      pname = "aos-bazel-fixture";
      version = "1";
      build = fixtures;
      packageLabel = "//tools/bazel/tests/fixture:package";
      runtimeDeps = [pkgs.gcc-libs];
    };
    runtime = pkgs.runCommand "aos-bazel-fixture-runtime" {} ''
      test "$(${package}/bin/rust-fixture)" = 'answer=42'
      test "$(${package}/bin/cpp-fixture)" = 'answer=42'
      test "$(${package}/bin/native-fixture)" = 'answer=84'
      mkdir -p "$out"
      cp ${package}/nix-support/bazel-package.json "$out/manifest.json"
    '';
    unit = pkgs.mkAosBazelCheck {
      pname = "aos-bazel-fixture-unit";
      inherit workspace;
      targets = ["//tools/bazel/tests/fixture:rust_test"];
    };
    runner = pkgs.runCommand "aos-bazel-runner-evidence" {buildDeps = [pkgs.python3];} ''
      ${pkgs.python3}/bin/python3 - ${unit}/evidence/tests <<'PY'
      import json
      from pathlib import Path
      import sys
      import xml.etree.ElementTree as ET

      root = Path(sys.argv[1])
      results = json.loads((root / "index.json").read_text())["results"]
      assert len(results) == 1 and results[0]["status"] == "PASSED", results
      cases = ET.parse(root / results[0]["outputs"]["test.xml"]).findall("testcase")
      assert len(cases) == 3, [case.attrib for case in cases]
      assert not any(case.find("failure") is not None for case in cases)
      PY
      mkdir -p "$out"
      cp -r ${unit}/evidence/tests "$out/tests"
    '';
    policy =
      pkgs.runCommand "aos-bazel-policy-checks" {
        buildDeps = [pkgs.python3];
        src = builtins.path {
          path = ../../tools/bazel;
          name = "aos-bazel-policy-tests";
          filter = path: type:
            type
            == "directory"
            && baseNameOf path != "__pycache__"
            || pkgs.lib.hasSuffix ".py" (baseNameOf path);
        };
      } ''
        ${pkgs.python3}/bin/python3 ${../../tools/bazel/metadata/test_policy.py} \
          --oracle ${../../crates/.config/nextest.toml} \
          --output ${../../tools/bazel/testing/policy.json} --check
        PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 -m unittest discover \
          -s "$src/tests" -p 'test_*.py'
        mkdir -p "$out"
        printf 'PASS\n' > "$out/result"
      '';
    all = pkgs.runCommand "aos-bazel-checks" {buildDeps = [runtime runner policy source-selection precision-parity license-boundary pilot.all];} ''
      mkdir -p "$out"
      printf 'PASS\n' > "$out/result"
    '';
  }
  // pkgs.lib.optionalAttrs (sharedBazelCacheDir != null) {
    cache = import ./_bazel-cache.nix {inherit pkgs workspace;};
  }
