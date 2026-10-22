##! Qualification entry points for the first-party Bazel migration.
{
  pkgs,
  sharedBazelCacheDir ? null,
}: let
  workspace = pkgs.mkAosBazelWorkspace {
    root = ../..;
    sourceDirectories = ["tools/bazel/toolchains" "tools/bazel/rules" "tools/bazel/metadata" "tools/bazel/tests/fixture"];
  };
in
  rec {
    source-selection = import ./_bazel-source-selection.nix {inherit pkgs;};
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
      mkdir -p "$out"
      cp ${package}/nix-support/bazel-package.json "$out/manifest.json"
    '';
    unit = pkgs.mkAosBazelCheck {
      pname = "aos-bazel-fixture-unit";
      inherit workspace;
      targets = ["//tools/bazel/tests/fixture:rust_test"];
    };
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
        PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 -m unittest discover \
          -s "$src/tests" -p 'test_*.py'
        mkdir -p "$out"
        printf 'PASS\n' > "$out/result"
      '';
    all = pkgs.runCommand "aos-bazel-checks" {buildDeps = [runtime unit policy source-selection precision-parity];} ''
      mkdir -p "$out"
      printf 'PASS\n' > "$out/result"
    '';
  }
  // pkgs.lib.optionalAttrs (sharedBazelCacheDir != null) {
    cache = import ./_bazel-cache.nix {inherit pkgs workspace;};
  }
