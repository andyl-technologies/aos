##! Qualifies feature cases and production boundaries from Bazel-owned inputs.
{
  pkgs,
  lib,
}: let
  policy = import ../build/_bazel-crucible-feature-policy.nix {inherit pkgs;};
  compilation = import ../build/_bazel-feature-powerset.nix {inherit pkgs;};
in
  pkgs.mkDerivation {
    pname = "crucible-phase1-crate-feature-powerset";
    version = "0";
    src = null;

    buildDeps = [pkgs.coreutils];
    phases = [
      {
        name = "write-result";
        script = ''
          set -eu
          test "$(cat ${policy.all}/result)" = PASS
          test "$(cat ${compilation.all}/result)" = PASS
          mkdir -p "$out"
          cp ${policy.all}/report.json "$out/policy.json"
          cp ${compilation.all}/report.json "$out/compilation.json"
          cat > "$out/result" <<'RESULT'
          PASS
          check=checks.crucible.phase1.crateFeaturePowerset
          gate=gate:harness-lint
          tasks=T-CRATE-6,T-CRATE-16
          rust_test=crucible_test_support::feature_powerset
          build_driver=bazel
          RESULT
        '';
      }
    ];
    passthru = {inherit policy compilation;};
  }
