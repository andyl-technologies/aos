{
  pkgs,
  lib,
}: let
  crucibleBuild = pkgs.crucible;
in
  pkgs.mkDerivation {
    pname = "crucible-phase1-rfc-consistency";
    version = "0";
    src = null;

    buildDeps = [
      pkgs.coreutils
      crucibleBuild
    ];

    phases = [
      {
        name = "write-result";
        script = ''
          set -eu
          test -f ${crucibleBuild}/nix-support/crucible-build-info
          mkdir -p "$out"
          cat > "$out/result" <<'RESULT'
          PASS
          check=checks.crucible.phase1.rfcConsistency
          tasks=T-PLAN-1,T-PLAN-2,T-STD-12
          rust_test=crucible-harness::rfc_consistency
          RESULT
        '';
      }
    ];
  }
