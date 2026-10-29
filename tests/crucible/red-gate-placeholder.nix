{pkgs}: {
  attrPath,
  gateName,
  owner,
  phase,
  reason,
  dependencies ? [],
}: let
  gateSlug = builtins.replaceStrings [":"] ["-"] gateName;
in
  pkgs.mkDerivation {
    pname = "crucible-${gateSlug}-placeholder";
    version = "0";
    src = null;

    buildDeps = [pkgs.coreutils] ++ dependencies;

    phases = [
      {
        name = "red-placeholder";
        script = ''
          set -eu
          mkdir -p "$out"
          cat > "$out/result" <<'RESULT'
          RED
          check=${attrPath}
          gate=${gateName}
          phase=${phase}
          owner=${owner}
          reason=${reason}
          RESULT
          cat "$out/result" >&2
          exit 1
        '';
      }
    ];
  }
