{
  pkgs,
  prerequisites,
}:
pkgs.mkDerivation {
  pname = "terrane-gate-gc-two-phase-delete";
  version = "0.1.0";
  src = null;
  buildDeps = prerequisites;
  phases = [
    {
      name = "check";
      script = ''
        set -eu
        for prerequisite in ${builtins.concatStringsSep " " (map toString prerequisites)}; do
          test -s "$prerequisite/result"
        done
        mkdir -p "$out"
        printf 'PASS: T1 local two-phase GC, copied first ownership and permanent residue recovery with fresh-placement restoration\n' \
          > "$out/result"
      '';
    }
  ];
}
