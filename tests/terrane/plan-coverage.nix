{pkgs}:
pkgs.mkDerivation {
  pname = "terrane-plan-coverage";
  version = "0.1.0";
  src = null;
  buildDeps = [pkgs.python3];
  phases = [
    {
      name = "check";
      script = ''
        set -eu
        export PYTHONDONTWRITEBYTECODE=1
        mkdir -p "$out"
        python3 ${./.}/test_plan_coverage.py
        python3 ${./plan_coverage.py} ${../../docs/rfcs/0024-terrane} > "$out/result"
      '';
    }
  ];
}
