##! tests/containers/default.nix -- Aggregate non-VM container qualification
{
  pkgs,
  checks,
}:
pkgs.mkDerivation {
  pname = "aos-container-checks-all";
  version = "1";
  src = null;
  buildDeps = checks;
  outputChecks.out = {};
  phases = [
    {
      name = "aggregate";
      script = ''
        mkdir -p "$out"
        printf '%s\n' PASS > "$out/result"
      '';
    }
  ];
  meta.description = "Aggregate production AOS container qualification";
}
