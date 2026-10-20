##! Ordinary package and native module for advisory oneshot fleet coverage.
{pkgs}:
pkgs.mkDerivation {
  pname = "aos-runtime-advisory-report";
  version = "0.1.0";
  src = null;
  module = ./_runtime-advisory-report;
  moduleDeps = [pkgs.service-management];
  runtimeDeps = {coreutils = pkgs.coreutils;};
  phases = [
    {
      name = "install";
      script = ''
        mkdir -p "$out/share/aos-runtime-advisory-report"
        printf '%s\n' 'Native advisory report fixture' > "$out/share/aos-runtime-advisory-report/identity"
      '';
    }
  ];
}
