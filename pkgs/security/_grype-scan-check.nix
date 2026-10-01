##! Offline Grype qualification against a real upstream vulnerability database
{
  pkgs,
  grype,
  databaseArchive,
}:
pkgs.mkDerivation {
  pname = "grype-scan-check";
  version = grype.version;
  src = null;
  buildDeps = [grype pkgs.syft pkgs.python3];
  phases = [
    {
      name = "check";
      script = ''
        ${pkgs.python3}/bin/python3 ${./_grype-scan-check.py} \
          --grype ${grype}/bin/grype \
          --syft ${pkgs.syft}/bin/syft \
          --database ${databaseArchive} \
          --output "$out"
      '';
    }
  ];
}
