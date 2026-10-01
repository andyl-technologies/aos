{pkgs}:
pkgs.mkDerivation {
  pname = "crucible-qmp-command-check";
  version = "0";
  src = null;
  buildDeps = [pkgs.python3];
  phases = [
    {
      name = "check";
      script = ''
        cp ${./_qmp-command.py} _qmp-command.py
        cp ${./test_qmp_command.py} test_qmp_command.py
        ${pkgs.python3}/bin/python3 -m unittest -v test_qmp_command
        mkdir -p "$out"
        printf '%s\n' PASS > "$out/result"
      '';
    }
  ];
}
