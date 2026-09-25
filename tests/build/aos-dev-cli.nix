{pkgs}:
pkgs.mkDerivation {
  pname = "aos-dev-cli-check";
  version = "0";
  src = ../..;
  buildDeps = [
    pkgs.bash
    pkgs.coreutils
    pkgs.grep
    pkgs.sed
  ];
  phases = [
    {
      name = "check";
      script = ''
        ${pkgs.bash}/bin/bash "$src/dev/tests/cli.bash" "$src" "$TMPDIR/aos-dev-test"
        mkdir -p "$out"
        echo PASS > "$out/result"
      '';
    }
  ];
}
