{pkgs}:
pkgs.mkDerivation {
  pname = "aos-dev-cli-check";
  version = "0";
  src = ../..;
  buildDeps = [
    pkgs.bash
    pkgs.coreutils
    pkgs.findutils
    pkgs.gawk
    pkgs.grep
    pkgs.nix
    pkgs.sed
    pkgs.util-linux
  ];
  phases = [
    {
      name = "check";
      script = ''
        ${pkgs.bash}/bin/bash "$src/tools/dev/tests/cli.bash" "$src" "$TMPDIR/aos-dev-test"
        ${pkgs.bash}/bin/bash "$src/tools/dev/tests/targets-eval.bash" "$src" "${pkgs.nix}/bin/nix" "$TMPDIR/targets-eval-test"
        ${pkgs.bash}/bin/bash "$src/tools/dev/tests/cargo-target-writable.bash" "$src" "$TMPDIR/cargo-target-test"
        mkdir -p "$out"
        echo PASS > "$out/result"
      '';
    }
  ];
}
