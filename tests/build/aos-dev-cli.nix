{pkgs}: let
  repositoryRoot = ../..;
  repositoryRootString = toString repositoryRoot;
  src = builtins.path {
    path = repositoryRoot;
    name = "aos-dev-cli-source";
    filter = path: _type: let
      pathString = toString path;
    in
      builtins.elem pathString [
        repositoryRootString
        "${repositoryRootString}/aos-dev"
        "${repositoryRootString}/dev"
        "${repositoryRootString}/dev/lib"
        "${repositoryRootString}/dev/tests"
        "${repositoryRootString}/dev/tests/cli.bash"
        "${repositoryRootString}/dev/cache-mount-smoke.nix"
      ]
      || builtins.match "${repositoryRootString}/dev/lib/[^/]+\\.bash" pathString != null;
  };
in
  pkgs.mkDerivation {
    pname = "aos-dev-cli-check";
    version = "0";
    inherit src;
    buildDeps = [
      pkgs.bash
      pkgs.coreutils
      pkgs.findutils
      pkgs.gawk
      pkgs.grep
      pkgs.sed
      pkgs.util-linux
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
