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
        "${repositoryRootString}/tools/dev/aos-dev"
        "${repositoryRootString}/tools"
        "${repositoryRootString}/tools/dev"
        "${repositoryRootString}/tools/dev/lib"
        "${repositoryRootString}/tools/dev/tests"
        "${repositoryRootString}/tools/dev/tests/cli.bash"
        "${repositoryRootString}/tools/dev/tests/targets-eval.bash"
        "${repositoryRootString}/tools/dev/tests/cargo-target-writable.bash"
        "${repositoryRootString}/stdenv"
        "${repositoryRootString}/stdenv/cargo-target-writable.sh"
        "${repositoryRootString}/tools/dev/cache-mount-smoke.nix"
        "${repositoryRootString}/tools/dev/nix-config.nix"
        "${repositoryRootString}/tools/dev/targets.nix"
      ]
      || builtins.match "${repositoryRootString}/tools/dev/lib/[^/]+\\.bash" pathString != null;
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
