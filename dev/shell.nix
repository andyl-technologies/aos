# dev/shell.nix — AOS development environment (no nixpkgs)
#
# On Linux: provides AOS-built `aos` and `just` in PATH.
# On Darwin: minimal shell with env vars + pre-commit hook;
#            tools come from the user's existing PATH.
{
  system,
  aos ? null,
  just ? null,
}: let
  packages = builtins.filter (p: p != null) [
    aos
    just
  ];
  binPath = builtins.concatStringsSep ":" (map (p: "${p}/bin") packages);
in
  builtins.derivation {
    name = "aos-dev";
    inherit system;
    builder = "/bin/bash";
    args = [
      "-c"
      "echo 'Use nix develop, not nix build'; exit 1"
    ];

    shellHook =
      (
        if binPath != ""
        then ''
          export PATH="${binPath}''${PATH:+:$PATH}"
        ''
        else ""
      )
      + ''
        export AOS_ROOT="$(pwd)"
      '';
  }
