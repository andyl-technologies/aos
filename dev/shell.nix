# dev/shell.nix — AOS development environment (no nixpkgs)
#
# On Linux: provides AOS-built `aos` and `just` in PATH.
# On Darwin: minimal shell with env vars + pre-commit hook;
#            tools come from the user's existing PATH.
{
  system,
  aos ? null,
  just ? null,
}:

let
  packages = builtins.filter (p: p != null) [
    aos
    just
  ];
  binPath = builtins.concatStringsSep ":" (map (p: "${p}/bin") packages);
in
builtins.derivation {
  name = "aos-dev";
  inherit system;
  builder = "/bin/sh";
  args = [
    "-c"
    "echo 'Use nix develop, not nix build'; exit 1"
  ];

  shellHook =
    (
      if binPath != "" then
        ''
          export PATH="${binPath}''${PATH:+:$PATH}"
        ''
      else
        ""
    )
    + ''
      export AOS_ROOT="$(pwd)"

      # Install pre-commit hook that auto-formats and re-stages .nix files.
      if [ -d .git ]; then
        cat > .git/hooks/pre-commit << 'HOOK'
      #!/usr/bin/env bash
      set -euo pipefail
      aos fmt
      git diff --name-only | grep '\.nix$' | while IFS= read -r f; do git add "$f"; done || true
      exec aos fmt --check
      HOOK
        chmod +x .git/hooks/pre-commit
      fi
    '';
}
