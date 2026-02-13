# dev/shell.nix — AOS development environment
{ pkgs, aos }:

pkgs.mkShellNoCC {
  name = "aos-dev";

  packages = [
    aos
    pkgs.just
  ];

  shellHook = ''
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
