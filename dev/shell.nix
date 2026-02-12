# dev/shell.nix — AOS development environment
{ pkgs, aos }:

pkgs.mkShellNoCC {
  name = "aos-dev";

  packages = [
    aos
    pkgs.nixfmt-rfc-style
    pkgs.just
  ];

  shellHook = ''
    export AOS_ROOT="$(pwd)"

    # Install pre-commit hook
    if [ -d .git ]; then
      cat > .git/hooks/pre-commit << 'HOOK'
#!/usr/bin/env bash
exec aos fmt --check
HOOK
      chmod +x .git/hooks/pre-commit
    fi
  '';
}
