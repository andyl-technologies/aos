##! Explicit host module roots must match authenticated module sources.
{
  pkgs,
  system,
}: let
  baseLib = system.config.aos.config.evalAtBoot.baseLib;
in
  pkgs.mkDerivation {
    pname = "aos-base-lib-roots-check";
    version = "1";
    src = null;
    buildDeps = [pkgs.coreutils pkgs.jq];

    phases = [
      {
        name = "check";
        script = ''
          set -eu

          ${pkgs.jq}/bin/jq -r '.[].configRoot' \
            ${baseLib}/host-package-modules.json \
            | ${pkgs.coreutils}/bin/sort -u > expected-roots

          : > retained-roots
          for root in ${baseLib}/host-authenticated-roots/*; do
            test -L "$root" || {
              echo "host authenticated root is not a symlink: $root" >&2
              exit 1
            }
            ${pkgs.coreutils}/bin/readlink "$root" >> retained-roots
          done
          ${pkgs.coreutils}/bin/sort -u retained-roots -o retained-roots

          test "$(cat expected-roots)" = "$(cat retained-roots)" || {
            echo "explicit host module roots differ from package module sources" >&2
            exit 1
          }

          mkdir -p "$out"
          echo PASS > "$out/result"
        '';
      }
    ];
  }
