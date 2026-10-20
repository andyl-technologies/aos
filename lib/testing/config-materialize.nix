##! Checks the retained native lower producer against its actual EROFS handler.
{
  pkgs,
  lib,
  mkSystem,
}: let
  fixture = import ../../tests/effects/_configuration-lower-fixture.nix {inherit lib pkgs;};
  invocation = pkgs.writeTextFile {
    name = "configuration-lower-invocation.json";
    text = builtins.toJSON fixture.invocation;
  };
  provider = pkgs.aos-configuration-lower;
in
  pkgs.mkDerivation {
    pname = "config-materialize-check";
    version = "0";
    src = null;
    buildDeps = [provider pkgs.coreutils pkgs.diffutils pkgs.grep pkgs.jq pkgs.erofs-utils];
    phases = [
      {
        name = "check";
        script = ''
          set -eu
          mkdir -p "$out"
          ${pkgs.jq}/bin/jq --arg root "$TMPDIR/retained" '.input.retainedRoot = $root' ${invocation} > invocation.json
          ${provider}/bin/aos-configuration-lower apply < invocation.json > first.json
          lower="$(${pkgs.jq}/bin/jq -r .directory first.json)"
          tree="$lower/etc-tree"
          ${pkgs.erofs-utils}/bin/fsck.erofs "$lower/etc.erofs"
          ${pkgs.grep}/bin/grep -qx host-owned "$tree/runtime-config/materialized.conf"
          [ "$(${pkgs.coreutils}/bin/stat -c %a "$tree/runtime-config/materialized.conf")" = 644 ]
          [ -d "$tree/package-tree" ] && [ ! -L "$tree/package-tree" ]
          ${pkgs.grep}/bin/grep -qx operator-override "$tree/package-tree/identity.txt"
          [ "$(${pkgs.coreutils}/bin/stat -c %a "$tree/package-tree/identity.txt")" = 640 ]
          [ "$(${pkgs.coreutils}/bin/readlink "$tree/systemd/system/multi-user.target.wants/fixture.service")" = ../fixture.service ]
          ${pkgs.grep}/bin/grep -q /etc/aos-job-scripts/start "$tree/systemd/system/fixture.service"
          [ -x "$tree/aos-job-scripts/start" ]

          ${provider}/bin/aos-configuration-lower apply < invocation.json > retry.json
          ${pkgs.diffutils}/bin/cmp first.json retry.json
          ${provider}/bin/aos-configuration-lower observe < invocation.json > observation.json
          ${pkgs.jq}/bin/jq -e '.status == "current"' observation.json
          ${pkgs.jq}/bin/jq '.action = "remove"' invocation.json > remove.json
          ${provider}/bin/aos-configuration-lower remove < remove.json > removed.json
          ${provider}/bin/aos-configuration-lower observe < remove.json > absent.json
          ${pkgs.jq}/bin/jq -e '.status == "absent"' absent.json
          [ -f "$lower/etc.erofs" ]

          ${pkgs.jq}/bin/jq 'del(.input.ownership.files["runtime-config/materialized.conf"])' invocation.json > unowned.json
          if ${provider}/bin/aos-configuration-lower apply < unowned.json; then
            echo 'unowned configuration input was accepted' >&2
            exit 1
          fi
          ${pkgs.coreutils}/bin/printf x >> "$lower/etc.erofs"
          if ${provider}/bin/aos-configuration-lower apply < invocation.json; then
            echo 'tampered native lower was accepted' >&2
            exit 1
          fi
          if ${provider}/bin/aos-configuration-lower observe < invocation.json; then
            echo 'tampered native lower was observed as current' >&2
            exit 1
          fi
          echo PASS > "$out/result"
        '';
      }
    ];
  }
