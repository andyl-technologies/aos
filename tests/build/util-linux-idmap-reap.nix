# Reproduces denied ID-map cleanup with the actual unpacked libmount helper.
{pkgs, ...}:
pkgs.util-linux.overrideAttrs (old: {
  pname = "util-linux-idmap-reap-check";
  outputs = ["out"];
  runtimeDeps = [];
  propagatedDeps = [];
  postFinalize = "";
  phases =
    builtins.filter (phase: phase.name == "unpack") old.phases
    ++ [
      {
        name = "check-reap";
        script = ''
          ${pkgs.python3}/bin/python3 ${./_util-linux-idmap-reap.py}
          for variant in original corrected; do
            $CC -Wall -Wextra -Werror -I. -DIDMAP_SOURCE=\"$variant-idmap.h\" \
              ${./_util-linux-idmap-reap.c} -o "$variant"
          done

          # Successful handoff must retain the namespace descriptor and reap.
          ${pkgs.coreutils}/bin/timeout 3 ./original 0
          ${pkgs.coreutils}/bin/timeout 3 ./corrected 0
          for failure in 1 2; do
            set +e
            ${pkgs.coreutils}/bin/timeout 3 ./original "$failure"
            original_status=$?
            set -e
            test "$original_status" -eq 124
            ${pkgs.coreutils}/bin/timeout 3 ./corrected "$failure"
          done

          mkdir -p "$out"
          printf '%s\n' 'ID-map and notification failures release and reap the namespace child even when kill is denied.' > "$out/result"
        '';
      }
    ];
})
