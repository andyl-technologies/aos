##! lib/testing/package-expose.nix — RFC-0001 package expose smoke check.
##!
##! Builds a normal discovered package with an `expose` block and verifies that
##! its integration artifacts are rendered in a separate store path.
{
  pkgs,
  lib,
  packagesWithExpose,
}: let
  pkg = pkgs.expose-smoke;
  overridden = pkg.overrideAttrs (_: {
    expose = {
      units."expose-smoke-override.service" = {
        description = "RFC-0001 expose override service";
        wantedBy = ["aos-pkg-expose-smoke.target"];
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
      };
      permissions.network = "private";
      requires = [];
    };
  });
in
  pkgs.mkDerivation {
    pname = "package-expose-check";
    version = "0";
    src = null;

    payload = pkg;
    exposePath = pkg.expose;
    overriddenPayload = overridden;
    overriddenExposePath = overridden.expose;

    buildDeps =
      (builtins.map (pkg: pkg.exposeCheck) (builtins.attrValues packagesWithExpose))
      ++ [overridden.exposeCheck];

    phases = [
      {
        name = "check";
        script = ''
          set -eu

          unit="$exposePath/units/expose-smoke.service"
          manifest="$exposePath/manifest.json"

          test -d "$exposePath/units"
          test -f "$unit"
          test -f "$manifest"

          grep -q 'Description=RFC-0001 expose smoke service' "$unit"
          grep -q 'WantedBy=aos-pkg-expose-smoke.target' "$unit"
          grep -q 'ExecStart=${pkgs.bash}/bin/bash -c true' "$unit"
          grep -q 'Where=/var/lib/exposesmoke' "$exposePath/units/var-lib-exposesmoke.mount"

          grep -q '"target":"aos-pkg-expose-smoke.target"' "$manifest"
          grep -q '"units":\["expose-smoke.service","var-lib-exposesmoke.mount"\]' "$manifest"
          grep -q '"network":"private"' "$manifest"
          grep -q '"syscalls":"restricted"' "$manifest"

          test "$payload" = "$overriddenPayload"
          test "$exposePath" != "$overriddenExposePath"
          test -f "$overriddenExposePath/units/expose-smoke-override.service"
          grep -q 'Description=RFC-0001 expose override service' \
            "$overriddenExposePath/units/expose-smoke-override.service"

          if grep -R "$exposePath" "$payload"; then
            echo "payload output must not contain a reference to its expose path" >&2
            exit 1
          fi

          mkdir -p "$out"
          echo "PASS" > "$out/result"
        '';
      }
    ];

    meta.description = "RFC-0001 package expose renderer regression check";
  }
