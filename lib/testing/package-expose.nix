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
  reservedCollision = builtins.tryEval (
    (pkg.overrideAttrs (_: {
      expose = {
        units."aos-pkg-expose-smoke-firewall.service" = {};
        permissions.network = "private";
        requires = [];
      };
    }))
    .expose
    .outPath
  );
  reservedCollisionRejected =
    if reservedCollision.success
    then throw "expose renderer must reject package-authored synthesized side-effect unit names"
    else "ok";
in
  pkgs.mkDerivation {
    pname = "package-expose-check";
    version = "0";
    src = null;

    payload = pkg;
    exposePath = pkg.expose;
    overriddenPayload = overridden;
    overriddenExposePath = overridden.expose;
    inherit reservedCollisionRejected;

    buildDeps =
      (builtins.map (pkg: pkg.exposeCheck) (builtins.attrValues packagesWithExpose))
      ++ [overridden.exposeCheck];

    phases = [
      {
        name = "check";
        script = ''
          set -eu

          unit="$exposePath/units/expose-smoke.service"
          target="$exposePath/units/aos-pkg-expose-smoke.target"
          modules="$exposePath/units/aos-pkg-expose-smoke-modules.service"
          sysctl="$exposePath/units/aos-pkg-expose-smoke-sysctl.service"
          firewall="$exposePath/units/aos-pkg-expose-smoke-firewall.service"
          manifest="$exposePath/manifest.json"

          test -d "$exposePath/units"
          test -f "$unit"
          test -f "$target"
          test -f "$modules"
          test -f "$sysctl"
          test -f "$firewall"
          test -f "$manifest"

          grep -q 'Description=RFC-0001 expose smoke service' "$unit"
          grep -q 'PartOf=aos-pkg-expose-smoke.target' "$unit"
          grep -q 'WantedBy=aos-pkg-expose-smoke.target' "$unit"
          grep -q 'After=network.target aos-pkg-expose-smoke-modules.service aos-pkg-expose-smoke-sysctl.service aos-pkg-expose-smoke-firewall.service' "$unit"
          grep -q 'Requires=aos-pkg-expose-smoke-modules.service aos-pkg-expose-smoke-sysctl.service aos-pkg-expose-smoke-firewall.service' "$unit"
          grep -q 'ExecStart=${pkgs.bash}/bin/bash -c true' "$unit"
          grep -q 'Where=/var/lib/exposesmoke' "$exposePath/units/var-lib-exposesmoke.mount"

          grep -q 'Description=Activation target for expose-smoke' "$target"
          grep -q 'Wants=expose-smoke.service var-lib-exposesmoke.mount aos-pkg-expose-smoke-modules.service aos-pkg-expose-smoke-sysctl.service aos-pkg-expose-smoke-firewall.service' "$target"
          test ! -e "$exposePath/units/multi-user.target.wants/aos-pkg-expose-smoke.target"
          test -L "$exposePath/units/aos-pkg-expose-smoke.target.wants/expose-smoke.service"
          test -L "$exposePath/units/aos-pkg-expose-smoke.target.wants/var-lib-exposesmoke.mount"
          test -L "$exposePath/units/aos-pkg-expose-smoke.target.wants/aos-pkg-expose-smoke-modules.service"
          test -L "$exposePath/units/aos-pkg-expose-smoke.target.wants/aos-pkg-expose-smoke-sysctl.service"
          test -L "$exposePath/units/aos-pkg-expose-smoke.target.wants/aos-pkg-expose-smoke-firewall.service"
          test ! -e "$exposePath/units/multi-user.target.wants/expose-smoke.service"
          test ! -e "$exposePath/units/multi-user.target.requires/expose-smoke.service"
          test ! -e "$exposePath/units/multi-user.target.upholds/expose-smoke.service"
          test ! -e "$exposePath/units/multi-user.target.wants/var-lib-exposesmoke.mount"
          if find "$exposePath" \
            \( -path '*/modules-load.d/*' -o -path '*/sysctl.d/*' -o -path '*/nftables.d/*' \) \
            | grep .; then
            echo "package expose output must not contain global scan-dir entries" >&2
            exit 1
          fi

          grep -q 'Description=Apply kernel modules for expose-smoke' "$modules"
          grep -q 'PartOf=aos-pkg-expose-smoke.target' "$modules"
          grep -q 'WantedBy=aos-pkg-expose-smoke.target' "$modules"
          grep -q 'ExecStart=${pkgs.kmod}/sbin/modprobe -a br_netfilter' "$modules"

          grep -q 'Description=Apply sysctl settings for expose-smoke' "$sysctl"
          grep -q 'PartOf=aos-pkg-expose-smoke.target' "$sysctl"
          grep -q 'After=aos-pkg-expose-smoke-modules.service' "$sysctl"
          grep -q 'Requires=aos-pkg-expose-smoke-modules.service' "$sysctl"
          grep -q 'ExecStart=${pkgs.procps-ng}/sbin/sysctl -w net.ipv4.ip_forward=1' "$sysctl"

          grep -q 'Description=Apply firewall rules for expose-smoke' "$firewall"
          grep -q 'PartOf=aos-pkg-expose-smoke.target' "$firewall"
          grep -q 'After=nftables.service' "$firewall"
          grep -q 'Requires=nftables.service' "$firewall"
          grep -q 'ReloadPropagatedFrom=nftables.service' "$firewall"
          grep -q 'ExecStart=${pkgs.nftables}/sbin/nft add element inet filter allowed_tcp { 8000, 8443 }' "$firewall"
          grep -q 'ExecStart=${pkgs.nftables}/sbin/nft add element inet filter allowed_udp { 5353 }' "$firewall"
          grep -q 'ExecReload=${pkgs.nftables}/sbin/nft add element inet filter allowed_tcp { 8000, 8443 }' "$firewall"
          grep -q 'ExecStop=${pkgs.nftables}/sbin/nft delete element inet filter allowed_tcp { 8000, 8443 }' "$firewall"
          grep -q 'aos-pkg-expose-smoke-firewall-forward-start' "$firewall"
          grep -q 'aos-pkg-expose-smoke-firewall-forward-stop' "$firewall"

          grep -q '"target":"aos-pkg-expose-smoke.target"' "$manifest"
          grep -q '"aos-pkg-expose-smoke.target"' "$manifest"
          grep -q '"aos-pkg-expose-smoke-modules.service"' "$manifest"
          grep -q '"aos-pkg-expose-smoke-sysctl.service"' "$manifest"
          grep -q '"aos-pkg-expose-smoke-firewall.service"' "$manifest"
          grep -q '"expose-smoke.service"' "$manifest"
          grep -q '"var-lib-exposesmoke.mount"' "$manifest"
          grep -q '"modules":\["br_netfilter"\]' "$manifest"
          grep -q '"sysctl":{"net.ipv4.ip_forward":"1"}' "$manifest"
          grep -q '"allowedTCP":\[8000,8443\]' "$manifest"
          grep -q '"allowedUDP":\[5353\]' "$manifest"
          grep -q '"forwardPolicy":"accept"' "$manifest"
          grep -q '"network":"private"' "$manifest"
          grep -q '"syscalls":"restricted"' "$manifest"

          test "$payload" = "$overriddenPayload"
          test "$exposePath" != "$overriddenExposePath"
          test -f "$overriddenExposePath/units/expose-smoke-override.service"
          grep -q 'Description=RFC-0001 expose override service' \
            "$overriddenExposePath/units/expose-smoke-override.service"
          test "$reservedCollisionRejected" = ok

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
