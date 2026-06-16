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
  privilegedExecPrefix = builtins.tryEval (
    (pkg.overrideAttrs (_: {
      expose = {
        units."expose-smoke-privileged-prefix.service" = {
          serviceConfig = {
            Type = "oneshot";
            ExecStart = "+${pkgs.bash}/bin/bash -c true";
          };
        };
        permissions.network = "private";
        requires = [];
      };
    }))
    .expose
    .outPath
  );
  privilegedExecPrefixRejected =
    if privilegedExecPrefix.success
    then throw "expose renderer must reject systemd privileged Exec* prefixes on workload services"
    else "ok";
  privateOutbound = builtins.tryEval (
    (pkg.overrideAttrs (_: {
      expose = {
        units."expose-smoke-private-outbound.service" = {
          serviceConfig = {
            Type = "oneshot";
            ExecStart = "${pkgs.bash}/bin/bash -c true";
          };
        };
        permissions.network = "private-outbound";
        requires = [];
      };
    }))
    .expose
    .outPath
  );
  privateOutboundRejected =
    if privateOutbound.success
    then throw "expose renderer must reject private-outbound until the netns/veth unit is implemented"
    else "ok";
  withHoles = pkg.overrideAttrs (_: {
    expose = {
      units."expose-smoke-holes.service" = {
        description = "RFC-0001 expose sandboxed-with-holes label service";
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
      };
      permissions = {
        network = "private";
        capabilities = ["CAP_NET_BIND_SERVICE"];
      };
      requires = [];
    };
  });
  unconfined = pkg.overrideAttrs (_: {
    expose = {
      units."expose-smoke-unconfined.service" = {
        description = "RFC-0001 expose unconfined label service";
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
      };
      permissions = {
        network = "host";
        capabilities = ["CAP_NET_ADMIN"];
        privileged-users = true;
      };
      requires = [];
    };
  });
  privilegedSyscalls = pkg.overrideAttrs (_: {
    expose = {
      units."expose-smoke-privileged-syscalls.service" = {
        description = "RFC-0001 expose privileged syscalls label service";
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
      };
      permissions = {
        network = "private";
        syscalls = "privileged";
      };
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
    withHolesExposePath = withHoles.expose;
    unconfinedExposePath = unconfined.expose;
    privilegedSyscallsExposePath = privilegedSyscalls.expose;
    inherit reservedCollisionRejected privilegedExecPrefixRejected privateOutboundRejected;

    buildDeps =
      (builtins.map (pkg: pkg.exposeCheck) (builtins.attrValues packagesWithExpose))
      ++ [
        overridden.exposeCheck
        withHoles.exposeCheck
        unconfined.exposeCheck
        privilegedSyscalls.exposeCheck
      ];

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
          grep -q "RootDirectory=$payload" "$unit"
          grep -q 'MountAPIVFS=true' "$unit"
          grep -q 'ProtectSystem=strict' "$unit"
          grep -q 'ProtectHome=true' "$unit"
          grep -q 'PrivateTmp=disconnected' "$unit"
          grep -q 'TemporaryFileSystem=/tmp' "$unit"
          grep -q 'TemporaryFileSystem=/var/tmp' "$unit"
          grep -q 'StateDirectory=aos-pkg-expose-smoke' "$unit"
          grep -q 'NoNewPrivileges=true' "$unit"
          grep -q 'DynamicUser=true' "$unit"
          grep -q 'PrivateUsers=identity' "$unit"
          grep -q 'PrivateNetwork=true' "$unit"
          grep -q 'DevicePolicy=closed' "$unit"
          grep -q '^CapabilityBoundingSet=$' "$unit"
          grep -q '^AmbientCapabilities=$' "$unit"
          grep -q 'BindReadOnlyPaths=/nix/store' "$unit"
          grep -q 'SystemCallFilter=@system-service' "$unit"
          grep -q 'SystemCallErrorNumber=EPERM' "$unit"
          grep -q 'SystemCallArchitectures=native' "$unit"
          grep -q 'RestrictAddressFamilies=AF_UNIX' "$unit"
          grep -q 'RestrictAddressFamilies=AF_INET' "$unit"
          grep -q 'RestrictAddressFamilies=AF_INET6' "$unit"
          grep -q 'RestrictNamespaces=true' "$unit"
          grep -q 'LockPersonality=true' "$unit"
          grep -q 'MemoryDenyWriteExecute=true' "$unit"
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
          if grep -q 'RootDirectory=' "$modules"; then
            echo "host-side modules service must not be RootDirectory-sandboxed" >&2
            exit 1
          fi
          grep -q 'PartOf=aos-pkg-expose-smoke.target' "$modules"
          grep -q 'WantedBy=aos-pkg-expose-smoke.target' "$modules"
          grep -q 'ExecStart=${pkgs.kmod}/sbin/modprobe -a br_netfilter' "$modules"

          grep -q 'Description=Apply sysctl settings for expose-smoke' "$sysctl"
          if grep -q 'RootDirectory=' "$sysctl"; then
            echo "host-side sysctl service must not be RootDirectory-sandboxed" >&2
            exit 1
          fi
          grep -q 'PartOf=aos-pkg-expose-smoke.target' "$sysctl"
          grep -q 'After=aos-pkg-expose-smoke-modules.service' "$sysctl"
          grep -q 'Requires=aos-pkg-expose-smoke-modules.service' "$sysctl"
          grep -q 'ExecStart=${pkgs.procps-ng}/sbin/sysctl -w net.ipv4.ip_forward=1' "$sysctl"

          grep -q 'Description=Apply firewall rules for expose-smoke' "$firewall"
          if grep -q 'RootDirectory=' "$firewall"; then
            echo "host-side firewall service must not be RootDirectory-sandboxed" >&2
            exit 1
          fi
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
          grep -q '"confinement":{"class":"sandboxed","holes":\[\],"label":"sandboxed"}' "$manifest"
          grep -q '"network":"private"' "$manifest"
          grep -q '"security-label":"aos.expose-smoke"' "$manifest"
          grep -q '"syscalls":"restricted"' "$manifest"

          test "$payload" = "$overriddenPayload"
          test "$exposePath" != "$overriddenExposePath"
          test -f "$overriddenExposePath/units/expose-smoke-override.service"
          grep -q 'Description=RFC-0001 expose override service' \
            "$overriddenExposePath/units/expose-smoke-override.service"
          test "$reservedCollisionRejected" = ok
          test "$privilegedExecPrefixRejected" = ok
          test "$privateOutboundRejected" = ok
          grep -q '"confinement":{"class":"sandboxed-with-holes","holes":\["capability:CAP_NET_BIND_SERVICE"\],"label":"sandboxed-with-holes (capability:CAP_NET_BIND_SERVICE)"}' \
            "$withHolesExposePath/manifest.json"
          grep -q '"security-label":"aos-pkg-expose-smoke"' \
            "$withHolesExposePath/manifest.json"
          grep -q 'CapabilityBoundingSet=CAP_NET_BIND_SERVICE' \
            "$withHolesExposePath/units/expose-smoke-holes.service"
          grep -q 'AmbientCapabilities=CAP_NET_BIND_SERVICE' \
            "$withHolesExposePath/units/expose-smoke-holes.service"
          grep -q '"confinement":{"class":"unconfined","holes":\["network:host","capability:CAP_NET_ADMIN","privileged-users"\],"label":"unconfined"}' \
            "$unconfinedExposePath/manifest.json"
          grep -q 'RestrictAddressFamilies=AF_NETLINK' \
            "$unconfinedExposePath/units/expose-smoke-unconfined.service"
          grep -q 'CapabilityBoundingSet=CAP_NET_ADMIN' \
            "$unconfinedExposePath/units/expose-smoke-unconfined.service"
          grep -q 'PrivateUsers=false' \
            "$unconfinedExposePath/units/expose-smoke-unconfined.service"
          grep -q 'DynamicUser=false' \
            "$unconfinedExposePath/units/expose-smoke-unconfined.service"
          grep -q '"confinement":{"class":"sandboxed-with-holes","holes":\["syscalls:privileged"\],"label":"sandboxed-with-holes (syscalls:privileged)"}' \
            "$privilegedSyscallsExposePath/manifest.json"
          if grep -q 'SystemCallFilter=' \
            "$privilegedSyscallsExposePath/units/expose-smoke-privileged-syscalls.service"; then
            echo "privileged syscall profile must not render a restrictive SystemCallFilter" >&2
            exit 1
          fi
          grep -q 'SystemCallArchitectures=native' \
            "$privilegedSyscallsExposePath/units/expose-smoke-privileged-syscalls.service"

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
