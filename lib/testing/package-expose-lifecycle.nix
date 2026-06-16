##! lib/testing/package-expose-lifecycle.nix — RFC-0001 live package expose check.
##!
##! Boots a full AOS system, copies rendered package-expose units into
##! `/etc/systemd/system` like a future package-manager activation step would,
##! then starts, inspects, reloads, and stops the package targets under systemd.
{
  pkgs,
  mkSystem,
  testing,
}: let
  privateOutboundNetnsHash = builtins.substring 0 8 (
    builtins.hashString "sha256" "expose-lifecycle-outbound"
  );
  privateOutboundHostIf = "aos${privateOutboundNetnsHash}h";
  privateOutboundPeerIf = "aos${privateOutboundNetnsHash}p";
  privateOutboundNatTable = "aos_pkg_${privateOutboundNetnsHash}";

  privatePackageCommand = pkgs.writeShellScriptBin "expose-lifecycle-private-command" ''
    state=/var/lib/aos-pkg-expose-lifecycle-private
    test -r /share/expose-lifecycle-private/payload.txt
    ${pkgs.coreutils}/bin/readlink /proc/self/ns/net > "$state/netns"
    ${pkgs.coreutils}/bin/readlink /proc/self/ns/user > "$state/userns"
    printf private-ok > "$state/result"
  '';

  privateOutboundCommand = pkgs.writeShellScriptBin "expose-lifecycle-outbound-command" ''
    state=/var/lib/aos-pkg-expose-lifecycle-outbound
    test -r /share/expose-lifecycle-outbound/payload.txt
    ${pkgs.coreutils}/bin/readlink /proc/self/ns/net > "$state/netns"
    ${pkgs.coreutils}/bin/readlink /proc/self/ns/user > "$state/userns"
    printf outbound-ok > "$state/result"
  '';

  privatePackage = pkgs.mkDerivation {
    pname = "expose-lifecycle-private";
    version = "0";
    src = null;

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/expose-lifecycle-private"
          printf private-payload > "$out/share/expose-lifecycle-private/payload.txt"
        '';
      }
    ];

    expose = {
      units."expose-lifecycle-private.service" = {
        description = "RFC-0001 live private package expose workload";
        wantedBy = ["multi-user.target"];
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${privatePackageCommand}/bin/expose-lifecycle-private-command";
        };
      };
      permissions = {
        network = "private";
        capabilities = [];
        devices = [];
        host-paths = [];
        syscalls = "restricted";
      };
      requires = [];
    };
  };

  privateOutboundPackage = pkgs.mkDerivation {
    pname = "expose-lifecycle-outbound";
    version = "0";
    src = null;

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/expose-lifecycle-outbound"
          printf outbound-payload > "$out/share/expose-lifecycle-outbound/payload.txt"
        '';
      }
    ];

    expose = {
      units."expose-lifecycle-outbound.service" = {
        description = "RFC-0001 live private-outbound package expose workload";
        wantedBy = ["multi-user.target"];
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${privateOutboundCommand}/bin/expose-lifecycle-outbound-command";
        };
      };
      permissions = {
        network = "private-outbound";
        capabilities = [];
        devices = [];
        host-paths = [];
        syscalls = "restricted";
      };
      requires = [];
    };
  };

  testSystem = mkSystem {
    modules = [
      ../../systems/server.nix
      ({pkgs, ...}: {
        environment.systemPackages = [
          privatePackage
          privatePackage.expose
          privateOutboundPackage
          privateOutboundPackage.expose
          pkgs.iproute2
          pkgs.nftables
          pkgs.procps-ng
        ];
      })
    ];
  };
in
  testing.mkVMTest {
    name = "package-expose-lifecycle";
    system = testSystem;
    timeout = 300;
    testScript = ''
      host_netns = vm.succeed("readlink /proc/1/ns/net").strip()
      host_userns = vm.succeed("readlink /proc/1/ns/user").strip()
      initial_ip_forward = vm.succeed("cat /proc/sys/net/ipv4/ip_forward").strip()

      vm.succeed("systemctl is-active nftables.service")
      vm.succeed("mkdir -p /etc/systemd/system")
      vm.succeed("cp -a ${privatePackage.expose}/units/. /etc/systemd/system/")
      vm.succeed("cp -a ${privateOutboundPackage.expose}/units/. /etc/systemd/system/")
      vm.succeed("systemctl daemon-reload")
      vm.succeed("grep -q '^PrivateUsers=identity$' /etc/systemd/system/expose-lifecycle-private.service")
      vm.succeed("grep -q '^PrivateUsers=identity$' /etc/systemd/system/expose-lifecycle-outbound.service")

      vm.succeed("systemctl start aos-pkg-expose-lifecycle-private.target")
      assert "private-ok" in vm.succeed(
          "cat /var/lib/aos-pkg-expose-lifecycle-private/result"
      )
      assert vm.succeed(
          "cat /var/lib/aos-pkg-expose-lifecycle-private/netns"
      ).strip() != host_netns
      assert vm.succeed(
          "cat /var/lib/aos-pkg-expose-lifecycle-private/userns"
      ).strip() != host_userns
      assert "${privatePackage}" in vm.succeed(
          "systemctl show -p RootDirectory --value expose-lifecycle-private.service"
      )
      assert "yes" in vm.succeed(
          "systemctl show -p PrivateNetwork --value expose-lifecycle-private.service"
      )
      assert "yes" in vm.succeed(
          "systemctl show -p DynamicUser --value expose-lifecycle-private.service"
      )
      vm.succeed("systemctl stop aos-pkg-expose-lifecycle-private.target")

      vm.succeed("systemctl start aos-pkg-expose-lifecycle-outbound.target")
      assert "outbound-ok" in vm.succeed(
          "cat /var/lib/aos-pkg-expose-lifecycle-outbound/result"
      )
      assert vm.succeed(
          "cat /var/lib/aos-pkg-expose-lifecycle-outbound/netns"
      ).strip() != host_netns
      assert vm.succeed(
          "cat /var/lib/aos-pkg-expose-lifecycle-outbound/userns"
      ).strip() != host_userns
      vm.succeed("ip netns exec aos-pkg-expose-lifecycle-outbound ${pkgs.iproute2}/sbin/ip route show default | grep -q ' dev ${privateOutboundPeerIf}'")
      vm.succeed("ip -4 route show dev ${privateOutboundHostIf}")
      assert "no" in vm.succeed(
          "systemctl show -p PrivateNetwork --value expose-lifecycle-outbound.service"
      )
      assert "/run/netns/aos-pkg-expose-lifecycle-outbound" in vm.succeed(
          "systemctl show -p NetworkNamespacePath --value expose-lifecycle-outbound.service"
      )
      vm.succeed(
          "ip netns list | grep -E '^aos-pkg-expose-lifecycle-outbound( |$)'"
      )
      vm.succeed("ip link show ${privateOutboundHostIf}")
      vm.succeed("nft list table ip ${privateOutboundNatTable}")
      vm.succeed(
          "nft list ruleset | grep -F 'aos-pkg-expose-lifecycle-outbound-netns-forward'"
      )
      vm.succeed(
          "test \"$(nft -a list chain inet filter forward | grep -F 'comment \"aos-pkg-expose-lifecycle-outbound-netns-forward\"' | wc -l)\" -eq 2"
      )
      vm.succeed("systemctl reload aos-pkg-expose-lifecycle-outbound-netns.service")
      vm.succeed(
          "test \"$(nft -a list chain inet filter forward | grep -F 'comment \"aos-pkg-expose-lifecycle-outbound-netns-forward\"' | wc -l)\" -eq 2"
      )
      vm.succeed("systemctl stop aos-pkg-expose-lifecycle-outbound.target")
      vm.succeed("systemctl start aos-pkg-expose-lifecycle-outbound.target")
      vm.succeed("ip netns exec aos-pkg-expose-lifecycle-outbound ${pkgs.iproute2}/sbin/ip route show default | grep -q ' dev ${privateOutboundPeerIf}'")
      vm.succeed("ip link show ${privateOutboundHostIf}")
      vm.succeed("systemctl stop aos-pkg-expose-lifecycle-outbound.target")
      vm.wait_until_succeeds(
          "test \"$(systemctl is-active aos-pkg-expose-lifecycle-outbound-netns.service || true)\" = inactive",
          timeout=30,
      )
      vm.wait_until_succeeds(
          "if ip netns list | grep -E '^aos-pkg-expose-lifecycle-outbound( |$)'; then exit 1; fi",
          timeout=30,
      )
      vm.wait_until_succeeds(
          "if ip link show ${privateOutboundHostIf}; then exit 1; fi",
          timeout=30,
      )
      vm.wait_until_succeeds(
          "if nft list table ip ${privateOutboundNatTable}; then exit 1; fi",
          timeout=30,
      )
      vm.wait_until_succeeds(
          "if nft list ruleset | grep -F 'aos-pkg-expose-lifecycle-outbound-netns-forward'; then exit 1; fi",
          timeout=30,
      )
      assert vm.succeed("cat /proc/sys/net/ipv4/ip_forward").strip() == initial_ip_forward
    '';
  }
