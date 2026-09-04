# Executable nspawn phase-0 proof for the exact AOS kernel and systemd build.
{
  mkSystem,
  pkgs,
  ...
}: let
  probe = pkgs.mkDerivation {
    pname = "aos-nspawn-platform-probe";
    version = "1";
    src = null;
    buildDeps = [pkgs.linux-headers];
    phases = [
      {
        name = "build";
        script = ''
          $CC -std=c17 -Wall -Wextra -Werror \
            ${../sandbox/nspawn-platform-probe.c} -o aos-nspawn-platform-probe
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/bin
          cp aos-nspawn-platform-probe $out/bin/
        '';
      }
    ];
    meta = {
      description = "Runtime evidence probe for the AOS nspawn isolation boundary";
      license = "Apache-2.0";
    };
  };

  defaultTarget = pkgs.writeTextFile {
    name = "aos-nspawn-proof-default-target";
    destination = "/default.target";
    text = ''
      [Unit]
      Description=AOS nspawn proof target
      DefaultDependencies=no
      Requires=aos-nspawn-payload-proof.service
      After=aos-nspawn-payload-proof.service
    '';
  };

  payloadService = pkgs.writeTextFile {
    name = "aos-nspawn-payload-proof-service";
    destination = "/aos-nspawn-payload-proof.service";
    text = ''
      [Unit]
      Description=Exercise inherited AOS payload isolation
      DefaultDependencies=no

      [Service]
      Type=oneshot
      RemainAfterExit=yes
      ExecStart=${probe}/bin/aos-nspawn-platform-probe /var/lib/aos-nspawn-proof/report.json
    '';
  };

  containerRoot = pkgs.runCommand "aos-nspawn-platform-proof-root" {} ''
    mkdir -p $out/etc/systemd/system $out/sbin $out/var/lib/aos-nspawn-proof
    cp ${defaultTarget}/default.target $out/etc/systemd/system/default.target
    cp ${payloadService}/aos-nspawn-payload-proof.service \
      $out/etc/systemd/system/aos-nspawn-payload-proof.service
    ln -s ${pkgs.systemd}/lib/systemd/systemd $out/sbin/init
    printf 'NAME=AOS-nspawn-platform-proof\nID=aos-nspawn-proof\n' > $out/etc/os-release
    printf 'a05a05a05a05a05a05a05a05a05a05a0\n' > $out/etc/machine-id
  '';

  networkRules = pkgs.writeTextFile {
    name = "aos-nspawn-platform-proof-network-rules";
    destination = "/rules.nft";
    text = ''
      table inet aos_nspawn_proof {
        chain input {
          type filter hook input priority filter; policy drop;
        }
        chain forward {
          type filter hook forward priority filter; policy drop;
        }
        chain output {
          type filter hook output priority filter; policy drop;
        }
      }
    '';
  };

  system = mkSystem [
    ../../systems/server-test.nix
    {
      environment.systemPackages = [
        pkgs.iproute2
        pkgs.jq
        pkgs.nftables
        pkgs.systemd
      ];

      # If settings loading is accidentally re-enabled, this disables boot,
      # requests a veth, injects an observable environment value, and exposes
      # host /etc. The fixed launch must ignore every field.
      environment.etc."systemd/nspawn/aos-proof.nspawn".text = ''
        [Exec]
        Boot=no
        Environment=AOS_HOSTILE_NSPAWN_SETTINGS=1

        [Files]
        BindReadOnly=/etc:/host-etc

        [Network]
        VirtualEthernet=yes
      '';

      systemd.services.aos-nspawn-proof-netns = {
        wantedBy = ["multi-user.target"];
        before = ["aos-nspawn-platform-proof.service"];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          CapabilityBoundingSet = "CAP_NET_ADMIN CAP_SYS_ADMIN";
          AmbientCapabilities = "CAP_NET_ADMIN CAP_SYS_ADMIN";
          NoNewPrivileges = false;
          RestrictAddressFamilies = "AF_UNIX AF_NETLINK";
        };
        script = ''
          set -eu
          ${pkgs.iproute2}/sbin/ip netns delete aos-proof 2>/dev/null || true
          ${pkgs.iproute2}/sbin/ip netns add aos-proof
          ${pkgs.iproute2}/sbin/ip netns exec aos-proof \
            ${pkgs.nftables}/bin/nft -f ${networkRules}/rules.nft
        '';
        preStop = ''
          ${pkgs.iproute2}/sbin/ip netns delete aos-proof
        '';
      };

      systemd.services.aos-nspawn-platform-proof = {
        wantedBy = ["multi-user.target"];
        requires = ["aos-nspawn-proof-netns.service"];
        after = ["aos-nspawn-proof-netns.service"];
        serviceConfig = {
          Type = "notify";
          NotifyAccess = "all";
          Delegate = true;
          KillMode = "mixed";
          TasksMax = 4096;
          NetworkNamespacePath = "/run/netns/aos-proof";
          CapabilityBoundingSet = "CAP_AUDIT_CONTROL CAP_AUDIT_WRITE CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_FSETID CAP_IPC_OWNER CAP_KILL CAP_LEASE CAP_LINUX_IMMUTABLE CAP_MKNOD CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_SETFCAP CAP_SETGID CAP_SETPCAP CAP_SETUID CAP_SYS_ADMIN CAP_SYS_CHROOT CAP_SYS_NICE CAP_SYS_PTRACE CAP_SYS_RESOURCE CAP_SYS_TTY_CONFIG";
          AmbientCapabilities = "CAP_NET_ADMIN CAP_SYS_ADMIN";
          NoNewPrivileges = false;
          RestrictAddressFamilies = "AF_UNIX AF_NETLINK";
          ExecStartPre = "${pkgs.bash}/bin/bash -c 'set -eu; rm -rf /var/lib/aos-nspawn-platform-proof/root; mkdir -p /var/lib/aos-nspawn-platform-proof; cp -a ${containerRoot} /var/lib/aos-nspawn-platform-proof/root'";
          ExecStart = "${pkgs.systemd}/bin/systemd-nspawn --boot --quiet --keep-unit --register=no --settings=no --notify-ready=yes --machine=aos-proof --directory=/var/lib/aos-nspawn-platform-proof/root --bind-ro=/nix/store --private-users=655360:65536 --private-users-ownership=map --no-new-privileges=yes --aos-payload-seccomp-profile=aos-sandbox-payload-v1";
        };
      };
    }
  ];
in {
  name = "sandbox-nspawn-platform-proof";
  timeout = 300;

  machines.vm = {inherit system;};

  testScript = ''
    import json

    vm.wait_for_unit("multi-user.target", timeout=120)
    vm.wait_until_succeeds(
        "test -s /var/lib/aos-nspawn-platform-proof/root/var/lib/aos-nspawn-proof/report.json",
        timeout=90,
    )

    report_path = "/var/lib/aos-nspawn-platform-proof/root/var/lib/aos-nspawn-proof/report.json"
    report = json.loads(vm.succeed(f"cat {report_path}"))
    assert report["schema"] == "aos.sandbox.nspawn-platform-proof/v1", report
    assert report["passed"] is True, report
    assert report["payload_pid"] != 1, report
    assert report["pid1_no_new_privileges"] == 1, report
    assert report["pid1_seccomp_mode"] == 2, report
    assert report["service_no_new_privileges"] == 1, report
    assert report["service_seccomp_mode"] == 2, report
    assert report["mount_denied_eperm"] is True, report
    assert report["unshare_denied_eperm"] is True, report
    assert report["setns_denied_eperm"] is True, report
    assert report["clone_namespace_denied_eperm"] is True, report
    assert report["clone3_hidden_enosys"] is True, report
    assert report["ordinary_fork_allowed"] is True, report
    assert report["hostile_settings_ignored"] is True, report
    assert report["uid_map"] == {"inside": 0, "outside": 655360, "length": 65536}, report

    version = vm.succeed("${pkgs.systemd}/bin/systemd-nspawn --version")
    assert version.splitlines()[0] == "systemd 259 (259.8)", version
    vm.fail("systemctl is-active --quiet systemd-machined.service")
    vm.fail("test -e /run/systemd/machines/aos-proof")

    pinned_inode = int(vm.succeed("stat -Lc %i /run/netns/aos-proof").strip())
    assert report["network_namespace_inode"] == pinned_inode, (report, pinned_inode)
    links = vm.succeed("${pkgs.iproute2}/sbin/ip netns exec aos-proof ${pkgs.iproute2}/sbin/ip -o link show")
    assert "lo:" in links, links
    assert "host0:" not in links, links
    vm.succeed("${pkgs.iproute2}/sbin/ip netns exec aos-proof ${pkgs.nftables}/bin/nft list table inet aos_nspawn_proof")

    unit = vm.succeed("systemctl show aos-nspawn-platform-proof.service -p Delegate -p KillMode -p NetworkNamespacePath -p NotifyAccess -p Type")
    assert "Delegate=yes" in unit, unit
    assert "KillMode=mixed" in unit, unit
    assert "NetworkNamespacePath=/run/netns/aos-proof" in unit, unit
    assert "NotifyAccess=all" in unit, unit
    assert "Type=notify" in unit, unit
    invocation = vm.succeed("systemctl show aos-nspawn-platform-proof.service -p ExecStart")
    assert "--settings=no" in invocation, invocation
    assert "--register=no" in invocation, invocation
    assert "--aos-payload-seccomp-profile=aos-sandbox-payload-v1" in invocation, invocation
    assert "--network-namespace-path" not in invocation, invocation
  '';
}
