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

  hostObserver = pkgs.mkDerivation {
    pname = "aos-nspawn-host-observer";
    version = "1";
    src = null;
    buildDeps = [pkgs.linux-headers];
    phases = [
      {
        name = "build";
        script = ''
          $CC -std=c17 -Wall -Wextra -Werror \
            ${../sandbox/nspawn-host-observer.c} -o aos-nspawn-host-observer
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/bin
          cp aos-nspawn-host-observer $out/bin/
        '';
      }
    ];
    meta = {
      description = "Host-side pidfd observer for the AOS nspawn platform proof";
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
      ExecStart=${probe}/bin/aos-nspawn-platform-probe /var/lib/aos-nspawn-proof/report.json /var/lib/aos-nspawn-proof/boot-generation
    '';
  };

  containerRoot = pkgs.runCommand "aos-nspawn-platform-proof-root" {} ''
    mkdir -p $out/etc/systemd/system $out/usr/lib $out/sbin $out/var/lib/aos-nspawn-proof
    cp ${defaultTarget}/default.target $out/etc/systemd/system/default.target
    cp ${payloadService}/aos-nspawn-payload-proof.service \
      $out/etc/systemd/system/aos-nspawn-payload-proof.service
    ln -s ${pkgs.systemd}/lib/systemd/systemd $out/sbin/init
    printf 'NAME=AOS-nspawn-platform-proof\nID=aos-nspawn-proof\n' > $out/usr/lib/os-release
    ln -s ../usr/lib/os-release $out/etc/os-release
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

  # This exercises upstream nspawn's procfs pathname handling at a declarative
  # VM seam. The sibling pin holder is test scaffolding, not the production
  # root-mount descriptor handoff, ownership, or transient-unit compiler. The
  # sandbox-host-worker gate exercises the actual production launch compiler.
  descriptorLauncher = pkgs.writeTextFile {
    name = "aos-nspawn-descriptor-launcher";
    destination = "/bin/aos-nspawn-descriptor-launcher";
    executable = true;
    text = ''
      #!${pkgs.bash}/bin/bash
      set -euo pipefail
      exec 3< /var/lib/aos-nspawn-platform-proof/root
      exec 4< ${pkgs.systemd}/bin/systemd-nspawn
      (
        exec ${pkgs.coreutils}/bin/sleep infinity
      ) &
      pin_holder=$!
      exec /proc/$pin_holder/fd/4 \
        --boot \
        --quiet \
        --keep-unit \
        --register=no \
        --settings=no \
        --notify-ready=yes \
        --machine=aos-proof \
        --directory=/proc/$pin_holder/fd/3 \
        --bind-ro=/nix/store \
        --private-users=655360:65536 \
        --private-users-ownership=map \
        --no-new-privileges=yes \
        --aos-payload-seccomp-profile=aos-sandbox-payload-v1
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
            ${pkgs.nftables}/sbin/nft -f ${networkRules}/rules.nft
        '';
        preStop = ''
          ${pkgs.iproute2}/sbin/ip netns delete aos-proof
        '';
      };

      systemd.services.aos-nspawn-platform-proof = {
        requires = ["aos-nspawn-proof-netns.service"];
        after = ["aos-nspawn-proof-netns.service"];
        unitConfig.CollectMode = "inactive-or-failed";
        serviceConfig = {
          Type = "notify";
          NotifyAccess = "main";
          Delegate = true;
          DelegateSubgroup = "supervisor";
          Slice = "aos-sandboxes.slice";
          Restart = "no";
          KillMode = "mixed";
          OOMPolicy = "kill";
          TasksMax = 4096;
          MemoryHigh = "768M";
          MemoryMax = "1G";
          MemorySwapMax = 0;
          CPUWeight = 100;
          MemoryAccounting = true;
          IOAccounting = true;
          TasksAccounting = true;
          TimeoutStartSec = 90;
          TimeoutStopSec = 30;
          NetworkNamespacePath = "/run/netns/aos-proof";
          CapabilityBoundingSet = "CAP_AUDIT_WRITE CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_FSETID CAP_KILL CAP_MKNOD CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_SETFCAP CAP_SETGID CAP_SETPCAP CAP_SETUID CAP_SYS_ADMIN CAP_SYS_CHROOT";
          AmbientCapabilities = "CAP_NET_ADMIN CAP_SYS_ADMIN";
          NoNewPrivileges = false;
          RestrictAddressFamilies = "AF_UNIX AF_NETLINK AF_INET AF_INET6";
          ExecStartPre = "${pkgs.bash}/bin/bash -c 'set -eu; rm -rf /var/lib/aos-nspawn-platform-proof/root; mkdir -p /var/lib/aos-nspawn-platform-proof; cp -a ${containerRoot} /var/lib/aos-nspawn-platform-proof/root'";
          ExecStart = "${descriptorLauncher}/bin/aos-nspawn-descriptor-launcher";
        };
      };

      # A restartable stand-in for the host worker observation boundary. It
      # deliberately discovers nested PID 1 from the delegated payload cgroup
      # on every invocation instead of retaining a process number in state.
      systemd.services.aos-nspawn-host-observer = {
        serviceConfig = {
          Type = "simple";
          Restart = "no";
          KillMode = "process";
          TimeoutStartSec = 15;
          TimeoutStopSec = 5;
        };
        script = ''
          set -eu
          unit_cgroup="$(${pkgs.systemd}/bin/systemctl show \
            aos-nspawn-platform-proof.service --property=ControlGroup --value)"
          test -n "$unit_cgroup"
          supervisor="$(${pkgs.systemd}/bin/systemctl show \
            aos-nspawn-platform-proof.service --property=MainPID --value)"
          test "$supervisor" -gt 1
          payload_cgroup="$unit_cgroup/payload"
          supervisor_cgroup="$unit_cgroup/supervisor"
          test -d "/sys/fs/cgroup$payload_cgroup"
          test -d "/sys/fs/cgroup$supervisor_cgroup"
          exec ${hostObserver}/bin/aos-nspawn-host-observer \
            "$supervisor" \
            /var/lib/aos-nspawn-platform-proof/root \
            /run/netns/aos-proof \
            "$payload_cgroup" \
            "$supervisor_cgroup" \
            ${pkgs.systemd}/bin/systemd-nspawn \
            /var/lib/aos-nspawn-platform-proof/root/var/lib/aos-nspawn-proof/boot-generation \
            /run/aos-nspawn-host-observer.json \
            aos-proof
        '';
      };
    }
  ];
in {
  name = "sandbox-nspawn-platform-proof";
  timeout = 300;

  machines.vm = {inherit system;};

  testScript = ''
    import json
    import re

    def wait_for_observer_report():
        try:
            vm.wait_until_succeeds("test -s /run/aos-nspawn-host-observer.json", timeout=15)
        except Exception:
            print(vm.execute("journalctl -u aos-nspawn-host-observer.service -u aos-nspawn-platform-proof.service --no-pager")[1].decode("utf-8", errors="replace"))
            print(vm.execute("${pkgs.systemd}/bin/systemd-cgls --no-pager /aos.slice/aos-sandboxes.slice/aos-nspawn-platform-proof.service")[1].decode("utf-8", errors="replace"))
            raise

    vm.wait_for_unit("multi-user.target", timeout=120)
    vm.succeed("systemctl mask --runtime --now systemd-machined.service")
    status, output, error = vm.execute("systemctl is-enabled systemd-machined.service")
    assert status == 1 and output.strip() == b"masked-runtime", (status, output, error)
    vm.fail("systemctl is-active --quiet systemd-machined.service")
    status, output, error = vm.execute("systemctl start aos-nspawn-platform-proof.service", timeout=100)
    if status != 0:
        print(vm.succeed("journalctl -u aos-nspawn-platform-proof.service -u aos-nspawn-proof-netns.service --no-pager"))
    assert status == 0, (status, output, error)
    vm.wait_until_succeeds(
        "test -s /var/lib/aos-nspawn-platform-proof/root/var/lib/aos-nspawn-proof/report.json",
        timeout=90,
    )

    report_path = "/var/lib/aos-nspawn-platform-proof/root/var/lib/aos-nspawn-proof/report.json"
    report = json.loads(vm.succeed(f"cat {report_path}"))
    assert report["schema"] == "aos.sandbox.nspawn-platform-proof/v1", report
    assert report["passed"] is True, report
    assert report["boot_generation"] == 1, report
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
    assert report["hostile_mount_absent"] is True, report
    assert report["uid_map"] == {"inside": 0, "outside": 655360, "length": 65536}, report

    version = vm.succeed("${pkgs.systemd}/bin/systemd-nspawn --version")
    assert version.splitlines()[0] == "systemd 259 (259.8)", version
    vm.fail("test -e /run/systemd/machines/aos-proof")

    pinned_inode = int(vm.succeed("stat -Lc %i /run/netns/aos-proof").strip())
    pinned_device = int(vm.succeed("stat -Lc %d /run/netns/aos-proof").strip())
    assert report["network_namespace_inode"] == pinned_inode, (report, pinned_inode)
    links = vm.succeed("${pkgs.iproute2}/sbin/ip netns exec aos-proof ${pkgs.iproute2}/sbin/ip -o link show")
    assert "lo:" in links, links
    assert "host0:" not in links, links
    vm.succeed("${pkgs.iproute2}/sbin/ip netns exec aos-proof ${pkgs.nftables}/sbin/nft list table inet aos_nspawn_proof")

    unit = vm.succeed("systemctl show aos-nspawn-platform-proof.service -p CollectMode -p Delegate -p DelegateSubgroup -p KillMode -p NetworkNamespacePath -p NotifyAccess -p OOMPolicy -p Restart -p Slice -p Type")
    assert "Delegate=yes" in unit, unit
    assert "DelegateSubgroup=supervisor" in unit, unit
    assert "KillMode=mixed" in unit, unit
    assert "NetworkNamespacePath=/run/netns/aos-proof" in unit, unit
    assert "NotifyAccess=main" in unit, unit
    assert "OOMPolicy=kill" in unit, unit
    assert "Restart=no" in unit, unit
    assert "Slice=aos-sandboxes.slice" in unit, unit
    assert "CollectMode=inactive-or-failed" in unit, unit
    assert "Type=notify" in unit, unit
    supervisor_pid = int(vm.succeed("systemctl show aos-nspawn-platform-proof.service -p MainPID --value").strip())
    assert supervisor_pid > 1
    invocation = vm.succeed(f"${pkgs.coreutils}/bin/tr '\\0' ' ' < /proc/{supervisor_pid}/cmdline")
    assert "--settings=no" in invocation, invocation
    assert "--register=no" in invocation, invocation
    assert "--machine=aos-proof" in invocation, invocation
    assert "--aos-payload-seccomp-profile=aos-sandbox-payload-v1" in invocation, invocation
    assert "--directory=/proc/" in invocation and "/fd/3" in invocation, invocation
    assert "--network-namespace-path" not in invocation, invocation
    pin_match = re.search(r"--directory=/proc/([0-9]+)/fd/3(?: |$)", invocation)
    assert pin_match is not None, invocation
    pin_holder = int(pin_match.group(1))
    assert vm.succeed(f"readlink /proc/{pin_holder}/fd/3").strip() == "/var/lib/aos-nspawn-platform-proof/root"
    assert vm.succeed(f"readlink /proc/{pin_holder}/fd/4").strip() == "${pkgs.systemd}/bin/systemd-nspawn"

    assert vm.succeed(f"readlink /proc/{supervisor_pid}/exe").strip() == "${pkgs.systemd}/bin/systemd-nspawn"
    control_group = vm.succeed("systemctl show aos-nspawn-platform-proof.service -p ControlGroup --value").strip()
    assert control_group == "/aos.slice/aos-sandboxes.slice/aos-nspawn-platform-proof.service", control_group
    vm.succeed(f"test -d /sys/fs/cgroup{control_group}/supervisor")
    vm.succeed(f"test -d /sys/fs/cgroup{control_group}/payload")

    vm.succeed("systemctl start aos-nspawn-host-observer.service")
    wait_for_observer_report()
    first_observation = json.loads(vm.succeed("cat /run/aos-nspawn-host-observer.json"))
    assert first_observation["state"] == "observing", first_observation
    assert first_observation["boot_generation"] == 1, first_observation
    assert first_observation["network_namespace"] == {"device": pinned_device, "inode": pinned_inode}, first_observation
    first_observer_pid = int(vm.succeed("systemctl show aos-nspawn-host-observer.service -p MainPID --value").strip())
    vm.succeed("rm /run/aos-nspawn-host-observer.json")
    vm.succeed("systemctl restart aos-nspawn-host-observer.service")
    wait_for_observer_report()
    restarted_observation = json.loads(vm.succeed("cat /run/aos-nspawn-host-observer.json"))
    assert restarted_observation == first_observation, (first_observation, restarted_observation)
    assert int(vm.succeed("systemctl show aos-nspawn-host-observer.service -p MainPID --value").strip()) != first_observer_pid
    assert int(vm.succeed("systemctl show aos-nspawn-platform-proof.service -p MainPID --value").strip()) == supervisor_pid

    vm.succeed("systemctl kill --kill-whom=main --signal=USR1 aos-nspawn-host-observer.service")
    try:
        vm.wait_until_succeeds(
            "test $(jq -r .state /run/aos-nspawn-host-observer.json) = rebooted",
            timeout=90,
        )
    except Exception:
        print(vm.execute("journalctl -u aos-nspawn-host-observer.service -u aos-nspawn-platform-proof.service --no-pager")[1].decode("utf-8", errors="replace"))
        print(vm.execute("systemd-cgls --no-pager /aos.slice/aos-sandboxes.slice/aos-nspawn-platform-proof.service")[1].decode("utf-8", errors="replace"))
        raise
    second_report = json.loads(vm.succeed(f"cat {report_path}"))
    assert second_report["passed"] is True, second_report
    assert second_report["network_namespace_inode"] == pinned_inode, second_report
    assert int(vm.succeed("systemctl show aos-nspawn-platform-proof.service -p MainPID --value").strip()) == supervisor_pid
    second_observation = json.loads(vm.succeed("cat /run/aos-nspawn-host-observer.json"))
    assert second_observation["state"] == "rebooted", second_observation
    assert second_observation["boot_generation"] == 2, second_observation
    assert second_observation["old_pid"] == first_observation["pid"], (first_observation, second_observation)
    assert second_observation["pid"] != first_observation["pid"], (first_observation, second_observation)
    assert second_observation["network_namespace"] == first_observation["network_namespace"]
    assert second_observation["mount_namespace"] != first_observation["mount_namespace"]
    assert second_observation["pid_namespace"] != first_observation["pid_namespace"]
    assert second_observation["user_namespace"] != first_observation["user_namespace"]
    assert second_observation["root"] == first_observation["root"]
    vm.succeed("systemctl is-active --quiet aos-nspawn-host-observer.service")
    vm.fail("systemctl is-active --quiet systemd-machined.service")
    status, output, error = vm.execute("systemctl is-enabled systemd-machined.service")
    assert status == 1 and output.strip() == b"masked-runtime", (status, output, error)
    vm.fail("test -e /run/systemd/machines/aos-proof")
  '';
}
