##! lib/testing/package-expose-lifecycle.nix — RFC-0001 live package expose check.
##!
##! Boots a full AOS system, seeds package-profile metadata, runs the package
##! manager's exposed-unit reconciler, then starts, inspects, reloads, and stops
##! the package targets under systemd.
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
  privateOutboundHttpRuleComment = "aos-pkg-expose-lifecycle-outbound-http-test";
  uidSharedPath = "/tmp/aos-expose-lifecycle-uid-shared";

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

  uidWriterCommand = pkgs.writeShellScriptBin "expose-lifecycle-uid-writer-command" ''
    set -eu
    state=/var/lib/aos-pkg-expose-lifecycle-uid-writer
    test -d ${uidSharedPath}
    ${pkgs.coreutils}/bin/id -u > "$state/uid"
    printf writer > ${uidSharedPath}/owned
    ${pkgs.coreutils}/bin/chmod 0600 ${uidSharedPath}/owned
    ${pkgs.coreutils}/bin/stat -c '%u:%a' ${uidSharedPath}/owned > "$state/owned_stat"
    printf ready > "$state/result"
    ${pkgs.coreutils}/bin/sleep infinity
  '';

  uidCheckerCommand = pkgs.writeShellScriptBin "expose-lifecycle-uid-checker-command" ''
    set -eu
    state=/var/lib/aos-pkg-expose-lifecycle-uid-checker
    test -d ${uidSharedPath}
    ${pkgs.coreutils}/bin/id -u > "$state/uid"
    if ${pkgs.bash}/bin/bash -c 'printf checker > "$1"' _ ${uidSharedPath}/owned 2> "$state/write_error"; then
      printf wrote > "$state/result"
      exit 1
    fi
    printf denied > "$state/result"
  '';

  socketServer = pkgs.writeTextFile {
    name = "expose-lifecycle-socket-server";
    destination = "/share/expose-lifecycle-socket/server.py";
    text = ''
      import os
      import pathlib
      import socket

      state = pathlib.Path("/var/lib/aos-pkg-expose-lifecycle-socket")
      state.mkdir(parents=True, exist_ok=True)
      state.joinpath("listen_fds").write_text(os.environ.get("LISTEN_FDS", ""))
      state.joinpath("listen_fdnames").write_text(os.environ.get("LISTEN_FDNAMES", ""))
      state.joinpath("netns").write_text(os.readlink("/proc/self/ns/net"))
      state.joinpath("userns").write_text(os.readlink("/proc/self/ns/user"))

      if not pathlib.Path("/share/expose-lifecycle-socket-consumer/payload.txt").is_file():
          raise SystemExit("missing socket consumer root payload")

      if os.environ.get("LISTEN_FDS") != "1":
          raise SystemExit("expected exactly one socket activation fd")

      listener = socket.socket(fileno=3)
      listener.settimeout(20)
      connection, _ = listener.accept()
      with connection:
          connection.recv(4096)
          body = b"socket-ok\n"
          connection.sendall(
              b"HTTP/1.1 200 OK\r\n"
              + b"Content-Type: text/plain\r\n"
              + b"Content-Length: "
              + str(len(body)).encode("ascii")
              + b"\r\nConnection: close\r\n\r\n"
              + body
          )
      state.joinpath("result").write_text("socket-ok")
    '';
  };

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

  socketProviderPackage = pkgs.mkDerivation {
    pname = "expose-lifecycle-socket-provider";
    version = "0";
    src = null;

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/expose-lifecycle-socket-provider"
          printf socket-provider-payload > "$out/share/expose-lifecycle-socket-provider/payload.txt"
        '';
      }
    ];

    expose = {
      units."expose-lifecycle-provider.socket" = {
        description = "RFC-0001 live inbound-private package socket";
        socketConfig = {
          ListenStream = "127.0.0.1:18080";
        };
      };
      permissions = {
        network = "private";
        tcp-bind = [18080];
        capabilities = [];
        devices = [];
        host-paths = [];
        syscalls = "restricted";
      };
      provides = [
        {
          name = "api";
          kind = "socket";
          unit = "expose-lifecycle-provider.socket";
        }
      ];
      requires = [];
    };
  };

  socketConsumerPackage = pkgs.mkDerivation {
    pname = "expose-lifecycle-socket-consumer";
    version = "0";
    src = null;

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/expose-lifecycle-socket-consumer"
          printf socket-consumer-payload > "$out/share/expose-lifecycle-socket-consumer/payload.txt"
        '';
      }
    ];

    expose = {
      units = {
        "expose-lifecycle-consumer.service" = {
          description = "RFC-0001 live inbound-private package socket workload";
          serviceConfig = {
            Type = "simple";
            ExecStart = "${pkgs.python3}/bin/python3 ${socketServer}/share/expose-lifecycle-socket/server.py";
            StateDirectory = "aos-pkg-expose-lifecycle-socket";
          };
        };
      };
      permissions = {
        network = "private";
        capabilities = [];
        devices = [];
        host-paths = [];
        syscalls = "restricted";
      };
      uses = [
        {
          provider = "expose-lifecycle-socket-provider";
          name = "api";
          kind = "socket";
          unit = "expose-lifecycle-consumer.service";
        }
      ];
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

  uidWriterPackage = pkgs.mkDerivation {
    pname = "expose-lifecycle-uid-writer";
    version = "0";
    src = null;

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/expose-lifecycle-uid-writer"
          printf uid-writer-payload > "$out/share/expose-lifecycle-uid-writer/payload.txt"
        '';
      }
    ];

    expose = {
      units."expose-lifecycle-uid-writer.service" = {
        description = "RFC-0001 live package UID identity writer";
        wantedBy = ["multi-user.target"];
        serviceConfig = {
          Type = "simple";
          ExecStart = "${uidWriterCommand}/bin/expose-lifecycle-uid-writer-command";
          StateDirectory = "aos-pkg-expose-lifecycle-uid-writer";
        };
      };
      permissions = {
        network = "private";
        capabilities = [];
        devices = [];
        host-paths = [
          {
            path = uidSharedPath;
            mode = "rw";
          }
        ];
        syscalls = "restricted";
      };
      requires = [];
    };
  };

  uidCheckerPackage = pkgs.mkDerivation {
    pname = "expose-lifecycle-uid-checker";
    version = "0";
    src = null;

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/expose-lifecycle-uid-checker"
          printf uid-checker-payload > "$out/share/expose-lifecycle-uid-checker/payload.txt"
        '';
      }
    ];

    expose = {
      units."expose-lifecycle-uid-checker.service" = {
        description = "RFC-0001 live package UID identity checker";
        wantedBy = ["multi-user.target"];
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${uidCheckerCommand}/bin/expose-lifecycle-uid-checker-command";
          StateDirectory = "aos-pkg-expose-lifecycle-uid-checker";
        };
      };
      permissions = {
        network = "private";
        capabilities = [];
        devices = [];
        host-paths = [
          {
            path = uidSharedPath;
            mode = "rw";
          }
        ];
        syscalls = "restricted";
      };
      requires = [];
    };
  };

  seedPackageProfile = pkgs.writeShellScriptBin "seed-expose-lifecycle-profile" ''
    set -eu
    profile=/var/lib/profiles/system-packages
    mkdir -p "$profile/gen-1" "$profile/meta"
    ln -sfn gen-1 "$profile/current"

    ${pkgs.python3}/bin/python3 - "$profile" \
      expose-lifecycle-private ${privatePackage} ${privatePackage.expose} \
      expose-lifecycle-socket-provider ${socketProviderPackage} ${socketProviderPackage.expose} \
      expose-lifecycle-socket-consumer ${socketConsumerPackage} ${socketConsumerPackage.expose} \
      expose-lifecycle-outbound ${privateOutboundPackage} ${privateOutboundPackage.expose} \
      expose-lifecycle-uid-writer ${uidWriterPackage} ${uidWriterPackage.expose} \
      expose-lifecycle-uid-checker ${uidCheckerPackage} ${uidCheckerPackage.expose} <<'PY'
    import json
    import pathlib
    import sys

    profile = pathlib.Path(sys.argv[1])
    triples = sys.argv[2:]
    for offset in range(0, len(triples), 3):
        name, store_path, expose_path = triples[offset : offset + 3]
        store_hash, separator, _ = pathlib.Path(store_path).name.partition("-")
        if not separator or not store_hash:
            raise SystemExit(f"cannot derive store hash from {store_path}")
        manifest = json.loads(pathlib.Path(expose_path, "manifest.json").read_text())
        meta = {
            "store_path": store_path,
            "pushed_at": 1,
            "pushed_by": "apm",
            "expires_at": None,
            "is_root": True,
            "last_accessed": 1,
            "access_count": 0,
            "apm": {
                "name": name,
                "version": "0",
                "explicit": True,
                "registry": "test",
                "installed_at": "2026-06-16T00:00:00Z",
                "held": False,
                "source_drv": "",
                "source_nar_hash": "",
                "expose": manifest["expose"],
                "expose_artifact": {
                    "store_path": expose_path,
                    "nar_hash": "sha256:test",
                    "nar_size": 1,
                },
                "permissions": manifest["permissions"],
            },
        }
        pathlib.Path(profile, "meta", f"{store_hash}.json").write_text(
            json.dumps(meta, sort_keys=True)
        )
    PY
  '';

  testSystem = mkSystem {
    modules = [
      ../../systems/server.nix
      ({pkgs, ...}: {
        environment.systemPackages = [
          privatePackage
          privatePackage.expose
          socketProviderPackage
          socketProviderPackage.expose
          socketConsumerPackage
          socketConsumerPackage.expose
          privateOutboundPackage
          privateOutboundPackage.expose
          uidWriterPackage
          uidWriterPackage.expose
          uidCheckerPackage
          uidCheckerPackage.expose
          seedPackageProfile
          pkgs.aos
          pkgs.curl
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
      vm.succeed("${seedPackageProfile}/bin/seed-expose-lifecycle-profile")
      vm.succeed("${pkgs.aos}/bin/apm _test-reconcile-exposed-units --system")
      vm.succeed("systemctl cat expose-lifecycle-private.service | grep -F '# /etc/systemd/system.attached/expose-lifecycle-private.service'")
      vm.succeed("systemctl cat expose-lifecycle-consumer.service | grep -F '# /etc/systemd/system.attached/expose-lifecycle-consumer.service'")
      vm.succeed("systemctl cat expose-lifecycle-provider.socket | grep -F '# /etc/systemd/system.attached/expose-lifecycle-provider.socket'")
      vm.succeed("systemctl cat expose-lifecycle-provider.socket | grep -F '# /etc/systemd/system.attached/expose-lifecycle-provider.socket.d/50-aos-capability-routes.conf'")
      vm.succeed("systemctl cat aos-pkg-expose-lifecycle-socket-consumer.target | grep -F '# /etc/systemd/system.attached/aos-pkg-expose-lifecycle-socket-consumer.target.d/50-aos-capability-routes.conf'")
      vm.succeed("systemctl cat expose-lifecycle-outbound.service | grep -F '# /etc/systemd/system.attached/expose-lifecycle-outbound.service'")
      vm.succeed("systemctl cat expose-lifecycle-uid-writer.service | grep -F '# /etc/systemd/system.attached/expose-lifecycle-uid-writer.service'")
      vm.succeed("systemctl cat expose-lifecycle-uid-checker.service | grep -F '# /etc/systemd/system.attached/expose-lifecycle-uid-checker.service'")
      vm.succeed("grep -q '^PrivateUsers=identity$' /etc/systemd/system.attached/expose-lifecycle-private.service")
      vm.succeed("grep -q '^PrivateUsers=identity$' /etc/systemd/system.attached/expose-lifecycle-consumer.service")
      vm.succeed("grep -q '^PrivateNetwork=true$' /etc/systemd/system.attached/expose-lifecycle-consumer.service")
      vm.succeed("grep -q '^Wants=.*expose-lifecycle-provider.socket' /etc/systemd/system.attached/aos-pkg-expose-lifecycle-socket-consumer.target.d/50-aos-capability-routes.conf")
      vm.succeed("if grep -q '^Wants=.*expose-lifecycle-consumer.service' /etc/systemd/system.attached/aos-pkg-expose-lifecycle-socket-consumer.target; then exit 1; fi")
      vm.succeed("grep -q '^Service=expose-lifecycle-consumer.service$' /etc/systemd/system.attached/expose-lifecycle-provider.socket.d/50-aos-capability-routes.conf")
      vm.succeed("grep -q '^FileDescriptorName=aos-expose-lifecycle-socket-provider-api$' /etc/systemd/system.attached/expose-lifecycle-provider.socket.d/50-aos-capability-routes.conf")
      vm.succeed("if grep -R -q '^PrivateNetwork=' /etc/systemd/system.attached/expose-lifecycle-provider.socket /etc/systemd/system.attached/expose-lifecycle-provider.socket.d; then exit 1; fi")
      vm.succeed("if grep -R -q '^NetworkNamespacePath=' /etc/systemd/system.attached/expose-lifecycle-provider.socket /etc/systemd/system.attached/expose-lifecycle-provider.socket.d; then exit 1; fi")
      vm.succeed("if grep -R -q '^JoinsNamespaceOf=' /etc/systemd/system.attached/expose-lifecycle-provider.socket /etc/systemd/system.attached/expose-lifecycle-provider.socket.d; then exit 1; fi")
      vm.succeed("grep -q '^PrivateUsers=identity$' /etc/systemd/system.attached/expose-lifecycle-outbound.service")
      vm.succeed("grep -q '^PrivateUsers=identity$' /etc/systemd/system.attached/expose-lifecycle-uid-writer.service")
      vm.succeed("grep -q '^PrivateUsers=identity$' /etc/systemd/system.attached/expose-lifecycle-uid-checker.service")

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

      vm.succeed("rm -rf ${uidSharedPath}")
      vm.succeed("mkdir -m 1777 ${uidSharedPath}")
      vm.succeed("systemctl start aos-pkg-expose-lifecycle-uid-writer.target")
      vm.wait_until_succeeds(
          "test \"$(cat /var/lib/aos-pkg-expose-lifecycle-uid-writer/result)\" = ready",
          timeout=30,
      )
      vm.succeed("systemctl start aos-pkg-expose-lifecycle-uid-checker.target")
      assert "denied" in vm.succeed(
          "cat /var/lib/aos-pkg-expose-lifecycle-uid-checker/result"
      )
      writer_uid = vm.succeed(
          "cat /var/lib/aos-pkg-expose-lifecycle-uid-writer/uid"
      ).strip()
      checker_uid = vm.succeed(
          "cat /var/lib/aos-pkg-expose-lifecycle-uid-checker/uid"
      ).strip()
      assert writer_uid != checker_uid
      assert vm.succeed(
          "cat /var/lib/aos-pkg-expose-lifecycle-uid-writer/owned_stat"
      ).strip() == f"{writer_uid}:600"
      vm.succeed("test \"$(cat ${uidSharedPath}/owned)\" = writer")
      vm.succeed("systemctl stop aos-pkg-expose-lifecycle-uid-writer.target aos-pkg-expose-lifecycle-uid-checker.target")

      vm.succeed("systemctl stop aos-pkg-expose-lifecycle-socket-provider.target aos-pkg-expose-lifecycle-socket-consumer.target expose-lifecycle-provider.socket")
      vm.succeed("systemctl reset-failed expose-lifecycle-consumer.service")
      vm.succeed("systemctl start aos-pkg-expose-lifecycle-socket-consumer.target")
      vm.succeed("systemctl is-active expose-lifecycle-provider.socket")
      vm.succeed("test \"$(systemctl is-active expose-lifecycle-consumer.service || true)\" = inactive")
      assert "socket-ok" in vm.succeed(
          "curl -sf --max-time 20 http://127.0.0.1:18080/"
      )
      vm.wait_until_succeeds(
          "test \"$(cat /var/lib/aos-pkg-expose-lifecycle-socket/result)\" = socket-ok",
          timeout=30,
      )
      assert "aos-expose-lifecycle-socket-provider-api" in vm.succeed(
          "cat /var/lib/aos-pkg-expose-lifecycle-socket/listen_fdnames"
      )
      assert vm.succeed(
          "cat /var/lib/aos-pkg-expose-lifecycle-socket/netns"
      ).strip() != host_netns
      assert vm.succeed(
          "cat /var/lib/aos-pkg-expose-lifecycle-socket/userns"
      ).strip() != host_userns
      assert "${socketConsumerPackage}" in vm.succeed(
          "systemctl show -p RootDirectory --value expose-lifecycle-consumer.service"
      )
      assert "yes" in vm.succeed(
          "systemctl show -p PrivateNetwork --value expose-lifecycle-consumer.service"
      )
      vm.succeed("systemctl stop aos-pkg-expose-lifecycle-socket-consumer.target expose-lifecycle-provider.socket aos-pkg-expose-lifecycle-socket-provider.target")

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
      vm.succeed("mkdir -p /tmp/expose-lifecycle-outbound-http")
      vm.succeed("printf outbound-via-netns > /tmp/expose-lifecycle-outbound-http/index.html")
      vm.succeed("nft insert rule inet filter input iifname \"${privateOutboundHostIf}\" tcp dport 18081 accept comment \"${privateOutboundHttpRuleComment}\"")
      vm.succeed("host_addr=$(ip -4 -o addr show dev ${privateOutboundHostIf} | sed -n 's|.*inet \\([0-9.]*\\)/.*|\\1|p'); test -n \"$host_addr\"; cd /tmp/expose-lifecycle-outbound-http; ${pkgs.python3}/bin/python3 -m http.server 18081 --bind \"$host_addr\" >/tmp/expose-lifecycle-outbound-http/server.log 2>&1 & echo $! >/tmp/expose-lifecycle-outbound-http/server.pid")
      vm.wait_until_succeeds(
          "host_addr=$(ip -4 -o addr show dev ${privateOutboundHostIf} | sed -n 's|.*inet \\([0-9.]*\\)/.*|\\1|p'); curl -sf --max-time 2 \"http://$host_addr:18081/\" | grep -q outbound-via-netns",
          timeout=30,
      )
      vm.succeed("host_addr=$(ip -4 -o addr show dev ${privateOutboundHostIf} | sed -n 's|.*inet \\([0-9.]*\\)/.*|\\1|p'); ip netns exec aos-pkg-expose-lifecycle-outbound curl -sf --max-time 5 \"http://$host_addr:18081/\" | grep -q outbound-via-netns")
      vm.succeed("kill \"$(cat /tmp/expose-lifecycle-outbound-http/server.pid)\"")
      vm.succeed("handle=$(nft -a list chain inet filter input | sed -n 's|.*comment \"${privateOutboundHttpRuleComment}\".*# handle \\([0-9][0-9]*\\).*|\\1|p' | head -n1); test -n \"$handle\"; nft delete rule inet filter input handle \"$handle\"")
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
