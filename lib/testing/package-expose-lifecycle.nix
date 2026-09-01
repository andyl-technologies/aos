##! lib/testing/package-expose-lifecycle.nix — RFC-0001 live package expose check.
##!
##! Boots a full AOS system, seeds package-profile metadata, runs the package
##! manager's exposed-unit reconciler, then starts, inspects, reloads, and stops
##! the package targets under systemd.
{
  pkgs,
  lib,
  mkSystem,
  testing,
}: let
  storePathHash = path:
    builtins.elemAt (lib.splitString "-" (baseNameOf (builtins.toString path))) 0;
  mkPackageRootImage = import ../build/package-root-image.nix {inherit pkgs lib;};

  privateOutboundNetnsHash = builtins.substring 0 8 (
    builtins.hashString "sha256" "expose-lifecycle-outbound"
  );
  privateOutboundHostIf = "aos${privateOutboundNetnsHash}h";
  privateOutboundPeerIf = "aos${privateOutboundNetnsHash}p";
  privateOutboundNatTable = "aos_pkg_${privateOutboundNetnsHash}";
  privateOutboundHttpRuleComment = "aos-pkg-expose-lifecycle-outbound-http-test";
  uidSharedPath = "/tmp/aos-expose-lifecycle-uid-shared";
  fakeVerityRootHash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

  privatePackageCommand = pkgs.writeShellScriptBin "expose-lifecycle-private-command" ''
    state=/var/lib/aos-pkg-expose-lifecycle-private
    test -r /share/expose-lifecycle-private/payload.txt
    ${pkgs.coreutils}/bin/readlink /proc/self/ns/net > "$state/netns"
    ${pkgs.coreutils}/bin/readlink /proc/self/ns/user > "$state/userns"
    printf private-ok > "$state/result"
  '';

  upgradePackageCommand = pkgs.writeShellScriptBin "expose-lifecycle-upgrade-command" ''
    state=/var/lib/aos-pkg-expose-lifecycle-upgrade
    ${pkgs.coreutils}/bin/cat /share/expose-lifecycle-upgrade/payload.txt > "$state/result"
  '';

  mkUpgradePackage = version: payload:
    pkgs.mkDerivation {
      pname = "expose-lifecycle-upgrade";
      inherit version;
      src = null;
      phases = [
        {
          name = "install";
          script = ''
            mkdir -p "$out/share/expose-lifecycle-upgrade"
            printf '${payload}' > "$out/share/expose-lifecycle-upgrade/payload.txt"
          '';
        }
      ];
      expose = {
        units."expose-lifecycle-upgrade.service" = {
          wantedBy = ["multi-user.target"];
          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = true;
            ExecStart = "${upgradePackageCommand}/bin/expose-lifecycle-upgrade-command";
          };
        };
        permissions = {
          network = "private";
          capabilities = [];
          devices = [];
          host-paths = [];
          syscalls = "restricted";
        };
      };
    };
  upgradePackageV1 = mkUpgradePackage "1" "upgrade-v1";
  upgradePackageV2 = mkUpgradePackage "2" "upgrade-v2";

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

  verityCommand = pkgs.writeShellScriptBin "expose-lifecycle-verity-command" ''
    state=/var/lib/aos-pkg-expose-lifecycle-verity
    test -r /share/expose-lifecycle-verity/payload.txt
    printf verity-ok > "$state/result"
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
    };
  };

  verityRoot = pkgs.mkDerivation {
    pname = "expose-lifecycle-verity-root";
    version = "0";
    src = null;

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin" "$out/share/expose-lifecycle-verity"
          ln -s ${verityCommand}/bin/expose-lifecycle-verity-command "$out/bin/expose-lifecycle-verity-command"
          printf verity-payload > "$out/share/expose-lifecycle-verity/payload.txt"
        '';
      }
    ];
  };

  verityImage = mkPackageRootImage {
    pname = "expose-lifecycle-verity-image";
    root = verityRoot;
    minSizeMiB = 16;
    headroomMiB = 2;
    rootHashKey = "${pkgs.secure-boot-test-keys}/db.key";
    rootHashCert = "${pkgs.secure-boot-test-keys}/db.crt";
  };
  verityImageHash = storePathHash verityImage;

  verityRenderedPackage = pkgs.mkDerivation {
    pname = "expose-lifecycle-verity";
    version = "0";
    src = null;

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/expose-lifecycle-verity-render"
          printf verity-render > "$out/share/expose-lifecycle-verity-render/payload.txt"
        '';
      }
    ];

    expose = {
      units."expose-lifecycle-verity.service" = {
        description = "RFC-0001 live verity RootImage package workload";
        onlyManualStart = true;
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "/bin/expose-lifecycle-verity-command";
          StateDirectory = "aos-pkg-expose-lifecycle-verity";
        };
      };
      images = [
        {
          format = "ext4-verity";
          store_path = "${verityImage}";
          nar_hash = "sha256:test";
          nar_size = 1;
          root_image = "root.img";
          root_verity = "root.verity";
          root_hash = "sha256:${fakeVerityRootHash}";
          root_hash_sig = "root.roothash.p7s";
        }
      ];
      permissions = {
        network = "private";
        capabilities = [];
        devices = [];
        host-paths = [];
        syscalls = "restricted";
      };
    };
  };

  verityExpose =
    pkgs.runCommand "expose-lifecycle-verity-expose" {
      buildDeps = [
        pkgs.coreutils
        pkgs.findutils
        pkgs.grep
        pkgs.sed
      ];
    } ''
      set -eu
      cp -a ${verityRenderedPackage.expose}/. "$out/"
      chmod -R u+w "$out"

      root_hash=$(cat ${verityImage}/root.roothash)
      for path in \
        "$out/manifest.json" \
        "$out/network-policy.json" \
        "$out/mac-profile.json" \
        "$out"/units/*.service \
        "$out"/mac/selinux/*.te; do
        [ -e "$path" ] || continue
        sed -i \
          -e "s|${verityRenderedPackage.expose}|$out|g" \
          -e "s|${fakeVerityRootHash}|$root_hash|g" \
          "$path"
      done

      grep -Eq "\"root_hash\"[[:space:]]*:[[:space:]]*\"sha256:$root_hash\"" "$out/manifest.json"
      grep -q "^RootHash=$root_hash$" "$out/units/expose-lifecycle-verity.service"
    '';

  seedPackageProfile = pkgs.writeShellScriptBin "seed-expose-lifecycle-profile" ''
    set -eu
    profile=/var/lib/profiles/system-packages
    mkdir -p "$profile/gen-1/usr" "$profile/gen-1/src" "$profile/meta"
    ln -sfn gen-1 "$profile/current"
    cat > "$profile/state.json" <<'JSON'
    {"current_generation":1,"next_generation":2}
    JSON

    ${pkgs.python3}/bin/python3 - "$profile" \
      expose-lifecycle-private ${privatePackage} ${privatePackage.expose} \
      expose-lifecycle-upgrade ${upgradePackageV1} ${upgradePackageV1.expose} \
      expose-lifecycle-socket-provider ${socketProviderPackage} ${socketProviderPackage.expose} \
      expose-lifecycle-socket-consumer ${socketConsumerPackage} ${socketConsumerPackage.expose} \
      expose-lifecycle-outbound ${privateOutboundPackage} ${privateOutboundPackage.expose} \
      expose-lifecycle-uid-writer ${uidWriterPackage} ${uidWriterPackage.expose} \
      expose-lifecycle-uid-checker ${uidCheckerPackage} ${uidCheckerPackage.expose} \
      expose-lifecycle-verity ${verityRoot} ${verityExpose} <<'PY'
    import json
    import pathlib
    import sys

    profile = pathlib.Path(sys.argv[1])
    usr_dir = profile / "gen-1" / "usr"
    meta_dir = profile / "meta"
    triples = sys.argv[2:]

    def store_hash_for(store_path):
        store_hash, separator, _ = pathlib.Path(store_path).name.partition("-")
        if not separator or not store_hash:
            raise SystemExit(f"cannot derive store hash from {store_path}")
        return store_hash

    def write_rooted_meta(store_path, meta):
        store_hash = store_hash_for(store_path)
        root = usr_dir / store_hash
        if root.exists() or root.is_symlink():
            root.unlink()
        root.symlink_to(store_path)
        pathlib.Path(meta_dir, f"{store_hash}.json").write_text(
            json.dumps(meta, sort_keys=True)
        )

    for offset in range(0, len(triples), 3):
        name, store_path, expose_path = triples[offset : offset + 3]
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
        write_rooted_meta(store_path, meta)
        if name == "expose-lifecycle-upgrade":
            pathlib.Path(profile, "upgrade-v1.json").write_text(
                json.dumps(meta, sort_keys=True)
            )

    # The candidate upgrade is authenticated metadata but is not selected by
    # generation 1. The VM swaps the same package name's rooted payload to
    # exercise direct attached-unit reconciliation in both directions.
    upgrade_v2_path = "${upgradePackageV2}"
    upgrade_v2_expose = "${upgradePackageV2.expose}"
    upgrade_v2_manifest = json.loads(pathlib.Path(upgrade_v2_expose, "manifest.json").read_text())
    pathlib.Path(profile, "upgrade-v2.json").write_text(json.dumps({
        "store_path": upgrade_v2_path,
        "pushed_at": 2,
        "pushed_by": "apm",
        "expires_at": None,
        "is_root": True,
        "last_accessed": 2,
        "access_count": 0,
        "apm": {
            "name": "expose-lifecycle-upgrade",
            "version": "2",
            "explicit": True,
            "registry": "test",
            "installed_at": "2026-06-16T00:00:01Z",
            "held": False,
            "source_drv": "",
            "source_nar_hash": "",
            "expose": upgrade_v2_manifest["expose"],
            "expose_artifact": {
                "store_path": upgrade_v2_expose,
                "nar_hash": "sha256:test",
                "nar_size": 1,
            },
            "permissions": upgrade_v2_manifest["permissions"],
        },
    }, sort_keys=True))

    bpf_policy_package = "${pkgs.aos-ebpf-lsm-policy}"
    write_rooted_meta(
        bpf_policy_package,
        {
            "store_path": bpf_policy_package,
            "pushed_at": 1,
            "pushed_by": "apm",
            "expires_at": None,
            "is_root": True,
            "last_accessed": 1,
            "access_count": 0,
            "apm": {
                "name": "aos-ebpf-lsm-policy",
                "version": "0",
                "explicit": True,
                "registry": "seed",
                "installed_at": "1970-01-01T00:00:00Z",
                "held": False,
                "source_drv": "",
                "source_nar_hash": "",
                "permissions": {},
                "bpf_lsm": {
                    "policies": [
                        {
                            "name": "aos-lsm-task-audit",
                            "policy": "share/aos/ebpf-lsm/aos-task-audit.json",
                            "object": "lib/bpf/aos-ebpf-lsm-task-audit.bpf.o",
                            "programs": ["aos_lsm_file_mprotect"],
                        }
                    ]
                },
            },
        },
    )
    PY
  '';

  testSystem = mkSystem {
    modules = [
      ../../systems/server.nix
      ({pkgs, ...}: {
        # mkVMTest's mutable fixture disk boots /dev/vda2 directly rather than
        # carrying the signed root hash and separate hash partition required by
        # the production server image's dm-verity contract.
        aos.security.verity.enable = false;

        environment.systemPackages = [
          privatePackage
          privatePackage.expose
          upgradePackageV1
          upgradePackageV1.expose
          upgradePackageV2
          upgradePackageV2.expose
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
          verityRoot
          verityImage
          verityExpose
          seedPackageProfile
          pkgs.aos
          pkgs.aos-ebpf-lsm-policy
          pkgs.aos-ebpf-net-policy
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
      import textwrap

      host_netns = vm.succeed("readlink /proc/1/ns/net").strip()
      host_userns = vm.succeed("readlink /proc/1/ns/user").strip()
      initial_ip_forward = vm.succeed("cat /proc/sys/net/ipv4/ip_forward").strip()

      vm.succeed("systemctl is-active nftables.service")
      vm.succeed("mkdir -p /sys/fs/cgroup/aos-ebpf-probe")
      vm.succeed(
          textwrap.dedent(
              """\
              cat >/tmp/aos-ebpf-probe-policy.json <<'JSON'
              {
                "version": 1,
                "package": "aos-ebpf-probe",
                "mode": "host",
                "securityLabel": "aos-pkg-aos-ebpf-probe",
                "tcp": {
                  "bind": [19080, 19081],
                  "connect": [19081]
                },
                "landlock": {
                  "abi": 4,
                  "tcp": {
                    "bind": [19080, 19081],
                    "connect": [19081]
                  }
                },
                "ebpf": {
                  "identity": "aos-pkg-aos-ebpf-probe",
                  "hooks": ["socket_bind", "socket_connect"],
                  "tcp": {
                    "bind": [19080, 19081],
                    "connect": [19081]
                  }
                }
              }
              JSON"""
          )
      )
      vm.succeed("${pkgs.aos-ebpf-net-policy}/bin/aos-ebpf-net-policy run --policy /tmp/aos-ebpf-probe-policy.json --cgroup /sys/fs/cgroup/aos-ebpf-probe --object ${pkgs.aos-ebpf-net-policy}/lib/bpf/aos-ebpf-net-policy.bpf.o >/tmp/aos-ebpf-probe.log 2>&1 & echo $! >/tmp/aos-ebpf-probe.pid")
      vm.wait_until_succeeds(
          "grep -q 'attached policy' /tmp/aos-ebpf-probe.log",
          timeout=30,
      )
      vm.succeed(
          textwrap.dedent(
              """\
              cat >/tmp/aos-ebpf-probe.py <<'PY'
              import errno
              import pathlib
              import socket
              import threading

              state = pathlib.Path("/tmp")
              denied = []

              def listener(port):
                  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                  sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                  sock.bind(("127.0.0.1", port))
                  return sock

              def expect_denied(name, action):
                  try:
                      action()
                  except OSError as err:
                      if err.errno in (errno.EACCES, errno.EPERM):
                          denied.append(f"{name}:{err.errno}")
                          return
                      raise
                  raise SystemExit(f"{name} unexpectedly succeeded")

              allowed_bind = listener(19080)
              allowed_bind.close()
              expect_denied("bind", lambda: listener(19082).close())

              server = listener(19081)
              server.listen(1)

              def accept_once():
                  conn, _ = server.accept()
                  with conn:
                      conn.recv(1)
                      conn.sendall(b"x")

              thread = threading.Thread(target=accept_once)
              thread.start()
              client = socket.create_connection(("127.0.0.1", 19081), timeout=5)
              with client:
                  client.sendall(b"?")
                  if client.recv(1) != b"x":
                      raise SystemExit("allowed connect returned unexpected data")
              thread.join(timeout=5)
              if thread.is_alive():
                  raise SystemExit("allowed connect listener did not finish")
              server.close()

              def denied_connect():
                  conn = socket.create_connection(("127.0.0.1", 19082), timeout=1)
                  conn.close()

              expect_denied("connect", denied_connect)
              state.joinpath("aos-ebpf-probe-denied").write_text("\\n".join(denied))
              state.joinpath("aos-ebpf-probe-result").write_text("ebpf-ok")
              PY"""
          )
      )
      vm.succeed("${pkgs.bash}/bin/bash -c 'echo $$ > /sys/fs/cgroup/aos-ebpf-probe/cgroup.procs; exec ${pkgs.python3}/bin/python3 /tmp/aos-ebpf-probe.py'")
      assert "ebpf-ok" in vm.succeed("cat /tmp/aos-ebpf-probe-result")
      assert "bind:" in vm.succeed("cat /tmp/aos-ebpf-probe-denied")
      assert "connect:" in vm.succeed("cat /tmp/aos-ebpf-probe-denied")
      vm.succeed("kill \"$(cat /tmp/aos-ebpf-probe.pid)\"")
      vm.wait_until_succeeds(
          "test \"$(cat /sys/fs/cgroup/aos-ebpf-probe/cgroup.procs)\" = \"\"",
          timeout=30,
      )
      vm.succeed("rmdir /sys/fs/cgroup/aos-ebpf-probe")

      vm.succeed("${seedPackageProfile}/bin/seed-expose-lifecycle-profile")
      vm.succeed(
          textwrap.dedent(
              """\
              mkdir -p /etc/aos
              cat >/etc/aos/policy.toml <<'TOML'
              tier = "baseline"

              [[ebpf-lsm.policies]]
              name = "aos-lsm-task-audit"
              registry = "seed"
              package = "aos-ebpf-lsm-policy"
              version = "0"
              policy = "share/aos/ebpf-lsm/aos-task-audit.json"
              object = "lib/bpf/aos-ebpf-lsm-task-audit.bpf.o"
              programs = ["aos_lsm_file_mprotect"]
              TOML
              """
          )
      )
      vm.succeed("grep -qw bpf /sys/kernel/security/lsm || { cat /sys/kernel/security/lsm || true; cat /proc/cmdline || true; exit 1; }")
      vm.succeed("test ! -e /sys/fs/bpf/aos/lsm/aos-lsm-task-audit-aos_lsm_file_mprotect")
      vm.succeed("${pkgs.aos}/bin/apm _load-ebpf-lsm-policies --system >/tmp/aos-ebpf-lsm-load.log 2>&1 || { cat /sys/kernel/security/lsm || true; cat /proc/cmdline || true; cat /tmp/aos-ebpf-lsm-load.log; exit 1; }")
      vm.succeed("grep -q 'loaded policy aos-lsm-task-audit' /tmp/aos-ebpf-lsm-load.log")
      vm.succeed("test -e /sys/fs/bpf/aos/lsm/aos-lsm-task-audit-aos_lsm_file_mprotect")
      vm.succeed("${pkgs.aos}/bin/apm _load-ebpf-lsm-policies --system >/tmp/aos-ebpf-lsm-load-again.log 2>&1")
      vm.succeed("grep -q 'already pinned' /tmp/aos-ebpf-lsm-load-again.log")

      vm.succeed("${pkgs.aos}/bin/apm _test-reconcile-exposed-units --system")
      vm.succeed("systemctl cat expose-lifecycle-private.service | grep -F '# /etc/systemd/system.attached/expose-lifecycle-private.service'")
      vm.succeed("systemctl cat expose-lifecycle-consumer.service | grep -F '# /etc/systemd/system.attached/expose-lifecycle-consumer.service'")
      vm.succeed("systemctl cat expose-lifecycle-provider.socket | grep -F '# /etc/systemd/system.attached/expose-lifecycle-provider.socket'")
      vm.succeed("systemctl cat expose-lifecycle-provider.socket | grep -F '# /etc/systemd/system.attached/expose-lifecycle-provider.socket.d/50-aos-capability-routes.conf'")
      vm.succeed("systemctl cat aos-pkg-expose-lifecycle-socket-consumer.target | grep -F '# /etc/systemd/system.attached/aos-pkg-expose-lifecycle-socket-consumer.target.d/50-aos-capability-routes.conf'")
      vm.succeed("systemctl cat expose-lifecycle-outbound.service | grep -F '# /etc/systemd/system.attached/expose-lifecycle-outbound.service'")
      vm.succeed("systemctl cat expose-lifecycle-uid-writer.service | grep -F '# /etc/systemd/system.attached/expose-lifecycle-uid-writer.service'")
      vm.succeed("systemctl cat expose-lifecycle-uid-checker.service | grep -F '# /etc/systemd/system.attached/expose-lifecycle-uid-checker.service'")
      vm.succeed("systemctl cat expose-lifecycle-verity.service | grep -F '# /etc/systemd/system.attached/expose-lifecycle-verity.service'")
      vm.succeed("test -L /var/lib/profiles/system-packages/current/expose-images/${verityImageHash}")
      assert "${verityImage}" == vm.succeed(
          "readlink /var/lib/profiles/system-packages/current/expose-images/${verityImageHash}"
      ).strip()
      vm.succeed("grep -q '^RootImage=${verityImage}/root.img$' /etc/systemd/system.attached/expose-lifecycle-verity.service")
      vm.succeed("grep -q '^RootVerity=${verityImage}/root.verity$' /etc/systemd/system.attached/expose-lifecycle-verity.service")
      vm.succeed("grep -q '^RootHashSignature=${verityImage}/root.roothash.p7s$' /etc/systemd/system.attached/expose-lifecycle-verity.service")
      vm.succeed("root_hash=$(cat ${verityImage}/root.roothash); grep -q \"^RootHash=$root_hash$\" /etc/systemd/system.attached/expose-lifecycle-verity.service")
      # Direct-kernel VM tests do not enroll the signing certificate into the
      # platform keyring; Secure Boot image tests cover RootImage runtime start.
      vm.succeed("test \"$(systemctl is-active expose-lifecycle-verity.service || true)\" = inactive")
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
      assert vm.succeed(
          "systemctl show -p RootDirectory --value expose-lifecycle-private.service"
      ).strip() == "/run/aos/service-roots/expose-lifecycle-private/expose-lifecycle-private.service/merged"
      assert "yes" in vm.succeed(
          "systemctl show -p PrivateNetwork --value expose-lifecycle-private.service"
      )
      assert "yes" in vm.succeed(
          "systemctl show -p DynamicUser --value expose-lifecycle-private.service"
      )
      vm.succeed("systemctl stop aos-pkg-expose-lifecycle-private.target")

      upgrade_root = "/run/aos/service-roots/expose-lifecycle-upgrade/expose-lifecycle-upgrade.service/merged"
      vm.succeed("systemctl start aos-pkg-expose-lifecycle-upgrade.target")
      assert "upgrade-v1" == vm.succeed(
          "cat /var/lib/aos-pkg-expose-lifecycle-upgrade/result"
      ).strip()
      vm.succeed("findmnt -n -o FS-OPTIONS " + upgrade_root + " | grep -F 'lowerdir=${upgradePackageV1}'")
      vm.succeed("touch " + upgrade_root + "/old-identity")

      vm.succeed("rm /var/lib/profiles/system-packages/gen-1/usr/${storePathHash upgradePackageV1}")
      vm.succeed("rm /var/lib/profiles/system-packages/meta/${storePathHash upgradePackageV1}.json")
      vm.succeed("ln -s ${upgradePackageV2} /var/lib/profiles/system-packages/gen-1/usr/${storePathHash upgradePackageV2}")
      vm.succeed("cp /var/lib/profiles/system-packages/upgrade-v2.json /var/lib/profiles/system-packages/meta/${storePathHash upgradePackageV2}.json")
      vm.succeed("${pkgs.aos}/bin/apm _test-reconcile-exposed-units --system")
      assert "upgrade-v2" == vm.succeed(
          "cat /var/lib/aos-pkg-expose-lifecycle-upgrade/result"
      ).strip()
      vm.succeed("findmnt -n -o FS-OPTIONS " + upgrade_root + " | grep -F 'lowerdir=${upgradePackageV2}'")
      vm.succeed("test ! -e /run/aos/service-roots/expose-lifecycle-upgrade/expose-lifecycle-upgrade.service/upper/root/old-identity")
      vm.succeed("touch " + upgrade_root + "/new-identity")

      vm.succeed("rm /var/lib/profiles/system-packages/gen-1/usr/${storePathHash upgradePackageV2}")
      vm.succeed("rm /var/lib/profiles/system-packages/meta/${storePathHash upgradePackageV2}.json")
      vm.succeed("ln -s ${upgradePackageV1} /var/lib/profiles/system-packages/gen-1/usr/${storePathHash upgradePackageV1}")
      vm.succeed("cp /var/lib/profiles/system-packages/upgrade-v1.json /var/lib/profiles/system-packages/meta/${storePathHash upgradePackageV1}.json")
      vm.succeed("${pkgs.aos}/bin/apm _test-reconcile-exposed-units --system")
      assert "upgrade-v1" == vm.succeed(
          "cat /var/lib/aos-pkg-expose-lifecycle-upgrade/result"
      ).strip()
      vm.succeed("findmnt -n -o FS-OPTIONS " + upgrade_root + " | grep -F 'lowerdir=${upgradePackageV1}'")
      vm.succeed("test ! -e /run/aos/service-roots/expose-lifecycle-upgrade/expose-lifecycle-upgrade.service/upper/root/new-identity")
      vm.succeed("systemctl is-active aos-pkg-expose-lifecycle-upgrade.target expose-lifecycle-upgrade.service")

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
      assert vm.succeed(
          "systemctl show -p RootDirectory --value expose-lifecycle-consumer.service"
      ).strip() == "/run/aos/service-roots/expose-lifecycle-socket-consumer/expose-lifecycle-consumer.service/merged"
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
