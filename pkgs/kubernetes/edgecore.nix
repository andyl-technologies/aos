##! EdgeCore — KubeEdge edge-side agent
{
  lib,
  mkDerivation,
  fetchurl,
  go,
  kubeedgeSource,
  writeShellScriptBin,
}: let
  inherit (kubeedgeSource) version src;
  control = writeShellScriptBin "edgecore-control" ''
    set -eu
    case "''${1:-}" in
      enabled) test "''${EDGECORE_ENABLED:-false}" = true ;;
      *) echo "usage: edgecore-control enabled" >&2; exit 64 ;;
    esac
  '';
in
  mkDerivation {
    pname = "edgecore";
    inherit version;
    inherit src;

    buildDeps = [go];
    runtimeDeps = [control];

    expose = {
      units."edgecore.service" = {
        description = "KubeEdge edge node agent";
        after = ["network-online.target" "containerd.service"];
        wants = ["network-online.target"];
        restartIfChanged = true;
        stopOnRemoval = true;
        serviceConfig = {
          Type = "simple";
          EnvironmentFile = "/etc/aos/packages/edgecore/runtime.env";
          ExecCondition = "/bin/edgecore-control enabled";
          ExecStart = "/bin/edgecore --config /etc/aos/packages/edgecore/edgecore.yaml";
          StateDirectory = "aos-pkg-edgecore";
          StateDirectoryMode = "0700";
          RuntimeDirectory = "aos-pkg-edgecore";
          RuntimeDirectoryMode = "0750";
          LogsDirectory = "edgecore";
          LogsDirectoryMode = "0750";
          Delegate = true;
          KillMode = "process";
          LimitNOFILE = 1048576;
          LimitNPROC = "infinity";
          TasksMax = "infinity";
          Restart = "always";
          RestartSec = "5s";
          UMask = "0077";
        };
      };
      config = {
        artifacts = [
          {
            name = "runtime";
            path = "/etc/aos/packages/edgecore/runtime.env";
            format = "env";
            required = ["EDGECORE_ENABLED"];
            units = ["edgecore.service"];
            reload = "restart";
          }
        ];
        credentials = builtins.map (name: {
          inherit name;
          source = "/run/credstore/edgecore/${name}";
          units = ["edgecore.service"];
          encrypted = false;
          optional = true;
        }) ["ca-certificate" "client-certificate" "client-private-key"];
      };
      prepareHostPathDirectories = ["/var/log/pods"];
      permissions = {
        network = "host";
        privileged-users = true;
        cgroup-delegate = true;
        capabilities = [
          "CAP_SYS_ADMIN"
          "CAP_NET_ADMIN"
          "CAP_NET_RAW"
          "CAP_SYS_RESOURCE"
          "CAP_SYS_PTRACE"
        ];
        devices = ["/dev/net/tun" "/dev/kmsg" "/dev/fuse"];
        host-paths = [
          {
            path = "/etc/aos/packages/edgecore/edgecore.yaml";
            mode = "read-only";
          }
          {
            path = "/run/containerd";
            mode = "rw";
          }
          {
            path = "/sys/fs/cgroup";
            mode = "rw";
          }
          {
            path = "/var/log/pods";
            mode = "rw";
          }
          {
            path = "/lib/modules";
            mode = "read-only";
          }
          {
            path = "/etc/resolv.conf";
            mode = "read-only";
          }
        ];
        kernel-modules = ["overlay" "br_netfilter"];
        syscalls = "privileged";
        security-label = "aos-pkg-edgecore";
      };
      kernel.modules = ["overlay" "br_netfilter"];
      kernel.sysctl = {
        "net.ipv4.ip_forward" = "1";
        "net.bridge.bridge-nf-call-iptables" = "1";
      };
    };

    configModule = {
      src = ./_edgecore-config;
      moduleAbiCompat = {
        min = 1;
        max = 2;
      };
      declares = [
        "edgecore.cgroupDriver"
        "edgecore.cloudHub.httpServer"
        "edgecore.cloudHub.server"
        "edgecore.enable"
        "edgecore.maxPods"
        "edgecore.nodeName"
        "edgecore.podSandboxImage"
        "edgecore.runtimeEndpoint"
        "edgecore.tls.caCertificate"
        "edgecore.tls.clientCertificate"
        "edgecore.tls.clientPrivateKey"
      ];
      ownsRoots = [
        {
          root = "edgecore";
          interfaceAbi = 1;
          contributable = [];
        }
      ];
      artifacts = {
        etc = ["aos/packages/edgecore/edgecore.yaml"];
        units = [];
        users = [];
        groups = [];
      };
      documentation = {
        summary = "Typed KubeEdge EdgeCore cloud connection, runtime, node, and TLS configuration.";
        sections = {
          deployment = lib.aosDoc.section "Edge deployment" [
            (lib.aosDoc.paragraph "EdgeCore runs on an edge node and connects to CloudCore using a stable node identity and explicit runtime endpoint. Review pod limits, cgroup driver, and sandbox image as one node contract.")
          ];
          credentials = lib.aosDoc.section "Client identity" [
            (lib.aosDoc.paragraph "The CA, client certificate, and private key are opaque references resolved only for the service and never embedded in edgecore.yaml.")
          ];
        };
      };
    };

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd kubeedge-${version}
        '';
      }
      {
        name = "build";
        script = ''
          export GOPATH=$TMPDIR/go
          export GOCACHE=$TMPDIR/go-cache
          export CGO_ENABLED=0
          export GOPROXY=off
          # KubeEdge uses a Go workspace (go.work) but the vendor dir was
          # created from go.mod replace directives. Disable workspace mode
          # so -mod=vendor uses go.mod consistently with vendor/modules.txt.
          export GOWORK=off
          export GOFLAGS="-trimpath -mod=vendor"
          mkdir -p "$GOPATH" "$GOCACHE"

          go build -ldflags "-s -w \
            -X github.com/kubeedge/kubeedge/pkg/version.Version=v${version}" \
            -o edgecore ./edge/cmd/edgecore
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/bin
          install -m 755 edgecore $out/bin/
        '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: let
      evaluated = lib.evalModules {
        inherit lib;
        modules = [
          ({lib, ...}: {
            options = {
              assertions = lib.mkOption {
                type = lib.types.listOf lib.types.attrs;
                default = [];
              };
              edgecore.config = lib.mkOption {
                type = lib.types.attrsOf (lib.types.attrsOf lib.types.anything);
                default = {};
              };
              edgecore.credentials = lib.mkOption {
                type = lib.types.attrsOf lib.types.attrs;
                default = {};
              };
              environment.etc = lib.mkOption {
                type = lib.types.attrsOf lib.types.attrs;
                default = {};
              };
            };
          })
          ./_edgecore-config/module.nix
          {
            edgecore = {
              enable = true;
              nodeName = "edge-01";
              cloudHub = {
                httpServer = "https://192.0.2.20:10002";
                server = "192.0.2.20:10000";
              };
              tls = {
                caCertificate.ref = "system-credential:kubeedge-ca";
                clientCertificate.ref = "system-credential:edge-01-cert";
                clientPrivateKey.ref = "system-credential:edge-01-key";
              };
            };
          }
        ];
      };
    in {
      version = testing.mkToolCheck {
        pname = "tool-edgecore";
        tool = self;
        command = "edgecore --help";
      };

      config = pkgs.runCommand "edgecore-config-module" {} ''
        config=${builtins.toFile "edgecore.yaml" evaluated.config.environment.etc."aos/packages/edgecore/edgecore.yaml".text}
        grep -F 'apiVersion: edgecore.config.kubeedge.io/v1alpha2' "$config"
        grep -F '    hostnameOverride: edge-01' "$config"
        grep -F '      server: 192.0.2.20:10000' "$config"
        test '${evaluated.config.edgecore.credentials.client-private-key.ref}' = 'system-credential:edge-01-key'
        touch "$out"
      '';
    };

    meta = {
      description = "EdgeCore — KubeEdge edge-side agent";
      homepage = "https://kubeedge.io";
      license = "Apache-2.0";
    };
  }
