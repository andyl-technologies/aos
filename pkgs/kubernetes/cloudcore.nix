##! CloudCore — KubeEdge cloud-side component
{
  lib,
  mkDerivation,
  fetchurl,
  go,
  kubeedgeSource,
  writeShellScriptBin,
}: let
  inherit (kubeedgeSource) version src;
  control = writeShellScriptBin "cloudcore-control" ''
    set -eu
    case "''${1:-}" in
      enabled) test "''${CLOUDCORE_ENABLED:-false}" = true ;;
      *) echo "usage: cloudcore-control enabled" >&2; exit 64 ;;
    esac
  '';
in
  mkDerivation {
    pname = "cloudcore";
    inherit version;
    inherit src;

    buildDeps = [go];
    runtimeDeps = [control];

    expose = {
      units."cloudcore.service" = {
        description = "KubeEdge cloud control plane";
        after = ["network-online.target"];
        wants = ["network-online.target"];
        restartIfChanged = true;
        stopOnRemoval = true;
        serviceConfig = {
          Type = "simple";
          DynamicUser = true;
          EnvironmentFile = "/etc/aos/packages/cloudcore/runtime.env";
          ExecCondition = "/bin/cloudcore-control enabled";
          ExecStart = "/bin/cloudcore --config /etc/aos/packages/cloudcore/cloudcore.yaml";
          StateDirectory = "aos-pkg-cloudcore";
          StateDirectoryMode = "0700";
          RuntimeDirectory = "aos-pkg-cloudcore";
          RuntimeDirectoryMode = "0750";
          LogsDirectory = "cloudcore";
          LogsDirectoryMode = "0750";
          Restart = "on-failure";
          RestartSec = "5s";
          UMask = "0077";
        };
      };
      config = {
        artifacts = [
          {
            name = "runtime";
            path = "/etc/aos/packages/cloudcore/runtime.env";
            format = "env";
            required = ["CLOUDCORE_ENABLED"];
            units = ["cloudcore.service"];
            reload = "restart";
          }
        ];
        credentials = builtins.map (name: {
          inherit name;
          source = "/run/credstore/cloudcore/${name}";
          units = ["cloudcore.service"];
          encrypted = false;
          optional = true;
        }) ["kubeconfig" "ca-certificate" "ca-private-key" "server-certificate" "server-private-key"];
      };
      firewall = {
        allowedTCP = [10000 10002];
        allowedUDP = [];
      };
      permissions = {
        network = "host";
        capabilities = [];
        devices = [];
        host-paths = [
          {
            path = "/etc/aos/packages/cloudcore/cloudcore.yaml";
            mode = "read-only";
          }
        ];
        syscalls = "system-service";
        security-label = "aos-pkg-cloudcore";
      };
    };

    configModule = {
      src = ./_cloudcore-config;
      moduleAbiCompat = {
        min = 1;
        max = 2;
      };
      declares = [
        "cloudcore.advertiseAddresses"
        "cloudcore.enable"
        "cloudcore.https.address"
        "cloudcore.https.enable"
        "cloudcore.https.port"
        "cloudcore.kubeApi.burst"
        "cloudcore.kubeApi.kubeconfig"
        "cloudcore.kubeApi.qps"
        "cloudcore.monitorAddress"
        "cloudcore.nodeLimit"
        "cloudcore.tls.caCertificate"
        "cloudcore.tls.caPrivateKey"
        "cloudcore.tls.serverCertificate"
        "cloudcore.tls.serverPrivateKey"
        "cloudcore.websocket.address"
        "cloudcore.websocket.enable"
        "cloudcore.websocket.port"
      ];
      ownsRoots = [
        {
          root = "cloudcore";
          interfaceAbi = 1;
          contributable = [];
        }
      ];
      artifacts = {
        etc = ["aos/packages/cloudcore/cloudcore.yaml"];
        units = [];
        users = [];
        groups = [];
      };
      documentation = {
        summary = "CloudCore — KubeEdge cloud-side component";
        sections = {
          deployment = lib.aosDoc.section "Cloud deployment" [
            (lib.aosDoc.paragraph "CloudCore connects KubeEdge nodes to an existing Kubernetes control plane. Configure stable advertised addresses and explicitly enable only the HTTPS and WebSocket listeners the fleet needs.")
          ];
          credentials = lib.aosDoc.section "Trust material" [
            (lib.aosDoc.paragraph "CA and server keys and certificates are opaque references delivered as systemd credentials; Kubernetes access uses the configured kubeconfig host path.")
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
            -o cloudcore ./cloud/cmd/cloudcore
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/bin
          install -m 755 cloudcore $out/bin/
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
              cloudcore.config = lib.mkOption {
                type = lib.types.attrsOf (lib.types.attrsOf lib.types.anything);
                default = {};
              };
              cloudcore.credentials = lib.mkOption {
                type = lib.types.attrsOf lib.types.attrs;
                default = {};
              };
              environment.etc = lib.mkOption {
                type = lib.types.attrsOf lib.types.attrs;
                default = {};
              };
            };
          })
          ./_cloudcore-config/module.nix
          {
            cloudcore = {
              enable = true;
              advertiseAddresses = ["192.0.2.20"];
              kubeApi.kubeconfig.ref = "system-credential:kubeconfig";
              tls = {
                caCertificate.ref = "system-credential:kubeedge-ca";
                caPrivateKey.ref = "system-credential:kubeedge-ca-key";
                serverCertificate.ref = "system-credential:kubeedge-server";
                serverPrivateKey.ref = "system-credential:kubeedge-server-key";
              };
            };
          }
        ];
      };
    in {
      version = testing.mkToolCheck {
        pname = "tool-cloudcore";
        tool = self;
        command = "cloudcore --help";
      };

      config = pkgs.runCommand "cloudcore-config-module" {} ''
        config=${builtins.toFile "cloudcore.yaml" evaluated.config.environment.etc."aos/packages/cloudcore/cloudcore.yaml".text}
        grep -F 'apiVersion: cloudcore.config.kubeedge.io/v1alpha1' "$config"
        grep -F '    - 192.0.2.20' "$config"
        grep -F 'kubeConfig: /run/credentials/cloudcore.service/kubeconfig' "$config"
        test '${evaluated.config.cloudcore.credentials.ca-private-key.ref}' = 'system-credential:kubeedge-ca-key'
        touch "$out"
      '';
    };

    meta = {
      description = "CloudCore — KubeEdge cloud-side component";
      homepage = "https://kubeedge.io";
      license = "Apache-2.0";
    };
  }
