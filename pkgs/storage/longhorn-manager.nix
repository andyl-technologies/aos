##! Longhorn Manager — Longhorn orchestration controller
{
  mkDerivation,
  fetchurl,
  go,
  longhorn-engine,
  longhorn-instance-manager,
  lib,
}: let
  version = "1.8.1";
in
  mkDerivation {
    pname = "longhorn-manager";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/longhorn/longhorn-manager/archive/v${version}/longhorn-manager-${version}.tar.gz"
      ];
      hash = "sha256-dZLMYwijkUDyxKh8wVoHIrCvVkuzHnOYgakF012u3Tc=";
    };

    buildDeps = [go];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd longhorn-manager-${version}
        '';
      }
      {
        name = "build";
        script = ''
          export GOPATH=$TMPDIR/go
          export GOCACHE=$TMPDIR/go-cache
          export CGO_ENABLED=0
          export GOPROXY=off
          export GOFLAGS="-trimpath -mod=vendor"
          mkdir -p "$GOPATH" "$GOCACHE"

          go build -ldflags "-s -w -X main.Version=${version}" \
            -o longhorn-manager .
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/bin $out/share
          install -m 755 longhorn-manager $out/bin/
          printf '%s\n' '${builtins.toJSON {inherit version;}}' > $out/share/longhorn-package.json
        '';
      }
    ];

    configModule = {
      src = ./_longhorn-config;
      moduleAbiCompat = {
        min = 1;
        max = 2;
      };
      declares = [
        "longhorn.defaultReplicaCount"
        "longhorn.enable"
        "longhorn.nodeLabel"
      ];
      ownsRoots = [
        {
          root = "longhorn";
          interfaceAbi = 1;
        }
      ];
      contributes = [
        {
          root = "k3s";
          interfaceAbi = 2;
          paths = [
            "integrations.csi.longhorn"
            "integrations.resources.longhorn"
          ];
        }
      ];
      dependencies = {
        inherit longhorn-engine longhorn-instance-manager;
      };
      documentation = {
        summary = "Authenticated Longhorn CSI and Kubernetes resource contribution for k3s.";
        sections.integration = lib.aosDoc.section "k3s integration" [
          (lib.aosDoc.paragraph "Longhorn contributes only its signed CSI settings, node label, and ordered resource bundle. Engine and instance-manager payloads are retained dependencies, not separate host daemons.")
        ];
      };
    };

    checks = {
      testing,
      self,
      pkgs,
    }: {
      version = testing.mkToolCheck {
        pname = "tool-longhorn-manager";
        tool = self;
        command = "longhorn-manager version";
      };
    };

    meta = {
      description = "Longhorn Manager — distributed block storage orchestrator";
      homepage = "https://longhorn.io";
      license = "Apache-2.0";
    };
  }
