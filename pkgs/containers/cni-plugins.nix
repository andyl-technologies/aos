##! CNI Plugins — Container Networking Interface reference plugins
{
  mkDerivation,
  fetchurl,
  fetchGoModules,
  gnumake,
  go,
}: let
  version = "1.9.0";
  flannelVersion = "1.9.0-flannel1";
  flannelSrc = fetchurl {
    urls = [
      "https://github.com/flannel-io/cni-plugin/archive/v${flannelVersion}/cni-plugin-${flannelVersion}.tar.gz"
    ];
    hash = "sha256-ie1V2EBX3o3DN+y/D9nQjAzZNJAl52zb6sPCbqkxQI0=";
  };
  flannelGoModules = fetchGoModules {
    src = flannelSrc;
    hash = "sha256-d+j+m9yj9BpMuPS01DBsrhSPoBnifcS262u6fp4/ffI=";
  };
in
  mkDerivation {
    pname = "cni-plugins";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/containernetworking/plugins/archive/v${version}/cni-plugins-${version}.tar.gz"
      ];
      hash = "sha256-UJGEGk83mrYVkVK1Ru/EUj1VaUyK3E8ZzHxo+dHbbXU=";
    };

    buildDeps = [
      gnumake
      go
    ];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          tar xf ${flannelSrc}
          cd plugins-${version}
        '';
      }
      {
        name = "build";
        script = ''
          export GOPATH=$TMPDIR/go
          export GOCACHE=$TMPDIR/go-cache
          export CGO_ENABLED=0
          export GOFLAGS="-trimpath -mod=vendor"
          export GOPROXY=off
          GO_LDFLAGS="-s -w -X github.com/containernetworking/plugins/pkg/utils/buildversion.BuildVersion=v${version}"
          mkdir -p "$GOCACHE"

          mkdir -p bin
          for plugin in bandwidth bridge dhcp dummy firewall host-device host-local \
                        ipvlan loopback macvlan portmap ptp sbr static tap tuning \
                        vlan vrf; do
            echo "Building $plugin..."
            # Find the plugin directory and build it
            plugindir=$(find ./plugins -type d -name "$plugin" | head -1)
            if [ -n "$plugindir" ]; then
              go build -o bin/$plugin -ldflags "$GO_LDFLAGS" "$plugindir"
            else
              echo "WARNING: plugin $plugin not found, skipping"
            fi
          done

          echo "Building flannel..."
          (
            cd ../cni-plugin-${flannelVersion}
            GOPATH="${flannelGoModules}" \
              GOFLAGS="-trimpath -mod=readonly" \
              go build \
                -tags "netgo osusergo no_stage static_build" \
                -ldflags "-s -w \
                  -X main.Program=flannel \
                  -X main.Version=v${flannelVersion} \
                  -X main.Commit=v${flannelVersion}" \
                -o ../plugins-${version}/bin/flannel .
          )
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/bin
          install -m 755 bin/* $out/bin/
        '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      binaries = testing.mkVMTest {
        name = "tool-cni-plugins";
        rootfsDeps = [self];
        testScript = ''
          echo "==> Verifying CNI plugin binaries exist"
          test -x ${self}/bin/bridge
          test -x ${self}/bin/loopback
          test -x ${self}/bin/host-local
          test -x ${self}/bin/portmap
          test -x ${self}/bin/flannel
          echo "==> CNI plugin binaries verified"
        '';
      };
    };

    meta = {
      description = "CNI Plugins — Container Networking Interface reference plugins";
      homepage = "https://github.com/containernetworking/plugins";
      license = "Apache-2.0";
    };
  }
