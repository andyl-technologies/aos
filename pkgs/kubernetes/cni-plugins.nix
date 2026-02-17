##! CNI Plugins — Container Networking Interface reference plugins
{
  mkDerivation,
  fetchurl,
  make,
  go,
}: let
  version = "1.9.0";
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
      make
      go
    ];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
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
      binaries = testing.mkFirecrackerTest {
        pname = "tool-cni-plugins";
        rootfsDeps = [self];
        testScript = ''
          echo "==> Verifying CNI plugin binaries exist"
          test -x ${self}/bin/bridge
          test -x ${self}/bin/loopback
          test -x ${self}/bin/host-local
          test -x ${self}/bin/portmap
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
