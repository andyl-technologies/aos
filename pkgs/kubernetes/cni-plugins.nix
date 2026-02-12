# CNI Plugins — Container Networking Interface reference plugins
{ mkDerivation, fetchurl, sources, versions, make }:

mkDerivation {
  name = "cni-plugins-${versions.kubernetes.cni-plugins}";
  version = versions.kubernetes.cni-plugins;

  src = fetchurl {
    inherit (sources.cni-plugins) url hash;
  };

  buildDeps = [ make ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd plugins-${versions.kubernetes.cni-plugins}
      '';
    }
    { name = "build";
      script = ''
        export GOPATH=$TMPDIR/go
        export CGO_ENABLED=0
        export GOFLAGS="-trimpath"
        export LDFLAGS="-s -w -X github.com/containernetworking/plugins/pkg/utils/buildversion.BuildVersion=v${versions.kubernetes.cni-plugins}"

        mkdir -p bin
        for plugin in bandwidth bridge dhcp dummy firewall host-device host-local \
                      ipvlan loopback macvlan portmap ptp sbr static tap tuning \
                      vlan vrf; do
          echo "Building $plugin..."
          go build -o bin/$plugin \
            -ldflags "$LDFLAGS" \
            ./plugins/*/''${plugin} 2>/dev/null || \
          go build -o bin/$plugin \
            -ldflags "$LDFLAGS" \
            ./plugins/*/*/''${plugin} 2>/dev/null || true
        done
      '';
    }
    { name = "install";
      script = ''
        mkdir -p $out/bin
        install -m 755 bin/* $out/bin/
      '';
    }
  ];

  meta = {
    description = "CNI Plugins — Container Networking Interface reference plugins";
    homepage = "https://github.com/containernetworking/plugins";
    license = "Apache-2.0";
  };
}
