##! CNI Plugins — Container Networking Interface reference plugins
{
  mkDerivation,
  fetchurl,
  make,
}:

let
  version = "1.6.1";
in
mkDerivation {
  pname = "cni-plugins";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/containernetworking/plugins/archive/v${version}/cni-plugins-${version}.tar.gz"
    ];
    hash = "sha256-Xi6mm8oIv7kpIfIvosweaTku4Tmlh4Bo37wcdWjjewE=";
  };

  buildDeps = [ make ];
  runtimeDeps = [ ];
  propagatedDeps = [ ];

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
        export LDFLAGS="-s -w -X github.com/containernetworking/plugins/pkg/utils/buildversion.BuildVersion=v${version}"
        mkdir -p "$GOCACHE"

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
    {
      name = "install";
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
