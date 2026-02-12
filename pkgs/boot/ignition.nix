# Ignition — First-boot provisioning utility
{ mkDerivation, fetchurl, make }:

let version = "2.19.0"; in
mkDerivation {
  pname = "ignition";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/coreos/ignition/archive/v${version}/ignition-${version}.tar.gz"
    ];
    hash = "sha256-OxlA9JfybOied5wFh/AAy25e3DnvhJru6ZhU0roSXcU=";
  };

  buildDeps = [ make ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd ignition-${version}
      '';
    }
    { name = "build";
      script = ''
        export GOPATH=$TMPDIR/go
        export CGO_ENABLED=0
        export GOFLAGS="-trimpath"
        go build -o ignition \
          -ldflags "-s -w -X github.com/coreos/ignition/v2/internal/version.Raw=v${version}" \
          ./internal
      '';
    }
    { name = "install";
      script = ''
        mkdir -p $out/bin $out/lib/dracut/modules.d
        install -m 755 ignition $out/bin/ignition

        # Install dracut module for initramfs integration
        if [ -d dracut ]; then
          cp -a dracut/* $out/lib/dracut/modules.d/
        fi
      '';
    }
  ];

  meta = {
    description = "Ignition — machine provisioning utility for first boot";
    homepage = "https://github.com/coreos/ignition";
    license = "Apache-2.0";
  };
}
