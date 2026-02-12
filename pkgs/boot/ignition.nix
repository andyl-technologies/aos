# Ignition — First-boot provisioning utility
{ mkDerivation, fetchurl, sources, versions, make }:

mkDerivation {
  name = "ignition-${versions.image-tools.ignition}";
  version = versions.image-tools.ignition;

  src = fetchurl {
    inherit (sources.ignition) url hash;
  };

  buildDeps = [ make ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd ignition-${versions.image-tools.ignition}
      '';
    }
    { name = "build";
      script = ''
        export GOPATH=$TMPDIR/go
        export CGO_ENABLED=0
        export GOFLAGS="-trimpath"
        go build -o ignition \
          -ldflags "-s -w -X github.com/coreos/ignition/v2/internal/version.Raw=v${versions.image-tools.ignition}" \
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
