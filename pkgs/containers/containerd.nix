# containerd — Container runtime
{ mkDerivation, fetchurl, sources, versions, make, runc }:

mkDerivation {
  name = "containerd-${versions.kubernetes.containerd}";
  version = versions.kubernetes.containerd;

  src = fetchurl {
    inherit (sources.containerd) url hash;
  };

  buildDeps = [ make ];
  runtimeDeps = [ runc ];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd containerd-${versions.kubernetes.containerd}
      '';
    }
    { name = "setup-gopath";
      script = ''
        export GOPATH=$TMPDIR/go
        mkdir -p $GOPATH/src/github.com/containerd
        ln -sf $PWD $GOPATH/src/github.com/containerd/containerd
      '';
    }
    { name = "build";
      script = ''
        export GOPATH=$TMPDIR/go
        export CGO_ENABLED=0
        make VERSION=v${versions.kubernetes.containerd} \
          REVISION=v${versions.kubernetes.containerd} \
          binaries
      '';
    }
    { name = "install";
      script = ''
        mkdir -p $out/bin
        install -m 755 bin/* $out/bin/
        # Install default configuration
        mkdir -p $out/etc/containerd
        $out/bin/containerd config default > $out/etc/containerd/config.toml
      '';
    }
  ];

  meta = {
    description = "containerd — industry-standard container runtime";
    homepage = "https://containerd.io";
    license = "Apache-2.0";
  };
}
