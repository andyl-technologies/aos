# nerdctl — Docker-compatible CLI for containerd
{ mkDerivation, fetchurl, sources, versions, make }:

mkDerivation {
  name = "nerdctl-${versions.kubernetes.nerdctl}";
  version = versions.kubernetes.nerdctl;

  src = fetchurl {
    inherit (sources.nerdctl) url hash;
  };

  buildDeps = [ make ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd nerdctl-${versions.kubernetes.nerdctl}
      '';
    }
    { name = "build";
      script = ''
        export GOPATH=$TMPDIR/go
        export CGO_ENABLED=0
        export GOFLAGS="-trimpath"
        go build -o nerdctl \
          -ldflags "-s -w -X github.com/containerd/nerdctl/pkg/version.Version=v${versions.kubernetes.nerdctl}" \
          ./cmd/nerdctl
      '';
    }
    { name = "install";
      script = ''
        mkdir -p $out/bin
        install -m 755 nerdctl $out/bin/nerdctl
      '';
    }
  ];

  meta = {
    description = "nerdctl — Docker-compatible CLI for containerd";
    homepage = "https://github.com/containerd/nerdctl";
    license = "Apache-2.0";
  };
}
