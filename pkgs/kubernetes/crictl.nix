# crictl — CLI for CRI-compatible container runtimes
{ mkDerivation, fetchurl, sources, versions, make }:

mkDerivation {
  name = "crictl-${versions.kubernetes.crictl}";
  version = versions.kubernetes.crictl;

  src = fetchurl {
    inherit (sources.crictl) url hash;
  };

  buildDeps = [ make ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd cri-tools-${versions.kubernetes.crictl}
      '';
    }
    { name = "build";
      script = ''
        export GOPATH=$TMPDIR/go
        export CGO_ENABLED=0
        export GOFLAGS="-trimpath"
        go build -o crictl \
          -ldflags "-s -w -X github.com/kubernetes-sigs/cri-tools/pkg/version.Version=v${versions.kubernetes.crictl}" \
          ./cmd/crictl
      '';
    }
    { name = "install";
      script = ''
        mkdir -p $out/bin
        install -m 755 crictl $out/bin/crictl
      '';
    }
  ];

  meta = {
    description = "crictl — CLI for CRI-compatible container runtimes";
    homepage = "https://github.com/kubernetes-sigs/cri-tools";
    license = "Apache-2.0";
  };
}
