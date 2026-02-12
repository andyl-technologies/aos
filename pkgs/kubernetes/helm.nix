# Helm — Kubernetes package manager
{ mkDerivation, fetchurl, sources, versions, make }:

mkDerivation {
  name = "helm-${versions.kubernetes.helm}";
  version = versions.kubernetes.helm;

  src = fetchurl {
    inherit (sources.helm) url hash;
  };

  buildDeps = [ make ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd helm-${versions.kubernetes.helm}
      '';
    }
    { name = "build";
      script = ''
        export GOPATH=$TMPDIR/go
        export CGO_ENABLED=0
        export GOFLAGS="-trimpath"
        go build -o helm \
          -ldflags "-s -w \
            -X helm.sh/helm/v3/internal/version.version=v${versions.kubernetes.helm} \
            -X helm.sh/helm/v3/internal/version.gitTreeState=clean" \
          ./cmd/helm
      '';
    }
    { name = "install";
      script = ''
        mkdir -p $out/bin
        install -m 755 helm $out/bin/helm
      '';
    }
  ];

  meta = {
    description = "Helm — the Kubernetes package manager";
    homepage = "https://helm.sh";
    license = "Apache-2.0";
  };
}
