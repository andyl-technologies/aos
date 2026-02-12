# kubectl — Kubernetes command-line tool
{ mkDerivation, fetchurl, make, kubeSource }:

mkDerivation {
  pname = "kubectl";
  inherit (kubeSource) version src;

  buildDeps = [ make ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd kubernetes-${kubeSource.version}
      '';
    }
    { name = "build";
      script = ''
        export GOPATH=$TMPDIR/go
        export CGO_ENABLED=0
        export GOFLAGS="-trimpath"
        export GOLDFLAGS="-s -w -X k8s.io/component-base/version.gitVersion=v${kubeSource.version}"
        go build -o kubectl \
          -ldflags "$GOLDFLAGS" \
          ./cmd/kubectl
      '';
    }
    { name = "install";
      script = ''
        mkdir -p $out/bin
        install -m 755 kubectl $out/bin/kubectl
      '';
    }
  ];

  meta = {
    description = "kubectl — Kubernetes command-line interface";
    homepage = "https://kubernetes.io";
    license = "Apache-2.0";
  };
}
