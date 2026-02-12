# kubelet — Kubernetes node agent
{ mkDerivation, fetchurl, sources, versions, make }:

mkDerivation {
  name = "kubelet-${versions.kubernetes.kubelet}";
  version = versions.kubernetes.kubelet;

  src = fetchurl {
    inherit (sources.kubernetes) url hash;
  };

  buildDeps = [ make ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd kubernetes-${versions.kubernetes.kubelet}
      '';
    }
    { name = "build";
      script = ''
        export GOPATH=$TMPDIR/go
        export CGO_ENABLED=0
        export GOFLAGS="-trimpath"
        export GOLDFLAGS="-s -w -X k8s.io/component-base/version.gitVersion=v${versions.kubernetes.kubelet}"
        go build -o kubelet \
          -ldflags "$GOLDFLAGS" \
          ./cmd/kubelet
      '';
    }
    { name = "install";
      script = ''
        mkdir -p $out/bin
        install -m 755 kubelet $out/bin/kubelet
      '';
    }
  ];

  meta = {
    description = "kubelet — Kubernetes node agent that manages pods";
    homepage = "https://kubernetes.io";
    license = "Apache-2.0";
  };
}
