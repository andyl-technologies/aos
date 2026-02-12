# kubeadm — Kubernetes cluster bootstrapping tool
{ mkDerivation, fetchurl, sources, versions, make }:

mkDerivation {
  name = "kubeadm-${versions.kubernetes.kubeadm}";
  version = versions.kubernetes.kubeadm;

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
        cd kubernetes-${versions.kubernetes.kubeadm}
      '';
    }
    { name = "build";
      script = ''
        export GOPATH=$TMPDIR/go
        export CGO_ENABLED=0
        export GOFLAGS="-trimpath"
        export GOLDFLAGS="-s -w -X k8s.io/component-base/version.gitVersion=v${versions.kubernetes.kubeadm}"
        go build -o kubeadm \
          -ldflags "$GOLDFLAGS" \
          ./cmd/kubeadm
      '';
    }
    { name = "install";
      script = ''
        mkdir -p $out/bin
        install -m 755 kubeadm $out/bin/kubeadm
      '';
    }
  ];

  meta = {
    description = "kubeadm — tool for bootstrapping Kubernetes clusters";
    homepage = "https://kubernetes.io";
    license = "Apache-2.0";
  };
}
