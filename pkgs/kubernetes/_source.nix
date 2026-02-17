##! Shared Kubernetes source — used by kubelet, kubeadm, kubectl
{fetchurl}: let
  version = "1.35.1";
in {
  inherit version;
  src = fetchurl {
    urls = [
      "https://github.com/kubernetes/kubernetes/archive/v${version}/kubernetes-${version}.tar.gz"
    ];
    hash = "sha256-W1lSqXSTfFoAfYvBG7WErtyNF/OcY54PzI+GdspOluI=";
  };
}
