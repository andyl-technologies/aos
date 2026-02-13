# Shared Kubernetes source — used by kubelet, kubeadm, kubectl
{ fetchurl }:

let
  version = "1.31.4";
in
{
  inherit version;
  src = fetchurl {
    urls = [
      "https://github.com/kubernetes/kubernetes/archive/v${version}/kubernetes-${version}.tar.gz"
    ];
    hash = "sha256-/zounK47RzS+Smzf65M4MMYyGertoFzE5Zt1WfzeUrA=";
  };
}
