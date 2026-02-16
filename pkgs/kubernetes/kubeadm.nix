##! kubeadm — Kubernetes cluster bootstrapping tool
{ mkGoPackage, kubeSource }:

mkGoPackage {
  pname = "kubeadm";
  inherit (kubeSource) version src;

  goPackage = "./cmd/kubeadm";
  goOutput = "kubeadm";
  ldflags = "-s -w -X k8s.io/component-base/version.gitVersion=v${kubeSource.version}";
  doCheck = false;

  checks =
    {
      testing,
      self,
      pkgs,
    }:
    {
      version = testing.mkToolCheck {
        pname = "tool-kubeadm";
        tool = self;
        command = "kubeadm version";
      };
    };

  meta = {
    description = "kubeadm — tool for bootstrapping Kubernetes clusters";
    homepage = "https://kubernetes.io";
    license = "Apache-2.0";
  };
}
