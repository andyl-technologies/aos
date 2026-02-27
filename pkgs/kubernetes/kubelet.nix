##! kubelet — Kubernetes node agent
{
  mkGoPackage,
  kubeSource,
}:
mkGoPackage {
  pname = "kubelet";
  inherit (kubeSource) version src;

  goPackage = "./cmd/kubelet";
  goOutput = "kubelet";
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
        pname = "tool-kubelet";
        tool = self;
        command = "kubelet --version";
      };
    };

  meta = {
    description = "kubelet — Kubernetes node agent that manages pods";
    homepage = "https://kubernetes.io";
    license = "Apache-2.0";
  };
}
