##! kubectl — Kubernetes command-line tool
{
  mkGoPackage,
  kubeSource,
}:
mkGoPackage {
  pname = "kubectl";
  inherit (kubeSource) version src;

  goPackage = "./cmd/kubectl";
  goOutput = "kubectl";
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
        pname = "tool-kubectl";
        tool = self;
        command = "kubectl version --client 2>&1";
      };
    };

  meta = {
    description = "kubectl — Kubernetes command-line interface";
    homepage = "https://kubernetes.io";
    license = "Apache-2.0";
  };
}
