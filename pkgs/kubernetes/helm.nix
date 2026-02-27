##! Helm — Kubernetes package manager
{
  mkGoPackage,
  fetchurl,
  fetchGoModules,
}:
let
  version = "4.1.1";
in
mkGoPackage {
  pname = "helm";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/helm/helm/archive/v${version}/helm-${version}.tar.gz"
    ];
    hash = "sha256-Gr26jVRYYMr/BfMYNASGFfaHouGLuTrmYl84/XH6aSg=";
  };

  goModules = fetchGoModules {
    src = fetchurl {
      urls = [
        "https://github.com/helm/helm/archive/v${version}/helm-${version}.tar.gz"
      ];
      hash = "sha256-Gr26jVRYYMr/BfMYNASGFfaHouGLuTrmYl84/XH6aSg=";
    };
    hash = "sha256-3bG0KJn4wwo9JtTl6DqQX4Mfu3cqBdMK7VUyy64xZAs=";
  };

  goPackage = "./cmd/helm";
  goOutput = "helm";
  ldflags = "-s -w -X helm.sh/helm/v4/internal/version.version=v${version} -X helm.sh/helm/v4/internal/version.gitTreeState=clean";
  doCheck = false;

  checks =
    {
      testing,
      self,
      pkgs,
    }:
    {
      version = testing.mkToolCheck {
        pname = "tool-helm";
        tool = self;
        command = "helm version";
      };
    };

  meta = {
    description = "Helm — the Kubernetes package manager";
    homepage = "https://helm.sh";
    license = "Apache-2.0";
  };
}
