##! Helm — Kubernetes package manager
{ mkGoPackage, fetchurl }:

let
  version = "3.16.4";
in
mkGoPackage {
  pname = "helm";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/helm/helm/archive/v${version}/helm-${version}.tar.gz"
    ];
    hash = "sha256-QooO0GE2zCAY/+KD9eT3+6TSo3vFZs0M9apVDEmF9bs=";
  };

  goPackage = "./cmd/helm";
  goOutput = "helm";
  ldflags = "-s -w -X helm.sh/helm/v3/internal/version.version=v${version} -X helm.sh/helm/v3/internal/version.gitTreeState=clean";
  doCheck = false;

  meta = {
    description = "Helm — the Kubernetes package manager";
    homepage = "https://helm.sh";
    license = "Apache-2.0";
  };
}
