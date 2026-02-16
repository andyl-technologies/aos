##! crictl — CLI for CRI-compatible container runtimes
{ mkGoPackage, fetchurl }:

let
  version = "1.31.1";
in
mkGoPackage {
  pname = "crictl";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/kubernetes-sigs/cri-tools/archive/v${version}/cri-tools-${version}.tar.gz"
    ];
    hash = "sha256-RlvRR2ioangsbksVs2g8Sl79A2PWiyQdV1enutqbzSE=";
  };

  goPackage = "./cmd/crictl";
  goOutput = "crictl";
  ldflags = "-s -w -X github.com/kubernetes-sigs/cri-tools/pkg/version.Version=v${version}";
  doCheck = false;

  checks =
    {
      testing,
      self,
      pkgs,
    }:
    {
      version = testing.mkToolCheck {
        pname = "tool-crictl";
        tool = self;
        command = "crictl --version";
      };
    };

  meta = {
    description = "crictl — CLI for CRI-compatible container runtimes";
    homepage = "https://github.com/kubernetes-sigs/cri-tools";
    license = "Apache-2.0";
  };
}
