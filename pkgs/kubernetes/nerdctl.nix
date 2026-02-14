{ mkGoPackage, fetchurl }:

let
  version = "1.7.7";
in
mkGoPackage {
  pname = "nerdctl";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/containerd/nerdctl/archive/v${version}/nerdctl-${version}.tar.gz"
    ];
    hash = "sha256-vN3y7jrSvIStxeIH+XFXmY/pc5EsfR3ZVAvUu0oHaY0=";
  };

  goPackage = "./cmd/nerdctl";
  goOutput = "nerdctl";
  ldflags = "-s -w -X github.com/containerd/nerdctl/pkg/version.Version=v${version}";
  doCheck = false;

  meta = {
    description = "nerdctl — Docker-compatible CLI for containerd";
    homepage = "https://github.com/containerd/nerdctl";
    license = "Apache-2.0";
  };
}
