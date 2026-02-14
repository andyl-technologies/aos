{ mkGoPackage, fetchurl }:

let
  version = "1.8.2";
in
mkGoPackage {
  pname = "node-exporter";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/prometheus/node_exporter/archive/v${version}/node_exporter-${version}.tar.gz"
    ];
    hash = "sha256-9hXHC+gWVQSY3WpQU5Hb7RqJZwXv+EJijeE6H6dlTo8=";
  };

  goPackage = ".";
  goOutput = "node_exporter";
  ldflags = "-s -w -X github.com/prometheus/common/version.Version=${version} -X github.com/prometheus/common/version.Branch=release -X github.com/prometheus/common/version.BuildUser=andyl-os";
  doCheck = false;

  meta = {
    description = "Prometheus Node Exporter — hardware and OS metrics for *nix kernels";
    homepage = "https://github.com/prometheus/node_exporter";
    license = "Apache-2.0";
  };
}
