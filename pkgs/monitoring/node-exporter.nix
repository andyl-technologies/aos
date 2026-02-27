##! Prometheus Node Exporter — hardware and OS metrics for *nix kernels
{
  mkGoPackage,
  fetchurl,
  fetchGoModules,
}:
let
  version = "1.10.2";
in
mkGoPackage {
  pname = "node-exporter";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/prometheus/node_exporter/archive/v${version}/node_exporter-${version}.tar.gz"
    ];
    hash = "sha256-rriK2YD9h+4IsbPlxwl3wyBlEVzIFS4/yEbi1gsqZi8=";
  };

  goModules = fetchGoModules {
    src = fetchurl {
      urls = [
        "https://github.com/prometheus/node_exporter/archive/v${version}/node_exporter-${version}.tar.gz"
      ];
      hash = "sha256-rriK2YD9h+4IsbPlxwl3wyBlEVzIFS4/yEbi1gsqZi8=";
    };
    hash = "sha256-Tpo6ZqtryFr+qUdhnE5jzPoZ10RF66W9xjeXzRiJVTY=";
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
