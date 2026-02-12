# Prometheus Node Exporter — Hardware and OS metrics exporter
{ mkDerivation, fetchurl, make }:

let version = "1.8.2"; in
mkDerivation {
  pname = "node-exporter";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/prometheus/node_exporter/archive/v${version}/node_exporter-${version}.tar.gz"
    ];
    hash = "sha256-9hXHC+gWVQSY3WpQU5Hb7RqJZwXv+EJijeE6H6dlTo8=";
  };

  buildDeps = [ make ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd node_exporter-${version}
      '';
    }
    { name = "build";
      script = ''
        export GOPATH=$TMPDIR/go
        export CGO_ENABLED=0
        export GOFLAGS="-trimpath"
        go build -o node_exporter \
          -ldflags "-s -w \
            -X github.com/prometheus/common/version.Version=${version} \
            -X github.com/prometheus/common/version.Branch=release \
            -X github.com/prometheus/common/version.BuildUser=andyl-os" \
          .
      '';
    }
    { name = "install";
      script = ''
        mkdir -p $out/bin
        install -m 755 node_exporter $out/bin/node_exporter
      '';
    }
  ];

  meta = {
    description = "Prometheus Node Exporter — hardware and OS metrics for *nix kernels";
    homepage = "https://github.com/prometheus/node_exporter";
    license = "Apache-2.0";
  };
}
