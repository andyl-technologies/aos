# Prometheus Node Exporter — Hardware and OS metrics exporter
{ mkDerivation, fetchurl, sources, versions, make }:

mkDerivation {
  name = "node-exporter-${versions.monitoring.node-exporter}";
  version = versions.monitoring.node-exporter;

  src = fetchurl {
    inherit (sources.node-exporter) url hash;
  };

  buildDeps = [ make ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd node_exporter-${versions.monitoring.node-exporter}
      '';
    }
    { name = "build";
      script = ''
        export GOPATH=$TMPDIR/go
        export CGO_ENABLED=0
        export GOFLAGS="-trimpath"
        go build -o node_exporter \
          -ldflags "-s -w \
            -X github.com/prometheus/common/version.Version=${versions.monitoring.node-exporter} \
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
