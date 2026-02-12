# Butane — Translates Butane configs to Ignition configs
{ mkDerivation, fetchurl, sources, versions, make }:

mkDerivation {
  name = "butane-${versions.image-tools.butane}";
  version = versions.image-tools.butane;

  src = fetchurl {
    inherit (sources.butane) url hash;
  };

  buildDeps = [ make ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd butane-${versions.image-tools.butane}
      '';
    }
    { name = "build";
      script = ''
        export GOPATH=$TMPDIR/go
        export CGO_ENABLED=0
        export GOFLAGS="-trimpath"
        go build -o butane \
          -ldflags "-s -w -X github.com/coreos/butane/internal/version.Raw=v${versions.image-tools.butane}" \
          ./internal
      '';
    }
    { name = "install";
      script = ''
        mkdir -p $out/bin
        install -m 755 butane $out/bin/butane
      '';
    }
  ];

  meta = {
    description = "Butane — human-readable config transpiler for Ignition";
    homepage = "https://github.com/coreos/butane";
    license = "Apache-2.0";
  };
}
