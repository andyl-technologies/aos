# Butane — Translates Butane configs to Ignition configs
{ mkDerivation, fetchurl, make }:

let version = "0.21.0"; in
mkDerivation {
  pname = "butane";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/coreos/butane/archive/v${version}/butane-${version}.tar.gz"
    ];
    hash = "sha256-RMH/E8AbTdirgxD9RwPD5+xBGxWSXOy0NK1fWV+dF9Y=";
  };

  buildDeps = [ make ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd butane-${version}
      '';
    }
    { name = "build";
      script = ''
        export GOPATH=$TMPDIR/go
        export CGO_ENABLED=0
        export GOFLAGS="-trimpath"
        go build -o butane \
          -ldflags "-s -w -X github.com/coreos/butane/internal/version.Raw=v${version}" \
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
