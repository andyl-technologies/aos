##! Longhorn Engine — Block device data plane
{
  mkDerivation,
  fetchurl,
  go,
  zlib,
  libqcow,
}:
let
  version = "1.8.1";
in
mkDerivation {
  pname = "longhorn-engine";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/longhorn/longhorn-engine/archive/v${version}/longhorn-engine-${version}.tar.gz"
    ];
    hash = "sha256-y5xSKdDfVtoZncdjadhxSpokmakfJ8H2VHbT1dhz2hI=";
  };

  buildDeps = [ go ];
  runtimeDeps = [ zlib libqcow ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd longhorn-engine-${version}
      '';
    }
    {
      name = "build";
      script = ''
        export GOPATH=$TMPDIR/go
        export GOCACHE=$TMPDIR/go-cache
        export CGO_ENABLED=1
        export GOPROXY=off
        export GOFLAGS="-trimpath -mod=vendor"
        mkdir -p "$GOPATH" "$GOCACHE"

        go build -ldflags "-s -w -X main.Version=${version}" \
          -o longhorn-engine .
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p $out/bin
        install -m 755 longhorn-engine $out/bin/
      '';
    }
  ];

  checks =
    {
      testing,
      self,
      pkgs,
    }:
    {
      version = testing.mkToolCheck {
        pname = "tool-longhorn-engine";
        tool = self;
        command = "longhorn-engine version";
      };
    };

  meta = {
    description = "Longhorn Engine — block device data plane";
    homepage = "https://longhorn.io";
    license = "Apache-2.0";
  };
}
