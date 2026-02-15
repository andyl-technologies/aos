##! containerd — Container runtime
{
  mkDerivation,
  fetchurl,
  make,
  go,
  runc,
}:

let
  version = "1.7.24";
in
mkDerivation {
  pname = "containerd";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/containerd/containerd/archive/v${version}/containerd-${version}.tar.gz"
    ];
    hash = "sha256-h2FPjIy80gOIEotK9PEMJF7SYNK/04NayfA6y2RQid0=";
  };

  buildDeps = [
    make
    go
  ];
  runtimeDeps = [ runc ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd containerd-${version}
      '';
    }
    {
      name = "setup-gopath";
      script = ''
        export GOPATH=$TMPDIR/go
        mkdir -p $GOPATH/src/github.com/containerd
        ln -sf $PWD $GOPATH/src/github.com/containerd/containerd
      '';
    }
    {
      name = "build";
      script = ''
        export GOPATH=$TMPDIR/go
        export GOCACHE=$TMPDIR/go-cache
        export CGO_ENABLED=0
        export GOPROXY=off
        mkdir -p "$GOCACHE"
        make SHELL="$CONFIG_SHELL" VERSION=v${version} \
          REVISION=v${version} \
          binaries
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p $out/bin
        install -m 755 bin/* $out/bin/
      '';
    }
  ];

  meta = {
    description = "containerd — industry-standard container runtime";
    homepage = "https://containerd.io";
    license = "Apache-2.0";
  };
}
