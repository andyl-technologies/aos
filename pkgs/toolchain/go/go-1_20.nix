##! Go 1.20 — third Go bootstrap stage, built with Go 1.17
{
  mkDerivation,
  fetchurl,
  go-1_17,
}:
let
  version = "1.20.14";
in
mkDerivation {
  pname = "go-1_20";
  inherit version;

  src = fetchurl {
    urls = [
      "https://go.dev/dl/go${version}.src.tar.gz"
    ];
    hash = "sha256-Gu8yGg4+OLfpHS1+tkBAZmyr3Md9OD3jyVItDWm2f04=";
  };

  buildDeps = [ go-1_17 ];
  runtimeDeps = [ ];
  dontStrip = true; # Go runtime metadata in custom ELF sections

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd go
      '';
    }
    {
      name = "build";
      script = ''
        export GOROOT_BOOTSTRAP=${go-1_17}
        export GOROOT_FINAL=$out
        export GOCACHE=$TMPDIR/go-cache
        export CGO_ENABLED=0
        cd src
        bash make.bash
        cd ..
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p $out/bin $out/src $out/pkg
        cp -a bin/* $out/bin/
        cp -a src/* $out/src/
        cp -a pkg/* $out/pkg/
      '';
    }
  ];

  meta = {
    description = "Go 1.20 bootstrap — built with Go 1.17";
    homepage = "https://go.dev";
    license = "BSD-3-Clause";
  };
}
