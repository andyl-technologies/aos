##! Go 1.4 — first Go bootstrap stage, compiled from C source
{
  mkDerivation,
  fetchurl,
}:
mkDerivation {
  pname = "go-1_4";
  version = "1.4-bootstrap-20171003";

  src = fetchurl {
    urls = [
      "https://go.dev/dl/go1.4-bootstrap-20171003.tar.gz"
    ];
    hash = "sha256-9P9bXrOjyuHJk3I/PqtRnFuuGIZrXl+W/hEC8MtcPlI=";
  };

  buildDeps = [];
  runtimeDeps = [];
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
    description = "Go 1.4 bootstrap — compiled from C source";
    homepage = "https://go.dev";
    license = "BSD-3-Clause";
  };
}
