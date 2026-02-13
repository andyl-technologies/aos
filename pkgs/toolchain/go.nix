# Go — the Go programming language, built from source
{
  mkDerivation,
  fetchurl,
  make,
  go-bootstrap,
}:

let
  version = "1.23.5";
in
mkDerivation {
  pname = "go";
  inherit version;

  src = fetchurl {
    urls = [
      "https://go.dev/dl/go${version}.src.tar.gz"
    ];
    hash = "sha256-pvP0u9PmvdYm95tmjyEvu1ZJ2vdQhPt5tnigrk2XQjs=";
  };

  buildDeps = [
    make
    go-bootstrap
  ];
  runtimeDeps = [ ];

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
        export GOROOT_BOOTSTRAP=${go-bootstrap}
        export GOROOT_FINAL=$out
        export GOCACHE=$TMPDIR/go-cache
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
        cp -a lib $out/ 2>/dev/null || true
        cp -a misc $out/ 2>/dev/null || true

        # Patch ELF binaries
        INTERP=$(patchelf --print-interpreter $(which bash))
        for f in $out/bin/* $out/pkg/tool/*/*; do
          if [ -f "$f" ] && [ ! -L "$f" ]; then
            patchelf --set-interpreter "$INTERP" "$f" 2>/dev/null || true
          fi
        done
      '';
    }
  ];

  meta = {
    description = "Go programming language";
    homepage = "https://go.dev";
    license = "BSD-3-Clause";
  };
}
