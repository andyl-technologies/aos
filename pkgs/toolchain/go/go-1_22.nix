##! Go 1.22 — fourth Go bootstrap stage, built with Go 1.20
{
  mkDerivation,
  fetchurl,
  go-1_20,
}: let
  version = "1.22.12";
in
  mkDerivation {
    pname = "go-1_22";
    inherit version;

    src = fetchurl {
      urls = [
        "https://go.dev/dl/go${version}.src.tar.gz"
      ];
      hash = "sha256-ASp+HzfzYsCRjB36MzRFisLaFijEuc9NnKAtuYbhfXE=";
    };

    buildDeps = [go-1_20];
    runtimeDeps = [];

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
          export GOROOT_BOOTSTRAP=${go-1_20}
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

          # Patch ELF binaries
          INTERP=$(patchelf --print-interpreter "$CONFIG_SHELL")
          for f in $out/bin/* $out/pkg/tool/*/*; do
            if [ -f "$f" ] && [ ! -L "$f" ]; then
              patchelf --set-interpreter "$INTERP" "$f" 2>/dev/null || true
            fi
          done
        '';
      }
    ];

    meta = {
      description = "Go 1.22 bootstrap — built with Go 1.20";
      homepage = "https://go.dev";
      license = "BSD-3-Clause";
    };
  }
