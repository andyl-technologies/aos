##! Go 1.22 — fourth Go bootstrap stage, built with Go 1.20
{
  mkDerivation,
  fetchurl,
  go-1_20,
  stdenv,
  buildPackages,
}: let
  version = "1.22.12";
  src = fetchurl {
    urls = [
      "https://go.dev/dl/go${version}.src.tar.gz"
    ];
    hash = "sha256-ASp+HzfzYsCRjB36MzRFisLaFijEuc9NnKAtuYbhfXE=";
  };
in
  if stdenv.hostPlatform.isDarwin
  then
    import ./_go-darwin.nix {
      inherit mkDerivation version src stdenv;
      pname = "go-1_22";
      nativeGo = buildPackages.go-1_22;
      description = "Go 1.22 bootstrap — Darwin-hosted toolchain built with native Go 1.22";
    }
  else
    mkDerivation {
      pname = "go-1_22";
      inherit version;

      inherit src;

      buildDeps = [go-1_20];
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
          '';
        }
      ];

      meta = {
        description = "Go 1.22 bootstrap — built with Go 1.20";
        homepage = "https://go.dev";
        license = "BSD-3-Clause";
      };
    }
