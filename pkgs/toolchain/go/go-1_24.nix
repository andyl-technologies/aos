##! Go 1.24 — fifth Go bootstrap stage, built with Go 1.22
{
  mkDerivation,
  fetchurl,
  go-1_22,
  stdenv,
  buildPackages,
}: let
  version = "1.24.13";
  src = fetchurl {
    urls = [
      "https://go.dev/dl/go${version}.src.tar.gz"
    ];
    hash = "sha256-Y5piBMJIaxN98etueO4+0Dj5h30OS1pGXnlqIVP4WNc=";
  };
in
  if stdenv.hostPlatform.isDarwin
  then
    import ./_go-darwin.nix {
      inherit mkDerivation version src stdenv;
      pname = "go-1_24";
      nativeGo = buildPackages.go-1_24;
      description = "Go 1.24 bootstrap — Darwin-hosted toolchain built with native Go 1.24";
    }
  else
    mkDerivation {
      pname = "go-1_24";
      inherit version;

      inherit src;

      buildDeps = [go-1_22];
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
            export GOROOT_BOOTSTRAP=${go-1_22}
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
        description = "Go 1.24 bootstrap — built with Go 1.22";
        homepage = "https://go.dev";
        license = "BSD-3-Clause";
      };
    }
