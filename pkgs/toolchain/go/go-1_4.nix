##! Go 1.4 — first Go bootstrap stage, compiled from C source
{
  mkDerivation,
  fetchurl,
  stdenv,
  buildPackages,
}: let
  pname = "go-1_4";
  version = "1.4-bootstrap-20171003";

  src = fetchurl {
    urls = [
      "https://go.dev/dl/go1.4-bootstrap-20171003.tar.gz"
    ];
    hash = "sha256-9P9bXrOjyuHJk3I/PqtRnFuuGIZrXl+W/hEC8MtcPlI=";
  };
in
  if stdenv.hostPlatform.isDarwin
  then
    import ./_go-darwin.nix {
      inherit mkDerivation pname version src stdenv;
      nativeGo = buildPackages.go-1_4;
      description = "Go 1.4 bootstrap — Darwin-hosted toolchain built with native Go 1.4";
    }
  else
    mkDerivation {
      inherit pname version src;

      buildDeps = [];
      runtimeDeps = [];
      dontStrip = true; # Go runtime metadata in custom ELF sections

      # The 2017-era Go 1.4 C bootstrap predates modern glibc hardening: its
      # Plan9-style p9jmp_buf is sized smaller than glibc's sigjmp_buf, so the
      # fortified __longjmp_chk aborts the dist tool with "buffer overflow
      # detected". Build the bootstrap compiler without injected hardening.
      hardeningDisable = ["all"];

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
