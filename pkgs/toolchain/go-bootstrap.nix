# Go bootstrap — pre-built binary for bootstrapping the Go compiler
{
  mkDerivation,
  fetchurl,
  lib,
}:

let
  version = "1.22.12";

  archFiles = {
    "x86_64-linux" = {
      url = "https://go.dev/dl/go${version}.linux-amd64.tar.gz";
      hash = "sha256-T6T4abD3/Gux6yZg50ZX+/BM3SkLWu+QVYXIYFGzTUM=";
    };
    "aarch64-linux" = {
      url = "https://go.dev/dl/go${version}.linux-arm64.tar.gz";
      hash = "sha256-/QF+ZH7ChSXoauggMjbgZTJCcip0NpKbH3dXROJieOc=";
    };
  };

  files = archFiles.${lib.system} or (throw "go-bootstrap: unsupported system '${lib.system}'");
in
mkDerivation {
  pname = "go-bootstrap";
  inherit version;

  src = fetchurl {
    urls = [ files.url ];
    hash = files.hash;
  };

  buildDeps = [ ];
  runtimeDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p $out
        cp -a go/* $out/

        # Patch ELF binaries to use the AOS sandbox dynamic linker
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
    description = "Go bootstrap — pre-built binary for compiler bootstrapping";
    homepage = "https://go.dev";
    license = "BSD-3-Clause";
  };
}
