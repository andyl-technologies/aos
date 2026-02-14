# Rust bootstrap — pre-built binary for bootstrapping the Rust compiler
{
  mkDerivation,
  fetchurl,
  lib,
  bash,
  which,
}:

let
  version = "1.83.0";

  arch =
    if lib.system == "aarch64-linux" then "aarch64-unknown-linux-gnu" else "x86_64-unknown-linux-gnu";

  archFiles = {
    "x86_64-linux" = {
      hash = "sha256-tkZ6DopsXco1JpeFyZTk2A2JdU1sYAFizJFG+QyH7gg=";
    };
    "aarch64-linux" = {
      hash = "sha256-XwLgC8pl9u66/irGsbvey18WDyYKnCIxpR7Y04LwraA=";
    };
  };

  files = archFiles.${lib.system} or (throw "rust-bootstrap: unsupported system '${lib.system}'");
in
mkDerivation {
  pname = "rust-bootstrap";
  inherit version;

  src = fetchurl {
    urls = [
      "https://static.rust-lang.org/dist/rust-${version}-${arch}.tar.xz"
    ];
    hash = files.hash;
  };

  buildDeps = [
    bash
    which
  ];
  runtimeDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd rust-${version}-${arch}
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p $out
        bash ./install.sh --prefix=$out --disable-ldconfig

        # Patch ELF binaries with the correct dynamic linker and rpath
        INTERP=$(patchelf --print-interpreter $(which bash))
        BT_LIB=$(dirname "$INTERP")
        for f in $out/bin/* $out/libexec/*; do
          if [ -f "$f" ] && [ ! -L "$f" ]; then
            patchelf --set-interpreter "$INTERP" --set-rpath "$out/lib:$BT_LIB" "$f" 2>/dev/null || true
          fi
        done
        for f in $out/lib/*.so $out/lib/*.so.*; do
          if [ -f "$f" ] && [ ! -L "$f" ]; then
            patchelf --set-rpath "$out/lib:$BT_LIB" "$f" 2>/dev/null || true
          fi
        done
      '';
    }
  ];

  meta = {
    description = "Rust bootstrap — pre-built binary for compiler bootstrapping";
    homepage = "https://www.rust-lang.org";
    license = "MIT OR Apache-2.0";
  };
}
