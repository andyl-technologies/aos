##! Rust bootstrap — pre-built binary for bootstrapping the Rust compiler
{
  mkDerivation,
  fetchurl,
  lib,
  bash,
  which,
}:

let
  version = "1.92.0";

  arch =
    if lib.system == "aarch64-linux" then "aarch64-unknown-linux-gnu" else "x86_64-unknown-linux-gnu";

  archFiles = {
    "x86_64-linux" = {
      hash = "sha256-bl79bCWVOycy1OaxhCUSU2ZQxoz3KouZoPxWYBLdbKU=";
    };
    "aarch64-linux" = {
      hash = "sha256-yBIChCPD1917qZ9mEB6eGqP2bqtEoShfQcNjgl1J3KQ=";
    };
  };

  files = archFiles.${lib.system} or (throw "rust-bootstrap: unsupported system '${lib.system}'");
in
mkDerivation {
  pname = "rust-bootstrap";
  inherit version;

  src = fetchurl {
    urls = [
      "https://static.rust-lang.org/dist/rust-${version}-${arch}.tar.gz"
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
        # Patch top-level binaries
        for f in $out/bin/* $out/libexec/*; do
          if [ -f "$f" ] && [ ! -L "$f" ]; then
            patchelf --set-interpreter "$INTERP" --set-rpath "$out/lib:$BT_LIB" "$f" 2>/dev/null || true
          fi
        done
        # Patch rustlib binaries (rust-lld, gcc-ld/ld.lld, llvm tools, etc.)
        find $out/lib/rustlib -type f -executable | while read f; do
          patchelf --set-interpreter "$INTERP" --set-rpath "$out/lib:$BT_LIB" "$f" 2>/dev/null || true
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
