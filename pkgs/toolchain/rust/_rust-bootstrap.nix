##! Shared builder for intermediate Rust bootstrap compilers.
##! Underscore prefix = not auto-discovered. Imported by rust-1_XX.nix files.
{
  fetchurl,
  mkDerivation,
  gnumake,
  cmake,
  ninja,
  pkg-config,
  python3,
  bash,
  which,
  openssl,
  zlib,
}:
{
  version,
  srcHash,
  changeId,
  prevRust,
  needsDownloadRustc ? false,
  useBootstrapToml ? false,
}:
let
  configFileName = if useBootstrapToml then "bootstrap.toml" else "config.toml";
in
mkDerivation {
  pname = "rust-${builtins.replaceStrings [ "." ] [ "_" ] (builtins.substring 0 4 version)}";
  inherit version;

  src = fetchurl {
    urls = [
      "https://static.rust-lang.org/dist/rustc-${version}-src.tar.gz"
    ];
    hash = srcHash;
  };

  buildDeps = [
    gnumake
    cmake
    ninja
    pkg-config
    python3
    bash
    which
    prevRust
    openssl
  ];
  runtimeDeps = [ zlib ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd rustc-${version}-src
      '';
    }
    {
      name = "configure";
      script = ''
        # Fake git so x.py doesn't panic
        mkdir -p .fake-bin
        printf '#!/bin/sh\nexit 0\n' > .fake-bin/git
        chmod +x .fake-bin/git
        export PATH="$PWD/.fake-bin:$PATH"

        cat > ${configFileName} << TOML
        change-id = ${toString changeId}

        [llvm]
        download-ci-llvm = false

        [build]
        docs = false
        extended = true
        tools = ["cargo"]
        vendor = true
        cargo = "${prevRust}/bin/cargo"
        rustc = "${prevRust}/bin/rustc"

        [install]
        prefix = "$out"
        sysconfdir = "etc"

        [rust]
        channel = "stable"
        codegen-units = 0
        rpath = true
        omit-git-hash = true
        ${if needsDownloadRustc then "download-rustc = false" else ""}
        TOML
      '';
    }
    {
      name = "build";
      script = ''
        export PATH="$PWD/.fake-bin:$PATH"
        python3 x.py build -j $NIX_BUILD_CORES
      '';
    }
    {
      name = "install";
      script = ''
        export PATH="$PWD/.fake-bin:$PATH"
        python3 x.py install

        INTERP=$(patchelf --print-interpreter $(which bash))
        BT_LIB=$(dirname "$INTERP")
        for f in $out/bin/*; do
          if [ -f "$f" ] && [ ! -L "$f" ]; then
            patchelf --set-interpreter "$INTERP" --set-rpath "$out/lib:$BT_LIB" "$f" 2>/dev/null || true
          fi
        done
        find $out/lib -type f -executable 2>/dev/null | while read f; do
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
    description = "Rust ${version} — bootstrap chain intermediate";
    homepage = "https://www.rust-lang.org";
    license = "MIT OR Apache-2.0";
  };
}
