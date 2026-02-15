##! Rust — the Rust programming language, built from source
{
  mkDerivation,
  fetchurl,
  make,
  cmake,
  ninja,
  pkg-config,
  python3,
  bash,
  which,
  llvm,
  rust-bootstrap,
  openssl,
  zlib,
}:

let
  version = "1.84.0";
in
mkDerivation {
  pname = "rust";
  inherit version;

  src = fetchurl {
    urls = [
      "https://static.rust-lang.org/dist/rustc-${version}-src.tar.xz"
    ];
    hash = "sha256-vCwWOfJoFMexejI5kvHgjDsB/ojN/5on2VGYfYhuALM=";
  };

  buildDeps = [
    make
    cmake
    ninja
    pkg-config
    python3
    bash
    which
    rust-bootstrap
    llvm
    openssl
  ];
  runtimeDeps = [
    llvm
    zlib
  ];

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
        # Create a fake git wrapper so x.py doesn't panic when running git commands
        mkdir -p .fake-bin
        printf '#!/bin/sh\nexit 0\n' > .fake-bin/git
        chmod +x .fake-bin/git
        export PATH="$PWD/.fake-bin:$PATH"
        cat > config.toml << TOML
        change-id = 133207

        [llvm]
        link-shared = true
        download-ci-llvm = false

        [build]
        docs = false
        extended = true
        tools = ["cargo"]
        vendor = true
        cargo = "${rust-bootstrap}/bin/cargo"
        rustc = "${rust-bootstrap}/bin/rustc"

        [install]
        prefix = "$out"
        sysconfdir = "etc"

        [rust]
        channel = "stable"
        codegen-units = 0
        rpath = true
        omit-git-hash = true
        download-rustc = false

        [target.x86_64-unknown-linux-gnu]
        llvm-config = "${llvm}/bin/llvm-config"

        [target.aarch64-unknown-linux-gnu]
        llvm-config = "${llvm}/bin/llvm-config"
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

        # Patch ELF binaries
        INTERP=$(patchelf --print-interpreter $(which bash))
        BT_LIB=$(dirname "$INTERP")
        for f in $out/bin/*; do
          if [ -f "$f" ] && [ ! -L "$f" ]; then
            patchelf --set-interpreter "$INTERP" --set-rpath "$out/lib:${llvm}/lib:${openssl}/lib:${zlib}/lib:$BT_LIB" "$f" 2>/dev/null || true
          fi
        done
      '';
    }
  ];

  meta = {
    description = "Rust programming language — compiler and cargo";
    homepage = "https://www.rust-lang.org";
    license = "MIT OR Apache-2.0";
  };
}
