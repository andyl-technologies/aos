##! Rust 1.74.0 — bootstrapped from C++ via mrustc (root of Rust bootstrap chain)
##! mrustc is an alternative Rust compiler written in C++ that translates Rust
##! source to C, then compiles with GCC. This builds rustc 1.74.0 + cargo
##! entirely from C++ source with no pre-existing Rust compiler.
{
  mkDerivation,
  fetchurl,
  gnumake,
  cmake,
  ninja,
  python3,
  pkg-config,
  bash,
  which,
  zlib,
  openssl,
}: let
  version = "1.74.0";
  mrustcVersion = "0.11.2";

  rustcSrc = fetchurl {
    urls = [
      "https://static.rust-lang.org/dist/rustc-${version}-src.tar.gz"
    ];
    hash = "sha256-iCtYS8Mhxdz+d82qafJ3kGuTYlXveAj81cdJKSXPEEk=";
  };
in
  mkDerivation {
    pname = "rust-1_74";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/thepowersgang/mrustc/archive/refs/tags/v${mrustcVersion}.tar.gz"
      ];
      hash = "sha256-uvHoYxHgBKY4s1cwtNfnJkSTimu7v2WoYiRbkrpTJa0=";
    };

    buildDeps = [
      gnumake
      cmake
      ninja
      python3
      pkg-config
      bash
      which
      zlib
      openssl
    ];
    runtimeDeps = [
      zlib
    ];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd mrustc-${mrustcVersion}
        '';
      }
      {
        name = "patch";
        script = ''
          # Create a fake git that returns static version info.
          # The Makefile uses $(shell git ...) to embed version metadata
          # into version.o — without .git these would fail.
          mkdir -p .fake-bin
          printf '%s\n' '#!/bin/sh' \
            'case "$1" in' \
            'show)         echo "v${mrustcVersion}" ;;' \
            'symbolic-ref) echo "v${mrustcVersion}" ;;' \
            'describe)     echo "v${mrustcVersion}" ;;' \
            'diff-index)   exit 0 ;;' \
            '*)            exit 0 ;;' \
            'esac' > .fake-bin/git
          chmod +x .fake-bin/git
          export PATH="$PWD/.fake-bin:$PATH"

          # The Makefile requires SHELL = bash; point it to our bash
          sed -i "s|^SHELL = bash|SHELL = ${bash}/bin/bash|" Makefile

          # Extract and patch rustc source
          tar xf ${rustcSrc}
          cd rustc-${version}-src
          patch -p0 < ../rustc-${version}-src.patch
          cd ..

          # Create the dl-version marker so minicargo.mk skips the download step
          touch rustc-${version}-src/dl-version
        '';
      }
      {
        name = "build-mrustc";
        script = ''
          # Build mrustc (the C++ Rust compiler)
          make -j$NIX_BUILD_CORES V=
          # Build minicargo (minimal cargo replacement)
          make -C tools/minicargo -j$NIX_BUILD_CORES V=
        '';
      }
      {
        name = "build-rustc";
        script = ''
          export RUSTC_VERSION=${version}
          export MRUSTC_TARGET_VER=1.74
          export OUTDIR_SUF=-${version}
          export PARLEVEL=$NIX_BUILD_CORES

          # Build standard libraries
          make -f minicargo.mk LIBS -j$NIX_BUILD_CORES

          # Build rustc using mrustc (this also builds LLVM via cmake)
          RUSTC_INSTALL_BINDIR=bin make -f minicargo.mk "output-${version}/rustc" -j$NIX_BUILD_CORES

          # Build cargo using mrustc
          LIBGIT2_SYS_USE_PKG_CONFIG=1 make -f minicargo.mk "output-${version}/cargo" -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "build-bootstrap";
        script = ''
          cd run_rustc

          # Run the 4-stage internal bootstrap:
          # 1. Build libstd with minicargo + mrustc-built rustc
          # 2. Build libstd again with cargo
          # 3. Build rustc with cargo (optimized)
          # 4. Build libstd with new rustc (matching ABI)
          make -j$NIX_BUILD_CORES RUSTC_VERSION=${version} PARLEVEL=$NIX_BUILD_CORES

          cd ..
        '';
      }
      {
        name = "install";
        script = ''
          PREFIX="run_rustc/output-${version}/prefix"

          mkdir -p $out/bin $out/lib

          # Copy the bootstrapped compiler and standard library
          cp -a "$PREFIX"/* $out/

          # Patch ELF binaries with correct dynamic linker and rpath
          INTERP=$(patchelf --print-interpreter $(which bash))
          BT_LIB=$(dirname "$INTERP")

          # Find the GCC libstdc++ directory for RPATH
          STDCXX_DIR=""
          STDCXX=$(find "$BT_LIB" -name 'libstdc++.so.6' -type f 2>/dev/null | head -1 || true)
          if [ -n "$STDCXX" ]; then
            STDCXX_DIR=$(dirname "$STDCXX")
          fi

          RPATH="$out/lib:${zlib}/lib:${openssl}/lib:$BT_LIB"
          if [ -n "$STDCXX_DIR" ]; then
            RPATH="$RPATH:$STDCXX_DIR"
          fi

          # Patch top-level binaries
          for f in $out/bin/*; do
            if [ -f "$f" ] && [ ! -L "$f" ]; then
              patchelf --set-interpreter "$INTERP" --set-rpath "$RPATH" "$f" 2>/dev/null || true
            fi
          done

          # Patch shared libraries
          for f in $out/lib/*.so $out/lib/*.so.*; do
            if [ -f "$f" ] && [ ! -L "$f" ]; then
              patchelf --set-rpath "$RPATH" "$f" 2>/dev/null || true
            fi
          done

          # Patch rustlib binaries and libraries
          if [ -d "$out/lib/rustlib" ]; then
            find $out/lib/rustlib -type f -executable | while read f; do
              patchelf --set-interpreter "$INTERP" --set-rpath "$RPATH" "$f" 2>/dev/null || true
            done
            find $out/lib/rustlib -name '*.so' -type f | while read f; do
              patchelf --set-rpath "$RPATH" "$f" 2>/dev/null || true
            done
          fi

          # The run_rustc output may produce a shell wrapper for rustc.
          # If bin/rustc is a shell script, patch it to use absolute paths.
          if [ -f "$out/bin/rustc" ] && head -1 "$out/bin/rustc" | grep -q '^#!'; then
            # It is a wrapper script; rewrite LD_LIBRARY_PATH to use $out paths
            ${bash}/bin/bash -c '
              sed -i "s|LD_LIBRARY_PATH=\"[^\"]*\"|LD_LIBRARY_PATH=\"'"$out"'/lib\"|" '"$out"'/bin/rustc
            '
          fi
        '';
      }
    ];

    meta = {
      description = "Rust 1.74.0 — bootstrapped from C++ via mrustc (root of Rust bootstrap chain)";
      homepage = "https://github.com/thepowersgang/mrustc";
      license = "MIT OR Apache-2.0";
    };
  }
