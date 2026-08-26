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
  stdenv,
  buildPackages,
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
  if stdenv.hostPlatform.isDarwin
  then
    import ./_rust-darwin.nix {
      inherit
        mkDerivation
        version
        buildPackages
        stdenv
        gnumake
        cmake
        ninja
        pkg-config
        python3
        openssl
        zlib
        ;
      pname = "rust-1_74";
      src = rustcSrc;
      changeId = 0;
      configFileName = "config.toml";
      nativeRust = buildPackages.rust-1_74;
      nativeLlvm = buildPackages.llvm-17;
      needsDownloadRustc = false;
      disableLld = false;
      description = "Rust 1.74.0 — Darwin-hosted bootstrap root built with native Rust 1.74";
    }
  else
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
        openssl
      ];

      # mrustc (the C++ bootstrap compiler) has an out-of-bounds
      # std::vector::operator[] access that _GLIBCXX_ASSERTIONS turns from
      # silent undefined behavior into an abort. Disable the libstdc++
      # assertions for this third-party C++ codebase; this is not a Rust
      # language-level opt-out.
      hardeningDisable = ["glibcxxassertions"];

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
              '*)            exit 1 ;;' \
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

            # Symlink the tarball so minicargo.mk doesn't try to download with curl
            ln -sf ${rustcSrc} rustc-${version}-src.tar.gz
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
            # Fix arc4random: cmake detects it in glibc but the header doesn't declare it.
            # Add cmake flag to prevent LLVM from trying to use arc4random.
            sed -i '/LLVM_CMAKE_OPTS += CMAKE_BUILD_TYPE/a LLVM_CMAKE_OPTS += HAVE_DECL_ARC4RANDOM=0\nLLVM_CMAKE_OPTS += BUILD_SHARED_LIBS=OFF\nLLVM_CMAKE_OPTS += LLVM_BUILD_EXAMPLES=OFF\nLLVM_CMAKE_OPTS += LLVM_ENABLE_PLUGINS=OFF\nLLVM_CMAKE_OPTS += LLVM_ENABLE_PIC=ON' minicargo.mk

            export RUSTC_VERSION=${version}
            export MRUSTC_TARGET_VER=1.74
            export OUTDIR_SUF=-${version}
            export PARLEVEL=$NIX_BUILD_CORES

            # openssl-sys build script needs these to find OpenSSL
            export OPENSSL_DIR=${openssl}
            export OPENSSL_LIB_DIR=${openssl}/lib
            export OPENSSL_INCLUDE_DIR=${openssl}/include
            export OPENSSL_NO_VENDOR=1
            export OPENSSL_STATIC=0

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

            # The Makefile sets LD_LIBRARY_PATH=$(abspath $(LIBDIR)), overriding any
            # external value. Patch it to also include OpenSSL/zlib for cargo to work.
            sed -i 's|LD_LIBRARY_PATH=\$(abspath \$(LIBDIR))|LD_LIBRARY_PATH=${openssl}/lib:${zlib}/lib:\$(abspath \$(LIBDIR))|' Makefile

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

                    # Set up LD_LIBRARY_PATH for all binaries via wrapper scripts.
                    # We don't have patchelf, so use wrappers instead.
                    LIB_PATH="$out/lib:$out/lib/rustlib/x86_64-unknown-linux-gnu/lib:${zlib}/lib:${openssl}/lib"

                    # Wrap ELF binaries in bin/
                    for f in $out/bin/*; do
                      if [ -f "$f" ] && [ ! -L "$f" ]; then
                        # Check if it's a shell script or ELF binary
                        if head -c4 "$f" | grep -q "ELF"; then
                          mv "$f" "$f.unwrapped"
                          cat > "$f" <<WRAP
            #!/bin/sh
            export LD_LIBRARY_PATH="$LIB_PATH''${LD_LIBRARY_PATH:+:}''${LD_LIBRARY_PATH:-}"
            exec "$f.unwrapped" "\$@"
            WRAP
                          chmod +x "$f"
                        elif head -1 "$f" | grep -q '^#!'; then
                          # Shell wrapper from run_rustc — fix LD_LIBRARY_PATH
                          sed -i "s|LD_LIBRARY_PATH=\"[^\"]*\"|LD_LIBRARY_PATH=\"$LIB_PATH\"|" "$f"
                        fi
                      fi
                    done
          '';
        }
      ];

      meta = {
        description = "Rust 1.74.0 — bootstrapped from C++ via mrustc (root of Rust bootstrap chain)";
        homepage = "https://github.com/thepowersgang/mrustc";
        license = "MIT OR Apache-2.0";
      };
    }
