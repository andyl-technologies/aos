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
  stdenv,
  buildPackages,
}: {
  version,
  srcHash,
  changeId,
  prevRust,
  llvm,
  needsDownloadRustc ? false,
  useBootstrapToml ? false,
  disableLld ? false,
}: let
  configFileName =
    if useBootstrapToml
    then "bootstrap.toml"
    else "config.toml";
  pname = "rust-${builtins.replaceStrings ["."] ["_"] (builtins.substring 0 4 version)}";
  src = fetchurl {
    urls = [
      "https://static.rust-lang.org/dist/rustc-${version}-src.tar.gz"
    ];
    hash = srcHash;
  };
in
  if stdenv.hostPlatform.isDarwin
  then
    import ./_rust-darwin.nix {
      inherit
        mkDerivation
        pname
        version
        src
        changeId
        configFileName
        buildPackages
        stdenv
        gnumake
        cmake
        ninja
        pkg-config
        python3
        openssl
        zlib
        needsDownloadRustc
        disableLld
        ;
      nativeRust = buildPackages.${prevRust.pname};
      nativeLlvm = buildPackages.${llvm.pname};
      description = "Rust ${version} — Darwin-hosted bootstrap chain intermediate";
    }
  else
    mkDerivation {
      inherit pname version src;

      buildDeps = [
        gnumake
        cmake
        ninja
        pkg-config
        python3
        bash
        which
        prevRust
        llvm
        openssl
      ];
      runtimeDeps = [zlib openssl llvm];

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
            # Fix arc4random: cmake detects it in glibc but the header doesn't
            # declare it. Force the check result to 0.
            # Now that we link external LLVM via llvm-config, the vendored LLVM is
            # not built; this fix is a harmless no-op kept for robustness.
            sed -i 's/check_symbol_exists(arc4random "stdlib.h" HAVE_DECL_ARC4RANDOM)/set(HAVE_DECL_ARC4RANDOM 0 CACHE BOOL "")/' \
              src/llvm-project/llvm/cmake/config-ix.cmake 2>/dev/null || true

            # Fake git so x.py doesn't panic.
            # Must return exit 1 for unknown commands (especially rev-parse),
            # otherwise bootstrap tries canonicalize("") and panics.
            mkdir -p .fake-bin
            printf '#!/bin/sh\nexit 1\n' > .fake-bin/git
            chmod +x .fake-bin/git
            export PATH="$PWD/.fake-bin:$PATH"

            cat > ${configFileName} << TOML
            change-id = ${toString changeId}

            [llvm]
            link-shared = true
            download-ci-llvm = false

            [target.x86_64-unknown-linux-gnu]
            llvm-config = "${llvm}/bin/llvm-config"

            [target.aarch64-unknown-linux-gnu]
            llvm-config = "${llvm}/bin/llvm-config"

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
            ${
              if needsDownloadRustc
              then "download-rustc = false"
              else ""
            }
            ${
              if disableLld
              then "lld = false\n        use-lld = false"
              else ""
            }
            TOML
          '';
        }
        {
          name = "build";
          script = ''
            export PATH="$PWD/.fake-bin:$PATH"
            export RUST_BACKTRACE=1

            # openssl-sys build script needs these to find OpenSSL
            export OPENSSL_DIR=${openssl}
            export OPENSSL_LIB_DIR=${openssl}/lib
            export OPENSSL_INCLUDE_DIR=${openssl}/include
            export OPENSSL_NO_VENDOR=1
            export OPENSSL_STATIC=0

            python3 x.py build -j $NIX_BUILD_CORES
          '';
        }
        {
          name = "install";
          script = ''
                    export PATH="$PWD/.fake-bin:$PATH"
                    export OPENSSL_DIR=${openssl}
                    export OPENSSL_LIB_DIR=${openssl}/lib
                    export OPENSSL_INCLUDE_DIR=${openssl}/include
                    export OPENSSL_NO_VENDOR=1
                    export OPENSSL_STATIC=0
                    python3 x.py install

                    # No patchelf available — use wrapper scripts (same pattern as rust-1_74.nix)
                    LIB_PATH="$out/lib:$out/lib/rustlib/x86_64-unknown-linux-gnu/lib:${llvm}/lib:${zlib}/lib:${openssl}/lib"

                    for f in $out/bin/*; do
                      if [ -f "$f" ] && [ ! -L "$f" ]; then
                        if head -c4 "$f" | grep -q "ELF"; then
                          mv "$f" "$f.unwrapped"
                          cat > "$f" <<WRAP
            #!/bin/sh
            export LD_LIBRARY_PATH="$LIB_PATH''${LD_LIBRARY_PATH:+:}''${LD_LIBRARY_PATH:-}"
            exec "$f.unwrapped" "\$@"
            WRAP
                          chmod +x "$f"
                        elif head -1 "$f" | grep -q '^#!'; then
                          sed -i "s|LD_LIBRARY_PATH=\"[^\"]*\"|LD_LIBRARY_PATH=\"$LIB_PATH\"|" "$f"
                        fi
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
