##! Shared builder for LLVM toolchain versions.
##! Underscore prefix = not auto-discovered. Imported by llvm-XX.nix files.
{
  mkDerivation,
  fetchurl,
  gnumake,
  cmake,
  ninja,
  python3,
  zlib,
  bootstrapTools,
}: {
  version,
  srcHash,
  # Projects (LLVM_ENABLE_PROJECTS)
  projects ? [
    "clang"
    "lld"
    "clang-tools-extra"
  ],
  # Runtimes (LLVM_ENABLE_RUNTIMES) — built with the just-built clang
  runtimes ? [
    "compiler-rt"
    "libunwind"
    "libcxxabi"
    "libcxx"
  ],
  # Target architectures
  targets ? [
    "X86"
    "AArch64"
    "BPF"
  ],
  # Version-specific workarounds
  needsArc4randomFix ? true,
  extraCmakeFlags ? [],
}: let
  projectsStr = builtins.concatStringsSep ";" projects;
  runtimesStr = builtins.concatStringsSep ";" runtimes;
  targetsStr = builtins.concatStringsSep ";" targets;
  extraFlagsStr = builtins.concatStringsSep " " extraCmakeFlags;
in
  mkDerivation {
    pname = "llvm";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/llvm/llvm-project/releases/download/llvmorg-${version}/llvm-project-${version}.src.tar.xz"
      ];
      hash = srcHash;
    };

    buildDeps = [
      gnumake
      cmake
      ninja
      python3
    ];
    runtimeDeps = [zlib];

    # Builds LLVM, clang, lld, compiler-rt, libunwind, libcxxabi and libcxx
    # together. Keep Fortify at level 2 and avoid x86 shadow stack for the
    # compiler toolchain package.
    hardeningDisable = [
      "fortify3"
      "shadowstack"
    ];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd llvm-project-${version}.src
        '';
      }
      {
        name = "configure";
        script = ''
          ${
            if needsArc4randomFix
            then ''
              # Fix arc4random not being visible in C++ — include stdlib.h directly
              sed -i '/#include.*Process\.inc/i #include <stdlib.h>' llvm/lib/Support/Process.cpp 2>/dev/null || true
              if grep -q 'arc4random' llvm/lib/Support/Unix/Process.inc; then
                sed -i '1i #include <stdlib.h>' llvm/lib/Support/Unix/Process.inc
              fi
            ''
            else ""
          }
          ${
            if runtimes != []
            then ''
              # Create clang config file so the just-built clang finds AOS
              # GCC toolchain and libraries when building runtimes.
              # Read real GCC/glibc paths from ccWrapper's nix-support files.
              # Headers live in glibc.dev (multi-output split); shared libs
              # and crt*.o stay in glibc.out.
              BT="${bootstrapTools}"
              REAL_CC=$(cat "$BT/nix-support/orig-cc")
              REAL_LIBC=$(cat "$BT/nix-support/orig-libc")
              REAL_LIBC_DEV=$(cat "$BT/nix-support/orig-libc-dev")
              GCC_DIR=$(echo "$REAL_CC"/lib/gcc/x86_64-unknown-linux-gnu/*)
              mkdir -p build/clang-cfg
              DL=$(echo "$REAL_LIBC"/lib/ld-linux-x86-64.so.*)
              {
                echo "--gcc-install-dir=$GCC_DIR"
                # Use -idirafter so glibc headers come AFTER GCC C++ headers
                # (needed for #include_next <stdlib.h> in cstdlib to work)
                echo "-idirafter"
                echo "$REAL_LIBC_DEV/include"
                echo "-B$REAL_LIBC/lib"
                echo "-B$GCC_DIR"
                echo "-L$REAL_LIBC/lib"
                echo "-L$REAL_CC/lib"
                echo "-L$REAL_CC/lib64"
                echo "-Wl,-dynamic-linker=$DL"
                echo "-Wl,-rpath,$REAL_LIBC/lib"
                echo "-Wl,-rpath,$REAL_CC/lib"
              } > build/clang-cfg/x86_64-unknown-linux-gnu.cfg
            ''
            else ""
          }
          cmake -S llvm -B build -G Ninja \
            -DCMAKE_BUILD_TYPE=Release \
            -DCMAKE_INSTALL_PREFIX=$out \
            -DLLVM_ENABLE_PROJECTS="${projectsStr}" \
            ${
            if runtimes != []
            then ''-DLLVM_ENABLE_RUNTIMES="${runtimesStr}"''
            else ""
          } \
            -DLLVM_TARGETS_TO_BUILD="${targetsStr}" \
            -DLLVM_LINK_LLVM_DYLIB=ON \
            -DLLVM_INSTALL_UTILS=ON \
            -DLLVM_ENABLE_ZLIB=FORCE_ON \
            -DZLIB_INCLUDE_DIR=${zlib}/include \
            -DZLIB_LIBRARY=${zlib}/lib/libz.so \
            -DLLVM_ENABLE_TERMINFO=OFF \
            -DLLVM_ENABLE_LIBXML2=OFF \
            -DLLVM_ENABLE_LIBEDIT=OFF \
            -DLLVM_INCLUDE_BENCHMARKS=OFF \
            -DLLVM_INCLUDE_EXAMPLES=OFF \
            -DLLVM_INCLUDE_TESTS=OFF \
            -DLLVM_INCLUDE_DOCS=OFF \
            -DCOMPILER_RT_DEFAULT_TARGET_ONLY=ON \
            ${
            if runtimes != []
            then ''
              -DDEFAULT_SYSROOT=/ \
              -DCLANG_CONFIG_FILE_SYSTEM_DIR=$PWD/build/clang-cfg \
            ''
            else ""
          } \
            ${
            if needsArc4randomFix
            then "-DHAVE_DECL_ARC4RANDOM=0"
            else ""
          } \
            ${extraFlagsStr}
        '';
      }
      {
        name = "build";
        script = ''
          ninja -C build -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          ninja -C build install

          # LLVM 22 moved PassPlugin.h from llvm/Passes/ to llvm/Plugins/.
          # Create backward-compat symlink for consumers expecting the old path
          # (e.g. Rust's llvm-wrapper/PassWrapper.cpp).
          if [ -f "$out/include/llvm/Plugins/PassPlugin.h" ] && \
             [ ! -f "$out/include/llvm/Passes/PassPlugin.h" ]; then
            ln -s ../Plugins/PassPlugin.h "$out/include/llvm/Passes/PassPlugin.h"
          fi
        '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      compile-c = testing.mkVMTest {
        name = "toolchain-llvm-compile-c";
        rootfsDeps = [self];
        testScript = ''
          cat > /tmp/hello.c << 'EOF'
          #include <stdio.h>
          int main(void) {
              printf("clang-c-ok\n");
              return 0;
          }
          EOF

          BT="${builtins.toString pkgs.bootstrapTools}"
          DL=$(ls $BT/lib/ld-linux-*.so.* | head -1)
          GCC_VER=$(ls "$BT/lib/gcc/x86_64-unknown-linux-gnu/")
          clang \
            --sysroot=/ \
            -B$BT/lib \
            -B$BT/lib/gcc/x86_64-unknown-linux-gnu/$GCC_VER \
            -isystem $BT/include-glibc \
            -L$BT/lib \
            -Wl,-dynamic-linker=$DL \
            -Wl,-rpath,$BT/lib \
            -o /tmp/hello /tmp/hello.c
          /tmp/hello
        '';
      };

      compile-cpp = testing.mkVMTest {
        name = "toolchain-llvm-compile-cpp";
        rootfsDeps = [self];
        testScript = ''
          cat > /tmp/test.cpp << 'EOF'
          #include <iostream>
          #include <vector>
          int main() {
              std::vector<int> v = {3, 1, 2};
              int sum = 0;
              for (int x : v) sum += x;
              if (sum != 6) return 1;
              std::cout << "clang-cpp-ok" << std::endl;
              return 0;
          }
          EOF

          BT="${builtins.toString pkgs.bootstrapTools}"
          BT_ROOT=$(dirname $BT/lib)
          CXX_VER=$(ls "$BT_ROOT/include/c++")
          DL=$(ls $BT/lib/ld-linux-*.so.* | head -1)
          clang++ \
            --sysroot=/ \
            -isystem "$BT_ROOT/include/c++/$CXX_VER" \
            -isystem "$BT_ROOT/include/c++/$CXX_VER/x86_64-unknown-linux-gnu" \
            -isystem $BT/include-glibc \
            -B$BT/lib \
            -B$BT/lib/gcc/x86_64-unknown-linux-gnu/$CXX_VER \
            -L$BT/lib \
            -L$BT/lib/gcc/x86_64-unknown-linux-gnu/$CXX_VER/ \
            -Wl,-dynamic-linker=$DL \
            -Wl,-rpath,$BT/lib \
            -o /tmp/test /tmp/test.cpp -lstdc++
          /tmp/test
        '';
      };

      libllvm = testing.mkVMTest {
        name = "toolchain-llvm-libllvm";
        rootfsDeps = [self];
        testScript = ''
          LLVM="${builtins.toString self}"

          # Verify libLLVM.so exists
          ls $LLVM/lib/libLLVM*.so > /dev/null 2>&1
          echo "==> libLLVM.so found"

          # Verify llvm-config works
          llvm-config --version
          llvm-config --libdir
          llvm-config --includedir

          LIBDIR=$(llvm-config --libdir)
          test -d "$LIBDIR"
          echo "==> llvm-config reports valid paths"
        '';
      };

      tools = testing.mkVMTest {
        name = "toolchain-llvm-tools";
        rootfsDeps = [self];
        testScript = ''
          cat > /tmp/tiny.c << 'EOF'
          int main(void) { return 0; }
          EOF

          # Compile with gcc wrapper to get a valid object file
          gcc -c -o /tmp/tiny.o /tmp/tiny.c

          LLVM="${builtins.toString self}"

          # llvm-ar: create static archive
          llvm-ar rcs /tmp/tiny.a /tmp/tiny.o
          test -f /tmp/tiny.a
          echo "  llvm-ar: OK"

          # llvm-nm: list symbols
          llvm-nm /tmp/tiny.o > /tmp/llvm-nm-out
          found_main=0
          while IFS= read -r line; do
            case "$line" in
              *main*) found_main=1 ;;
            esac
          done < /tmp/llvm-nm-out
          test "$found_main" = "1"
          echo "  llvm-nm: OK"

          # ld.lld: verify exists
          if [ -x "$LLVM/bin/ld.lld" ]; then
            ld.lld --version
            echo "  ld.lld: OK"
          else
            echo "  ld.lld: not found (skipped)"
          fi

          echo "==> LLVM tools verified"
        '';
      };

      link-openssl = testing.mkVMTest {
        name = "toolchain-llvm-link-openssl";
        rootfsDeps = [
          self
          pkgs.openssl
        ];
        testScript = ''
          cat > /tmp/ssl_test.c << 'EOF'
          #include <stdio.h>
          #include <openssl/crypto.h>
          int main(void) {
              printf("openssl-via-clang: %s\n", OpenSSL_version(OPENSSL_VERSION));
              return 0;
          }
          EOF

          BT="${builtins.toString pkgs.bootstrapTools}"
          OPENSSL="${builtins.toString pkgs.openssl}"
          DL=$(ls $BT/lib/ld-linux-*.so.* | head -1)
          GCC_VER=$(ls "$BT/lib/gcc/x86_64-unknown-linux-gnu/")

          clang \
            --sysroot=/ \
            -isystem $OPENSSL/include \
            -isystem $BT/include-glibc \
            -B$BT/lib \
            -B$BT/lib/gcc/x86_64-unknown-linux-gnu/$GCC_VER \
            -L$BT/lib \
            -L$OPENSSL/lib \
            -Wl,-dynamic-linker=$DL \
            -Wl,-rpath,$BT/lib \
            -Wl,-rpath,$OPENSSL/lib \
            -o /tmp/ssl_test /tmp/ssl_test.c -lcrypto
          /tmp/ssl_test
        '';
      };
    };

    meta = {
      description = "LLVM ${version} compiler infrastructure";
      homepage = "https://llvm.org";
      license = "Apache-2.0";
    };
  }
