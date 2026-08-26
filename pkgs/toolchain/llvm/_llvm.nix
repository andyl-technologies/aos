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
  stdenv,
  buildPackages,
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
  isDarwinCross = stdenv.isCross && stdenv.hostPlatform.isDarwin;
  versionMatch = builtins.match "([0-9]+)\\..*" version;
  versionMajor = builtins.elemAt versionMatch 0;
  nativeLlvm = buildPackages."llvm-${versionMajor}";
  enabledRuntimes =
    if isDarwinCross
    then []
    else runtimes;
  zlibLibrary =
    if isDarwinCross
    then "${zlib}/lib/libz.dylib"
    else "${zlib}/lib/libz.so";
  projectsStr = builtins.concatStringsSep ";" projects;
  runtimesStr = builtins.concatStringsSep ";" enabledRuntimes;
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
    runtimeDeps =
      [zlib]
      ++ (
        if isDarwinCross
        then [stdenv.darwinRuntimes]
        else []
      );

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
        script =
          (
            if isDarwinCross
            then ''
              # LLVM always creates a nested NATIVE tool build when CMake is
              # cross-compiling.  Give it explicit Linux compiler launchers;
              # otherwise target hardening, SDK, and search-path variables
              # leak into the build-machine compiler probes.
              mkdir -p native-tools
              cat > native-tools/cc <<'AOS_NATIVE_CC'
              #!${buildPackages.bash}/bin/bash
              unset AOS_HARDENING_ENABLE NIX_LDFLAGS
              unset CFLAGS CXXFLAGS CPPFLAGS LDFLAGS
              unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH CPATH LIBRARY_PATH
              unset SDKROOT MACOSX_DEPLOYMENT_TARGET
              exec ${buildPackages.cc}/bin/cc "$@"
              AOS_NATIVE_CC
              cat > native-tools/c++ <<'AOS_NATIVE_CXX'
              #!${buildPackages.bash}/bin/bash
              unset AOS_HARDENING_ENABLE NIX_LDFLAGS
              unset CFLAGS CXXFLAGS CPPFLAGS LDFLAGS
              unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH CPATH LIBRARY_PATH
              unset SDKROOT MACOSX_DEPLOYMENT_TARGET
              exec ${buildPackages.cc}/bin/c++ "$@"
              AOS_NATIVE_CXX
              chmod +x native-tools/cc native-tools/c++
            ''
            else ""
          )
          + ''
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
              if enabledRuntimes != []
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
              if enabledRuntimes != []
              then ''-DLLVM_ENABLE_RUNTIMES="${runtimesStr}"''
              else ""
            } \
              -DLLVM_TARGETS_TO_BUILD="${targetsStr}" \
              ${
              if isDarwinCross
              then ''
                -DLLVM_DEFAULT_TARGET_TRIPLE=${stdenv.hostPlatform.config} \
                -DLLVM_HOST_TRIPLE=${stdenv.hostPlatform.config} \
                -DLLVM_NATIVE_TOOL_DIR=${nativeLlvm}/bin \
                -DLLVM_TABLEGEN=${nativeLlvm}/bin/llvm-tblgen \
                -DCLANG_TABLEGEN=${nativeLlvm}/bin/clang-tblgen \
                -DLLVM_CONFIG_PATH=${nativeLlvm}/bin/llvm-config \
                -DCLANG=${nativeLlvm}/bin/clang \
                -DLLVM_AS=${nativeLlvm}/bin/llvm-as \
                -DLLVM_LINK=${nativeLlvm}/bin/llvm-link \
                -DLLVM_NM=${nativeLlvm}/bin/llvm-nm \
                -DLLVM_READOBJ=${nativeLlvm}/bin/llvm-readobj \
                -DOPT=${nativeLlvm}/bin/opt \
                -DCROSS_TOOLCHAIN_FLAGS_NATIVE="-DCMAKE_C_COMPILER=$PWD/native-tools/cc;-DCMAKE_CXX_COMPILER=$PWD/native-tools/c++;-DCMAKE_BUILD_WITH_INSTALL_RPATH=ON" \
                -DLLVM_USE_HOST_TOOLS=ON \
              ''
              else ""
            } \
              -DLLVM_LINK_LLVM_DYLIB=ON \
              -DLLVM_INSTALL_UTILS=ON \
              -DLLVM_ENABLE_ZLIB=FORCE_ON \
              -DZLIB_INCLUDE_DIR=${zlib}/include \
              -DZLIB_LIBRARY=${zlibLibrary} \
              -DLLVM_ENABLE_TERMINFO=OFF \
              -DLLVM_ENABLE_LIBXML2=OFF \
              -DLLVM_ENABLE_LIBEDIT=OFF \
              -DLLVM_INCLUDE_BENCHMARKS=OFF \
              -DLLVM_INCLUDE_EXAMPLES=OFF \
              -DLLVM_INCLUDE_TESTS=OFF \
              -DLLVM_INCLUDE_DOCS=OFF \
              -DCOMPILER_RT_DEFAULT_TARGET_ONLY=ON \
              ${
              if enabledRuntimes != []
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
              ${extraFlagsStr} \
              $cmakeFlags${
              if isDarwinCross
              then " \\\n            -DCMAKE_TRY_COMPILE_TARGET_TYPE=EXECUTABLE"
              else ""
            }
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

          ${
            if isDarwinCross
            then ''
              # compiler-rt, libc++, libc++abi and libunwind were bootstrapped
              # before this target LLVM so no Darwin executable has to run
              # while cross-compiling.  Install that exact runtime surface as
              # part of the complete Darwin LLVM toolchain.
              cp -a ${stdenv.darwinRuntimes}/include/. "$out/include/"
              cp -a ${stdenv.darwinRuntimes}/lib/. "$out/lib/"

              # LLVM and the copied runtime install some directories without
              # owner write permission. The following scrub phase creates an
              # adjacent temporary file for each Mach-O before atomically
              # replacing it, so make this build output writable while it is
              # still owned by the sandbox builder. Nix canonicalizes store
              # permissions after the derivation completes.
              chmod -R u+w "$out"
            ''
            else ""
          }

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
          REAL_CC=$(cat "$BT/nix-support/orig-cc")
          REAL_LIBC=$(cat "$BT/nix-support/orig-libc")
          REAL_LIBC_DEV=$(cat "$BT/nix-support/orig-libc-dev")
          DL=$(cat "$BT/nix-support/dynamic-linker")
          GCC_DIR=$(echo "$REAL_CC"/lib/gcc/x86_64-unknown-linux-gnu/*)
          # --sysroot=/ points at the Firecracker guest rootfs assembled for
          # this VM test, not at the host filesystem or Nix build sandbox root.
          clang \
            --sysroot=/ \
            -B$REAL_LIBC/lib \
            -B$GCC_DIR \
            -isystem $REAL_LIBC_DEV/include \
            -L$REAL_LIBC/lib \
            -L$GCC_DIR \
            -Wl,-dynamic-linker=$DL \
            -Wl,-rpath,$REAL_LIBC/lib \
            -Wl,-rpath,$GCC_DIR \
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
          REAL_CC=$(cat "$BT/nix-support/orig-cc")
          REAL_LIBC=$(cat "$BT/nix-support/orig-libc")
          REAL_LIBC_DEV=$(cat "$BT/nix-support/orig-libc-dev")
          DL=$(cat "$BT/nix-support/dynamic-linker")
          CXX_VER=$(ls "$REAL_CC/include/c++")
          GCC_DIR=$(echo "$REAL_CC"/lib/gcc/x86_64-unknown-linux-gnu/*)
          # --sysroot=/ points at the Firecracker guest rootfs assembled for
          # this VM test, not at the host filesystem or Nix build sandbox root.
          clang++ \
            --sysroot=/ \
            -isystem "$REAL_CC/include/c++/$CXX_VER" \
            -isystem "$REAL_CC/include/c++/$CXX_VER/x86_64-unknown-linux-gnu" \
            -isystem "$REAL_CC/include/c++/$CXX_VER/backward" \
            -isystem $REAL_LIBC_DEV/include \
            -B$REAL_LIBC/lib \
            -B$GCC_DIR \
            -L$REAL_LIBC/lib \
            -L$REAL_CC/lib \
            -L$REAL_CC/lib64 \
            -L$GCC_DIR \
            -Wl,-dynamic-linker=$DL \
            -Wl,-rpath,$REAL_LIBC/lib \
            -Wl,-rpath,$REAL_CC/lib \
            -Wl,-rpath,$REAL_CC/lib64 \
            -Wl,-rpath,$GCC_DIR \
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
          REAL_CC=$(cat "$BT/nix-support/orig-cc")
          REAL_LIBC=$(cat "$BT/nix-support/orig-libc")
          REAL_LIBC_DEV=$(cat "$BT/nix-support/orig-libc-dev")
          DL=$(cat "$BT/nix-support/dynamic-linker")
          GCC_DIR=$(echo "$REAL_CC"/lib/gcc/x86_64-unknown-linux-gnu/*)

          # --sysroot=/ points at the Firecracker guest rootfs assembled for
          # this VM test, not at the host filesystem or Nix build sandbox root.
          clang \
            --sysroot=/ \
            -isystem $OPENSSL/include \
            -isystem $REAL_LIBC_DEV/include \
            -B$REAL_LIBC/lib \
            -B$GCC_DIR \
            -L$REAL_LIBC/lib \
            -L$GCC_DIR \
            -L$OPENSSL/lib \
            -Wl,-dynamic-linker=$DL \
            -Wl,-rpath,$REAL_LIBC/lib \
            -Wl,-rpath,$GCC_DIR \
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
