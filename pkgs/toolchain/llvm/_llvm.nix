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
  needsClOptStringFix ? false,
  needsCstdintFixes ? false,
  needsGccIteratorCompat ? false,
  extraRuntimeDeps ? [],
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
      ++ extraRuntimeDeps
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
            if stdenv.isCross
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
          + (
            if isDarwinCross && needsClOptStringFix
            then ''
              # LLVM 17's cl::opt<std::string> does not implicitly convert
              # through nested initializer lists with current libc++.
              sed -i \
                's/{{ClIgnorelist}}/{{std::string(ClIgnorelist)}}/' \
                llvm/tools/sancov/sancov.cpp
            ''
            else ""
          )
          + (
            if needsCstdintFixes
            then ''
              # GCC 16 no longer exposes fixed-width integer types through
              # LLVM 17's transitive includes. Include their owning header in
              # the declarations that use those types directly.
              sed -i \
                '/#include <algorithm>/a #include <cstdint>' \
                llvm/include/llvm/ADT/SmallVector.h
              sed -i \
                '/#include <string>/i #include <cstdint>' \
                llvm/lib/Target/X86/MCTargetDesc/X86MCTargetDesc.h
              sed -i \
                '/#include <memory>/i #include <cstdint>' \
                compiler-rt/lib/orc/error.h
            ''
            else ""
          )
          + (
            if versionMajor == "17" && stdenv.hostPlatform.isAarch64
            then ''
              # GCC's ACLE macro expands before Clang 17's nested token
              # concatenation (llvm-project issue 78691). Suppress it only
              # while expanding this token database, then restore it for
              # consumers of the installed headers.
              token_kinds=clang/include/clang/Basic/TokenKinds.def
              sed -i '1i #pragma push_macro("__arm_streaming")\n#undef __arm_streaming' "$token_kinds"
              printf '\n#pragma pop_macro("__arm_streaming")\n' >> "$token_kinds"
            ''
            else ""
          )
          + (
            if builtins.elem versionMajor ["17" "18"] && stdenv.isCross && stdenv.hostPlatform.isLinux
            then ''
              # GCC 14+ emits this exception ABI entry point. Backport the
              # libc++abi implementation from llvm-project PR 95759 so the
              # GCC-built runtime resolves its own termination calls.
              abi_header=libcxxabi/include/cxxabi.h
              test "$(grep -c '^// 2.5.4 Rethrowing Exceptions$' "$abi_header")" -eq 1
              sed -i \
                '/^\/\/ 2.5.4 Rethrowing Exceptions$/i // GNU extension: begins catching the exception before invoking terminate.\nextern _LIBCXXABI_FUNC_VIS _LIBCXXABI_NORETURN void __cxa_call_terminate(void*) throw();\n' \
                "$abi_header"

              abi_source=libcxxabi/src/cxa_exception.cpp
              test "$(grep -c '^// Note:  exception_header may be masquerading' "$abi_source")" -eq 1
              sed -i \
                '/^\/\/ Note:  exception_header may be masquerading/i void __cxa_call_terminate(void* unwind_arg) throw() {\n  __cxa_begin_catch(unwind_arg);\n  std::terminate();\n}\n' \
                "$abi_source"

              # CMAKE_REQUIRED_FLAGS also reaches C library probes. GCC's
              # C++ driver accepts -nostdlib++, but its C driver rejects it.
              # Test both drivers before applying the option to shared checks.
              runtime_config=runtimes/CMakeLists.txt
              test "$(grep -c '^if (CXX_SUPPORTS_NOSTDLIBXX_FLAG)$' "$runtime_config")" -eq 1
              sed -i \
                '/^if (CXX_SUPPORTS_NOSTDLIBXX_FLAG)$/c\llvm_check_compiler_linker_flag(C "-nostdlib++" C_SUPPORTS_NOSTDLIBXX_FLAG)\nif (CXX_SUPPORTS_NOSTDLIBXX_FLAG AND C_SUPPORTS_NOSTDLIBXX_FLAG)' \
                "$runtime_config"

              # GCC exposes these builtins but cannot mangle them in dependent
              # function signatures. Keep libc++'s portable trait fallback
              # for GCC while retaining Clang's builtin implementation.
              decay_header=libcxx/include/__type_traits/decay.h
              test "$(grep -c '^#if __has_builtin(__decay)$' "$decay_header")" -eq 1
              sed -i \
                's/^#if __has_builtin(__decay)$/#if __has_builtin(__decay) \&\& !defined(_LIBCPP_COMPILER_GCC)/' \
                "$decay_header"

              pointer_header=libcxx/include/__type_traits/remove_pointer.h
              test "$(grep -c '^#if .*__has_builtin(__remove_pointer)$' "$pointer_header")" -eq 1
              sed -i \
                '/^#if .*__has_builtin(__remove_pointer)$/s/$/ \&\& !defined(_LIBCPP_COMPILER_GCC)/' \
                "$pointer_header"
            ''
            else ""
          )
          + (
            if builtins.elem versionMajor ["19" "20" "21"] && stdenv.isCross && stdenv.hostPlatform.isLinux
            then
              ''
                # These releases already provide GCC's termination ABI and
                # remove_pointer alias fix. Their shared C probes still inherit
                # the C++-only flag; LLVM 22 restricts that flag to Clang.
                runtime_config=runtimes/CMakeLists.txt
                test "$(grep -c '^if (CXX_SUPPORTS_NOSTDLIBXX_FLAG)$' "$runtime_config")" -eq 1
                sed -i \
                  '/^if (CXX_SUPPORTS_NOSTDLIBXX_FLAG)$/c\llvm_check_compiler_linker_flag(C "-nostdlib++" C_SUPPORTS_NOSTDLIBXX_FLAG)\nif (CXX_SUPPORTS_NOSTDLIBXX_FLAG AND C_SUPPORTS_NOSTDLIBXX_FLAG)' \
                  "$runtime_config"
              ''
              + (
                if builtins.elem versionMajor ["19" "20"]
                then ''
                  # LLVM 21 routes GCC's decay alias through the class trait.
                  # Earlier headers need the portable fallback for mangling.
                  decay_header=libcxx/include/__type_traits/decay.h
                  test "$(grep -c '^#if __has_builtin(__decay)$' "$decay_header")" -eq 1
                  sed -i \
                    's/^#if __has_builtin(__decay)$/#if __has_builtin(__decay) \&\& !defined(_LIBCPP_COMPILER_GCC)/' \
                    "$decay_header"
                ''
                else ""
              )
            else ""
          )
          + (
            if builtins.elem versionMajor ["18" "19" "20"] && stdenv.isCross && stdenv.hostPlatform.isLinux
            then ''
              # libunwind links with the C driver. Its C++ flag probe can
              # succeed for GCC while the actual C link rejects -nostdlib++.
              # Keep the existing explicit-library fallback when C rejects it.
              unwind_checks=libunwind/cmake/config-ix.cmake
              unwind_targets=libunwind/src/CMakeLists.txt
              test "$(grep -c '^llvm_check_compiler_linker_flag(CXX "-nostdlib++" CXX_SUPPORTS_NOSTDLIBXX_FLAG)$' "$unwind_checks")" -eq 1
              sed -i \
                -e 's/CXX_SUPPORTS_NOSTDLIBXX_FLAG/C_SUPPORTS_NOSTDLIBXX_FLAG/g' \
                -e 's/llvm_check_compiler_linker_flag(CXX "-nostdlib++"/llvm_check_compiler_linker_flag(C "-nostdlib++"/' \
                "$unwind_checks" "$unwind_targets"
            ''
            else ""
          )
          + (
            if builtins.elem versionMajor ["20" "21" "22"] && stdenv.isCross && stdenv.hostPlatform.isLinux
            then ''
              # The PAC-with-PC helper copies the register context and may call
              # memcpy. Finish that call before binding caller-saved x16/x17;
              # otherwise GCC can lose the return address before authentication.
              unwind_header=libunwind/src/DwarfInstructions.hpp
              test "$(grep -Fc 'if (isReturnAddressSignedWithPC(addressSpace, registers, cfa, prolog)) {' "$unwind_header")" -eq 1
              test "$(grep -Fc 'register unsigned long long x17 __asm("x17") = returnAddress;' "$unwind_header")" -eq 1
              sed -i \
                -e '/register unsigned long long x17 __asm("x17") = returnAddress;/i\        const bool signedWithPC = isReturnAddressSignedWithPC(addressSpace, registers, cfa, prolog);' \
                -e 's/if (isReturnAddressSignedWithPC(addressSpace, registers, cfa, prolog)) {/if (signedWithPC) {/' \
                "$unwind_header"
            ''
            else ""
          )
          + (
            if versionMajor == "22" && stdenv.isCross && stdenv.hostPlatform.isLinux
            then ''
              # GCC supports the C23 spelling for complex binary128. Its
              # __float128 alias cannot appear in this C++ typeof expression.
              # Preserve the full type rather than disabling quad precision.
              complex_header=libc/include/llvm-libc-types/cfloat128.h
              test "$(grep -c '^typedef __typeof__(_Complex __float128) cfloat128;$' "$complex_header")" -eq 1
              sed -i \
                's/^typedef __typeof__(_Complex __float128) cfloat128;$/typedef _Complex _Float128 cfloat128;/' \
                "$complex_header"
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
              # Cross runtime projects inherit CMake's cross compiler through
              # LLVMExternalProjectUtils; only native builds run the new Clang.
              if enabledRuntimes != [] && !stdenv.isCross
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
                ${
                  if needsGccIteratorCompat
                  then ''
                    # GCC 16 made this mixed-iterator overload a hidden friend
                    # whose trailing return type inspects the still-incomplete
                    # class. Clang 17 rejects that form. Keep the GCC header's
                    # behavior while spelling its established difference type.
                    CXX_VERSION=$(ls "$REAL_CC/include/c++")
                    COMPAT_INCLUDE="$out/lib/clang-gcc-compat/include"
                    mkdir -p "$COMPAT_INCLUDE/bits"
                    cp \
                      "$REAL_CC/include/c++/$CXX_VERSION/bits/stl_iterator.h" \
                      "$COMPAT_INCLUDE/bits/stl_iterator.h"
                    chmod u+w "$COMPAT_INCLUDE/bits/stl_iterator.h"
                    sed -i \
                      's/-> decltype(__lhs.base() - __rhs.base())/-> difference_type/' \
                      "$COMPAT_INCLUDE/bits/stl_iterator.h"
                  ''
                  else ""
                }
                DL=$(echo "$REAL_LIBC"/lib/ld-linux-x86-64.so.*)
                {
                  ${
                  if needsGccIteratorCompat
                  then ''
                    echo "-isystem"
                    echo "$COMPAT_INCLUDE"
                  ''
                  else ""
                }
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
              if stdenv.isCross
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
              if enabledRuntimes != [] && !stdenv.isCross
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
        script =
          ''
            ninja -C build install

          ''
          + (
            if stdenv.isCross && stdenv.hostPlatform.isLinux
            then ''
              # libc++ depends on its sibling libc++abi, but the C toolchain's
              # injected RUNPATH only names external dependencies. Each runtime
              # must resolve siblings itself: a consumer's RUNPATH is not inherited
              # when the dynamic loader follows indirect DT_NEEDED entries.
              runtime_dir="$out/lib/${stdenv.hostPlatform.config}"
              for runtime_library in "$runtime_dir"/*.so.*; do
                if [ ! -f "$runtime_library" ] || [ -L "$runtime_library" ]; then
                  continue
                fi
                runtime_rpath=$(${buildPackages.patchelf}/bin/patchelf --print-rpath "$runtime_library")
                ${buildPackages.patchelf}/bin/patchelf --set-rpath \
                  "$runtime_dir''${runtime_rpath:+:$runtime_rpath}" "$runtime_library"
              done
            ''
            else ""
          )
          + ''
            ${
              if isDarwinCross
              then ''
                # compiler-rt, libc++, libc++abi and libunwind were bootstrapped
                # before this target LLVM so no Darwin executable has to run
                # while cross-compiling.  Install that exact runtime surface as
                # part of the complete Darwin LLVM toolchain.
                cp -a ${stdenv.darwinRuntimes}/include/. "$out/include/"
                cp -a ${stdenv.darwinRuntimes}/lib/. "$out/lib/"

                # Installed llvm-config discovers its real prefix relative to
                # argv[0], but retains the configured source and object roots as
                # binary fallback strings. Normalize only the sandbox prefix
                # with an equal-length replacement so Mach-O offsets stay valid
                # and the target toolchain does not expose an ephemeral build
                # directory.
                stable_source=$(printf '%s\n' "$PWD" | sed 's|^/build|/.aos_|')
                sed -i "s|$PWD|$stable_source|g" "$out/bin/llvm-config"

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
