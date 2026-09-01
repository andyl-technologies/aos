##! Darling — x86_64 macOS userspace runtime for Linux VM tests
{
  lib,
  mkDerivation,
  fetchurl,
  cmake,
  ninja,
  llvm,
  bison,
  flex,
  python3,
  bash,
  xz,
  libcap,
  libbsd,
  libmd,
  bootstrapTools,
}: let
  version = "0-unstable-2026-08-19";
  sources = import ./_darling-sources.nix {inherit fetchurl;};

  populateSubmodule = source: ''
    rm -rf "${source.path}"
    mkdir -p "${source.path}"
    tar xf ${source.archive} --strip-components=1 -C "${source.path}"
  '';
  populateSubmodules = builtins.concatStringsSep "\n" (map populateSubmodule sources.submodules);
  sourceManifest = map (source: builtins.removeAttrs source ["archive"]) sources.submodules;
in
  mkDerivation {
    pname = "darling";
    inherit version;

    src = sources.archive;

    buildDeps = [
      cmake
      ninja
      llvm
      bison
      flex
      python3
      bash
      xz
      libcap
      libbsd
      libmd
    ];
    runtimeDeps = [];

    # One CMake tree builds ELF host processes and Mach-O guest libraries with
    # the same global flags. Upstream's Debian build deliberately clears the
    # distribution hardening flags for this mixed-target build as well.
    hardeningDisable = ["all"];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd darling-${sources.revision}

          ${populateSubmodules}
        '';
      }
      {
        name = "patch";
        script = ''
          # CMake runs this generator on the Linux build machine.
          sed -i '1c#!${python3}/bin/python3' \
            src/external/darlingserver/scripts/generate-rpc-wrappers.py

          # The build-mig generator preserves this Bash shebang verbatim.
          sed -i '1c#!${bash}/bin/bash' \
            src/external/bootstrap_cmds/migcom.tproj/mig.sh
          sed -i 's|/bin/rmdir|rmdir|' \
            src/external/bootstrap_cmds/migcom.tproj/mig.sh

          # The Nix sandbox intentionally has no /bin/mkdir.
          sed -i 's|/bin/mkdir -p|mkdir -p|' cmake/mig.cmake

          # objc4 marks its target as a debug build unconditionally, but its
          # own DEBUG macro follows NDEBUG. Keep the public build marker in
          # lockstep with this package's Release configuration.
          sed -i \
            's/-DOBJC_NO_GC -DOBJC_IS_DEBUG_BUILD=1/-DOBJC_NO_GC -DOBJC_IS_DEBUG_BUILD=0/' \
            src/external/objc4/runtime/CMakeLists.txt

          # Darling's bundled ld64 does not implement a chained bind emitted
          # by current Clang for libunwind's register-name switch table. Encode
          # dyld with the classic bind opcodes that the same loader supports.
          sed -i 's/ -Wl,-fixup_chains//' \
            src/external/dyld/CMakeLists.txt

          # The classic-bind dyld is linked and loaded at its preferred address,
          # so it has no chained rebases to apply. Upstream's bootstrap assumes
          # chained fixups unconditionally; its resulting diagnostic aborts
          # before mach_init can install Darling's ELF syscall table. Retain the
          # chained path when present, but initialize the syscall layer for both
          # encodings.
          patch -p1 <<'PATCH'
          --- a/src/external/dyld/src/dyldInitialization.cpp
          +++ b/src/external/dyld/src/dyldInitialization.cpp
          @@ -94,15 +94,16 @@ static void rebaseDyld(const dyld3::MachOLoaded* dyldMH)
           {
               // walk all fixups chains and rebase dyld
               const dyld3::MachOAnalyzer* ma = (dyld3::MachOAnalyzer*)dyldMH;
          -    assert(ma->hasChainedFixups());
          -    uintptr_t slide = (long)ma; // all fixup chain based images have a base address of zero, so slide == load address
          -    __block Diagnostics diag;
          -    ma->withChainStarts(diag, 0, ^(const dyld_chained_starts_in_image* starts) {
          -        ma->fixupAllChainedFixups(diag, starts, slide, dyld3::Array<const void*>(), nullptr);
          -    });
          -    diag.assertNoError();
          +    if (ma->hasChainedFixups()) {
          +        uintptr_t slide = (long)ma; // all fixup chain based images have a base address of zero, so slide == load address
          +        __block Diagnostics diag;
          +        ma->withChainStarts(diag, 0, ^(const dyld_chained_starts_in_image* starts) {
          +            ma->fixupAllChainedFixups(diag, starts, slide, dyld3::Array<const void*>(), nullptr);
          +        });
          +        diag.assertNoError();
          +    }

               // now that rebasing done, initialize mach/syscall layer
           #ifdef DARLING
          PATCH

          # Store outputs cannot carry setuid executables. Retain ordinary
          # executable permissions here; the isolated VM payload reapplies the
          # setuid bit that Darling needs for its namespace setup.
          sed -i 's/    SETUID)/    )/' \
            src/startup/CMakeLists.txt
        '';
      }
      {
        name = "configure";
        script = ''
          unset CFLAGS CXXFLAGS CPPFLAGS LDFLAGS

          # The installed AOS clang intentionally needs an explicit GCC/glibc
          # search path for ELF host programs. Darling then reuses that same
          # compiler executable with `-target x86_64-apple-darwin11`; keep the
          # Linux paths out of those Mach-O invocations.
          REAL_CC=$(cat ${bootstrapTools}/nix-support/orig-cc)
          REAL_LIBC=$(cat ${bootstrapTools}/nix-support/orig-libc)
          REAL_LIBC_DEV=$(cat ${bootstrapTools}/nix-support/orig-libc-dev)
          GCC_DIR=$(echo "$REAL_CC"/lib/gcc/x86_64-unknown-linux-gnu/*)
          DL=$(echo "$REAL_LIBC"/lib/ld-linux-x86-64.so.*)

          # glibc 2.34 folded these libraries into libc, but retains versioned
          # DSOs for ABI compatibility. The AOS glibc dev output has none of
          # their unversioned link names, which Darling's Linux host tools still
          # use. Supply those names only to ELF links; NEEDED entries remain the
          # versioned DSOs from the AOS glibc runtime.
          HOST_COMPAT_LIB=$PWD/.aos-toolchain/lib
          mkdir -p "$HOST_COMPAT_LIB"
          ln -s "$REAL_LIBC/lib/libdl.so.2" "$HOST_COMPAT_LIB/libdl.so"
          ln -s "$REAL_LIBC/lib/libpthread.so.0" "$HOST_COMPAT_LIB/libpthread.so"
          ln -s "$REAL_LIBC/lib/librt.so.1" "$HOST_COMPAT_LIB/librt.so"
          ln -s "$REAL_LIBC/lib/libutil.so.1" "$HOST_COMPAT_LIB/libutil.so"
          ln -s "$REAL_LIBC/lib/libnsl.so.1" "$HOST_COMPAT_LIB/libnsl.so"

          for compiler in clang clang++; do
            {
              printf '%s\n' '#!${bash}/bin/bash'
              printf '%s\n' 'darwin_target=false'
              printf '%s\n' 'next_is_target=false'
              printf '%s\n' 'for argument in "$@"; do'
              printf '%s\n' '  if $next_is_target; then'
              printf '%s\n' '    case "$argument" in *apple-darwin*) darwin_target=true ;; esac'
              printf '%s\n' '    next_is_target=false'
              printf '%s\n' '  fi'
              printf '%s\n' '  case "$argument" in'
              printf '%s\n' '    -target|--target) next_is_target=true ;;'
              printf '%s\n' '    -target=*apple-darwin*|--target=*apple-darwin*) darwin_target=true ;;'
              printf '%s\n' '  esac'
              printf '%s\n' 'done'
              printf '%s\n' 'if $darwin_target; then exec ${llvm}/bin/'"$compiler"' "$@"; fi'
              printf '%s\n' 'case " $* " in'
              printf '%s\n' '  *" -c "*|*" -E "*|*" -S "*|*" -fsyntax-only "*)'
              printf '%s\n' '    exec ${llvm}/bin/'"$compiler"' --gcc-install-dir='"$GCC_DIR"' -idirafter '"$REAL_LIBC_DEV"'/include -B'"$REAL_LIBC"'/lib -B'"$GCC_DIR"' "$@" ;;'
              printf '%s\n' 'esac'
              printf '%s\n' 'exec ${llvm}/bin/'"$compiler"' -idirafter '"$REAL_LIBC_DEV"'/include -L'"$HOST_COMPAT_LIB"' -L'"$REAL_LIBC"'/lib --gcc-install-dir='"$GCC_DIR"' -B'"$REAL_LIBC"'/lib -B'"$GCC_DIR"' -Wl,-dynamic-linker='"$DL"' -Wl,-rpath,'"$REAL_LIBC"'/lib -Wl,-rpath,'"$REAL_CC"'/lib "$@"'
            } > ".aos-toolchain/$compiler"
            chmod +x ".aos-toolchain/$compiler"
          done

          cmake -S . -B build -G Ninja \
            -DCMAKE_BUILD_TYPE=Release \
            -DCMAKE_INSTALL_PREFIX=$out \
            -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
            -DCMAKE_C_COMPILER=$PWD/.aos-toolchain/clang \
            -DCMAKE_CXX_COMPILER=$PWD/.aos-toolchain/clang++ \
            -DCMAKE_ASM_COMPILER=$PWD/.aos-toolchain/clang \
            -DCMAKE_MAKE_PROGRAM=${ninja}/bin/ninja \
            -DBISON_EXECUTABLE=${bison}/bin/bison \
            -DFLEX_EXECUTABLE=${flex}/bin/flex \
            -DPython3_EXECUTABLE=${python3}/bin/python3 \
            -DXZ_PROGRAM=${xz}/bin/xz \
            -DSETCAP_EXECUTABLE=${libcap}/sbin/setcap \
            -DCOMPONENTS=core \
            -DCOMPILE_PY2_BYTECODE=OFF \
            -DENABLE_METAL=OFF \
            -DENABLE_TESTS=OFF \
            -DREGENERATE_SDK=OFF \
            -DDARLING_NO_CCACHE=ON \
            -DDEBIAN_PACKAGING=ON \
            -DDSERVER_TOOLS=OFF \
            -DDSERVER_ASAN=OFF \
            -DDSERVER_UBSAN=OFF \
            -DTARGET_i386=OFF \
            -DTARGET_x86_64=ON
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
          cmake --install build --component core

          test -x "$out/bin/darling"
          test -x "$out/bin/darlingserver"
          test -x "$out/libexec/darling/usr/libexec/darling/mldr"
          test -f "$out/libexec/darling/usr/lib/dyld"
          test -e "$out/libexec/darling/usr/lib/libSystem.dylib"

          # Retain the exact upstream notices. The core is a license aggregate:
          # Apple's APSL sources, Darling GPL sources, and several permissive
          # runtime libraries are all installed into one prefix.
          mkdir -p "$out/share/licenses/darling"
          cp LICENSE "$out/share/licenses/darling/LICENSE"
          find src/external -maxdepth 3 -type f \
            \( -iname 'license*' -o -iname 'copying*' -o -iname 'apple_license' \) |
            while IFS= read -r notice; do
              destination="$out/share/licenses/darling/$notice"
              mkdir -p "$(dirname "$destination")"
              cp "$notice" "$destination"
            done
        '';
      }
    ];

    passthru = {
      sourceRevision = sources.revision;
      inherit sourceManifest;
      supportedGuestCpu = "x86_64";
      runtimeEntrypoints = {
        launcher = "bin/darling";
        server = "bin/darlingserver";
        mldr = "libexec/darling/usr/libexec/darling/mldr";
        dyld = "libexec/darling/usr/lib/dyld";
      };
    };

    meta = {
      description = "Darling core macOS compatibility runtime for x86_64 Linux";
      homepage = "https://www.darlinghq.org/";
      platforms = ["x86_64-linux"];
      license = [
        "GPL-3.0-or-later"
        "GPL-2.0-or-later WITH GCC-exception-2.0"
        "APSL-2.0"
        "MPL-2.0"
        "Apache-2.0 WITH LLVM-exception"
        "Apache-2.0"
        "BSD-2-Clause"
        "BSD-3-Clause"
        "MIT"
        "ISC"
        "NCSA"
        "Unicode-3.0"
        "Zlib"
        "Vim"
      ];
    };
  }
