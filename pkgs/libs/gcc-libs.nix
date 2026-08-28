##! GCC runtime shared libraries (libstdc++.so, libgcc_s.so)
##!
##! Our bootstrap GCC 14 is built with --disable-shared for hermetic static
##! linking. This package builds GCC from source with --enable-shared to
##! produce properly versioned shared libraries (with GLIBCXX_3.4.x symbol
##! versions), for use by pre-built binaries (e.g. bazel-bootstrap) that
##! need shared libstdc++.
##!
##! Uses builtins.derivation (not mkDerivation) to match the gcc14 tier
##! build environment — the cc-wrapper interferes with GMP's CC_FOR_BUILD.
{
  mkDerivation,
  lib,
  bootstrapTools,
}: let
  # Use the same sources as the gcc14 tier (builtins.fetchTarball)
  gcc-src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/gcc/gcc-14.3.0/gcc-14.3.0.tar.xz";
    sha256 = "18slj57b3zizzmc1bn4b6x8rygijfjjmwfzipdvyyzrbspaa5x21";
  };
  gmp-src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/gmp/gmp-6.3.0.tar.xz";
    sha256 = "1kc3dy4jxand0y118yb9715g9xy1fnzqgkwxy02vd57y2fhg2pcw";
  };
  mpfr-src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/mpfr/mpfr-4.2.1.tar.xz";
    sha256 = "1irpgc9aqyhgkwqk7cvib1dgr5v5hf4m0vaaknssyfpkjmab9ydq";
  };
  mpc-src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/mpc/mpc-1.3.1.tar.gz";
    sha256 = "1b6layaybj039fajx8dpy2zvcfy7s02y3y4lficz16vac0fsd0jk";
  };

  # Pull derivations (not just paths) from cc-wrapper's passthru so we
  # can reach the multi-output glibc's $dev / $static. orig-libc /
  # orig-cc in nix-support/ are string paths; reading them via readFile
  # would lose the attribute set. The dynamic-linker file remains a
  # readFile since it's a plain path to ld-linux.so inside glibc.$out.
  glibc = bootstrapTools.libc;
  gcc = bootstrapTools.cc;
  trim = s: lib.removeSuffix "\n" s;
  interp = trim (builtins.readFile "${bootstrapTools}/nix-support/dynamic-linker");
in
  # Use mkDerivation but bypass the cc-wrapper by setting CC/CXX directly
  mkDerivation {
    pname = "gcc-libs";
    version = "14.3.0";

    # No fetchurl source — we use builtins.fetchTarball inline
    src = null;

    buildDeps = [];
    runtimeDeps = [];
    propagatedDeps = [];

    # Builds the GCC target runtime libraries with explicit raw-GCC flags,
    # bypassing the production wrapper. Keep it outside the package hardening
    # policy so verification does not expect wrapper effects here.
    hardeningDisable = ["all"];

    phases = [
      {
        name = "build";
        script = ''
          # Clear cc-wrapper environment that interferes with GCC's
          # internal sub-configures (e.g. GMP's CC_FOR_BUILD test)
          unset C_INCLUDE_PATH CPATH CPLUS_INCLUDE_PATH LIBRARY_PATH
          unset NIX_CFLAGS_COMPILE NIX_LDFLAGS PKG_CONFIG_PATH

          cd "$TMPDIR"

          # Copy GCC source (tar pipe to avoid cp -r fchmodat bug)
          mkdir gcc-14.3.0 && (cd ${gcc-src} && tar cf - .) | (cd gcc-14.3.0 && tar xf -)
          cd gcc-14.3.0
          chmod -R u+w .

          # In-tree GMP/MPFR/MPC
          mkdir gmp && (cd ${gmp-src} && tar cf - .) | (cd gmp && tar xf -)
          chmod -R u+w gmp
          mkdir mpfr && (cd ${mpfr-src} && tar cf - .) | (cd mpfr && tar xf -)
          chmod -R u+w mpfr
          mkdir mpc && (cd ${mpc-src} && tar cf - .) | (cd mpc && tar xf -)
          chmod -R u+w mpc

          # Touch autotools timestamps to prevent regeneration.
          # Order: inputs (.y/.l/.am/.ac) oldest, then .c/.h, then outputs
          # (configure/Makefile.in) newest. This prevents make from trying
          # to regenerate flex/bison/autotools outputs.
          for dir in . gmp mpfr mpc; do
            find "$dir" -type f \( -name '*.y' -o -name '*.l' -o -name 'Makefile.am' -o -name 'configure.ac' -o -name 'configure.in' -o -name 'acinclude.m4' \) \
              -exec touch -t 200001010000.00 {} + 2>/dev/null || true
          done
          for dir in . gmp mpfr mpc; do
            find "$dir" -type f \( -name '*.c' -o -name '*.cc' -o -name '*.h' \) \
              -exec touch -t 200001010030.00 {} + 2>/dev/null || true
          done
          for dir in . gmp mpfr mpc; do
            find "$dir" \( -name 'configure' -o -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'config.h.in' \) \
              -exec touch -t 200001010100.00 {} + 2>/dev/null || true
          done
          # Generated .info and man pages must be newer than sources
          for dir in . gmp mpfr mpc; do
            find "$dir" \( -name '*.1' -o -name '*.info' \) \
              -exec touch -t 200001010200.00 {} + 2>/dev/null || true
          done

          # Set up target sysroot
          mkdir -p "$TMPDIR/sysroot/usr/include"
          ln -sf ${glibc.dev}/include/* "$TMPDIR/sysroot/usr/include/"
          # Real lib dirs (not symlinks to $glibc/lib) so we can mix
          # shared libs from $out/lib and static archives from $static/lib —
          # -static linking finds them.
          mkdir -p "$TMPDIR/sysroot/usr/lib" "$TMPDIR/sysroot/lib"
          for f in ${glibc}/lib/* ${glibc.static}/lib/*.a; do
            bn=$(basename "$f")
            ln -sf "$f" "$TMPDIR/sysroot/usr/lib/$bn"
            ln -sf "$f" "$TMPDIR/sysroot/lib/$bn"
          done

          mkdir -p "$TMPDIR/build"
          cd "$TMPDIR/build"

          # Use the unwrapped GCC directly (not cc-wrapper) to match gcc14 build.
          # CC_FOR_BUILD must include -static because GMP configure runs
          # $CC_FOR_BUILD conftest.c without CFLAGS — the resulting dynamic
          # executable can't run in the sandbox (linker path not available).
          # No -isystem ${glibc.dev}/include here: ${gcc} is the wrapped tier
          # gcc which already injects -idirafter ${glibc.dev}/include via its
          # specs. -isystem would place stdlib.h before the C++ stdlib dir,
          # and GCC dedups includes — so the later -idirafter is dropped
          # as redundant, leaving stdlib.h only at the prepended position
          # where <cstdlib>'s #include_next <stdlib.h> can't reach it.
          # Same hazard fix as patchelf.nix / gcc-stage2.nix.
          CC="${gcc}/bin/gcc" CXX="${gcc}/bin/g++" \
          CC_FOR_BUILD="${gcc}/bin/gcc -static" \
          CFLAGS="-O2 -static" \
          CXXFLAGS="-O2 -static" \
          LDFLAGS="-L${glibc.static}/lib -L${glibc}/lib -static" \
          CFLAGS_FOR_BUILD="-O2 -static" \
          LDFLAGS_FOR_BUILD="-static" \
          AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true \
          "$TMPDIR/gcc-14.3.0/configure" \
            --prefix="$out" \
            --build=x86_64-unknown-linux-gnu --host=x86_64-unknown-linux-gnu --target=x86_64-unknown-linux-gnu \
            --enable-languages=c,c++ \
            --enable-shared --disable-nls --enable-threads=posix \
            --disable-multilib --disable-bootstrap \
            --disable-libsanitizer --disable-libvtv --disable-libgomp --disable-libatomic \
            --with-native-system-header-dir="/usr/include" \
            --with-build-sysroot="$TMPDIR/sysroot" \
            --program-transform-name=

          # Build the compiler (needed to build target libs).
          # CC_FOR_BUILD on the command line ensures GMP's configure test
          # produces static executables that can run in the sandbox.
          make -j"$NIX_BUILD_CORES" all-gcc \
            AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true \
            BOOT_CFLAGS="-O2 -static" \
            CFLAGS_FOR_TARGET="-O2" \
            LDFLAGS_FOR_TARGET="-static" \
            "CC_FOR_BUILD=${gcc}/bin/gcc -static" \
            "CFLAGS_FOR_BUILD=-O2 -static"

          # Build shared target libraries.
          # LDFLAGS_FOR_TARGET includes -dynamic-linker so configure test
          # programs can actually run in the Nix sandbox (no /lib64/ld-linux).
          TARGET_LDFLAGS="-Wl,-dynamic-linker=${interp} -Wl,-rpath,${glibc}/lib"
          make -j"$NIX_BUILD_CORES" all-target-libgcc \
            AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true \
            CFLAGS_FOR_TARGET="-O2 -fPIC" \
            "LDFLAGS_FOR_TARGET=$TARGET_LDFLAGS"
          make -j"$NIX_BUILD_CORES" all-target-libstdc++-v3 \
            AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true \
            CFLAGS_FOR_TARGET="-O2 -fPIC" \
            CXXFLAGS_FOR_TARGET="-O2 -fPIC" \
            "LDFLAGS_FOR_TARGET=$TARGET_LDFLAGS"

          # Install
          make install-target-libgcc \
            AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
          make install-target-libstdc++-v3 \
            AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true

          # Clean up — keep only shared libraries
          rm -rf "$out/bin" "$out/include" "$out/share" "$out/libexec"
          find "$out" -name '*.a' -delete
          find "$out" -name '*.la' -delete
          find "$out" -name '*.py' -delete
          # Move libs to $out/lib
          if [ -d "$out/lib64" ] && [ ! -d "$out/lib" ]; then
            mv "$out/lib64" "$out/lib"
          elif [ -d "$out/lib64" ]; then
            cp -a "$out/lib64"/* "$out/lib/" 2>/dev/null || true
            rm -rf "$out/lib64"
          fi
          rm -rf "$out/x86_64-unknown-linux-gnu" 2>/dev/null || true
          find "$out/lib" -type d -name 'gcc' -exec rm -rf {} + 2>/dev/null || true

          echo "gcc-libs installed to $out"
          find "$out" -name '*.so*' -type f -o -name '*.so*' -type l | sort
        '';
      }
    ];

    passthru.evidenceSources = [gcc-src gmp-src mpfr-src mpc-src];

    meta = {
      description = "GCC runtime shared libraries (libstdc++.so, libgcc_s.so)";
      homepage = "https://gcc.gnu.org/";
      license = "GPL-3.0-or-later";
    };
  }
