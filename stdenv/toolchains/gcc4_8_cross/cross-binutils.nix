# stdenv/toolchains/gcc4_8_cross/cross-binutils.nix — Phase 1
#
# Cross binutils 2.25: runs on x86_64, targets target arch.
# Produces ${hostPlatform.config}-{as,ld,ar,...} prefixed tools.
#
{
  prev,
  buildPlatform,
  hostPlatform,
  ...
}: let
  src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/binutils/binutils-2.25.tar.bz2";
    sha256 = "sha256:12axyrxx1f74zd338l40s6033vjxm3ifx94lx2sxg4mbksq9xrca";
  };
in
  builtins.derivation {
    name = "cross-binutils-2.25";
    system = buildPlatform.system;
    builder = "${prev.bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu
        export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
        export PATH="${prev.coreutils}/bin:${prev.gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.bzip2}/bin:${prev.diffutils}/bin:${prev.patch}/bin:${prev.bash}/bin:${prev.m4}/bin:${prev.flex}/bin:${prev.bison}/bin:${prev.texinfo}/bin"
        export CONFIG_SHELL="${prev.bash}/bin/bash"

        cd "$TMPDIR"
        mkdir -p "$TMPDIR/src"
        (cd ${src} && tar cf - .) | (cd "$TMPDIR/src" && tar xf -)
        chmod -R u+w "$TMPDIR/src"

        # Pin source helpers that configure or make can execute directly.
        AOS_RUNTIME_SHELL="${prev.bash}/bin/bash" \
          "${prev.bash}/bin/bash" ${../../runtime-scripts.sh} "$TMPDIR/src"

        # Touch all files first, then touch generated .c/.h to prevent regeneration
        find "$TMPDIR/src" -type f -exec touch {} + 2>/dev/null || true
        sleep 1
        find "$TMPDIR/src" -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true
        sleep 1
        find "$TMPDIR/src" \( -name 'configure' -o -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'config.h.in' \) -exec touch {} + 2>/dev/null || true

        # Libtool consumes -static as its own library-selection flag. Keep it
        # in the compiler wrapper so GCC also selects static startup and linking.
        mkdir -p "$TMPDIR/ccwrap"
        cat > "$TMPDIR/ccwrap/gcc" <<'AOS_COMPILER'
        #!${prev.bash}/bin/bash
        exec ${prev.gcc}/bin/gcc -static "$@"
        AOS_COMPILER
        cat > "$TMPDIR/ccwrap/g++" <<'AOS_COMPILER'
        #!${prev.bash}/bin/bash
        exec ${prev.gcc}/bin/g++ -static "$@"
        AOS_COMPILER
        chmod +x "$TMPDIR/ccwrap/gcc" "$TMPDIR/ccwrap/g++"

        mkdir -p "$TMPDIR/build"
        cd "$TMPDIR/build"

        CC="$TMPDIR/ccwrap/gcc" \
        CXX="$TMPDIR/ccwrap/g++" \
        CFLAGS="-O2 -isystem ${prev.glibc}/include" \
        CXXFLAGS="-O2 -isystem ${prev.glibc}/include" \
        LDFLAGS="-L${prev.glibc}/lib -static" \
        "${prev.bash}/bin/bash" "$TMPDIR/src/configure" \
          --prefix="$out" \
          --build=${buildPlatform.config} \
          --host=${buildPlatform.config} \
          --target=${hostPlatform.config} \
          --disable-shared --disable-nls \
          --disable-gdb --disable-gdbserver --disable-libdecnumber --disable-readline --disable-sim \
          --with-sysroot=/

        make SHELL="${prev.bash}/bin/bash" -j"$NIX_BUILD_CORES" MAKEINFO=true
        make SHELL="${prev.bash}/bin/bash" install MAKEINFO=true

        echo "Cross binutils 2.25 (${buildPlatform.config} → ${hostPlatform.config}) installed to $out"
      ''
    ];
  }
