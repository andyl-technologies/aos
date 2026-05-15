# stdenv/toolchains/gcc14/gawk.nix — GNU awk 5.3.1 (RHEL 10)
#
# Production GNU awk built with THIS tier's GCC 14.3.0 + binutils 2.41 + glibc 2.39.
#
{
  prev,
  gcc,
  binutils,
  glibc,
  m4,
  flex,
  bison,
  autoconf,
  automake,
  texinfo,
  help2man,
  buildPlatform,
  hostPlatform,
}: let
  src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/gawk/gawk-5.3.1.tar.xz";
    sha256 = "1gl40cia5iyil2gdwwy5lsw5nldswp6f707jbja1zfi1ahy1c3kp";
  };
in
  builtins.derivation {
    name = "gawk-5.3.1";
    system = buildPlatform.system;
    builder = "${prev.bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu
        export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO="${texinfo}/bin/makeinfo"
        export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin:${m4}/bin:${flex}/bin:${bison}/bin:${autoconf}/bin:${automake}/bin:${texinfo}/bin:${help2man}/bin"
        export CONFIG_SHELL="${prev.bash}/bin/bash"

        cd "$TMPDIR"
        mkdir gawk-5.3.1 && (cd ${src} && ${prev.tar}/bin/tar cf - .) | (cd gawk-5.3.1 && ${prev.tar}/bin/tar xf -)
        cd gawk-5.3.1
        chmod -R u+w .

        # Break all hardlinks in doc/ (version.texi/stamp-vti, versionmaint.texi/stamp-1, etc.)
        find doc -type f -links +1 -exec sh -c 'cp "$1" "$1.tmp" && mv "$1.tmp" "$1"' _ {} \; 2>/dev/null || true

        # Touch autotools inputs first, then generated .c/.h, then autotools outputs
        find . -type f \( -name '*.y' -o -name '*.l' -o -name 'Makefile.am' -o -name 'configure.ac' -o -name 'configure.in' -o -name 'acinclude.m4' \) -exec touch {} + 2>/dev/null || true
        sleep 1
        find . -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true
        sleep 1
        find . \( -name 'configure' -o -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'config.h.in' \) -exec touch {} + 2>/dev/null || true
        find . -name '*.info' -exec touch -t 200001010200.00 {} + 2>/dev/null || true
        find . -name '*.1' -exec touch {} + 2>/dev/null || true

        mkdir -p "$TMPDIR/build"
        cd "$TMPDIR/build"

        export LIBRARY_PATH="${glibc}/lib"
        CC="${gcc}/bin/gcc" \
        CFLAGS="-O2 -isystem ${glibc}/include" \
        CPPFLAGS="-isystem ${glibc}/include" \
        LDFLAGS="-L${glibc}/lib -static -no-pie" \
        "$TMPDIR/gawk-5.3.1/configure" \
          --prefix="$out" \
          --build=${buildPlatform.config} --host=${hostPlatform.config} --target=${hostPlatform.config} \
          --disable-nls

        make -j"$NIX_BUILD_CORES" AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true
        make install AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true

        [ -f "$out/bin/gawk" ] && [ ! -f "$out/bin/awk" ] && ln -sf gawk "$out/bin/awk"

        # gawkbug is a bug-report-generator shell script that bakes the
        # build-time CC path into a `CC="..."` line for the user to copy
        # into their report. The embedded path pins gcc-14.3.0-wrapped
        # (and stage2, 232 MiB) into every consumer's runtime closure
        # because nothing else references it. Replace the absolute path
        # with the bare command name — gawkbug is a debugging aid; it
        # doesn't need the exact compiler path to function.
        if [ -f "$out/bin/gawkbug" ]; then
          ${prev.sed}/bin/sed -i 's|^CC=.*|CC="gcc"|' "$out/bin/gawkbug"
        fi

        echo "GNU awk 5.3.1 installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "GNU awk 5.3.1 pattern scanning and processing language";
      homepage = "https://www.gnu.org/software/gawk/";
      license = "GPL-3.0-or-later";
      build = {
        os = "linux";
      };
      execute = {
        os = "linux";
      };
    };
  }
