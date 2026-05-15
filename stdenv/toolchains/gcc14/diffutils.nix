# stdenv/toolchains/gcc14/diffutils.nix — GNU diffutils 3.10 (RHEL 10)
#
# Production GNU diffutils built with THIS tier's GCC 14.3.0 + binutils 2.41 + glibc 2.39.
#
{
  prev,
  coreutils,
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
    url = "https://mirrors.kernel.org/gnu/diffutils/diffutils-3.10.tar.xz";
    sha256 = "13cxlscmjns6dk4yp0nmmyp1ldjkbag68lmgrizcd5dzz00xi8j7";
  };
in
  builtins.derivation {
    name = "diffutils-3.10";
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
        mkdir diffutils-3.10 && (cd ${src} && ${prev.tar}/bin/tar cf - .) | (cd diffutils-3.10 && ${prev.tar}/bin/tar xf -)
        cd diffutils-3.10
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
        # Pre-set PR_PROGRAM so configure.ac's `AC_PATH_PROG(PR_PROGRAM,
        # pr, "")` skips its PATH search and embeds this-tier coreutils'
        # pr binary into the compiled `diff` (it goes into src/util.c's
        # `pr_program[]`). Without this, configure finds prev.coreutils-
        # 8.32 first on PATH and bakes its store path into the binary —
        # not currently in the runtime closure but would leak the moment
        # anything in toplevel pulled diff in.
        export PR_PROGRAM="${coreutils}/bin/pr"
        CC="${gcc}/bin/gcc" \
        CFLAGS="-O2 -isystem ${glibc}/include" \
        CPPFLAGS="-isystem ${glibc}/include" \
        LDFLAGS="-L${glibc}/lib -static -no-pie" \
        "$TMPDIR/diffutils-3.10/configure" \
          --prefix="$out" \
          --build=${buildPlatform.config} --host=${hostPlatform.config} --target=${hostPlatform.config} \
          --disable-nls

        make -j"$NIX_BUILD_CORES" AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true
        make install AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true

        echo "GNU diffutils 3.10 installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "GNU diffutils 3.10 (diff, cmp, sdiff, diff3)";
      homepage = "https://www.gnu.org/software/diffutils/";
      license = "GPL-3.0-or-later";
      build = {
        os = "linux";
      };
      execute = {
        os = "linux";
      };
    };
  }
