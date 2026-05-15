# stdenv/toolchains/gcc14/grep.nix — GNU grep 3.11 (RHEL 10)
#
# Production GNU grep built with THIS tier's GCC 14.3.0 + binutils 2.41 + glibc 2.39.
#
{
  prev,
  bash,
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
    url = "https://mirrors.kernel.org/gnu/grep/grep-3.11.tar.xz";
    sha256 = "0pm0zpzmmy6lq5ii03y1nqr1sdjalnwp69i5c926c9dm03v7v0bv";
  };
in
  builtins.derivation {
    name = "grep-3.11";
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
        mkdir grep-3.11 && (cd ${src} && ${prev.tar}/bin/tar cf - .) | (cd grep-3.11 && ${prev.tar}/bin/tar xf -)
        cd grep-3.11
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
        "$TMPDIR/grep-3.11/configure" \
          --prefix="$out" \
          --build=${buildPlatform.config} --host=${hostPlatform.config} --target=${hostPlatform.config} \
          --disable-nls \
          --disable-perl-regexp

        make -j"$NIX_BUILD_CORES" AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true
        make install AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true

        # ./configure substitutes CONFIG_SHELL (= prev.bash, the gcc11
        # tier bash-5.1) into the generated egrep/fgrep wrapper script
        # shebangs. That pins bash-5.1 → gcc-11.5.0-wrapped → entire
        # mes/tcc/cross-* bootstrap chain (~700 MiB, 13 paths) into the
        # runtime closure of every consumer. Rewrite to the same-tier
        # bash-5.2.37 (glibc-2.39-only closure) so the chain dies here.
        for f in "$out/bin/egrep" "$out/bin/fgrep"; do
          [ -f "$f" ] || continue
          ${prev.sed}/bin/sed -i "1s|^#!.*|#!${bash}/bin/bash|" "$f"
        done

        echo "GNU grep 3.11 installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "GNU grep 3.11 pattern matching utility";
      homepage = "https://www.gnu.org/software/grep/";
      license = "GPL-3.0-or-later";
      build = {
        os = "linux";
      };
      execute = {
        os = "linux";
      };
    };
  }
