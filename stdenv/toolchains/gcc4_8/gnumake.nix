# stdenv/toolchains/gcc4_8/gnumake.nix — GNU Make 4.2.1 (RHEL 7)
#
# Built with GCC 4.8.5 + glibc 2.17 from this tier.
# Upgraded from 3.82 to 4.2.1 so gcc8's glibc 2.28 (which needs make >= 4.0)
# can use prev.gnumake directly without a separate early build.
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
  fetchSrc = {
    name,
    url,
    hash,
  }:
    builtins.derivation {
      inherit name;
      system = buildPlatform.system;
      builder = "builtin:fetchurl";
      inherit url;
      outputHash = hash;
      outputHashMode = "flat";
      outputHashAlgo = "sha256";
      preferLocalBuild = true;
    };

  make-src = fetchSrc {
    name = "make-4.2.1.tar.bz2";
    url = "https://mirrors.kernel.org/gnu/make/make-4.2.1.tar.bz2";
    hash = "sha256-1uJivzYBtC0rHk74MQAp4dzyAIPFRGtLeqZwgf3/xYk=";
  };
in
  builtins.derivation {
    name = "gnumake-4.2.1";
    system = buildPlatform.system;
    builder = "${prev.bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu
        export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
        export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.bash}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.diffutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.bzip2}/bin:${prev.patch}/bin:${m4}/bin:${flex}/bin:${bison}/bin:${autoconf}/bin:${automake}/bin:${texinfo}/bin:${help2man}/bin"

        cd "$TMPDIR"
        tar xjf ${make-src}

        SRC="$TMPDIR/make-4.2.1"
        cd "$SRC"
        chmod -R u+w .
        find . -name configure -exec chmod +x {} + 2>/dev/null || true
        find . -name '*.sh' -exec chmod +x {} + 2>/dev/null || true
        chmod +x install-sh missing mkinstalldirs build-aux/install-sh 2>/dev/null || true
        find . -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true
        sleep 1
        find . \( -name 'configure' -o -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'config.h.in' \) -exec touch {} + 2>/dev/null || true

        mkdir -p "$TMPDIR/build"
        cd "$TMPDIR/build"

        CC="${gcc}/bin/gcc" \
        CFLAGS="-O2 -isystem ${glibc}/include" \
        CPPFLAGS="-isystem ${glibc}/include" \
        LDFLAGS="-L${glibc}/lib -static" \
        "$SRC/configure" \
          --prefix="$out" \
          --build=${hostPlatform.config} --host=${hostPlatform.config} --target=${hostPlatform.config} \
          --disable-nls

        make -j"$NIX_BUILD_CORES" AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true
        make install AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true

        echo "GNU Make 4.2.1 installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "GNU Make build automation tool, version 4.2.1";
      homepage = "https://www.gnu.org/software/make/";
      license = "GPL-3.0-or-later";
      build = {
        os = "linux";
      };
      execute = {
        os = "linux";
      };
    };
  }
