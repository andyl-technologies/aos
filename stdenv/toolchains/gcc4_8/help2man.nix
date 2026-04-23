# stdenv/toolchains/gcc4_8/help2man.nix — GNU help2man 1.41.1 (RHEL 7)
#
# Built from source with GCC 4.8.5 + glibc 2.17 from this tier.
# help2man is a Perl script that generates man pages from --help output.
#
{
  prev,
  gcc,
  binutils,
  glibc,
  perl,
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

  help2man-src = fetchSrc {
    name = "help2man-1.41.1.tar.gz";
    url = "https://mirrors.kernel.org/gnu/help2man/help2man-1.41.1.tar.gz";
    hash = "sha256-OmUK2pRTcA40NVdw1PdPJX+x3aGg8k9EuKPB1Mse5A0=";
  };
in
  builtins.derivation {
    name = "help2man-1.41.1";
    system = buildPlatform.system;
    builder = "${prev.bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu
        export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
        export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.bash}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.diffutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.bzip2}/bin:${prev.patch}/bin:${perl}/bin"
        export CONFIG_SHELL="${prev.bash}/bin/bash"

        cd "$TMPDIR"
        tar xzf ${help2man-src}

        SRC="$TMPDIR/help2man-1.41.1"
        cd "$SRC"
        chmod -R u+w .
        find . -name configure -exec chmod +x {} + 2>/dev/null || true
        find . -name '*.sh' -exec chmod +x {} + 2>/dev/null || true
        find . -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true
        sleep 1
        find . \( -name 'configure' -o -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'config.h.in' \) -exec touch {} + 2>/dev/null || true

        CC="${gcc}/bin/gcc" \
        CFLAGS="-O2 -isystem ${glibc}/include" \
        CPPFLAGS="-isystem ${glibc}/include" \
        LDFLAGS="-L${glibc}/lib -static" \
        PERL="${perl}/bin/perl" \
        ./configure \
          --prefix="$out" \
          --build=${hostPlatform.config} --host=${hostPlatform.config}

        make -j"$NIX_BUILD_CORES" AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true
        make install AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true

        echo "GNU help2man 1.41.1 installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "GNU help2man 1.41.1 — generates man pages from --help output";
      homepage = "https://www.gnu.org/software/help2man/";
      license = "GPL-3.0-or-later";
      build = {
        os = "linux";
      };
      execute = {
        os = "linux";
      };
    };
  }
