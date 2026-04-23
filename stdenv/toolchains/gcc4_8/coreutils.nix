# stdenv/toolchains/gcc4_8/coreutils.nix — GNU Coreutils 8.22 (RHEL 7)
#
# Built with GCC 4.8.5 + glibc 2.17 from this tier.
#
{
  prev,
  gcc,
  binutils,
  glibc,
  xz,
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

  coreutils-src = fetchSrc {
    name = "coreutils-8.22.tar.xz";
    url = "https://mirrors.kernel.org/gnu/coreutils/coreutils-8.22.tar.xz";
    hash = "sha256-Wz6UmYFSwBfmx11WubmUGI63G/RtQDimQsuRQfb/EhI=";
  };
in
  builtins.derivation {
    name = "coreutils-8.22";
    system = buildPlatform.system;
    builder = "${prev.bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu
        export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO="${texinfo}/bin/makeinfo"
        export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.bash}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.diffutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.bzip2}/bin:${prev.patch}/bin:${xz}/bin:${m4}/bin:${flex}/bin:${bison}/bin:${autoconf}/bin:${automake}/bin:${texinfo}/bin:${help2man}/bin"

        cd "$TMPDIR"
        tar xJf ${coreutils-src}

        SRC="$TMPDIR/coreutils-8.22"
        cd "$SRC"
        chmod -R u+w .
        find . -name configure -exec chmod +x {} + 2>/dev/null || true
        find . -name '*.sh' -exec chmod +x {} + 2>/dev/null || true
        chmod +x install-sh missing mkinstalldirs 2>/dev/null || true
        # Use fixed timestamps to prevent regeneration
        find . -type f -exec touch -t 200001010000.00 {} + 2>/dev/null || true
        find . -type f \( -name '*.c' -o -name '*.h' \) -exec touch -t 200001010030.00 {} + 2>/dev/null || true
        find . \( -name 'configure' -o -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'config.h.in' \) -exec touch -t 200001010100.00 {} + 2>/dev/null || true
        # Touch pre-generated man pages and version files so make doesn't try to rebuild them
        find . \( -name '*.1' -o -name '*.info' \) -exec touch -t 200001010200.00 {} + 2>/dev/null || true
        touch -t 200001010200.00 .version .tarball-version src/fs.h src/version.c src/version.h lib/config.hin 2>/dev/null || true

        # Fix gnulib gets() warning — glibc 2.17 removed gets() declaration
        ${prev.sed}/bin/sed -i '/_GL_WARN_ON_USE (gets,/d' lib/stdio.in.h 2>/dev/null || true

        CC="${gcc}/bin/gcc" \
        CFLAGS="-O2 -isystem ${glibc}/include" \
        CPPFLAGS="-isystem ${glibc}/include" \
        LDFLAGS="-L${glibc}/lib -static" \
        ./configure \
          --prefix="$out" \
          --build=${hostPlatform.config} --host=${hostPlatform.config} --target=${hostPlatform.config} \
          --disable-nls \
          --enable-no-install-program=stdbuf

        # Replace dummy-man with a working stub (no help2man/perl)
        printf '#!/bin/sh\necho ".TH dummy 1"\n' > man/dummy-man
        chmod +x man/dummy-man
        touch -t 200001010200.00 man/*.1 man/*.x 2>/dev/null || true

        # Man pages need help2man/perl; tolerate their failure
        make -j"$NIX_BUILD_CORES" AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true -k || true
        test -f src/ls || { echo "FATAL: coreutils binaries not built"; exit 1; }
        # install-exec skips man pages/data files
        make install-exec AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true
        test -f "$out/bin/ls" || { echo "FATAL: coreutils not installed"; exit 1; }

        echo "Coreutils 8.22 installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "GNU core utilities (ls, cat, cp, mv, etc.), version 8.22";
      homepage = "https://www.gnu.org/software/coreutils/";
      license = "GPL-3.0-or-later";
      build = {
        os = "linux";
      };
      execute = {
        os = "linux";
      };
    };
  }
