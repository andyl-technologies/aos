# stdenv/toolchains/gcc4_8/m4.nix — GNU m4 1.4.16 (RHEL 7)
#
# Built with THIS tier's GCC 4.8.5 + glibc 2.17.
# First package in the autotools chain — no dependencies beyond a C compiler.
#
{
  prev,
  gcc,
  binutils,
  glibc,
  texinfo,
  help2man,
  buildPlatform,
  hostPlatform,
}:
let
  src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/m4/m4-1.4.16.tar.bz2";
    sha256 = "sha256-tcR+IRdi1HPrOSIdiAIOVKcjT5E2lst/LFKJ5peQx2M=";
  };
in
builtins.derivation {
  name = "m4-1.4.16";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
      export PATH="${texinfo}/bin:${help2man}/bin:${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.bash}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.diffutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.bzip2}/bin:${prev.patch}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cd "$TMPDIR"
      mkdir -p m4-1.4.16 && (cd ${src} && tar cf - .) | (cd m4-1.4.16 && tar xf -)
      cd m4-1.4.16
      chmod -R u+w .

      # Touch source files first, then autotools-generated outputs
      find . -type f \( -name '*.c' -o -name '*.h' -o -name '*.m4' -o -name '*.ac' -o -name '*.am' \) -exec touch {} + 2>/dev/null || true
      sleep 1
      find . \( -name 'configure' -o -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'config.h.in' -o -name 'config.hin' \) -exec touch {} + 2>/dev/null || true

      # glibc 2.17 removed gets() — gnulib's stdio replacement references
      # it via _GL_WARN_ON_USE, causing a compile error. Patch it out.
      ${prev.sed}/bin/sed -i '/_GL_WARN_ON_USE (gets,/d' lib/stdio.in.h

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      CC="${gcc}/bin/gcc" \
      CFLAGS="-O2 -isystem ${glibc}/include" \
      CPPFLAGS="-isystem ${glibc}/include" \
      LDFLAGS="-L${glibc}/lib -static" \
      "$TMPDIR/m4-1.4.16/configure" \
        --prefix="$out" \
        --build=${hostPlatform.config} --host=${hostPlatform.config} \
        --disable-nls

      make -j"$NIX_BUILD_CORES" AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true
      make install AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true

      echo "GNU m4 1.4.16 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU m4 macro processor, version 1.4.16";
    homepage = "https://www.gnu.org/software/m4/";
    license = "GPL-3.0-or-later";
    build = {
      os = "linux";
    };
    execute = {
      os = "linux";
    };
  };
}
