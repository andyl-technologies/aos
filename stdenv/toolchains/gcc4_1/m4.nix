# stdenv/toolchains/gcc4_1/m4.nix — GNU m4 1.4.9 (autotools bootstrap)
#
# Built with THIS tier's GCC 4.1.2 + binutils 2.17 + glibc 2.5.
# First package in the autotools chain — no dependencies beyond a C compiler.
#
{
  prev,
  gcc,
  texinfo,
  help2man,
  buildPlatform,
  hostPlatform,
}:
let
  inherit (import ../../../lib/derivations.nix { system = builtins.currentSystem; }) fetchTarball;

  src = fetchTarball {
    url = "https://mirrors.kernel.org/gnu/m4/m4-1.4.9.tar.bz2";
    hash = "1vxf44182dn77mvx90w3ycyhxzra3msw607ifd8rq46ym9zsiia3";
  };
in
builtins.derivation {
  name = "m4-1.4.9";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${texinfo}/bin:${help2man}/bin:${prev.coreutils}/bin:${gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cd "$TMPDIR"
      cp -r ${src} m4-1.4.9
      cd m4-1.4.9
      chmod -R u+w .

      # Touch source files first, then autotools-generated outputs
      find . -type f \( -name '*.c' -o -name '*.h' -o -name '*.m4' -o -name '*.ac' -o -name '*.am' \) -exec touch {} + 2>/dev/null || true
      sleep 1
      find . \( -name 'configure' -o -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'config.h.in' -o -name 'config.hin' \) -exec touch {} + 2>/dev/null || true

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      CC="${gcc}/bin/gcc -static" \
      CFLAGS="-O2 -I${prev.glibc}/include" \
      LDFLAGS="-L${prev.glibc}/lib -static -Wl,--whole-archive ${prev.glibc}/lib/libnss_files.a ${prev.glibc}/lib/libnss_dns.a ${prev.glibc}/lib/libresolv.a -Wl,--no-whole-archive -Wl,--defsym=__res_iclose=0 -Wl,-u,dl_iterate_phdr" \
      "$TMPDIR/m4-1.4.9/configure" \
        --prefix="$out" \
        --build=${hostPlatform.config} --host=${hostPlatform.config} \
        --disable-nls

      make -j"$NIX_BUILD_CORES"
      make install

      echo "GNU m4 1.4.9 installed to $out"
    ''
  ];
}
// {
  meta = {
    build = {
      os = "linux";
      cpu = [
        "x86_64"
        "i686"
      ];
    };
    execute = {
      os = "linux";
      cpu = [
        "x86_64"
        "i686"
      ];
    };
  };
}
