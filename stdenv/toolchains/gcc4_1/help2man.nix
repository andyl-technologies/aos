# stdenv/toolchains/gcc4_1/help2man.nix — GNU help2man 1.36.4 (RHEL 5)
#
# Built from source with THIS tier's GCC 4.1.2 + glibc 2.5.
# help2man is a Perl script that generates man pages from --help output.
#
{
  prev,
  gcc,
  perl,
  buildPlatform,
  hostPlatform,
}:
let
  inherit (import ../../../lib/derivations.nix { system = builtins.currentSystem; }) fetchTarball;

  src = fetchTarball {
    url = "https://mirrors.kernel.org/gnu/help2man/help2man-1.36.4.tar.gz";
    hash = "124i3pfk6j1ggpkixsbyxsm374k0yz3n8rdphgkkzzx8cy4ai779";
  };
in
builtins.derivation {
  name = "help2man-1.36.4";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${prev.coreutils}/bin:${gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin:${perl}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cd "$TMPDIR"
      cp -r ${src} help2man-1.36.4
      cd help2man-1.36.4
      chmod -R u+w .
      find . -type f -exec touch {} + 2>/dev/null || true

      CC="${gcc}/bin/gcc -static" \
      CFLAGS="-O2 -I${prev.glibc}/include" \
      LDFLAGS="-L${prev.glibc}/lib -static -Wl,--whole-archive ${prev.glibc}/lib/libnss_files.a ${prev.glibc}/lib/libnss_dns.a ${prev.glibc}/lib/libresolv.a -Wl,--no-whole-archive -Wl,--defsym=__res_iclose=0 -Wl,-u,dl_iterate_phdr" \
      PERL="${perl}/bin/perl" \
      ./configure \
        --prefix="$out" \
        --build=${hostPlatform.config} --host=${hostPlatform.config} \
        --disable-nls

      make -j"$NIX_BUILD_CORES"
      make install

      echo "GNU help2man 1.36.4 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU help2man 1.36.4 — generates man pages from --help output";
    homepage = "https://www.gnu.org/software/help2man/";
    license = "GPL-3.0-or-later";
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
