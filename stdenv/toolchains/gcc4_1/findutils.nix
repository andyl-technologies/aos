# stdenv/toolchains/gcc4_1/findutils.nix — GNU findutils 4.2.27 (RHEL 5)
#
# Built with THIS tier's GCC 4.1.2 + binutils 2.17 + glibc 2.5.
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
}: let
  src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/findutils/findutils-4.2.27.tar.gz";
    sha256 = "008jzg0bapzqz4vnyx00dvl73j3z289p5m3j26km99l2x9xamm92";
  };
in
  builtins.derivation {
    name = "findutils-4.2.27";
    system = buildPlatform.system;
    builder = "${prev.bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu

        export PATH="${texinfo}/bin:${help2man}/bin:${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"
        export CONFIG_SHELL="${prev.bash}/bin/bash"

        # Stub autotools — prevents Makefiles from re-running real autoconf/automake
        mkdir -p "$TMPDIR/fakebin"
        for tool in autoconf autoheader aclocal automake autoreconf autom4te; do
          printf '#!/bin/sh\nexit 0\n' > "$TMPDIR/fakebin/$tool"
          chmod +x "$TMPDIR/fakebin/$tool"
        done
        export PATH="$TMPDIR/fakebin:$PATH"

        cd "$TMPDIR"
        cp -r ${src} findutils-4.2.27
        cd findutils-4.2.27
        chmod -R u+w .
        find . -type f -exec touch {} + 2>/dev/null || true

        mkdir -p "$TMPDIR/build"
        cd "$TMPDIR/build"

        CC="${gcc}/bin/gcc -static" \
        CFLAGS="-O2 -I${glibc}/include" \
        LDFLAGS="-L${glibc}/lib -static -Wl,-z,muldefs -Wl,--whole-archive ${glibc}/lib/libnss_files.a ${glibc}/lib/libnss_dns.a ${glibc}/lib/libresolv.a -Wl,--no-whole-archive -Wl,--defsym=__res_iclose=0 -Wl,-u,dl_iterate_phdr" \
        "$TMPDIR/findutils-4.2.27/configure" \
          --prefix="$out" \
          --build=${hostPlatform.config} --host=${hostPlatform.config} --target=${hostPlatform.config} \
          --disable-nls

        # Strip prerequisites from autotools regeneration rules
        find . -name Makefile | while read f; do
          sed -i 's/^Makefile:.*/Makefile:/; s/^config\.status:.*/config.status:/; s/^configure:.*/configure:/' "$f"
        done

        make -j"$NIX_BUILD_CORES" \
          AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true
        make install \
          AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true

        echo "GNU findutils 4.2.27 installed to $out"
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
