# stdenv/toolchains/gcc4_8/glibc.nix — glibc 2.17 (RHEL 7)
#
# Built with GCC 4.8.5 + binutils 2.25 from this tier. Includes
# linux-headers 3.10 for kernel interface definitions.
#
{
  prev,
  gcc,
  binutils,
  linuxHeaders,
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

  glibc-src = fetchSrc {
    name = "glibc-2.17.tar.bz2";
    url = "https://mirrors.kernel.org/gnu/glibc/glibc-2.17.tar.bz2";
    hash = "sha256-gPWs0LvFc62AV5rpjHiRQ8dfE/s55NvSRJwIZ3S4MVw=";
  };

  elfClass =
    if hostPlatform.is64bit
    then "64"
    else "32";
  stubsSuffix =
    if hostPlatform.is64bit
    then "64"
    else "32";
  linkSysdep =
    if hostPlatform.constraints.cpu == "x86_64"
    then "x86_64"
    else "i386";
in
  builtins.derivation {
    name = "glibc-2.17";
    system = buildPlatform.system;
    builder = "${prev.bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu
        export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
        export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.bash}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.diffutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.bzip2}/bin:${prev.patch}/bin"

        cd "$TMPDIR"
        tar xjf ${glibc-src}
        cd glibc-2.17
        chmod -R u+w .

        # Remove libidn add-on — not needed for bootstrap, and its
        # configure fragment fails when AUTOCONF=true regenerates it
        rm -rf libidn

        find . -name configure -exec chmod +x {} + 2>/dev/null || true
        find . -name '*.sh' -exec chmod +x {} + 2>/dev/null || true
        find . -name install-sh -exec chmod +x {} + 2>/dev/null || true
        # Use fixed timestamps to robustly prevent autoconf/automake
        # regeneration: set all files to a base time, then set generated
        # outputs (configure, Makefile.in, etc.) 1 hour later.
        find . -type f -exec touch -t 200001010000.00 {} + 2>/dev/null || true
        find . \( -name 'configure' -o -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'config.h.in' \) -exec touch -t 200001010100.00 {} + 2>/dev/null || true

        # Replace /bin/pwd with pwd (Nix sandbox has no /bin/)
        ${prev.sed}/bin/sed -i 's|/bin/pwd|pwd|g' configure

        mkdir -p "$TMPDIR/build"
        cd "$TMPDIR/build"

        CC="${gcc}/bin/gcc" \
        AR="${binutils}/bin/ar" \
        RANLIB="${binutils}/bin/ranlib" \
        BISON="${prev.bison}/bin/bison" \
        INSTALL_INFO="${prev.texinfo}/bin/install-info" \
        CFLAGS="-O2 -isystem ${prev.glibc}/include" \
        CPPFLAGS="-isystem ${prev.glibc}/include" \
        "$TMPDIR/glibc-2.17/configure" \
          --prefix="$out" \
          --build=${hostPlatform.config} \
          --host=${hostPlatform.config} \
          --with-headers="${linuxHeaders}/include" \
          --disable-shared \
          --disable-profile \
          --disable-nscd \
          --enable-add-ons=nptl \
          --enable-static-nss \
          --disable-multi-arch \
          --without-gd \
          --without-selinux \
          libc_cv_forced_unwind=yes \
          libc_cv_c_cleanup=yes

        # nscd links its own res_hconf.o against libc.a which also has
        # res_hconf.o, causing multiple-definition errors. Tolerate the failure.
        make -j"$NIX_BUILD_CORES" AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true || true
        test -f libc.a || { echo "FATAL: libc.a not built"; exit 1; }

        # -k: keep going past errors.  The manual subdirectory's install
        # fails because MAKEINFO=true generates no .info output.  Without
        # -k, make stops there and never installs nptl (libpthread), nss,
        # resolv, and other late subdirectories.
        # PERL=true: prevents "no libm-err-tab.pl" error in manual build
        # (configure set PERL=no since Perl isn't available).
        make -k install PERL=true AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true || true
        test -f "$out/lib/libc.a" || { echo "FATAL: libc.a not installed"; exit 1; }
        test -f "$out/include/stdio.h" || { echo "FATAL: headers not installed"; exit 1; }

        # elf.h and related headers may not be installed with --disable-shared
        for h in elf/elf.h elf/link.h; do
          bn="$(basename "$h")"
          if [ ! -f "$out/include/$bn" ] && [ -f "$TMPDIR/glibc-2.17/$h" ]; then
            cp "$TMPDIR/glibc-2.17/$h" "$out/include/$bn"
          fi
        done
        if [ ! -f "$out/include/bits/elfclass.h" ]; then
          mkdir -p "$out/include/bits"
          printf '#ifndef _BITS_ELFCLASS_H\n#define _BITS_ELFCLASS_H\n#define __ELF_NATIVE_CLASS ${elfClass}\n#endif\n' \
            > "$out/include/bits/elfclass.h"
        fi
        if [ ! -f "$out/include/bits/link.h" ] && [ -f "$TMPDIR/glibc-2.17/sysdeps/${linkSysdep}/bits/link.h" ]; then
          cp "$TMPDIR/glibc-2.17/sysdeps/${linkSysdep}/bits/link.h" "$out/include/bits/link.h"
        fi
        # gnu/stubs-{32,64}.h — needed by glibc's stubs.h
        mkdir -p "$out/include/gnu"
        touch "$out/include/gnu/stubs-${stubsSuffix}.h"

        # Copy linux headers into glibc output for downstream use
        cp -r "${linuxHeaders}/include/linux" "$out/include/" 2>/dev/null || true
        cp -r "${linuxHeaders}/include/asm" "$out/include/" 2>/dev/null || true
        cp -r "${linuxHeaders}/include/asm-generic" "$out/include/" 2>/dev/null || true

        echo "glibc 2.17 installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "GNU C Library, version 2.17";
      homepage = "https://www.gnu.org/software/libc/";
      license = "LGPL-2.1-or-later";
      build = {
        os = "linux";
      };
      execute = {
        os = "linux";
      };
    };
  }
