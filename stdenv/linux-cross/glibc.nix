##! GNU libc cross-compiled for the selected Linux host platform.
{
  buildStdenv,
  buildPackages,
  buildPlatform,
  hostPlatform,
  sources,
  binutils,
  linuxHeaders,
  gccStage1,
}:
buildStdenv.mkDerivation {
  pname = "glibc";
  version = "2.39";
  src = sources.glibc;
  outputs = [
    "out"
    "bin"
    "dev"
    "static"
    "getent"
  ];
  hostPlatform = hostPlatform;
  targetPlatform = hostPlatform;

  buildDeps = [
    buildPackages.gnumake
    buildPackages.gawk
    buildPackages.bison
    buildPackages.perl
    buildPackages.python3
    gccStage1
    binutils
  ];
  runtimeDeps = [];
  propagatedDeps = [];

  hardeningDisable = ["all"];

  phases = [
    {
      name = "unpack";
      script = ''
        mkdir source
        (cd $src && tar cf - .) | (cd source && tar xf -)
        chmod -R u+w source
        sed -i 's|/bin/pwd|pwd|g' source/configure
      '';
    }
    {
      name = "configure";
      script = ''
        mkdir build
        cd build
        BUILD_CC=${buildStdenv.cc}/bin/cc \
        CC=${gccStage1}/bin/gcc \
        CXX=false \
        AR=${binutils}/bin/ar \
        AS=${binutils}/bin/as \
        LD=${binutils}/bin/ld \
        NM=${binutils}/bin/nm \
        OBJCOPY=${binutils}/bin/objcopy \
        OBJDUMP=${binutils}/bin/objdump \
        RANLIB=${binutils}/bin/ranlib \
        READELF=${binutils}/bin/readelf \
        STRIP=${binutils}/bin/strip \
        CFLAGS="-O2" \
        ../source/configure \
          --prefix="$out" \
          --build=${buildPlatform.config} \
          --host=${hostPlatform.config} \
          --with-headers=${linuxHeaders}/include \
          --disable-profile \
          --disable-nscd \
          --disable-timezone-tools \
          --disable-werror \
          --enable-kernel=4.19 \
          --enable-static-nss \
          --without-gd \
          --without-selinux \
          libc_cv_forced_unwind=yes \
          libc_cv_c_cleanup=yes
      '';
    }
    {
      name = "build";
      script = ''
        make -j"$NIX_BUILD_CORES"
      '';
    }
    {
      name = "install";
      script = ''
        make install

        mkdir -p "$dev" "$static/lib" "$bin/bin" "$bin/sbin" "$getent/bin"
        mv "$out/include" "$dev/include"
        for directory in linux asm asm-generic; do
          rm -rf "$dev/include/$directory"
          cp -r "${linuxHeaders}/include/$directory" "$dev/include/$directory"
        done

        for archive in "$out"/lib/*.a; do
          test -e "$archive" || continue
          mv "$archive" "$static/lib/"
        done
        for archive in libc_nonshared.a libpthread_nonshared.a; do
          if test -f "$static/lib/$archive"; then
            mv "$static/lib/$archive" "$out/lib/$archive"
          fi
        done

        if test -f "$out/bin/getent"; then
          mv "$out/bin/getent" "$getent/bin/getent"
        fi
        if test -d "$out/bin"; then
          for program in "$out"/bin/*; do
            test -e "$program" && mv "$program" "$bin/bin/"
          done
          rmdir "$out/bin" 2>/dev/null || true
        fi
        if test -d "$out/sbin"; then
          for program in "$out"/sbin/*; do
            test -e "$program" && mv "$program" "$bin/sbin/"
          done
          rmdir "$out/sbin" 2>/dev/null || true
        fi

        test -f "$out/lib/${hostPlatform.dynamicLinker}"
        test -f "$dev/include/stdio.h"
        test -f "$static/lib/libc.a"
      '';
    }
  ];

  meta = {
    description = "GNU C Library 2.39 for ${hostPlatform.system}";
    homepage = "https://www.gnu.org/software/libc/";
    license = "LGPL-2.1-or-later";
    build = {
      os = "linux";
      cpu = [buildPlatform.constraints.cpu];
    };
    execute = {
      os = "linux";
      cpu = [hostPlatform.constraints.cpu];
    };
  };
}
