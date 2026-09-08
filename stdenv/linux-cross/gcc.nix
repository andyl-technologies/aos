##! Native-executable GCC 16 cross compiler stages.
{
  buildStdenv,
  buildPackages,
  buildPlatform,
  hostPlatform,
  sources,
  binutils,
  linuxHeaders,
  libc ? null,
  stage,
}: let
  finalStage = stage == "final";
  version = "16.2.0";
in
  buildStdenv.mkDerivation {
    pname = "gcc";
    inherit version;
    src = sources.gcc;
    hostPlatform = buildPlatform;
    targetPlatform = hostPlatform;

    buildDeps = [
      buildPackages.gnumake
      buildPackages.m4
      buildPackages.flex
      buildPackages.bison
      buildPackages.texinfo
      buildPackages.perl
      buildPackages.python3
      binutils
    ];
    runtimeDeps = [binutils];
    propagatedDeps = [];

    hardeningDisable = ["all"];

    phases = [
      {
        name = "unpack";
        script = ''
          mkdir source
          (cd $src && tar cf - .) | (cd source && tar xf -)
          chmod -R u+w source

          for dependency in gmp mpfr mpc isl; do
            mkdir "source/$dependency"
          done
          (cd ${sources.gmp} && tar cf - .) | (cd source/gmp && tar xf -)
          (cd ${sources.mpfr} && tar cf - .) | (cd source/mpfr && tar xf -)
          (cd ${sources.mpc} && tar cf - .) | (cd source/mpc && tar xf -)
          (cd ${sources.isl} && tar cf - .) | (cd source/isl && tar xf -)
          chmod -R u+w source/gmp source/mpfr source/mpc source/isl

          # GCC's option generators rely on unset array elements behaving as
          # empty strings, while gawk 5.4 can preserve a numeric zero type.
          patch -p1 -d source < ${./gcc-16-gawk-5.4.patch}

          find source -type f \( -name '*.y' -o -name '*.l' -o -name 'Makefile.am' -o -name 'configure.ac' -o -name 'configure.in' \) -exec touch {} + 2>/dev/null || true
          sleep 1
          find source -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true
          sleep 1
          find source \( -name configure -o -name Makefile.in -o -name aclocal.m4 -o -name config.h.in \) -exec touch {} + 2>/dev/null || true
        '';
      }
      {
        name = "configure";
        script = ''
          export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true

          ${
            if finalStage
            then ''
              sysroot="$out/${hostPlatform.config}/sys-root"
              mkdir -p "$sysroot/usr/include" "$sysroot/usr/lib" "$sysroot/lib"
              for entry in ${libc.dev}/include/*; do
                ln -s "$entry" "$sysroot/usr/include/$(basename "$entry")"
              done
              for entry in ${libc}/lib/*; do
                ln -s "$entry" "$sysroot/lib/$(basename "$entry")"
                ln -s "$entry" "$sysroot/usr/lib/$(basename "$entry")"
              done
              for entry in ${libc.static}/lib/*; do
                name="$(basename "$entry")"
                if test ! -e "$sysroot/usr/lib/$name"; then
                  ln -s "$entry" "$sysroot/usr/lib/$name"
                fi
              done
            ''
            else ''
              sysroot="$TMPDIR/empty-sysroot"
              mkdir -p "$sysroot/usr/include"
              for entry in ${linuxHeaders}/include/*; do
                ln -s "$entry" "$sysroot/usr/include/$(basename "$entry")"
              done
            ''
          }

          mkdir build
          cd build
          CC=${buildStdenv.cc}/bin/cc \
          CXX=${buildStdenv.cc}/bin/c++ \
          ../source/configure \
            --prefix="$out" \
            --build=${buildPlatform.config} \
            --host=${buildPlatform.config} \
            --target=${hostPlatform.config} \
            --with-as=${binutils}/bin/${hostPlatform.config}-as \
            --with-ld=${binutils}/bin/${hostPlatform.config}-ld \
            --with-sysroot="$sysroot" \
            --with-native-system-header-dir=/usr/include \
            --disable-bootstrap \
            --disable-libsanitizer \
            --disable-libvtv \
            --disable-multilib \
            --disable-nls \
            ${
            if finalStage
            then "--enable-languages=c,c++ --enable-shared --enable-threads=posix"
            else "--enable-languages=c --disable-libatomic --disable-shared --disable-threads --with-newlib --without-headers"
          }
        '';
      }
      {
        name = "build";
        script = ''
          export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
          make -j"$NIX_BUILD_CORES" all-gcc
          make -j"$NIX_BUILD_CORES" all-target-libgcc
          ${
            if finalStage
            then ''
              make -j"$NIX_BUILD_CORES" all-target-libstdc++-v3
              make -j"$NIX_BUILD_CORES" all-target-libatomic
              make -j"$NIX_BUILD_CORES" all-target-libgomp
            ''
            else ""
          }
        '';
      }
      {
        name = "install";
        script = ''
          export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
          make install-gcc
          make install-target-libgcc
          ${
            if finalStage
            then ''
              make install-target-libstdc++-v3
              make install-target-libatomic
              make install-target-libgomp
            ''
            else ""
          }

          for pair in \
            "${hostPlatform.config}-gcc gcc" \
            "${hostPlatform.config}-g++ g++" \
            "${hostPlatform.config}-gcc cc" \
            "${hostPlatform.config}-g++ c++"; do
            set -- $pair
            if test -x "$out/bin/$1"; then
              if test -e "$out/bin/$2"; then
                test -x "$out/bin/$2"
              else
                ln -s "$1" "$out/bin/$2"
              fi
            fi
          done
          test -x "$out/bin/gcc"
          test -x "$out/bin/${hostPlatform.config}-gcc"
        '';
      }
    ];

    meta = {
      description = "GCC ${version} running on ${buildPlatform.system} and targeting ${hostPlatform.system}";
      homepage = "https://gcc.gnu.org/";
      license = "GPL-3.0-or-later";
      mainProgram = "${hostPlatform.config}-gcc";
      build = {
        os = "linux";
        cpu = [buildPlatform.constraints.cpu];
      };
      execute = {
        os = "linux";
        cpu = [buildPlatform.constraints.cpu];
      };
      target = {
        os = "linux";
        cpu = [hostPlatform.constraints.cpu];
      };
    };
  }
