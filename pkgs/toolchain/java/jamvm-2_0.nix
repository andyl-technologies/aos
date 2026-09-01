##! jamvm-2_0 — JamVM 2.0.0 Java Virtual Machine with Classpath 0.99
{
  mkDerivation,
  fetchurl,
  gnumake,
  stdenv,
  buildPackages,
  classpath-0_99,
  libffi,
  zlib,
}: let
  version = "2.0.0";
  isDarwinCross = stdenv.isCross && stdenv.hostPlatform.isDarwin;
  aarch64Patch = fetchurl {
    urls = [
      "https://cgit.git.savannah.gnu.org/cgit/guix.git/plain/gnu/packages/patches/jamvm-2.0.0-aarch64-support.patch?id=f23b95a3b24003f46293d67ce2ab4c2d1785853d"
    ];
    hash = "sha256-mvn8e9E7P7qfjtoLNcQpafOaU9VOCFaEHwnFKFz6lqw=";
  };
in
  mkDerivation {
    pname = "jamvm-2_0";
    inherit version;

    src = fetchurl {
      urls = [
        "https://downloads.sourceforge.net/project/jamvm/jamvm/JamVM%20${version}/jamvm-${version}.tar.gz"
      ];
      hash = "sha256-dkKOlt8K6d2WTHp8dMHpqDfi8xLDnpo1f6gXj37/gNo=";
    };

    buildDeps =
      [gnumake]
      ++ (
        if isDarwinCross
        then [
          buildPackages.autoconf
          buildPackages.automake
          buildPackages.libtool
          buildPackages.m4
        ]
        else []
      );
    runtimeDeps =
      [
        classpath-0_99
        zlib
      ]
      ++ (
        if isDarwinCross
        then [libffi]
        else []
      );
    hardeningDisable = ["fortify3"];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd jamvm-${version}
        '';
      }
      {
        name = "patch";
        script =
          if isDarwinCross
          then ''
            # Add _GNU_SOURCE for pthread_getattr_np (GNU extension)
            sed -i '1i #define _GNU_SOURCE' src/os/linux/os.c 2>/dev/null || true

            patch -p1 < ${aarch64Patch}

            sed -i \
              -e '/i\[\[3456\]\]86-\*-darwin/a x86_64-*-darwin*) host_os=darwin libdl_needed=no ;;' \
              -e '/arm\*-\*-darwin/a aarch64*-*-darwin*) host_cpu=aarch64 host_os=darwin libdl_needed=no ;;' \
              -e '/src\/os\/darwin\/i386\/Makefile/a\    src/os/darwin/x86_64/Makefile \\' \
              -e '/src\/os\/darwin\/arm\/Makefile/a\    src/os/darwin/aarch64/Makefile \\' \
              configure.ac

            cp -a src/os/darwin/i386 src/os/darwin/x86_64
            cp -a src/os/linux/aarch64 src/os/darwin/aarch64
            sed -i 's/ init.c dll_md.c callNative.S/ init.c dll_md.c/' \
              src/os/darwin/aarch64/Makefile.am
            sed -i 's/DIST_SUBDIRS = /DIST_SUBDIRS = x86_64 aarch64 /' \
              src/os/darwin/Makefile.am

            # The inlining interpreter uses GNU statement expressions only
            # to group handler bodies. Clang rejects indirect branches into
            # those expressions, but accepts the equivalent compound blocks.
            # Keep the inlining engine enabled and preserve every handler.
            test "$(grep -o '({' src/interp/engine/interp-inlining.h | wc -l)" -eq 15
            test "$(grep -o '});' src/interp/engine/interp-inlining.h | wc -l)" -eq 15
            sed -i -e 's/({/{/g' -e 's/});/}/g' \
              src/interp/engine/interp-inlining.h
            ! grep -q -e '({' -e '});' src/interp/engine/interp-inlining.h

            ACLOCAL_PATH=${buildPackages.libtool}/share/aclocal autoreconf -fi
          ''
          else ''
            # Add _GNU_SOURCE for pthread_getattr_np (GNU extension)
            sed -i '1i #define _GNU_SOURCE' src/os/linux/os.c 2>/dev/null || true
          '';
      }
      {
        name = "configure";
        script =
          if isDarwinCross
          then ''
            CFLAGS="-O2 -std=gnu11 -Wno-error -Wno-implicit-function-declaration -Wno-incompatible-pointer-types" \
            ./configure \
              --build=${stdenv.buildPlatform.config} \
              --host=${stdenv.hostPlatform.config} \
              --prefix=$out \
              --enable-ffi \
              --with-classpath-install-dir=${classpath-0_99}
          ''
          else ''
            CFLAGS="-O2 -std=gnu11 -Wno-error -Wno-implicit-function-declaration -Wno-incompatible-pointer-types" \
            ./configure \
              --prefix=$out \
              --with-classpath-install-dir=${classpath-0_99}
          '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          make install
          # Create java symlink so this can be used as JAVA_HOME
          ln -s jamvm $out/bin/java
        '';
      }
    ];

    meta = {
      description = "JamVM 2.0.0 — Java Virtual Machine with Classpath 0.99";
      homepage = "https://jamvm.sourceforge.net/";
      license = "GPL-2.0";
    };
  }
