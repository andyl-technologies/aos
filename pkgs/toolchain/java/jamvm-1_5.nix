##! jamvm-1_5 — JamVM 1.5.1 pure-C Java Virtual Machine
{
  mkDerivation,
  fetchurl,
  gnumake,
  stdenv,
  buildPackages,
  classpath-0_93,
  libffi,
  zlib,
}: let
  version = "1.5.1";
  isDarwinCross = stdenv.isCross && stdenv.hostPlatform.isDarwin;
  aarch64Patch = fetchurl {
    urls = [
      "https://cgit.git.savannah.gnu.org/cgit/guix.git/plain/gnu/packages/patches/jamvm-1.5.1-aarch64-support.patch?id=f23b95a3b24003f46293d67ce2ab4c2d1785853d"
    ];
    hash = "sha256-jI6HCWLDoBJ5P6RLitlXiq3CxS5OBIwEoeO8PxPudpc=";
  };
in
  mkDerivation {
    pname = "jamvm-1_5";
    inherit version;

    src = fetchurl {
      urls = [
        "https://downloads.sourceforge.net/project/jamvm/jamvm/JamVM%20${version}/jamvm-${version}.tar.gz"
      ];
      hash = "sha256-ZjiVvWnK86H9pq9e6oJj2Qpf01yo9MMuIhCsQQeIkBo=";
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
        classpath-0_93
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
            sed -i '1i #define _GNU_SOURCE' src/os/linux/os.c

            # Backport Guix's reviewed AArch64 definitions. Darwin uses
            # libffi for native calls, so no Linux assembly enters the target.
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

            ACLOCAL_PATH=${buildPackages.libtool}/share/aclocal autoreconf -fi
          ''
          else ''
            # Add _GNU_SOURCE for pthread_getattr_np (GNU extension)
            sed -i '1i #define _GNU_SOURCE' src/os/linux/os.c
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
              --with-classpath-install-dir=${classpath-0_93}
          ''
          else ''
            CFLAGS="-O2 -std=gnu11 -Wno-error -Wno-implicit-function-declaration -Wno-incompatible-pointer-types" \
            ./configure \
              --prefix=$out \
              --with-classpath-install-dir=${classpath-0_93}
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
      description = "JamVM 1.5.1 — compact pure-C Java Virtual Machine";
      homepage = "https://jamvm.sourceforge.net/";
      license = "GPL-2.0";
    };
  }
