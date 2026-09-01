##! libqcow — QEMU Copy-On-Write (QCOW) image file library
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  zlib,
  openssl,
  stdenv,
}: let
  version = "20240308";
in
  mkDerivation {
    pname = "libqcow";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/libyal/libqcow/releases/download/${version}/libqcow-alpha-${version}.tar.gz"
      ];
      hash = "sha256-94E7RvRtTWVoPyCvBz1zYvmSAs/bpzQhEmEWGAbXN7I=";
    };

    buildDeps = [
      gnumake
      pkg-config
    ];
    runtimeDeps = [
      zlib
      openssl
    ];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libqcow-${version}
        '';
      }
      {
        name = "configure";
        script =
          if stdenv.isCross && stdenv.hostPlatform.isDarwin
          then ''
            # This capability is true for the same AOS OpenSSL in the
            # native build, but Autoconf otherwise tries to execute the
            # Darwin probe binary while cross compiling.
            export ac_cv_openssl_xts_duplicate_keys=yes
            ./configure \
              $configureFlags \
              --prefix=$out \
              --enable-shared \
              --disable-static \
              --with-zlib=${zlib} \
              --with-openssl=${openssl} \
              --disable-python
          ''
          else ''
            ./configure \
              $configureFlags \
              --prefix=$out \
              --enable-shared \
              --disable-static \
              --with-zlib=${zlib} \
              --with-openssl=${openssl} \
              --disable-python
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
        '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      soname = testing.mkSONAMECheck {
        pkg = self;
        libs = ["libqcow.so"];
      };

      link = testing.mkLinkCheck {
        pname = "lib-libqcow";
        library = self;
        libs = ["-lqcow"];
        extraDeps = [
          pkgs.zlib
          pkgs.openssl
        ];
        testSource = ''
          #include <libqcow.h>
          #include <stdio.h>
          int main() {
            const char *version = libqcow_get_version();
            printf("libqcow version: %s\n", version);
            return 0;
          }
        '';
      };
    };

    meta = {
      description = "libqcow — QEMU Copy-On-Write image file library";
      homepage = "https://github.com/libyal/libqcow";
      license = "LGPL-3.0-or-later";
    };
  }
