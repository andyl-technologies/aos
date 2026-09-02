##! libssh2 — Client-side C library implementing the SSH2 protocol
{
  mkDerivation,
  fetchurl,
  gnumake,
  openssl,
  zlib,
  stdenv,
}: let
  version = "1.11.1";
in
  mkDerivation {
    pname = "libssh2";
    inherit version;

    src = fetchurl {
      urls = [
        "https://www.libssh2.org/download/libssh2-${version}.tar.gz"
      ];
      hash = "sha256-2ex2y+NNuY7sNTn+LImdJrDIN8s+tGalaw8QnKv2WPc=";
    };

    buildDeps = [
      gnumake
    ];
    runtimeDeps = [
      openssl
      zlib
    ];
    propagatedDeps = [openssl];

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf $src
            cd libssh2-${version}
          '';
        }
      ]
      ++ (
        if stdenv.isCross && stdenv.hostPlatform.isDarwin
        then [
          {
            name = "darwin-build-paths";
            script = ''
              export CFLAGS="$CFLAGS \
                -ffile-prefix-map=$PWD=. \
                -fdebug-prefix-map=$PWD=."
            '';
          }
        ]
        else []
      )
      ++ [
        {
          name = "configure";
          script = ''
            ./configure \
              $configureFlags \
              --prefix=$out \
              --with-crypto=openssl \
              --with-libssl-prefix=${openssl} \
              --with-libz \
              --enable-shared \
              --disable-static
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

    meta = {
      description = "libssh2 — client-side C library implementing the SSH2 protocol";
      homepage = "https://libssh2.org";
      license = "BSD-3-Clause";
    };

    checks = {
      testing,
      self,
      pkgs,
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-libssh2";
        library = self;
        libs = ["-lssh2"];
        extraDeps = [pkgs.openssl];
        testSource = ''
          #include <libssh2.h>
          #include <stdio.h>
          int main() {
            const char *ver = libssh2_version(0);
            if (!ver) return 1;
            printf("libssh2 version: %s\n", ver);
            return 0;
          }
        '';
      };
    };
  }
