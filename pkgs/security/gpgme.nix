##! gpgme — High-level API for GnuPG operations
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  texinfo,
  gnupg,
  libassuan,
  libgpg-error,
  npth,
  glib,
}: let
  version = "2.0.1";
in
  mkDerivation {
    pname = "gpgme";
    inherit version;

    src = fetchurl {
      urls = [
        "https://gnupg.org/ftp/gcrypt/gpgme/gpgme-${version}.tar.bz2"
      ];
      hash = "sha256-ghqwaVyELqtRdSqBmAySsEEMfq3QQQP3kdXSpSZ4SWY=";
    };

    buildDeps = [gnumake pkg-config texinfo gnupg];
    runtimeDeps = [libassuan libgpg-error npth glib];
    propagatedDeps = [libassuan libgpg-error];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd gpgme-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix="$out" \
            --enable-fixed-path=${gnupg}/bin \
            --with-libgpg-error-prefix=${libgpg-error} \
            --with-libassuan-prefix=${libassuan}
        '';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "check";
        script = ''make -j"$NIX_BUILD_CORES" check'';
      }
      {
        name = "install";
        script = ''make install'';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-gpgme";
        library = self;
        libs = ["-lgpgme"];
        testSource = ''
          #include <gpgme.h>

          int main(void) {
              return gpgme_check_version(NULL) == NULL;
          }
        '';
      };
      tool = testing.mkToolCheck {
        pname = "tool-gpgme";
        tool = self;
        command = "gpgme-tool --version";
      };
    };

    meta = {
      description = "High-level API for GnuPG operations";
      homepage = "https://gnupg.org/software/gpgme/";
      license = "LGPL-2.1-or-later AND GPL-3.0-or-later";
    };
  }
