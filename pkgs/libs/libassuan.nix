##! libassuan — IPC library implementing the Assuan protocol used by GnuPG
{
  mkDerivation,
  fetchurl,
  gnumake,
  libgpg-error,
}: let
  version = "3.0.2";
in
  mkDerivation {
    pname = "libassuan";
    inherit version;

    src = fetchurl {
      urls = [
        "https://gnupg.org/ftp/gcrypt/libassuan/libassuan-${version}.tar.bz2"
        "https://mirrors.dotsrc.org/gcrypt/libassuan/libassuan-${version}.tar.bz2"
      ];
      hash = "sha256-0pMc2tJm5jNRD5lw4aLzRgVeNRuxn5t4kSR1uAdMNvY=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [libgpg-error];
    propagatedDeps = [libgpg-error];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libassuan-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out \
            --disable-static \
            --with-libgpg-error-prefix=${libgpg-error}
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
      description = "IPC library implementing the Assuan protocol used by GnuPG";
      homepage = "https://gnupg.org/software/libassuan/";
      license = "LGPL-2.1-or-later";
    };
  }
