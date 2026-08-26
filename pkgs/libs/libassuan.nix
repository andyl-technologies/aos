##! libassuan — IPC library implementing the Assuan protocol used by GnuPG
{
  mkDerivation,
  fetchurl,
  gnumake,
  libgpg-error,
  bash,
  stdenv,
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
    runtimeDeps =
      [libgpg-error]
      ++ (
        if stdenv.hostPlatform.isDarwin
        then [bash]
        else []
      );
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
            $configureFlags \
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
        script =
          if stdenv.hostPlatform.isDarwin
          then ''
            make install
            sed -i "1s|^#!.*|#!${bash}/bin/bash|" "$out/bin/libassuan-config"
          ''
          else ''
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
