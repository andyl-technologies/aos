##! GNU m4 — Macro processor
{
  mkDerivation,
  fetchurl,
  gnumake,
  stdenv,
}: let
  version = "1.4.20";
in
  mkDerivation {
    pname = "m4";
    inherit version;

    src = fetchurl {
      urls = [
        "https://mirrors.kernel.org/gnu/m4/m4-${version}.tar.xz"
      ];
      hash = "sha256-4jbqOhzPX2wnCxxLtgcm83H6SUWajqrryQshazKNrys=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd m4-${version}
        '';
      }
      {
        name = "configure";
        script =
          if stdenv.hostPlatform.isDarwin
          then ''
            CFLAGS="-g -O2 -Wno-error=format-security" ./configure \
              $configureFlags \
              --prefix=$out
          ''
          else ''
            ./configure \
              $configureFlags \
              --prefix=$out
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
      description = "GNU m4 — macro processor";
      homepage = "https://www.gnu.org/software/m4/";
      license = "GPL-3.0-or-later";
    };
  }
