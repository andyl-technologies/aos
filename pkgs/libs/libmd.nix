##! libmd — BSD message-digest functions
{
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "1.2.0";
in
  mkDerivation {
    pname = "libmd";
    inherit version;

    src = fetchurl {
      urls = [
        "https://libbsd.freedesktop.org/releases/libmd-${version}.tar.xz"
      ];
      hash = "sha256-rBX/uEMFAvuszexmxagu4OqwsPNiIN9WcQ/q3+sT0KA=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libmd-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out \
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

          mkdir -p "$out/share/licenses/libmd"
          cp COPYING "$out/share/licenses/libmd/COPYING"
        '';
      }
    ];

    meta = {
      description = "BSD message-digest functions";
      homepage = "https://www.hadrons.org/software/libmd/";
      platforms = ["x86_64-linux" "aarch64-linux"];
      license = [
        "BSD-2-Clause"
        "BSD-3-Clause"
        "ISC"
        "Beerware"
        "LicenseRef-Public-Domain"
      ];
    };
  }
