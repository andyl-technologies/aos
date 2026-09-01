##! libbsd — BSD compatibility interfaces for Linux
{
  mkDerivation,
  fetchurl,
  gnumake,
  libmd,
}: let
  version = "0.12.2";
in
  mkDerivation {
    pname = "libbsd";
    inherit version;

    src = fetchurl {
      urls = [
        "https://libbsd.freedesktop.org/releases/libbsd-${version}.tar.xz"
      ];
      hash = "sha256-uIzJFj0MZSqvOamZkdl03bocOpcR248bWDivKhRzEBQ=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [libmd];
    # libbsd.so is an ld script whose GROUP contains AS_NEEDED(-lmd), so every
    # downstream link against -lbsd must also be able to resolve libmd.
    propagatedDeps = [libmd];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libbsd-${version}
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

          mkdir -p "$out/share/licenses/libbsd"
          cp COPYING "$out/share/licenses/libbsd/COPYING"
        '';
      }
    ];

    meta = {
      description = "BSD compatibility interfaces for Linux";
      homepage = "https://libbsd.freedesktop.org/";
      platforms = ["x86_64-linux" "aarch64-linux"];
      license = [
        "BSD-2-Clause"
        "BSD-3-Clause"
        "LicenseRef-BSD-5-Clause-Peter-Wemm"
        "ISC"
        "MIT"
        "Beerware"
        "LicenseRef-Public-Domain"
      ];
    };
  }
