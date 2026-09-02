##! minisign — Dead simple signing tool
{
  mkDerivation,
  fetchurl,
  gnumake,
  cmake,
  pkg-config,
  libsodium,
}: let
  version = "0.12";
in
  mkDerivation {
    pname = "minisign";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/jedisct1/minisign/archive/${version}/minisign-${version}.tar.gz"
      ];
      hash = "sha256-eW3OE3b5vLGhns5ynAdcRwVDZDVf4MDB6+UQTVCMfbA=";
    };

    buildDeps = [
      gnumake
      cmake
      pkg-config
    ];
    runtimeDeps = [libsodium];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd minisign-${version}
        '';
      }
      {
        name = "build";
        script = ''
          mkdir -p build && cd build
          cmake .. \
            $cmakeFlags \
            -DCMAKE_INSTALL_PREFIX=$out \
            -DCMAKE_BUILD_TYPE=Release
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
      description = "minisign — simple tool to sign and verify files";
      homepage = "https://jedisct1.github.io/minisign/";
      license = "ISC";
    };
  }
