##! fmt — Modern C++ formatting library.
{
  mkDerivation,
  fetchurl,
  cmake,
  gnumake,
  unzip,
}: let
  version = "12.1.0";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "fmt";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/fmtlib/fmt/releases/download/${version}/fmt-${version}.zip"
      ];
      hash = "sha256-aV/Rl/pa/4/Ge18rvBEEkKh1zfekFoashRL7SA+orac=";
    };

    buildDeps = [cmake gnumake unzip];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          unzip "$src"
          cd fmt-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          mkdir build
          cd build
          cmake .. \
            -DCMAKE_BUILD_TYPE=Release \
            -DCMAKE_INSTALL_PREFIX="$out" \
            -DFMT_DOC=OFF \
            -DFMT_TEST=ON
        '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "check";
        script = ''
          make test
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
      description = "fmt — modern C++ formatting library";
      homepage = "https://fmt.dev/";
      license = "MIT";
    };
  }
