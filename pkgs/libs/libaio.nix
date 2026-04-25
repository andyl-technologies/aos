##! libaio — Linux-native asynchronous I/O facility
{
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "0.3.113";
in
  mkDerivation {
    pname = "libaio";
    inherit version;

    src = fetchurl {
      urls = [
        "https://pagure.io/libaio/archive/libaio-${version}/libaio-libaio-${version}.tar.gz"
      ];
      hash = "sha256-cWxwWXAyRzROsGa1TsvDyiE08BAzBxkubCt9q1+VKKs=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libaio-libaio-${version}
        '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES prefix=$out libdir=$out/lib
        '';
      }
      {
        name = "install";
        script = ''
          make install prefix=$out libdir=$out/lib
        '';
      }
    ];

    meta = {
      description = "Linux-native asynchronous I/O facility";
      homepage = "https://pagure.io/libaio";
      license = "LGPL-2.1-or-later";
    };
  }
