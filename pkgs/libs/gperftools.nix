##! gperftools — Fast memory allocation and performance analysis tools
{
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "2.18.1";
in
  mkDerivation {
    pname = "gperftools";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/gperftools/gperftools/releases/download/gperftools-${version}/gperftools-${version}.tar.gz"
      ];
      hash = "sha256-0Y2RkXX55NdArOa1Lw9PkShBYMRU6Rs2/9ZFYoKgIgY=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd gperftools-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          $CONFIG_SHELL ./configure \
            $configureFlags \
            --prefix="$out" \
            --enable-shared \
            --enable-static
        '';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "install";
        script = ''
          make install
          test -f "$out/lib/libtcmalloc_minimal.so"
        '';
      }
    ];

    meta = {
      description = "Fast memory allocation and performance analysis tools";
      homepage = "https://github.com/gperftools/gperftools";
      license = "BSD-3-Clause";
    };
  }
