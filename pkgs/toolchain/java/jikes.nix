##! jikes — Jikes Java compiler (C++ implementation, outputs Java 1.4 bytecode)
{
  mkDerivation,
  fetchurl,
  stdenv,
  buildPackages,
  gnumake,
}: let
  version = "1.22";
  isDarwinCross = stdenv.isCross && stdenv.hostPlatform.isDarwin;
in
  mkDerivation {
    pname = "jikes";
    inherit version;

    src = fetchurl {
      urls = [
        "https://downloads.sourceforge.net/project/jikes/Jikes/${version}/jikes-${version}.tar.bz2"
      ];
      hash = "sha256-DLAsdjvEQTSfbTjKzVKt92IwLM46COJp8fdfcm5uFOM=";
    };

    buildDeps =
      [gnumake]
      ++ (
        if isDarwinCross
        then [buildPackages.automake]
        else []
      );
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd jikes-${version}
        '';
      }
      {
        name = "configure";
        script =
          if isDarwinCross
          then ''
              # Jikes predates AArch64 and otherwise treats a target C++
              # executable as a runnable configure probe. Refresh only the
              # canonical triplet table and use the stdenv cross tuple.
              cp ${buildPackages.automake}/share/automake-*/config.sub config.sub

            # Jikes targets the pre-C++17 language where `register` remains
            # accepted; modern Clang otherwise rejects its bundled inflater.
            CXXFLAGS="-fpermissive -std=gnu++14" \
              ./configure $configureFlags --prefix=$out
          ''
          else ''
            CXXFLAGS="-fpermissive" ./configure --prefix=$out
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
      description = "Jikes — fast Java compiler written in C++";
      homepage = "https://jikes.sourceforge.net/";
      license = "IPL-1.0";
    };
  }
