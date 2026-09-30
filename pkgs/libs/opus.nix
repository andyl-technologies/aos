##! opus — Low-latency speech and audio codec
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  doxygen,
  graphviz,
  perl,
  stdenv,
  buildPackages,
}: let
  version = "1.6.1";
in
  mkDerivation {
    pname = "opus";
    inherit version;

    src = fetchurl {
      urls = ["https://downloads.xiph.org/releases/opus/opus-${version}.tar.gz"];
      hash = "sha256-b/y1kyB76SWE3xWzJGbtZLvsmRCfAHyCIF8BlFckEaE=";
    };

    buildDeps =
      if stdenv.isCross
      then [
        buildPackages.gnumake
        buildPackages.pkg-config
        buildPackages.doxygen
        buildPackages.graphviz
        buildPackages.perl
      ]
      else [gnumake pkg-config doxygen graphviz perl];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd opus-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          # Release sources include the neural model data. Build the production
          # recovery and speech enhancements without fetching weights at build
          # time; applications retain their runtime complexity controls.
          "$CONFIG_SHELL" ./configure \
            $configureFlags \
            --prefix="$out" \
            --enable-shared \
            --enable-static \
            --enable-custom-modes \
            --enable-opus-custom-api \
            --enable-deep-plc \
            --enable-dred \
            --enable-osce
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
        script =
          if stdenv.isCross
          then ""
          else ''
            make -j$NIX_BUILD_CORES check
          '';
      }
      {
        name = "install";
        script = ''
          make install
          mkdir -p "$out/share/licenses/opus"
          cp COPYING "$out/share/licenses/opus/COPYING"
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      soname = testing.mkSONAMECheck {
        pkg = self;
        libs = ["libopus.so"];
      };
    };

    meta = {
      description = "Low-latency speech and audio codec with neural recovery";
      homepage = "https://opus-codec.org/";
      license = "BSD-3-Clause";
    };
  }
