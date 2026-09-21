##! X font encodings and generated lookup indexes.
{
  mkDerivation,
  fetchurl,
  buildPackages,
}: let
  version = "1.1.0";
  # The indexer reads the source encodings explicitly, so it can bootstrap
  # without an installed encoding database. Only the final library is published.
  bootstrapFontenc = import ./_libfontenc.nix {
    inherit (buildPackages) fetchurl stdenv xorgproto zlib;
    mkDerivation = args: buildPackages.mkDerivation (args // {pname = "fontenc-indexer-bootstrap";});
    inherit buildPackages;
  };
  indexer = import ../tools/mkfontscale.nix {
    inherit (buildPackages) fetchurl stdenv freetype zlib bzip2 xorgproto;
    mkDerivation = args: buildPackages.mkDerivation (args // {pname = "font-encoding-indexer";});
    inherit buildPackages;
    libfontenc = bootstrapFontenc;
  };
in
  mkDerivation {
    pname = "encodings";
    inherit version;
    src = fetchurl {
      urls = ["https://www.x.org/releases/individual/font/encodings-${version}.tar.xz"];
      hash = "0xg99nmpvik6vaz4h03xay7rx0r3bf5a8azkjlpa3ksn2xi3rwcz";
    };
    buildDeps = [buildPackages.meson buildPackages.ninja buildPackages.python3 buildPackages.gzip indexer];
    runtimeDeps = [];
    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd encodings-${version}
          sed -i '1s|^#!.*|#!${buildPackages.bash}/bin/bash|' mkencodingsdir.in
        '';
      }
      {
        name = "configure";
        script = ''
          meson setup build $mesonFlags --prefix="$out" --libdir=lib --buildtype=release -Dencodingsdir="$out/share/fonts/X11/encodings"
        '';
      }
      {
        name = "build";
        script = ''
          PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages ninja -C build
        '';
      }
      {
        name = "check";
        script = ''
          PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages \
            meson test -C build --print-errorlogs
        '';
      }
      {
        name = "install";
        script = ''
          meson install -C build
          mkdir -p "$out/share/licenses/encodings"
          cp COPYING "$out/share/licenses/encodings/"
          test -s "$out/share/fonts/X11/encodings/encodings.dir"
          test -s "$out/share/fonts/X11/encodings/large/encodings.dir"
        '';
      }
    ];
    meta = {
      description = "X font encodings and lookup indexes";
      homepage = "https://www.x.org/";
      license = "MIT";
    };
  }
