##! Shared X.Org documentation stylesheets and cross-reference databases.
{
  mkDerivation,
  fetchurl,
  buildPackages,
}: let
  version = "1.12.1";
in
  mkDerivation {
    pname = "xorg-sgml-doctools";
    inherit version;
    src = fetchurl {
      urls = ["https://www.x.org/releases/individual/doc/xorg-sgml-doctools-${version}.tar.xz"];
      hash = "0vvdnl1x82mr2phcq9z6dg94mas56zdmbm6lmkaqjkkbf3058p8a";
    };
    buildDeps = [buildPackages.meson buildPackages.ninja];
    runtimeDeps = [];
    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd xorg-sgml-doctools-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          meson setup build $mesonFlags --prefix="$out" --libdir=lib
        '';
      }
      {
        name = "install";
        script = ''
          meson install -C build
          mkdir -p "$out/lib/pkgconfig" "$out/share/licenses/xorg-sgml-doctools"
          ln -s ../../share/pkgconfig/xorg-sgml-doctools.pc "$out/lib/pkgconfig/xorg-sgml-doctools.pc"
          cp COPYING "$out/share/licenses/xorg-sgml-doctools/"
          test -s "$out/share/sgml/X11/xorg.xsl"
        '';
      }
    ];
    meta = {
      description = "Shared X.Org documentation stylesheets and cross-reference databases";
      homepage = "https://www.x.org/";
      license = "MIT";
    };
  }
