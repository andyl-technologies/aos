##! Xorg Autoconf macros
{
  mkDerivation,
  fetchurl,
  buildPackages,
}: let
  version = "1.20.2";
in
  mkDerivation {
    pname = "xorg-util-macros";
    inherit version;

    src = fetchurl {
      urls = ["https://www.x.org/releases/individual/util/util-macros-${version}.tar.xz"];
      hash = "sha256-msJp66JPZy19ezV05L5fMz0T8Ep3EjA7GCGypRrILo4=";
    };

    buildDeps = [buildPackages.gnumake buildPackages.pkg-config];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd util-macros-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          $CONFIG_SHELL ./configure $configureFlags --prefix="$out"
        '';
      }
      {
        name = "build";
        script = ''
          make -j"$NIX_BUILD_CORES"
        '';
      }
      {
        name = "check";
        script = ''
          make check
        '';
      }
      {
        name = "install";
        script = ''
          make install
          mkdir -p "$out/lib/pkgconfig"
          ln -s ../../share/pkgconfig/xorg-macros.pc "$out/lib/pkgconfig/xorg-macros.pc"
          mkdir -p "$out/share/licenses/xorg-util-macros"
          cp COPYING "$out/share/licenses/xorg-util-macros/"
        '';
      }
    ];

    meta = {
      description = "Xorg Autoconf macros";
      homepage = "https://www.x.org/";
      license = "MIT";
    };
  }
