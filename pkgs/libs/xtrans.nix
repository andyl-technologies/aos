##! X11 transport interface headers
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
}: let
  version = "1.5.2";
in
  mkDerivation {
    pname = "xtrans";
    inherit version;

    src = fetchurl {
      urls = ["https://www.x.org/releases/individual/lib/xtrans-${version}.tar.xz"];
      hash = "sha256-XFy/40dkqRMdBI8DwxwZ5X+0xoLWdxPqtqZVQbTf+Gw=";
    };

    buildDeps = [gnumake pkg-config];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd xtrans-${version}
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
          ln -s ../../share/pkgconfig/xtrans.pc "$out/lib/pkgconfig/xtrans.pc"
          mkdir -p "$out/share/licenses/xtrans"
          cp COPYING "$out/share/licenses/xtrans/"
        '';
      }
    ];

    meta = {
      description = "X11 transport interface headers";
      homepage = "https://www.x.org/";
      license = "MIT";
    };
  }
