##! pixman — Low-level pixel manipulation library
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  meson,
  ninja,
  buildPackages,
}: let
  version = "0.46.4";
in
  mkDerivation {
    pname = "pixman";
    inherit version;

    src = fetchurl {
      urls = [
        "https://cairographics.org/releases/pixman-${version}.tar.gz"
        "https://www.x.org/releases/individual/lib/pixman-${version}.tar.gz"
      ];
      hash = "sha256-0JxE68O9W+5wIcefki/o+y+1f3Mg9V6X/5kU0jRqWRw=";
    };

    buildDeps = [
      gnumake
      pkg-config
      meson
      ninja
    ];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd pixman-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          meson setup build \
            $mesonFlags \
            --prefix=$out \
            --buildtype=release \
            -Dgtk=disabled \
            -Dlibpng=disabled \
            -Dtests=disabled \
            -Ddemos=disabled
        '';
      }
      {
        name = "build";
        script = ''
          ninja -C build -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          # Meson records its Python module invocation in build.ninja, not the
          # environment-setting launcher used during setup.
          PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages \
            ninja -C build install
        '';
      }
    ];

    meta = {
      description = "pixman — low-level pixel manipulation library";
      homepage = "https://pixman.org";
      license = "MIT";
    };
  }
