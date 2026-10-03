##! Video acceleration API with DRM, X11, GLX and Wayland transports
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  lib,
  libdrm,
  libx11,
  libxext,
  libxfixes,
  libxcb,
  libglvnd,
  wayland,
  mathjax,
}: let
  version = "2.24.1";
in
  mkDerivation {
    pname = "libva";
    inherit version;
    src = fetchurl {
      urls = ["https://github.com/intel/libva/releases/download/${version}/libva-${version}.tar.bz2"];
      hash = "sha256-7sYFC1KHbyKb016d8XzTGgZ4Xhjm95kMRFtYRihIPWc=";
    };

    buildDeps = [buildPackages.meson buildPackages.ninja buildPackages.pkg-config buildPackages.python3 buildPackages.wayland buildPackages.doxygen mathjax];
    runtimeDeps = [libdrm libx11 libxext libxfixes libxcb libglvnd wayland];
    propagatedDeps = [libdrm libx11 libxext libxfixes libxcb libglvnd wayland];
    PYTHONPATH = "${buildPackages.meson}/lib/python3/site-packages";

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd libva-${version}
            # Render every formula offline in the installed HTML documentation.
            # Doxygen's default bitmap path otherwise requires a TeX toolchain.
            sed -i \
              -e 's/^USE_MATHJAX .*/USE_MATHJAX = YES/' \
              -e 's/^MATHJAX_FORMAT .*/MATHJAX_FORMAT = SVG/' \
              -e 's|^MATHJAX_RELPATH .*|MATHJAX_RELPATH = mathjax|' \
              doc/Doxyfile.in
          '';
        }
        {
          name = "configure";
          script = ''
            meson setup build $mesonFlags --prefix="$out" --libdir=lib \
              --buildtype=release -Dwith_x11=yes -Dwith_glx=yes \
              -Dwith_wayland=yes -Denable_docs=true
          '';
        }
        {
          name = "build";
          script = ''
            ninja -C build -j"$NIX_BUILD_CORES"
          '';
        }
      ]
      ++ lib.optionals (!stdenv.isCross) [
        {
          name = "check";
          script = ''
            meson test -C build --print-errorlogs
          '';
        }
      ]
      ++ [
        {
          name = "install";
          script = ''
              ninja -C build install
              cp -R ${mathjax}/share/mathjax "$out/share/doc/libva/html-out/mathjax"
            mkdir -p "$out/share/licenses/libva"
            cp COPYING "$out/share/licenses/libva/"
          '';
        }
      ];

    meta = {
      description = "Video acceleration API with DRM, X11, GLX and Wayland support";
      homepage = "https://github.com/intel/libva";
      license = "MIT";
    };
  }
