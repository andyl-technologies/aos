##! cairo — Two-dimensional graphics library
{
  mkDerivation,
  fetchurl,
  meson,
  ninja,
  pkg-config,
  python3,
  gtk-doc,
  pixman,
  fontconfig,
  freetype,
  expat,
  libpng,
  glib,
  libffi,
  pcre2,
  zlib,
  lzo,
  buildPackages,
}: let
  version = "1.18.4";
in
  mkDerivation {
    pname = "cairo";
    inherit version;

    src = fetchurl {
      urls = ["https://cairographics.org/releases/cairo-${version}.tar.xz"];
      hash = "sha256-RF7YIIpuSCPeEianTKMZ02AOg/Y2n5mxQmUAZZnDLMs=";
    };

    buildDeps = [meson ninja pkg-config python3 gtk-doc glib.dev];
    runtimeDeps = [pixman fontconfig freetype expat libpng glib libffi pcre2 zlib lzo];
    propagatedDeps = [pixman fontconfig freetype libpng glib libffi pcre2 zlib];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd cairo-${version}

          # Meson executes this source helper while configuring. Point it at
          # the AOS Python rather than the unavailable host interpreter.
          sed -i '1s|.*|#!${python3}/bin/python3|' version.py
        '';
      }
      {
        name = "configure";
        script = ''
          export PKG_CONFIG_PATH=${fontconfig}/lib/pkgconfig:${freetype}/lib/pkgconfig:${expat}/lib/pkgconfig:${libpng}/lib/pkgconfig:${zlib}/lib/pkgconfig:${glib.dev}/lib/pkgconfig:${libffi}/lib/pkgconfig:${pcre2}/lib/pkgconfig:${pixman}/lib/pkgconfig:$PKG_CONFIG_PATH
          meson setup build \
            $mesonFlags \
            --prefix="$out" \
            --buildtype=release \
            -Dfontconfig=enabled \
            -Dfreetype=enabled \
            -Dpng=enabled \
            -Dtee=enabled \
            -Dzlib=enabled \
            -Dlzo=enabled \
            -Dglib=enabled \
            -Dxcb=disabled \
            -Dxlib=disabled \
            -Dxlib-xcb=disabled \
            -Dquartz=disabled \
            -Ddwrite=disabled \
            -Dgtk2-utils=disabled \
            -Dspectre=disabled \
            -Dsymbol-lookup=disabled \
            -Dtests=disabled \
            -Dgtk_doc=true
        '';
      }
      {
        name = "build";
        script = ''
          PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages \
            ninja -C build -j"$NIX_BUILD_CORES"
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
          PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages \
            ninja -C build install
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-cairo";
        library = self;
        includes = ["${self}/include/cairo"];
        libs = ["-lcairo"];
        testSource = ''
          #include <cairo.h>

          int main(void) {
              cairo_surface_t *surface =
                  cairo_image_surface_create(CAIRO_FORMAT_ARGB32, 1, 1);
              int failed = cairo_surface_status(surface) != CAIRO_STATUS_SUCCESS;
              cairo_surface_destroy(surface);
              return failed;
          }
        '';
      };
    };

    meta = {
      description = "Vector graphics library with multiple output targets";
      homepage = "https://cairographics.org/";
      license = "LGPL-2.1-only OR MPL-1.1";
    };
  }
