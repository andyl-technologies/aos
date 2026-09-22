##! libvips with the image-format support distributed by Sharp.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  callPackage,
  mozjpeg,
  libpng,
  libwebp,
  libtiff,
  libexif,
  lcms2,
  cgif,
  libimagequant,
  pango,
  cairo,
  librsvg,
  fontconfig,
  freetype,
  libarchive,
  highway,
  zlib,
  expat,
  util-linux,
}: let
  version = "8.18.6";
  glib = callPackage ./_image-glib.nix {};
  heif = callPackage ./_sharp-libheif.nix {};
  ultrahdr = callPackage ./_sharp-ultrahdr.nix {};
in
  mkDerivation {
    pname = "sharp-vips";
    inherit version;
    src = fetchurl {
      urls = ["https://github.com/libvips/libvips/releases/download/v${version}/vips-${version}.tar.xz"];
      hash = "0gnsklmn6ma5fqkq18b0cxfcfnb2qhbf2m5wlnjbz0c08pay2h9w";
    };
    buildDeps = [buildPackages.meson buildPackages.ninja buildPackages.python3 buildPackages.pkg-config buildPackages.bc buildPackages.glib.tools buildPackages.gettext];
    runtimeDeps = [glib mozjpeg libpng libwebp libtiff libexif lcms2 cgif libimagequant pango cairo librsvg fontconfig freetype libarchive highway zlib expat heif ultrahdr];
    # Export the public and private pkg-config requirements used by native addons.
    propagatedDeps = [glib glib.dev mozjpeg libpng libwebp libtiff libexif lcms2 cgif libimagequant pango cairo librsvg fontconfig freetype libarchive highway zlib expat heif ultrahdr util-linux];
    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd vips-${version}
            patch -p1 < ${./patches/sharp-vips-optional-format-tests.patch}
          '';
        }
        {
          name = "configure";
          # Match sharp-libvips 1.3.3's codec scope, while retaining CLI tests.
          script = ''
            export PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages:''${PYTHONPATH:-}
            export PKG_CONFIG_PATH="${glib.dev}/lib/pkgconfig:$PKG_CONFIG_PATH"
            export LDFLAGS="-L${glib.dev}/lib $NIX_LDFLAGS ''${LDFLAGS:-}"
            meson setup build $mesonFlags --prefix="$out" --libdir=lib --buildtype=release \
              -Ddeprecated=false -Dexamples=false -Dauto_features=enabled \
              -Dintrospection=disabled -Dmodules=disabled \
              -Dcfitsio=disabled -Dfftw=disabled -Djpeg-xl=disabled -Dorc=disabled \
              -Dmagick=disabled -Dmatio=disabled -Dnifti=disabled -Dopenexr=disabled \
              -Dopenjpeg=disabled -Dopenslide=disabled -Dpdfium=disabled \
              -Dpoppler=disabled -Dquantizr=disabled -Draw=disabled -Dspng=disabled \
              -Dppm=false -Danalyze=false -Dradiance=false
          '';
        }
        {
          name = "build";
          script = ''ninja -C build -j "$NIX_BUILD_CORES"'';
        }
      ]
      ++ (
        if stdenv.isCross
        then []
        else [
          {
            name = "check";
            script = ''meson test -C build --print-errorlogs'';
          }
        ]
      )
      ++ [
        {
          name = "install";
          script = ''
            ninja -C build install
            mkdir -p "$out/share/licenses/sharp-vips"
            cp LICENSE "$out/share/licenses/sharp-vips/"
            cp libvips/foreign/libnsgif/COPYING "$out/share/licenses/sharp-vips/libnsgif-COPYING"
          '';
        }
      ];
    meta = {
      description = "Image processing library for Sharp";
      homepage = "https://www.libvips.org/";
      license = "LGPL-2.1-or-later";
    };
  }
