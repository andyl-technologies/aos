##! Wayland client/server libraries, scanner and EGL integration
{
  mkDerivation,
  gcc-libs,
  buildPackages,
  stdenv,
  lib,
  fetchurl,
  libxml2,
  expat,
  libffi,
}: let
  version = "1.23.1";
in
  mkDerivation {
    pname = "wayland";
    inherit version;

    src = fetchurl {
      urls = ["https://gitlab.freedesktop.org/wayland/wayland/-/releases/${version}/downloads/wayland-${version}.tar.xz"];
      hash = "sha256-hk+yqDmeLQ7DnVbp2bdTwJN3W+rcYCLOgfRBkpqB5e0=";
    };

    buildDeps =
      [
        buildPackages.meson
        buildPackages.ninja
        buildPackages.pkg-config
        buildPackages.python3
        buildPackages.doxygen
        buildPackages.graphviz
        buildPackages.xmlto
        buildPackages.libxslt
        buildPackages.docbook-xsl
        buildPackages.docbook-xml
      ]
      ++ lib.optionals stdenv.isCross [buildPackages.wayland];
    XML_CATALOG_FILES = "${buildPackages.docbook-xsl}/share/xml/docbook/stylesheet/catalog.xml ${buildPackages.docbook-xml}/share/xml/docbook/schema/dtd/4.5/catalog.xml";

    runtimeDeps = [expat libffi libxml2 gcc-libs];
    propagatedDeps = [expat libffi libxml2];

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd wayland-${version}
            sed -i "1s|.*|#!${buildPackages.python3}/bin/python3|" doc/doxygen/gen-doxygen.py
          '';
        }
        {
          name = "configure";
          script = ''
            # glibc loads libgcc_s when pthread cancellation unwinds. Retain
            # that runtime even when ordinary code has no explicit reference.
            meson setup build $mesonFlags --prefix="$out" --libdir=lib \
              --buildtype=release \
              '-Dc_link_args=-Wl,--push-state,--no-as-needed,-l:libgcc_s.so.1,--pop-state'
          '';
        }
        {
          name = "build";
          script = ''
            PYTHONPATH="${buildPackages.meson}/lib/python3/site-packages" \
              ninja -C build -j"$NIX_BUILD_CORES"
          '';
        }
      ]
      ++ lib.optionals (!stdenv.isCross) [
        {
          name = "check";
          script = ''
            PYTHONPATH="${buildPackages.meson}/lib/python3/site-packages" \
              meson test -C build --print-errorlogs
          '';
        }
      ]
      ++ [
        {
          name = "install";
          script = ''
            PYTHONPATH="${buildPackages.meson}/lib/python3/site-packages" \
              ninja -C build install
            mkdir -p "$out/share/licenses/wayland"
            cp COPYING "$out/share/licenses/wayland/"
          '';
        }
      ];

    meta = {
      description = "Wayland client/server libraries, scanner and EGL integration";
      homepage = "https://wayland.freedesktop.org/";
      license = "MIT";
    };
  }
