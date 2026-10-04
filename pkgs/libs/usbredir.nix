##! usbredir — USB redirection protocol libraries and utilities
{
  mkDerivation,
  fetchurl,
  pkg-config,
  meson,
  ninja,
  python3,
  glib,
  libusb1,
  stdenv,
  buildPackages,
}: let
  version = "0.15.0";
  buildMeson =
    if stdenv.isCross
    then buildPackages.meson
    else meson;
in
  mkDerivation {
    pname = "usbredir";
    inherit version;

    src = fetchurl {
      urls = ["https://www.spice-space.org/download/usbredir/usbredir-${version}.tar.xz"];
      hash = "sha256-bcKjgCd2iKBoGRJF2sKrcGOlUpmdisOtjoQcEP8FCWE=";
    };

    buildDeps =
      (
        if stdenv.isCross
        then [
          buildPackages.pkg-config
          buildMeson
          buildPackages.ninja
          buildPackages.python3
        ]
        else [pkg-config buildMeson ninja python3 glib.tools]
      )
      ++ [glib.dev];
    runtimeDeps = [glib libusb1];
    propagatedDeps = [libusb1];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd usbredir-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          # GLib's headers, pkg-config files and linker names live in its dev
          # output. Cross builds keep these target paths and native build tools.
          export PKG_CONFIG_PATH="${glib.dev}/lib/pkgconfig''${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
          export LDFLAGS="''${LDFLAGS:-} -L${glib.dev}/lib"

          meson setup build \
            $mesonFlags \
            --prefix="$out" \
            --libdir=lib \
            --buildtype=release \
            -Dtools=enabled \
            -Dtests=enabled
        '';
      }
      {
        name = "build";
        script = ''
          PYTHONPATH=${buildMeson}/lib/python3/site-packages \
            ninja -C build -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "check";
        # Cross builds still compile the upstream tests but cannot run target
        # executables on the build platform.
        script =
          if stdenv.isCross
          then ""
          else ''
            PYTHONPATH=${buildMeson}/lib/python3/site-packages \
              meson test -C build --no-rebuild --print-errorlogs
          '';
      }
      {
        name = "install";
        script = ''
          PYTHONPATH=${buildMeson}/lib/python3/site-packages \
            ninja -C build install
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
        libs = ["libusbredirparser.so" "libusbredirhost.so"];
      };
    };

    meta = {
      description = "USB redirection protocol libraries and redirect utilities";
      homepage = "https://www.spice-space.org/usbredir.html";
      license = "LGPL-2.1-or-later";
    };
  }
