##! python3-dbus — Python bindings for the reference D-Bus implementation
{
  mkDerivation,
  fetchurl,
  meson,
  ninja,
  pkg-config,
  python3,
  bash,
  dbus,
  glib,
  buildPackages,
}: let
  version = "1.3.2";
  sitePackages = "lib/python3.14/site-packages";
in
  mkDerivation {
    pname = "python3-dbus";
    inherit version;

    src = fetchurl {
      urls = ["https://dbus.freedesktop.org/releases/dbus-python/dbus-python-${version}.tar.gz"];
      hash = "sha256-rWeBkwhhi1BpU3viN/jmjKHH/Mle5KEh/mhFsUGCSPg=";
    };

    buildDeps = [meson ninja pkg-config python3 bash dbus glib.dev];
    runtimeDeps = [python3 dbus glib];
    propagatedDeps = [python3 dbus glib];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd dbus-python-${version}

          sed -i '1s|.*|#!${bash}/bin/bash|' test/run-test.sh
          find test -type f -name '*.py' -exec \
            sed -i '1s|^#!.*python.*$|#!${python3}/bin/python3|' {} +
        '';
      }
      {
        name = "configure";
        script = ''
          PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages \
            meson setup build \
              $mesonFlags \
              --prefix="$out" \
              --buildtype=release \
              -Dpython=${python3}/bin/python3 \
              -Dtests=true \
              -Dinstalled_tests=false \
              -Ddoc=false
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

          PYTHONPATH="$out/${sitePackages}" ${python3}/bin/python3 -c \
            'import dbus; assert dbus.__version__ == "${version}"'
        '';
      }
    ];

    meta = {
      description = "Python bindings for the reference D-Bus implementation";
      homepage = "https://dbus.freedesktop.org/doc/dbus-python/";
      license = "MIT";
    };
  }
