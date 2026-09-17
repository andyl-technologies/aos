##! python3-dbus — Python bindings for the reference D-Bus implementation
{
  mkDerivation,
  lib,
  stdenv,
  fetchurl,
  meson,
  ninja,
  pkg-config,
  python3,
  bash,
  dbus,
  systemd,
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

    # dbus-1.pc exposes libsystemd through Requires.private, including for
    # compile flags, so consumers must provide it while resolving D-Bus.
    buildDeps = [meson ninja pkg-config python3 bash dbus systemd glib.dev];
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
        script =
          lib.optionalString (stdenv.isCross && stdenv.hostPlatform.isLinux) ''
            # Native Python and D-Bus tools also expose pkg-config files. Resolve
            # the extension's libraries from target metadata before those tools.
            export PKG_CONFIG_PATH="${python3}/lib/pkgconfig:${dbus}/lib/pkgconfig:${glib.dev}/lib/pkgconfig:${systemd}/lib/pkgconfig''${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
            # GLib's unversioned linker symlinks live in its development output.
            export LDFLAGS="-L${glib.dev}/lib''${LDFLAGS:+ $LDFLAGS}"

            # The embedding test has no interpreter executable from which to
            # locate its standard library. Keep native Python on the build PATH
            # while directing target test processes to the target installation.
            sed -i "/^test_env = environment()/a test_env.set('PYTHONHOME', '${python3}')" \
              test/meson.build
          ''
          + ''
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
        # Reinitializing Python 100 times takes about seven minutes under
        # emulation; preserve the full repeated-import regression test.
        script = ''
          PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages \
            meson test -C build --print-errorlogs${lib.optionalString (stdenv.isCross && stdenv.hostPlatform.isLinux) " --timeout-multiplier=20"}
        '';
      }
      {
        name = "install";
        script = ''
          PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages \
            ninja -C build install

          ${lib.optionalString (stdenv.isCross && stdenv.hostPlatform.isLinux) ''
            # Meson replaces cross-linker RUNPATHs during installation. Target
            # extension modules must locate their own direct library dependencies.
            for extension in "$out/${sitePackages}/"_dbus*.so; do
              patchelf --add-rpath "${dbus}/lib:${glib}/lib" "$extension"
            done
          ''}PYTHONPATH="$out/${sitePackages}" ${python3}/bin/python3 -c \
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
