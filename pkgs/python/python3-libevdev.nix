##! Python bindings for the AOS input device library.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  python3,
  libevdev,
  stdenv,
}: let
  version = "0.13.1";
  sitePackages = "lib/python3.14/site-packages";
in
  mkDerivation {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
      ];
      target = [];
      role = "public-package";
    };
    pname = "python3-libevdev";
    inherit version;
    src = fetchurl {
      urls = ["https://files.pythonhosted.org/packages/86/ff/4f8ab38330965168be742b772bcd151a7a052ea17b2481c43a607875d4ed/libevdev-${version}.tar.gz"];
      hash = "13ay87cyka8hlyaid7mxwcw91fpsfdmws5qirfg7nxh12k6njcyw";
    };
    buildDeps = [buildPackages.python3];
    runtimeDeps = [python3 libevdev];
    propagatedDeps = [python3 libevdev];
    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd libevdev-${version}
            # ctypes must resolve the packaged library without an ambient loader path.
            sed -i 's|ctypes.CDLL("libevdev.so.2"|ctypes.CDLL("${libevdev}/lib/libevdev.so.2"|g' libevdev/_clib.py
          '';
        }
        {
          name = "install";
          script = ''
            mkdir -p "$out/${sitePackages}/libevdev-${version}.dist-info"
            cp -R libevdev "$out/${sitePackages}/"
            cp PKG-INFO "$out/${sitePackages}/libevdev-${version}.dist-info/METADATA"
            mkdir -p "$out/share/licenses/python3-libevdev"
            cp COPYING "$out/share/licenses/python3-libevdev/"
          '';
        }
      ]
      ++ (
        if stdenv.isCross
        then []
        else [
          {
            name = "check";
            script = ''
              PYTHONPATH="$out/${sitePackages}" ${python3}/bin/python3 - <<'PY'
              import libevdev

              assert libevdev.EV_KEY.KEY_A.value == 30
              device = libevdev.Device()
              device.name = "AOS input capability check"
              device.enable(libevdev.EV_KEY.KEY_A)
              assert device.has(libevdev.EV_KEY.KEY_A)
              assert not device.has(libevdev.EV_KEY.KEY_B)
              PY
            '';
          }
        ]
      );
    meta = {
      description = "Python bindings for libevdev input devices";
      homepage = "https://gitlab.freedesktop.org/libevdev/python-libevdev";
      license = "MIT";
    };
  }
