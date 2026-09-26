##! Python bindings for the AOS input device library.
{
  lib,
  mkDerivation,
  fetchurl,
  buildPackages,
  python3,
  libevdev,
  stdenv,
}: let
  version = "0.13.1";
  sitePackages = "lib/python3.14/site-packages";
  probeScript = ''
    import sys

    sys.path.insert(0, sys.argv[1])
    import libevdev

    if sys.argv[2] == "invalid":
        try:
            libevdev.Device(fd=-1)
        except libevdev.InvalidFileError:
            print("python3-libevdev rejected invalid descriptor")
        else:
            raise SystemExit(1)
    else:
        device = libevdev.Device()
        device.name = "AOS input capability"
        device.enable(libevdev.EV_KEY.KEY_A)
        assert device.has(libevdev.EV_KEY.KEY_A)
        assert not device.has(libevdev.EV_KEY.KEY_B)
        print("python3-libevdev event descriptor passed")
  '';
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
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "An in-memory input device with one enabled key.";
        operation = "Use the installed Python binding to configure and inspect the device.";
        expected = "The enabled key is present and a different key is absent.";
        files = {};
        artifacts = [];
        steps = [
          {
            argv = ["@python@" "-c" probeScript "@out@/${sitePackages}" "valid"];
            exit_code = 0;
            stdout.exact = "python3-libevdev event descriptor passed\n";
            stderr.exact = "";
          }
        ];
      };
      badInput = {
        input = "An invalid input-device file descriptor.";
        operation = "Construct a device through the installed Python binding.";
        expected = "The binding rejects it with InvalidFileError.";
        files = {};
        artifacts = [];
        steps = [
          {
            argv = ["@python@" "-c" probeScript "@out@/${sitePackages}" "invalid"];
            exit_code = 0;
            observes_rejection = true;
            stdout.exact = "python3-libevdev rejected invalid descriptor\n";
            stderr.exact = "";
          }
        ];
      };
    };
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
