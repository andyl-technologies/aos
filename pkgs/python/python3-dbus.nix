##! python3-dbus — Python bindings for the reference D-Bus implementation
{
  lib,
  mkDerivation,
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
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      role = "public-package";
    };
    pname = "python3-dbus";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The signature contains one complete array type and round-trips unchanged.";
        "files" = {
          "probe.py" = "import glob\nimport sys\n\nlocations = glob.glob(\"@out@/lib/python*/site-packages\")\nif len(locations) != 1:\n    raise RuntimeError(\"package does not expose one site-packages directory\")\nsys.path.insert(0, locations[0])\n\nimport dbus\nsignature = dbus.Signature(\"a{sv}\")\nassert str(signature) == \"a{sv}\"\nassert len(list(signature)) == 1\n\nprint(\"python3-dbus primary passed\")\n";
        };
        "input" = "The D-Bus signature a{sv} for a string-to-variant dictionary.";
        "operation" = "Parse and iterate the signature through dbus.Signature.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "probe.py"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "python3-dbus primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "dbus-python raises ValueError.";
        "files" = {
          "probe.py" = "import glob\nimport sys\n\nlocations = glob.glob(\"@out@/lib/python*/site-packages\")\nif len(locations) != 1:\n    raise RuntimeError(\"package does not expose one site-packages directory\")\nsys.path.insert(0, locations[0])\n\nimport dbus\ntry:\n    dbus.Signature(\"a\")\nexcept ValueError:\n    pass\nelse:\n    raise RuntimeError(\"dbus-python accepted an incomplete signature\")\n\nprint(\"python3-dbus rejected invalid input\", file=sys.stderr)\nraise SystemExit(7)\n";
        };
        "input" = "A D-Bus array signature with no element type.";
        "operation" = "Parse the incomplete signature through dbus.Signature.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "probe.py"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "python3-dbus rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

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
