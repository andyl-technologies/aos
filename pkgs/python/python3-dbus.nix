##! python3-dbus — Python bindings for the reference D-Bus implementation
{
  lib,
  mkDerivation,
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
