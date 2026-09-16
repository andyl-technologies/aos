##! python3-dbusmock — Mock D-Bus objects for service test suites
{
  lib,
  mkDerivation,
  fetchurl,
  python3,
  python3-dbus,
  dbus,
}: let
  version = "0.38.1";
  sitePackages = "lib/python3.14/site-packages";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      role = "public-package";
    };
    pname = "python3-dbusmock";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The private daemon accepts a connection and owns the standard D-Bus service name.";
        "files" = {};
        "input" = "A private session bus managed by python3-dbusmock.";
        "operation" = "Start the bus, connect through its public BusType API, and inspect its registered names.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, os, pathlib, sys\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\nsite_directories = []\nexecutable_directories = []\nfor root_text in closure:\n    root = pathlib.Path(root_text)\n    site = root / \"lib/python3.14/site-packages\"\n    binaries = root / \"bin\"\n    if site.is_dir():\n        site_directories.append(str(site))\n    if binaries.is_dir():\n        executable_directories.append(str(binaries))\nsys.path[:0] = site_directories\nos.environ[\"PATH\"] = os.pathsep.join(executable_directories)\n\nfrom dbusmock import BusType, PrivateDBus\nwith PrivateDBus(BusType.SESSION):\n    connection = BusType.SESSION.get_connection()\n    names = connection.list_names()\n    connection.close()\nassert \"org.freedesktop.DBus\" in names\nprint(\"python3-dbusmock operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "python3-dbusmock operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Python-dbusmock rejects the request without creating a service link.";
        "files" = {};
        "input" = "A request to enable a service absent from the configured D-Bus data directories.";
        "operation" = "Resolve the missing service through PrivateDBus.enable_service.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, os, pathlib, sys\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\nsite_directories = []\nexecutable_directories = []\nfor root_text in closure:\n    root = pathlib.Path(root_text)\n    site = root / \"lib/python3.14/site-packages\"\n    binaries = root / \"bin\"\n    if site.is_dir():\n        site_directories.append(str(site))\n    if binaries.is_dir():\n        executable_directories.append(str(binaries))\nsys.path[:0] = site_directories\nos.environ[\"PATH\"] = os.pathsep.join(executable_directories)\n\nimport pathlib, sys\nfrom dbusmock import BusType, PrivateDBus\nos.environ[\"XDG_DATA_DIRS\"] = str(pathlib.Path(\"empty-data\").resolve())\nbus = PrivateDBus(BusType.SESSION)\ntry:\n    bus.enable_service(\"org.example.QualificationMissing\")\nexcept AssertionError as error:\n    assert \"Service org.example.QualificationMissing not found\" in str(error)\nelse:\n    raise AssertionError(\"missing service was accepted\")\nfinally:\n    bus.stop()\nsys.stderr.write(\"python3-dbusmock rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "python3-dbusmock rejected invalid input\n";
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
      urls = ["https://files.pythonhosted.org/packages/source/p/python-dbusmock/python_dbusmock-${version}.tar.gz"];
      hash = "sha256-Ihtl4cLkjen9Eb9+jBZa2vkWSPSaEfOQ0IakmDhvKYQ=";
    };

    buildDeps = [python3];
    runtimeDeps = [python3 python3-dbus dbus];
    propagatedDeps = [python3 python3-dbus dbus];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd python_dbusmock-${version}
        '';
      }
      {
        name = "install";
        script = ''
          site="$out/${sitePackages}"
          mkdir -p "$site" "$out/bin"
          cp -R dbusmock python_dbusmock.egg-info "$site/"

          # The installed modules contain no store paths of their own. Keep
          # their interpreter, Python D-Bus bindings, and daemon reachable from
          # the runtime closure through the documented module entry point.
          cat > "$out/bin/python3-dbusmock" <<'PY'
          #!${python3}/bin/python3
          import os
          import runpy
          import sys

          sys.path.insert(0, "${builtins.placeholder "out"}/${sitePackages}")
          sys.path.insert(0, "${python3-dbus}/${sitePackages}")
          os.environ["PATH"] = "${dbus}/bin:" + os.environ.get("PATH", "")
          runpy.run_module("dbusmock", run_name="__main__")
          PY
          chmod 0755 "$out/bin/python3-dbusmock"

          PYTHONPATH="$site:${python3-dbus}/${sitePackages}" \
            ${python3}/bin/python3 -c \
              'import dbusmock; assert dbusmock.__version__ == "${version}"'
        '';
      }
    ];

    meta = {
      description = "Mock D-Bus objects for service test suites";
      homepage = "https://github.com/martinpitt/python-dbusmock";
      license = "LGPL-3.0-or-later";
      mainProgram = "python3-dbusmock";
    };
  }
