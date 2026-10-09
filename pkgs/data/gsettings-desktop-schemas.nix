##! gsettings-desktop-schemas — Shared desktop settings schemas
{
  lib,
  mkDerivation,
  fetchurl,
  meson,
  ninja,
  pkg-config,
  gettext,
  buildPackages,
}: let
  version = "50.1";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "gsettings-desktop-schemas";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The catalog contains org.gnome.desktop.interface with a typed color-scheme key.";
        "files" = {};
        "input" = "The installed desktop-interface GSettings schema XML.";
        "operation" = "Parse the schema catalog and locate its color-scheme key.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import pathlib, xml.etree.ElementTree as ET\nroots = [ET.parse(path).getroot() for path in pathlib.Path(\"@out@/share/glib-2.0/schemas\").glob(\"*.xml\")]\nschemas = [schema for root in roots for schema in root.findall(\"schema\")]\ninterface = next(schema for schema in schemas if schema.get(\"id\") == \"org.gnome.desktop.interface\")\ncolor_scheme = next(key for key in interface.findall(\"key\") if key.get(\"name\") == \"color-scheme\")\nassert color_scheme.get(\"type\") == \"s\" and color_scheme.find(\"default\") is not None\nprint(\"gsettings-desktop-schemas data passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "gsettings-desktop-schemas data passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The catalog lookup rejects the unknown schema ID.";
        "files" = {};
        "input" = "A request for a schema ID absent from the installed catalog.";
        "operation" = "Resolve the nonexistent schema through the parsed catalog.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import pathlib, sys, xml.etree.ElementTree as ET\nids = {schema.get(\"id\") for path in pathlib.Path(\"@out@/share/glib-2.0/schemas\").glob(\"*.xml\") for schema in ET.parse(path).getroot().findall(\"schema\")}\nif \"org.aos.nonexistent\" in ids:\n    raise SystemExit(2)\nsys.stderr.write(\"gsettings-desktop-schemas rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "gsettings-desktop-schemas rejected invalid input\n";
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
      urls = [
        "https://download.gnome.org/sources/gsettings-desktop-schemas/50/gsettings-desktop-schemas-${version}.tar.xz"
      ];
      hash = "sha256-CiqiUIJnJYXRb82rYcew4z8DX7h0dlBceU8pVlr6SFs=";
    };

    # Schema compilation runs during the build, including for Darwin outputs.
    buildDeps = [meson ninja pkg-config gettext buildPackages.glib.tools];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd gsettings-desktop-schemas-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          meson setup build \
            $mesonFlags \
            --prefix="$out" \
            --buildtype=release \
            -Dintrospection=false
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
        name = "install";
        script = ''
          PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages \
            ninja -C build install
          ${buildPackages.glib.tools}/bin/glib-compile-schemas "$out/share/glib-2.0/schemas"
        '';
      }
    ];

    meta = {
      description = "GSettings schemas shared by desktop components";
      homepage = "https://gitlab.gnome.org/GNOME/gsettings-desktop-schemas";
      license = "LGPL-2.1-or-later";
    };
  }
