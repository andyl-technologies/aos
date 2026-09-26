##! Shared X.Org documentation stylesheets and cross-reference databases.
{
  lib,
  mkDerivation,
  fetchurl,
  buildPackages,
}: let
  version = "1.12.1";
  probeScript = ''
    import pathlib
    import sys
    import xml.etree.ElementTree as ET

    root = pathlib.Path(sys.argv[1])
    stylesheet = ET.parse(root / "xorg.xsl").getroot()
    ET.parse(root / "dbs/masterdb.html.xml")
    ET.parse(root / "dbs/masterdb.pdf.xml")

    namespace = "{http://www.w3.org/1999/XSL/Transform}"
    parameters = {
        parameter.get("name"): parameter.get("select")
        for parameter in stylesheet.findall(f"{namespace}param")
    }
    name = sys.argv[2]
    if name not in parameters:
        sys.stderr.write("xorg-sgml-doctools rejected unknown parameter\n")
        raise SystemExit(7)

    assert parameters[name] == "'xorg.css'"
    assert (root / "xorg.css").is_file()
    print("xorg-sgml-doctools data passed")
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
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      target = [];
      role = "public-package";
    };
    pname = "xorg-sgml-doctools";
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "The installed X.Org stylesheet, CSS, and documentation databases.";
        operation = "Parse the XML resources and resolve the documented CSS parameter.";
        expected = "The stylesheet selects the installed X.Org CSS resource.";
        files = {};
        artifacts = [];
        steps = [
          {
            argv = ["@python@" "-c" probeScript "@out@/share/sgml/X11" "html.stylesheet"];
            exit_code = 0;
            stdout.exact = "xorg-sgml-doctools data passed\n";
            stderr.exact = "";
          }
        ];
      };
      badInput = {
        input = "A stylesheet parameter name absent from the installed X.Org stylesheet.";
        operation = "Resolve the unknown parameter against the installed stylesheet.";
        expected = "The lookup rejects the unknown parameter.";
        files = {};
        artifacts = [];
        steps = [
          {
            argv = ["@python@" "-c" probeScript "@out@/share/sgml/X11" "aos-unknown-parameter"];
            exit_code = 7;
            observes_rejection = true;
            stdout.exact = "";
            stderr.exact = "xorg-sgml-doctools rejected unknown parameter\n";
          }
        ];
      };
    };
    inherit version;
    src = fetchurl {
      urls = ["https://www.x.org/releases/individual/doc/xorg-sgml-doctools-${version}.tar.xz"];
      hash = "0vvdnl1x82mr2phcq9z6dg94mas56zdmbm6lmkaqjkkbf3058p8a";
    };
    buildDeps = [buildPackages.meson buildPackages.ninja];
    runtimeDeps = [];
    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd xorg-sgml-doctools-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          meson setup build $mesonFlags --prefix="$out" --libdir=lib
        '';
      }
      {
        name = "install";
        script = ''
          meson install -C build
          mkdir -p "$out/lib/pkgconfig" "$out/share/licenses/xorg-sgml-doctools"
          ln -s ../../share/pkgconfig/xorg-sgml-doctools.pc "$out/lib/pkgconfig/xorg-sgml-doctools.pc"
          cp COPYING "$out/share/licenses/xorg-sgml-doctools/"
          test -s "$out/share/sgml/X11/xorg.xsl"
        '';
      }
    ];
    meta = {
      description = "Shared X.Org documentation stylesheets and cross-reference databases";
      homepage = "https://www.x.org/";
      license = "MIT";
    };
  }
