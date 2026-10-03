##! Public virglrenderer API and its upstream version header
{
  mkDerivation,
  fetchurl,
  buildPackages,
}: let
  version = "1.3.0";
in
  mkDerivation {
    pname = "virglrenderer-headers";
    inherit version;

    src = fetchurl {
      urls = ["https://gitlab.freedesktop.org/virgl/virglrenderer/-/archive/${version}/virglrenderer-${version}.tar.gz"];
      hash = "sha256-BlvFbonm9jH5YQHNYuugdI5I64iLQ07chuidBTledvM=";
    };

    buildDeps = [buildPackages.python3];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd virglrenderer-${version}
        '';
      }
      {
        name = "generate";
        script = ''
          # Match upstream's configuration_data substitutions using the
          # version declared by the source project itself.
          ${buildPackages.python3}/bin/python3 - <<'PY'
          from pathlib import Path
          import re

          project = Path("meson.build").read_text()
          match = re.search(r"version:\s*'([0-9]+\.[0-9]+\.[0-9]+)'", project)
          if match is None or match.group(1) != "${version}":
              raise SystemExit("unexpected virglrenderer source version")

          header = Path("src/virgl-version.h.meson").read_text()
          for name, value in zip(("MAJOR", "MINOR", "MICRO"), match.group(1).split(".")):
              header = header.replace("@VIRGL_" + name + "_VERSION@", value)
          if "@" in header:
              raise SystemExit("unresolved version header substitution")
          Path("src/virgl-version.h").write_text(header)
          PY
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/include/virgl" "$out/share/licenses/virglrenderer-headers"
          cp src/virglrenderer.h src/virgl-version.h "$out/include/virgl/"
          cp COPYING "$out/share/licenses/virglrenderer-headers/"
        '';
      }
    ];

    meta = {
      description = "Public virglrenderer headers generated from its source release";
      homepage = "https://gitlab.freedesktop.org/virgl/virglrenderer";
      license = "MIT";
    };
  }
