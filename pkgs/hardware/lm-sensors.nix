##! lm-sensors — Hardware monitoring tools and library
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  bison,
  flex,
  which,
  perl,
  bash,
}: let
  version = "3.6.2";
  tag = "V3-6-2";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "lm-sensors";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Libsensors accepts the prefix, bus type, and hexadecimal address.";
        "files" = {
          "primary.c" = "#include <sensors/sensors.h>\n\nint main(void) {\n    sensors_chip_name chip;\n    int status = sensors_parse_chip_name(\"coretemp-isa-0000\", &chip);\n    if (status == 0) sensors_free_chip_name(&chip);\n    return status == 0 ? 0 : 2;\n}\n";
        };
        "input" = "The canonical hwmon chip name coretemp-isa-0000.";
        "operation" = "Parse and release the chip name through libsensors.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nimport json, os, pathlib, subprocess\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ncommand = [\"@cc@\", \"primary.c\"]\nfor root_text in closure:\n    root = pathlib.Path(root_text)\n    include = root / \"include\"\n    library = root / \"lib\"\n    if include.is_dir():\n        command.append(\"-I\" + str(include))\n    if library.is_dir():\n        command.extend([\"-L\" + str(library), \"-Wl,-rpath,\" + str(library)])\ncommand.extend([\"-lsensors\"] + [\"-o\", \"primary-check\"])\nresult = subprocess.run(command, capture_output=True, text=True)\nassert result.returncode == 0, (result.returncode, result.stdout, result.stderr)\n\nresult = subprocess.run([\"./primary-check\"], capture_output=True, text=True)\nassert result.returncode == 0, (result.stdout, result.stderr)\nprint(\"lm-sensors operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "lm-sensors operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Libsensors returns its chip-name parse error.";
        "files" = {
          "bad-input.c" = "#include <sensors/error.h>\n#include <sensors/sensors.h>\n\nint main(void) {\n    sensors_chip_name chip;\n    return sensors_parse_chip_name(\"bad/name\", &chip) == -SENSORS_ERR_CHIP_NAME ? 0 : 2;\n}\n";
        };
        "input" = "A chip name containing a slash where a bus description is required.";
        "operation" = "Parse the malformed name through libsensors.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import sys\nimport subprocess\nimport json, os, pathlib, subprocess\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ncommand = [\"@cc@\", \"bad-input.c\"]\nfor root_text in closure:\n    root = pathlib.Path(root_text)\n    include = root / \"include\"\n    library = root / \"lib\"\n    if include.is_dir():\n        command.append(\"-I\" + str(include))\n    if library.is_dir():\n        command.extend([\"-L\" + str(library), \"-Wl,-rpath,\" + str(library)])\ncommand.extend([\"-lsensors\"] + [\"-o\", \"bad-input-check\"])\nresult = subprocess.run(command, capture_output=True, text=True)\nassert result.returncode == 0, (result.returncode, result.stdout, result.stderr)\n\nresult = subprocess.run([\"./bad-input-check\"], capture_output=True, text=True)\nassert result.returncode == 0, (result.stdout, result.stderr)\n\nsys.stderr.write(\"lm-sensors rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "lm-sensors rejected invalid input\n";
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
      urls = ["https://github.com/hramrach/lm-sensors/archive/refs/tags/${tag}.tar.gz"];
      hash = "sha256-xqBYflZXeKQNiIkZKL+JQ/J9NT84LVt0Wpl9Y1l4qPA=";
    };

    buildDeps = [gnumake bison flex which];
    runtimeDeps = [perl bash];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd lm-sensors-3-6-2
        '';
      }
      {
        name = "patch";
        script = ''
          sed -i 's|ETCDIR "/sensors.d"|"/etc/sensors.d"|' lib/init.c
        '';
      }
      {
        name = "build";
        script = ''
          make -j"$NIX_BUILD_CORES" \
            PREFIX="$out" \
            ETCDIR="$out/etc" \
            BUILD_SHARED_LIB=1 \
            BUILD_STATIC_LIB=0
        '';
      }
      {
        name = "install";
        script = ''
          make install \
            PREFIX="$out" \
            ETCDIR="$out/etc" \
            BUILD_SHARED_LIB=1 \
            BUILD_STATIC_LIB=0

          for program in sensors-detect sensors-conf-convert; do
            if [ -f "$out/sbin/$program" ]; then
              sed -i "1s|^#!.*|#!${perl}/bin/perl|" "$out/sbin/$program"
            fi
          done
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-lm-sensors";
        library = self;
        libs = ["-lsensors"];
        testSource = ''
          #include <sensors/sensors.h>

          int main(void) {
              return sensors_init(0);
          }
        '';
      };
      tool = testing.mkToolCheck {
        pname = "tool-lm-sensors";
        tool = self;
        command = "sensors --version";
      };
    };

    meta = {
      description = "Tools and library for reading hardware sensors";
      homepage = "https://hwmon.wiki.kernel.org/lm_sensors";
      license = "LGPL-2.1-or-later AND GPL-2.0-or-later";
      mainProgram = "sensors";
    };
  }
