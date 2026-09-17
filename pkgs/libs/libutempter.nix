##! libutempter — Pseudoterminal accounting helper library
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "1.2.3";
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
    pname = "libutempter";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Libutempter invokes the helper and reports a successful update.";
        "files" = {
          "helper" = "#!@bash@\nexit 0\n";
          "primary.c" = "#define _XOPEN_SOURCE 600\n#include <fcntl.h>\n#include <stdlib.h>\n#include <utempter.h>\n\nint main(void) {\n    int descriptor = posix_openpt(O_RDWR | O_NOCTTY);\n    if (descriptor < 0 || grantpt(descriptor) != 0 || unlockpt(descriptor) != 0) return 2;\n    utempter_set_helper(\"@work@/primary/helper\");\n    return utempter_add_record(descriptor, \"qualification\") == 1 ? 0 : 3;\n}\n";
        };
        "input" = "A pseudoterminal master and an accounting helper that accepts the update.";
        "operation" = "Submit an add-record request through libutempter's public helper protocol.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import pathlib, subprocess\npathlib.Path(\"helper\").chmod(0o755)\nimport json, os, pathlib, subprocess\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ncommand = [\"@cc@\", \"primary.c\"]\nfor root_text in closure:\n    root = pathlib.Path(root_text)\n    include = root / \"include\"\n    library = root / \"lib\"\n    if include.is_dir():\n        command.append(\"-I\" + str(include))\n    if library.is_dir():\n        command.extend([\"-L\" + str(library), \"-Wl,-rpath,\" + str(library)])\ncommand.extend([\"-lutempter\"] + [\"-o\", \"primary-check\"])\nresult = subprocess.run(command, capture_output=True, text=True)\nassert result.returncode == 0, (result.returncode, result.stdout, result.stderr)\n\nresult = subprocess.run([\"./primary-check\"], capture_output=True, text=True)\nassert result.returncode == 0, (result.stdout, result.stderr)\nprint(\"libutempter operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "libutempter operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Libutempter reports that the accounting record was not added.";
        "files" = {
          "bad-input.c" = "#define _XOPEN_SOURCE 600\n#include <fcntl.h>\n#include <stdlib.h>\n#include <utempter.h>\n\nint main(void) {\n    int descriptor = posix_openpt(O_RDWR | O_NOCTTY);\n    if (descriptor < 0 || grantpt(descriptor) != 0 || unlockpt(descriptor) != 0) return 2;\n    utempter_set_helper(\"@work@/bad-input/helper\");\n    return utempter_add_record(descriptor, \"qualification\") == 0 ? 0 : 3;\n}\n";
          "helper" = "#!@bash@\nexit 1\n";
        };
        "input" = "A pseudoterminal master and an accounting helper that refuses the update.";
        "operation" = "Submit the add-record request and observe the helper failure through libutempter.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import sys\nimport pathlib, subprocess\npathlib.Path(\"helper\").chmod(0o755)\nimport json, os, pathlib, subprocess\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ncommand = [\"@cc@\", \"bad-input.c\"]\nfor root_text in closure:\n    root = pathlib.Path(root_text)\n    include = root / \"include\"\n    library = root / \"lib\"\n    if include.is_dir():\n        command.append(\"-I\" + str(include))\n    if library.is_dir():\n        command.extend([\"-L\" + str(library), \"-Wl,-rpath,\" + str(library)])\ncommand.extend([\"-lutempter\"] + [\"-o\", \"bad-input-check\"])\nresult = subprocess.run(command, capture_output=True, text=True)\nassert result.returncode == 0, (result.returncode, result.stdout, result.stderr)\n\nresult = subprocess.run([\"./bad-input-check\"], capture_output=True, text=True)\nassert result.returncode == 0, (result.stdout, result.stderr)\n\nsys.stderr.write(\"libutempter rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "libutempter rejected invalid input\n";
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
      urls = ["https://github.com/altlinux/libutempter/archive/refs/tags/${version}-alt1.tar.gz"];
      hash = "sha256-UoCcda+bDhMklSEXfe+FeH9FeIjLzuVRG/lv4G4UZxE=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    abilities = ./_libutempter;

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd libutempter-${version}-alt1/libutempter
        '';
      }
      {
        name = "patch";
        script = ''
          sed -i 's/-m2711/-m0711/' Makefile
          sed -i \
            's|LIBEXECDIR "/utempter/utempter"|"/run/wrappers/bin/utempter"|' \
            iface.c
        '';
      }
      {
        name = "build";
        script = ''
          make -j"$NIX_BUILD_CORES" \
            libdir="$out/lib" \
            libexecdir="$out/libexec" \
            includedir="$out/include" \
            mandir="$out/share/man"
        '';
      }
      {
        name = "install";
        script = ''
          make install \
            libdir="$out/lib" \
            libexecdir="$out/libexec" \
            includedir="$out/include" \
            mandir="$out/share/man"
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-libutempter";
        library = self;
        libs = ["-lutempter"];
        testSource = ''
          #include <utempter.h>

          int main(void) {
              utempter_set_helper(0);
              return 0;
          }
        '';
      };
    };

    meta = {
      description = "Interface for recording pseudoterminal sessions";
      homepage = "https://github.com/altlinux/libutempter";
      license = "LGPL-2.1-or-later";
    };
  }
