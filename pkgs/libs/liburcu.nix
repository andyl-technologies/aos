##! liburcu — Userspace Read-Copy-Update (RCU) library
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "0.14.1";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "liburcu";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The stack returns the nodes in last-in, first-out order.";
        "files" = {
          "primary.c" = "#include <stdio.h>\n\nstatic int pass(void) {\n    return puts(\"liburcu primary passed\") == EOF;\n}\n\nstatic int reject(void) {\n    fputs(\"liburcu rejected invalid input\\n\", stderr);\n    return 7;\n}\n\n#include <urcu/lfstack.h>\n\nint main(void) {\n    struct cds_lfs_stack stack;\n    struct cds_lfs_node first;\n    struct cds_lfs_node second;\n    cds_lfs_init(&stack);\n    cds_lfs_node_init(&first);\n    cds_lfs_node_init(&second);\n    cds_lfs_push(&stack, &first);\n    cds_lfs_push(&stack, &second);\n    struct cds_lfs_node *popped_second = cds_lfs_pop_blocking(&stack);\n    struct cds_lfs_node *popped_first = cds_lfs_pop_blocking(&stack);\n    int valid = popped_second == &second && popped_first == &first;\n    cds_lfs_destroy(&stack);\n    return valid ? pass() : 2;\n}\n\n";
        };
        "input" = "Two initialized nodes pushed onto a lock-free stack.";
        "operation" = "Push and pop them through liburcu's blocking stack API.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, os, pathlib, subprocess\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ncommand = [\"@cc@\", \"primary.c\"]\nfor root_text in closure:\n    root = pathlib.Path(root_text)\n    include = root / \"include\"\n    library = root / \"lib\"\n    if include.is_dir():\n        command.append(\"-I\" + str(include))\n    for nested in (root / \"include/glib-2.0\", root / \"lib/glib-2.0/include\"):\n        if nested.is_dir():\n            command.append(\"-I\" + str(nested))\n    if library.is_dir():\n        command.extend([\"-L\" + str(library), \"-Wl,-rpath,\" + str(library)])\ncommand.extend([\"-lurcu-cds\",\"-lurcu-common\",\"-lpthread\"] + [\"-o\", \"primary-check\"])\nresult = subprocess.run(command, capture_output=True, text=True)\nassert result.returncode == 0, (result.returncode, result.stdout, result.stderr)\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@work@/primary/primary-check"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "liburcu primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Liburcu rejects the empty input by returning null.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\n\nstatic int pass(void) {\n    return puts(\"liburcu primary passed\") == EOF;\n}\n\nstatic int reject(void) {\n    fputs(\"liburcu rejected invalid input\\n\", stderr);\n    return 7;\n}\n\n#include <stddef.h>\n#include <urcu/lfstack.h>\n\nint main(void) {\n    struct cds_lfs_stack stack;\n    cds_lfs_init(&stack);\n    struct cds_lfs_node *node = cds_lfs_pop_blocking(&stack);\n    cds_lfs_destroy(&stack);\n    return node == NULL ? reject() : 2;\n}\n\n";
        };
        "input" = "A pop request on an empty initialized stack.";
        "operation" = "Pop the absent node through the blocking stack API.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, os, pathlib, subprocess\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ncommand = [\"@cc@\", \"bad-input.c\"]\nfor root_text in closure:\n    root = pathlib.Path(root_text)\n    include = root / \"include\"\n    library = root / \"lib\"\n    if include.is_dir():\n        command.append(\"-I\" + str(include))\n    for nested in (root / \"include/glib-2.0\", root / \"lib/glib-2.0/include\"):\n        if nested.is_dir():\n            command.append(\"-I\" + str(nested))\n    if library.is_dir():\n        command.extend([\"-L\" + str(library), \"-Wl,-rpath,\" + str(library)])\ncommand.extend([\"-lurcu-cds\",\"-lurcu-common\",\"-lpthread\"] + [\"-o\", \"bad-input-check\"])\nresult = subprocess.run(command, capture_output=True, text=True)\nassert result.returncode == 0, (result.returncode, result.stdout, result.stderr)\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@work@/bad-input/bad-input-check"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "liburcu rejected invalid input\n";
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
        "https://lttng.org/files/urcu/userspace-rcu-${version}.tar.bz2"
      ];
      hash = "sha256-IxrLE9xuwCPoNqDwZm9qq0fcYh7LHSzZ2cIvkiZ4q8A=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd userspace-rcu-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out \
            --disable-static
        '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          make install
        '';
      }
    ];

    meta = {
      description = "Userspace Read-Copy-Update (RCU) library";
      homepage = "https://liburcu.org/";
      license = "LGPL-2.1-or-later";
    };
  }
