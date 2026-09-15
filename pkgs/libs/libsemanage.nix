##! libsemanage — SELinux policy management library
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  bison,
  flex,
  bzip2,
  libsepol,
  libselinux,
  audit,
}: let
  version = "3.11";
in
  mkDerivation {
    pname = "libsemanage";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The handle preserves priority 42.";
        "files" = {
          "primary.c" = "#include <stdio.h>\n\nstatic int pass(void) {\n    return puts(\"libsemanage primary passed\") == EOF;\n}\n\nstatic int reject(void) {\n    fputs(\"libsemanage rejected invalid input\\n\", stderr);\n    return 7;\n}\n\n#include <semanage/handle.h>\n\nint main(void) {\n    semanage_handle_t *handle = semanage_handle_create();\n    if (handle == NULL) return 2;\n    int status = semanage_set_default_priority(handle, 42);\n    int valid = status == 0 && semanage_get_default_priority(handle) == 42;\n    semanage_handle_destroy(handle);\n    return valid ? pass() : 3;\n}\n\n";
        };
        "input" = "A disconnected SELinux management handle and module priority 42.";
        "operation" = "Set and retrieve the default priority through libsemanage.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, os, pathlib, subprocess\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ncommand = [\"@cc@\", \"primary.c\"]\nfor root_text in closure:\n    root = pathlib.Path(root_text)\n    include = root / \"include\"\n    library = root / \"lib\"\n    if include.is_dir():\n        command.append(\"-I\" + str(include))\n    for nested in (root / \"include/glib-2.0\", root / \"lib/glib-2.0/include\"):\n        if nested.is_dir():\n            command.append(\"-I\" + str(nested))\n    if library.is_dir():\n        command.extend([\"-L\" + str(library), \"-Wl,-rpath,\" + str(library)])\ncommand.extend([\"-lsemanage\",\"-lsepol\"] + [\"-o\", \"primary-check\"])\nresult = subprocess.run(command, capture_output=True, text=True)\nassert result.returncode == 0, (result.returncode, result.stdout, result.stderr)\n"
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
              "exact" = "libsemanage primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Libsemanage rejects the out-of-range priority.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\n\nstatic int pass(void) {\n    return puts(\"libsemanage primary passed\") == EOF;\n}\n\nstatic int reject(void) {\n    fputs(\"libsemanage rejected invalid input\\n\", stderr);\n    return 7;\n}\n\n#include <stdio.h>\n#include <unistd.h>\n#include <semanage/handle.h>\n\nint main(void) {\n    semanage_handle_t *handle = semanage_handle_create();\n    if (handle == NULL) return 2;\n\n    int saved_stderr = dup(fileno(stderr));\n    FILE *discard = fopen(\"/dev/null\", \"w\");\n    if (saved_stderr < 0 || discard == NULL) return 3;\n    if (dup2(fileno(discard), fileno(stderr)) < 0) return 4;\n    int status = semanage_set_default_priority(handle, 0);\n    fflush(stderr);\n    if (dup2(saved_stderr, fileno(stderr)) < 0) return 5;\n    close(saved_stderr);\n    fclose(discard);\n\n    semanage_handle_destroy(handle);\n    return status < 0 ? reject() : 6;\n}\n\n";
        };
        "input" = "Module priority zero, outside libsemanage's supported range.";
        "operation" = "Set the invalid default priority.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, os, pathlib, subprocess\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ncommand = [\"@cc@\", \"bad-input.c\"]\nfor root_text in closure:\n    root = pathlib.Path(root_text)\n    include = root / \"include\"\n    library = root / \"lib\"\n    if include.is_dir():\n        command.append(\"-I\" + str(include))\n    for nested in (root / \"include/glib-2.0\", root / \"lib/glib-2.0/include\"):\n        if nested.is_dir():\n            command.append(\"-I\" + str(nested))\n    if library.is_dir():\n        command.extend([\"-L\" + str(library), \"-Wl,-rpath,\" + str(library)])\ncommand.extend([\"-lsemanage\",\"-lsepol\"] + [\"-o\", \"bad-input-check\"])\nresult = subprocess.run(command, capture_output=True, text=True)\nassert result.returncode == 0, (result.returncode, result.stdout, result.stderr)\n"
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
              "exact" = "libsemanage rejected invalid input\n";
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
        "https://github.com/SELinuxProject/selinux/releases/download/${version}/selinux-${version}.tar.gz"
      ];
      hash = "sha256-a21Hqw81/hwJvaDGKCHI2XoMvn9ulASzON973gGCxPQ=";
    };

    buildDeps = [
      gnumake
      pkg-config
      bison
      flex
    ];
    runtimeDeps = [
      bzip2
      libsepol
      libselinux
      audit
    ];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd selinux-${version}/libsemanage
        '';
      }
      {
        name = "build";
        script = ''
          make PREFIX=$out SHLIBDIR=$out/lib \
            CFLAGS="-I${libsepol}/include -I${libselinux}/include -I${audit}/include -I${bzip2}/include" \
            LDFLAGS="-L${libsepol}/lib -L${libselinux}/lib -L${audit}/lib -L${bzip2}/lib" \
            -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          make install PREFIX=$out SHLIBDIR=$out/lib SYSCONFDIR=$out/etc
        '';
      }
    ];

    meta = {
      description = "libsemanage — SELinux policy management library";
      homepage = "https://github.com/SELinuxProject/selinux";
      license = "LGPL-2.1-or-later";
    };
  }
