##! libnetfilter_cttimeout — Connection tracking timeout policy library
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  libmnl,
}: let
  version = "1.0.1";
in
  mkDerivation {
    pname = "libnetfilter_cttimeout";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The rendered policy contains the declared name and protocol values.";
        "files" = {
          "primary.c" = "#include <stdio.h>\n\nstatic int pass(void) {\n    return puts(\"libnetfilter_cttimeout primary passed\") == EOF;\n}\n\nstatic int reject(void) {\n    fputs(\"libnetfilter_cttimeout rejected invalid input\\n\", stderr);\n    return 7;\n}\n\n#include <netinet/in.h>\n#include <string.h>\n#include <libnetfilter_cttimeout/libnetfilter_cttimeout.h>\n\nint main(void) {\n    struct nfct_timeout *timeout = nfct_timeout_alloc();\n    char output[256] = {0};\n    if (timeout == NULL) return 2;\n    int status = nfct_timeout_attr_set(timeout, NFCT_TIMEOUT_ATTR_NAME, \"qualification\");\n    status |= nfct_timeout_attr_set_u16(timeout, NFCT_TIMEOUT_ATTR_L3PROTO, AF_INET);\n    status |= nfct_timeout_attr_set_u8(timeout, NFCT_TIMEOUT_ATTR_L4PROTO, IPPROTO_TCP);\n    int written = nfct_timeout_snprintf(output, sizeof(output), timeout, NFCT_TIMEOUT_O_DEFAULT, 0);\n    int valid = status == 0\n        && written > 0\n        && strstr(output, \".qualification\") != NULL\n        && strstr(output, \".l3proto = 2\") != NULL\n        && strstr(output, \".l4proto = 6\") != NULL;\n    nfct_timeout_free(timeout);\n    return valid ? pass() : 3;\n}\n\n";
        };
        "input" = "A TCP timeout policy named qualification with IPv4 protocol metadata.";
        "operation" = "Populate and render it through libnetfilter_cttimeout.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, os, pathlib, subprocess\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ncommand = [\"@cc@\", \"primary.c\"]\nfor root_text in closure:\n    root = pathlib.Path(root_text)\n    include = root / \"include\"\n    library = root / \"lib\"\n    if include.is_dir():\n        command.append(\"-I\" + str(include))\n    for nested in (root / \"include/glib-2.0\", root / \"lib/glib-2.0/include\"):\n        if nested.is_dir():\n            command.append(\"-I\" + str(nested))\n    if library.is_dir():\n        command.extend([\"-L\" + str(library), \"-Wl,-rpath,\" + str(library)])\ncommand.extend([\"-lnetfilter_cttimeout\",\"-lmnl\"] + [\"-o\", \"primary-check\"])\nresult = subprocess.run(command, capture_output=True, text=True)\nassert result.returncode == 0, (result.returncode, result.stdout, result.stderr)\n"
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
              "exact" = "libnetfilter_cttimeout primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Libnetfilter_cttimeout rejects the protocol by returning null.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\n\nstatic int pass(void) {\n    return puts(\"libnetfilter_cttimeout primary passed\") == EOF;\n}\n\nstatic int reject(void) {\n    fputs(\"libnetfilter_cttimeout rejected invalid input\\n\", stderr);\n    return 7;\n}\n\n#include <stdio.h>\n#include <unistd.h>\n#include <libnetfilter_cttimeout/libnetfilter_cttimeout.h>\n\nint main(void) {\n    int saved_stderr = dup(fileno(stderr));\n    int saved_stdout = dup(fileno(stdout));\n    FILE *discard = fopen(\"/dev/null\", \"w\");\n    if (saved_stderr < 0 || saved_stdout < 0 || discard == NULL) return 2;\n    if (dup2(fileno(discard), fileno(stderr)) < 0) return 3;\n    if (dup2(fileno(discard), fileno(stdout)) < 0) return 4;\n    const char *name = nfct_timeout_policy_attr_to_name(0, 0);\n    fflush(stderr);\n    fflush(stdout);\n    if (dup2(saved_stderr, fileno(stderr)) < 0) return 5;\n    if (dup2(saved_stdout, fileno(stdout)) < 0) return 6;\n    close(saved_stderr);\n    close(saved_stdout);\n    fclose(discard);\n    return name == NULL ? reject() : 8;\n}\n\n";
        };
        "input" = "A timeout-state lookup using the unsupported transport protocol zero.";
        "operation" = "Resolve the state through nfct_timeout_policy_attr_to_name.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, os, pathlib, subprocess\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ncommand = [\"@cc@\", \"bad-input.c\"]\nfor root_text in closure:\n    root = pathlib.Path(root_text)\n    include = root / \"include\"\n    library = root / \"lib\"\n    if include.is_dir():\n        command.append(\"-I\" + str(include))\n    for nested in (root / \"include/glib-2.0\", root / \"lib/glib-2.0/include\"):\n        if nested.is_dir():\n            command.append(\"-I\" + str(nested))\n    if library.is_dir():\n        command.extend([\"-L\" + str(library), \"-Wl,-rpath,\" + str(library)])\ncommand.extend([\"-lnetfilter_cttimeout\",\"-lmnl\"] + [\"-o\", \"bad-input-check\"])\nresult = subprocess.run(command, capture_output=True, text=True)\nassert result.returncode == 0, (result.returncode, result.stdout, result.stderr)\n"
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
              "exact" = "libnetfilter_cttimeout rejected invalid input\n";
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
        "https://netfilter.org/projects/libnetfilter_cttimeout/files/libnetfilter_cttimeout-${version}.tar.bz2"
      ];
      hash = "sha256-C1naLzIE4cgMuF0fbXIoX8B7AaL1Z4q/Xcz7vv1lAyU=";
    };

    buildDeps = [
      gnumake
      pkg-config
    ];
    runtimeDeps = [libmnl];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libnetfilter_cttimeout-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out \
            --disable-static \
            --enable-shared
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
      description = "libnetfilter_cttimeout — connection tracking timeout policy library";
      homepage = "https://netfilter.org/projects/libnetfilter_cttimeout/";
      license = "GPL-2.0-or-later";
    };
  }
