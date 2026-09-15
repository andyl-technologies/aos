##! libnetfilter_cthelper — User-space connection tracking helper library
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
    pname = "libnetfilter_cthelper";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The helper preserves the exact name and queue number.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libnetfilter_cthelper primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libnetfilter_cthelper rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <stdint.h>\n#include <string.h>\n#include <libnetfilter_cthelper/libnetfilter_cthelper.h>\nint main(void) {\n    struct nfct_helper *helper = nfct_helper_alloc();\n    if (helper == NULL) return 2;\n    nfct_helper_attr_set_str(helper, NFCTH_ATTR_NAME, \"qualification\");\n    nfct_helper_attr_set_u16(helper, NFCTH_ATTR_QUEUE_NUM, 42);\n    int valid = strcmp(nfct_helper_attr_get_str(helper, NFCTH_ATTR_NAME), \"qualification\") == 0\n        && nfct_helper_attr_get_u16(helper, NFCTH_ATTR_QUEUE_NUM) == 42;\n    nfct_helper_free(helper);\n    return valid ? pass() : 3;\n}\n\n";
        };
        "input" = "A connection-tracking helper named qualification on queue 42.";
        "operation" = "Set and retrieve the helper attributes through the object API.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lnetfilter_cthelper"
              "-o"
              "primary-check"
            ];
            "exit_code" = 0;
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
              "exact" = "libnetfilter_cthelper primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The helper parser returns a negative malformed-message status.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libnetfilter_cthelper primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libnetfilter_cthelper rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <stdint.h>\n#include <linux/netlink.h>\n#include <libnetfilter_cthelper/libnetfilter_cthelper.h>\nint main(void) {\n    struct nfct_helper *helper = nfct_helper_alloc();\n    struct nlmsghdr header = {.nlmsg_len = sizeof(header)};\n    if (helper == NULL) return 2;\n    int status = nfct_helper_nlmsg_parse_payload(&header, helper);\n    nfct_helper_free(helper);\n    return status < 0 ? reject() : 3;\n}\n\n";
        };
        "input" = "A netlink header with no connection-tracking helper payload.";
        "operation" = "Parse the empty payload through nfct_helper_nlmsg_parse_payload.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lnetfilter_cthelper"
              "-o"
              "bad-input-check"
            ];
            "exit_code" = 0;
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
              "exact" = "libnetfilter_cthelper rejected invalid input\n";
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
        "https://netfilter.org/projects/libnetfilter_cthelper/files/libnetfilter_cthelper-${version}.tar.bz2"
      ];
      hash = "sha256-FAc9VIcjOJc1XT/wTdwcjQPMW6jSNWI2qogWGp8tyRI=";
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
          cd libnetfilter_cthelper-${version}
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
      description = "libnetfilter_cthelper — user-space connection tracking helper library";
      homepage = "https://www.netfilter.org/projects/libnetfilter_cthelper/";
      license = "GPL-2.0-or-later";
    };
  }
