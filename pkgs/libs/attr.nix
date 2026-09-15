##! attr — userspace library and tools for POSIX extended attributes
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  gettext,
}: let
  version = "2.6.0";
in
  mkDerivation {
    pname = "attr";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The public API returns the expected result and the consumer prints the fixed success line.";
        "files" = {
          "primary.c" = "#include <fcntl.h>\n#include <stdio.h>\n#include <string.h>\n#include <unistd.h>\n#include <attr/attributes.h>\n\nint main(void) {\n    int descriptor = open(\"target\", O_CREAT | O_WRONLY, 0600);\n    if (descriptor < 0 || close(descriptor) != 0) {\n        return 2;\n    }\n    if (attr_set(\"target\", \"user.aos_probe\", \"42\", 2, 0) != 0) {\n        return 3;\n    }\n    char value[8] = {0};\n    int length = sizeof(value);\n    if (attr_get(\"target\", \"user.aos_probe\", value, &length, 0) != 0\n        || length != 2 || memcmp(value, \"42\", 2) != 0) {\n        return 4;\n    }\n    return puts(\"attr api passed\") == EOF;\n}\n";
        };
        "input" = "A user extended-attribute name and two-byte value on a regular file.";
        "operation" = "Store the attribute with attr_set and retrieve it with attr_get.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lattr"
              "-o"
              "primary-consumer"
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
              "@work@/primary/primary-consumer"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "attr api passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The public API reports rejection and the consumer returns the fixed rejection status.";
        "files" = {
          "bad-input.c" = "#include <fcntl.h>\n#include <stdio.h>\n#include <unistd.h>\n#include <attr/attributes.h>\n\nint main(void) {\n    int descriptor = open(\"target\", O_CREAT | O_WRONLY, 0600);\n    if (descriptor < 0 || close(descriptor) != 0) {\n        return 2;\n    }\n    if (attr_set(\"target\", \"\", \"42\", 2, 0) == 0) {\n        return 3;\n    }\n    fputs(\"attr rejected invalid input\\n\", stderr);\n    return 7;\n}\n";
        };
        "input" = "An empty extended-attribute name.";
        "operation" = "Store a value under the invalid name with attr_set.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lattr"
              "-o"
              "bad-input-consumer"
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
              "@work@/bad-input/bad-input-consumer"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      name = "attr-${version}.tar.xz";
      urls = [
        "https://mirror.fi.ossplanet.net/nongnu/attr/attr-${version}.tar.xz"
        "https://download.savannah.gnu.org/releases/attr/attr-${version}.tar.xz"
        "https://download-mirror.savannah.gnu.org/releases/attr/attr-${version}.tar.xz"
      ];
      hash = "sha256-bIohSKe4UEO2hJK85DMWsOLiFPxOYox+3geOduIWMws=";
    };

    buildDeps = [gnumake gettext];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd attr-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out \
            --disable-static \
            --disable-nls
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
      description = "Library and tools for manipulating POSIX extended attributes";
      homepage = "https://savannah.nongnu.org/projects/attr/";
      license = "LGPL-2.1-or-later";
    };
  }
