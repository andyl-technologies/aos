##! acl — POSIX Access Control Lists userspace library and tools
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  gettext,
  attr,
}: let
  version = "2.4.0";
in
  mkDerivation {
    pname = "acl";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The public API returns the expected value and the consumer prints the fixed success line.";
        "files" = {
          "primary.c" = "#include <stdio.h>\n#include <sys/acl.h>\n\nint main(void) {\n    acl_t acl = acl_from_text(\"u::rw-,g::r--,o::---\");\n    if (acl == NULL || acl_valid(acl) != 0) {\n        return 2;\n    }\n    acl_free(acl);\n    return puts(\"acl api passed\") == EOF;\n}\n";
        };
        "input" = "A complete access ACL in the library's text notation.";
        "operation" = "Parse the ACL with acl_from_text and validate its structure.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lacl"
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
              "exact" = "acl api passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The public API reports rejection and the consumer exits with the fixed rejection status and diagnostic.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\n#include <sys/acl.h>\n\nint main(void) {\n    acl_t acl = acl_from_text(\"u::rwx,g::r-z,o::---\");\n    if (acl != NULL) {\n        acl_free(acl);\n        return 2;\n    }\n    fputs(\"acl rejected invalid input\\n\", stderr);\n    return 7;\n}\n";
        };
        "input" = "An ACL containing an unknown permission letter.";
        "operation" = "Parse the malformed ACL with acl_from_text.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lacl"
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
            "stderr" = {
              "exact" = "acl rejected invalid input\n";
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
      name = "acl-${version}.tar.xz";
      urls = [
        "https://source.ipfire.org/source-2.x/acl-${version}.tar.xz"
        "https://download.savannah.gnu.org/releases/acl/acl-${version}.tar.xz"
      ];
      hash = "sha256-5mETFFbScIoBxhSg9ADhHX0b+utvPnS3W7mAty8BYaM=";
    };

    buildDeps = [gnumake gettext];
    runtimeDeps = [attr];
    propagatedDeps = [attr];

    # libacl's variable-length objects use a `char s_str[0]` trailing array
    # (libacl/libobj.h) that __acl_to_any_text fills via `strncpy(text_p, str,
    # size)` with `size` = the remaining malloc'd space. -fstrict-flex-arrays=3
    # narrows `[0]` to a fixed zero-length array, so __builtin_object_size(s_str)
    # is 0 and _FORTIFY_SOURCE's __strncpy_chk aborts ("buffer overflow
    # detected") whenever an ACL is formatted to text — e.g. systemd-tmpfiles
    # applying an `a` (ACL) entry such as `a /var/log/journal`. The write is in
    # fact bounded by the allocation; step down to level 1 (where `[0]` is still
    # honoured as a flexible array) so the check sees the real size. fortify3 and
    # the rest of the hardening stay on. Mirrors the systemd/dbus step-down.
    hardeningDisable = ["strictflexarrays3"];
    hardeningEnable = ["strictflexarrays1"];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd acl-${version}
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
      description = "POSIX Access Control Lists userspace library and tools";
      homepage = "https://savannah.nongnu.org/projects/acl/";
      license = "LGPL-2.1-or-later";
    };
  }
