##! gdbm — GNU database manager
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  gettext,
  patch,
  readline,
  ncurses,
  stdenv,
}: let
  version = "1.26";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "gdbm";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The API returns the expected value and the consumer prints the fixed success line.";
        "files" = {
          "primary.c" = "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include <gdbm.h>\n\nint main(void) {\n    GDBM_FILE database = gdbm_open(\"probe.gdbm\", 0, GDBM_NEWDB, 0600, NULL);\n    datum key = {.dptr = \"answer\", .dsize = 6};\n    datum value = {.dptr = \"42\", .dsize = 2};\n    if (database == NULL || gdbm_store(database, key, value, GDBM_INSERT) != 0) {\n        return 2;\n    }\n    datum fetched = gdbm_fetch(database, key);\n    int failed = fetched.dptr == NULL || fetched.dsize != 2 || memcmp(fetched.dptr, \"42\", 2) != 0;\n    free(fetched.dptr);\n    gdbm_close(database);\n    if (failed) {\n        return 3;\n    }\n    return puts(\"gdbm api passed\") == EOF;\n}\n";
        };
        "input" = "A key and value to persist in a new GDBM database.";
        "operation" = "Store the record, fetch it, and compare the returned bytes.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lgdbm"
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
              "exact" = "gdbm api passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The API reports rejection and the consumer emits the fixed diagnostic and rejection status.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\n#include <gdbm.h>\n\nint main(void) {\n    GDBM_FILE database = gdbm_open(\"missing.gdbm\", 0, GDBM_READER, 0, NULL);\n    if (database != NULL) {\n        gdbm_close(database);\n        return 2;\n    }\n    fputs(\"gdbm rejected invalid input\\n\", stderr);\n    return 7;\n}\n";
        };
        "input" = "A request to open a nonexistent database read-only.";
        "operation" = "Open the missing path with GDBM_READER.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lgdbm"
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
              "exact" = "gdbm rejected invalid input\n";
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
      urls = ["https://ftp.gnu.org/gnu/gdbm/gdbm-${version}.tar.gz"];
      hash = "sha256-aiRQShTeSnRBA9y5Nr6Xbfb76IzP8mBl5UwcR5RvSl4=";
    };

    buildDeps = [gnumake gettext] ++ lib.optionals stdenv.hostPlatform.isLinux [patch];

    # Strict flexible-array checks reject the lexer's one-element tail buffers.
    # Patch both the lexer input and its generated C without weakening hardening.
    patches = lib.optionals stdenv.hostPlatform.isLinux [./gdbm-patches/flexible-lexer-buffers.patch];

    # Linux gdbmtool links ncurses directly in addition to readline.
    runtimeDeps = [readline] ++ lib.optionals stdenv.hostPlatform.isLinux [ncurses];
    propagatedDeps = [readline];
    configureFlags = builtins.concatStringsSep " " [
      "--enable-libgdbm-compat"
      "--enable-nls"
      "--enable-memory-mapped-io"
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "link-gdbm";
        library = self;
        libs = ["-lgdbm"];
        testSource = ''
          #include <gdbm.h>

          int main(void) {
              return gdbm_version == 0;
          }
        '';
      };
      tool = testing.mkToolCheck {
        pname = "tool-gdbm";
        tool = self;
        command = "gdbmtool --version";
      };

      tool-store = testing.mkToolCheck {
        pname = "tool-gdbm-store";
        tool = self;
        command = ''
          gdbmtool -N -n /tmp/tool.gdbm store 'key with spaces' 'value with spaces' &&
          gdbmtool -N -r /tmp/tool.gdbm fetch 'key with spaces'
        '';
        expectedOutput = "value with spaces";
      };
    };

    meta = {
      description = "GNU library for extensible hash databases";
      homepage = "https://www.gnu.org/software/gdbm/";
      license = "GPL-3.0-or-later";
      mainProgram = "gdbmtool";
    };
  }
