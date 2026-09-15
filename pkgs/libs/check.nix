##! Check — Unit testing framework for C
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
}: let
  version = "0.15.2";
in
  mkDerivation {
    pname = "check";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Check records no failures and the consumer prints the fixed success line.";
        "files" = {
          "passing.c" = "#include <stdio.h>\n#include <check.h>\n\nSTART_TEST(addition_passes) {\n    ck_assert_int_eq(19 + 23, 42);\n}\nEND_TEST\n\nint main(void) {\n    Suite *suite = suite_create(\"qualification\");\n    TCase *test_case = tcase_create(\"arithmetic\");\n    tcase_add_test(test_case, addition_passes);\n    suite_add_tcase(suite, test_case);\n\n    SRunner *runner = srunner_create(suite);\n    srunner_run_all(runner, CK_SILENT);\n    int failures = srunner_ntests_failed(runner);\n    srunner_free(runner);\n    if (failures != 0) {\n        return 2;\n    }\n    return puts(\"check api passed\") == EOF;\n}\n";
        };
        "input" = "A Check test case asserting the result of integer addition.";
        "operation" = "Compile and run the test suite, then inspect its failure count.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "passing.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lcheck"
              "-lm"
              "-pthread"
              "-lrt"
              "-o"
              "passing"
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
              "@work@/primary/passing"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "check api passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Check records exactly one failed test and the consumer returns the fixed rejection status.";
        "files" = {
          "failing.c" = "#include <stdio.h>\n#include <check.h>\n\nSTART_TEST(addition_fails) {\n    ck_assert_int_eq(19 + 22, 42);\n}\nEND_TEST\n\nint main(void) {\n    Suite *suite = suite_create(\"qualification\");\n    TCase *test_case = tcase_create(\"arithmetic\");\n    tcase_add_test(test_case, addition_fails);\n    suite_add_tcase(suite, test_case);\n\n    SRunner *runner = srunner_create(suite);\n    srunner_run_all(runner, CK_SILENT);\n    int failures = srunner_ntests_failed(runner);\n    srunner_free(runner);\n    if (failures != 1) {\n        return 2;\n    }\n    fputs(\"check rejected invalid input\\n\", stderr);\n    return 7;\n}\n";
        };
        "input" = "A Check test case containing a deliberately false assertion.";
        "operation" = "Run the suite and inspect the framework's recorded failure count.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "failing.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lcheck"
              "-lm"
              "-pthread"
              "-lrt"
              "-o"
              "failing"
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
              "@work@/bad-input/failing"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "check rejected invalid input\n";
            };
          }
        ];
      };
    };

    inherit version;
    src = fetchurl {
      urls = ["https://github.com/libcheck/check/releases/download/${version}/check-${version}.tar.gz"];
      hash = "sha256-qN5OC6z7TXbdHGGN7SY1I7U7hdkqFG2INesaUpMvogo=";
    };
    buildDeps = [gnumake pkg-config];
    runtimeDeps = [];
    propagatedDeps = [];
    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd check-${version}
        '';
      }
      {
        name = "configure";
        script = ''./configure $configureFlags --prefix="$out"'';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "install";
        script = ''
          make install
          test -x "$out/bin/checkmk"
        '';
      }
    ];
    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "link-check";
        library = self;
        libs = ["-lcheck"];
        testSource = ''
          #include <check.h>
          int main(void) {
            Suite *suite = suite_create("aos");
            return suite == 0;
          }
        '';
      };
    };
    meta = {
      description = "Provides a unit testing framework for C";
      homepage = "https://libcheck.github.io/check/";
      license = "LGPL-2.1-or-later";
      mainProgram = "checkmk";
    };
  }
