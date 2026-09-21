##! Exercises A-G C test frameworks through passing and deliberately failing tests.
{testing}: {
  check = testing.mkQualificationPackageProbe {
    name = "check";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "check";
      primary = {
        input = "A Check test case asserting the result of integer addition.";
        operation = "Compile and run the test suite, then inspect its failure count.";
        expected = "Check records no failures and the consumer prints the fixed success line.";
        files."passing.c" = ''
          #include <stdio.h>
          #include <check.h>

          START_TEST(addition_passes) {
              ck_assert_int_eq(19 + 23, 42);
          }
          END_TEST

          int main(void) {
              Suite *suite = suite_create("qualification");
              TCase *test_case = tcase_create("arithmetic");
              tcase_add_test(test_case, addition_passes);
              suite_add_tcase(suite, test_case);

              SRunner *runner = srunner_create(suite);
              srunner_run_all(runner, CK_SILENT);
              int failures = srunner_ntests_failed(runner);
              srunner_free(runner);
              if (failures != 0) {
                  return 2;
              }
              return puts("check api passed") == EOF;
          }
        '';
        steps = [
          {
            argv = ["@cc@" "passing.c" "-I@out@/include" "-L@out@/lib" "-Wl,-rpath,@out@/lib" "-lcheck" "-lm" "-pthread" "-lrt" "-o" "passing"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@work@/primary/passing"];
            exit_code = 0;
            stdout.exact = "check api passed\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "A Check test case containing a deliberately false assertion.";
        operation = "Run the suite and inspect the framework's recorded failure count.";
        expected = "Check records exactly one failed test and the consumer returns the fixed rejection status.";
        files."failing.c" = ''
          #include <stdio.h>
          #include <check.h>

          START_TEST(addition_fails) {
              ck_assert_int_eq(19 + 22, 42);
          }
          END_TEST

          int main(void) {
              Suite *suite = suite_create("qualification");
              TCase *test_case = tcase_create("arithmetic");
              tcase_add_test(test_case, addition_fails);
              suite_add_tcase(suite, test_case);

              SRunner *runner = srunner_create(suite);
              srunner_run_all(runner, CK_SILENT);
              int failures = srunner_ntests_failed(runner);
              srunner_free(runner);
              if (failures != 1) {
                  return 2;
              }
              fputs("check rejected invalid input\n", stderr);
              return 7;
          }
        '';
        steps = [
          {
            argv = ["@cc@" "failing.c" "-I@out@/include" "-L@out@/lib" "-Wl,-rpath,@out@/lib" "-lcheck" "-lm" "-pthread" "-lrt" "-o" "failing"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@work@/bad-input/failing"];
            exit_code = 7;
            stderr.exact = "check rejected invalid input\n";
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };

  cmocka = testing.mkQualificationPackageProbe {
    name = "cmocka";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "cmocka";
      primary = {
        input = "A cmocka test case asserting a fixed string value.";
        operation = "Compile and run the one-test group through cmocka.";
        expected = "Cmocka returns a zero failure count and the consumer prints the fixed success line.";
        files."passing.c" = ''
          #include <stddef.h>
          #include <setjmp.h>
          #include <stdarg.h>
          #include <stdio.h>
          #include <cmocka.h>

          static void string_passes(void **state) {
              (void)state;
              assert_string_equal("qualified", "qualified");
          }

          int main(void) {
              const struct CMUnitTest tests[] = {
                  cmocka_unit_test(string_passes),
              };
              if (cmocka_run_group_tests(tests, NULL, NULL) != 0) {
                  return 2;
              }
              return puts("cmocka api passed") == EOF;
          }
        '';
        steps = [
          {
            argv = ["@cc@" "passing.c" "-I@out@/include" "-L@out@/lib" "-Wl,-rpath,@out@/lib" "-lcmocka" "-o" "passing"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@work@/primary/passing"];
            exit_code = 0;
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "A cmocka test case containing a deliberately false integer assertion.";
        operation = "Run the one-test group and inspect cmocka's failure count.";
        expected = "Cmocka reports one failed test and the consumer returns the fixed rejection status.";
        files."failing.c" = ''
          #include <stddef.h>
          #include <setjmp.h>
          #include <stdarg.h>
          #include <stdio.h>
          #include <cmocka.h>

          static void integer_fails(void **state) {
              (void)state;
              assert_int_equal(41, 42);
          }

          int main(void) {
              const struct CMUnitTest tests[] = {
                  cmocka_unit_test(integer_fails),
              };
              if (cmocka_run_group_tests(tests, NULL, NULL) != 1) {
                  return 2;
              }
              fputs("cmocka rejected invalid input\n", stderr);
              return 7;
          }
        '';
        steps = [
          {
            argv = ["@cc@" "failing.c" "-I@out@/include" "-L@out@/lib" "-Wl,-rpath,@out@/lib" "-lcmocka" "-o" "failing"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@work@/bad-input/failing"];
            exit_code = 7;
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };
}
