##! Exercises remaining fifth-slice A-G libraries and libc runtime data.
{testing}: {
  fstrm = testing.mkQualificationPackageProbe {
    name = "fstrm";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "fstrm";
      primary = {
        input = "A writer-options object and a short Frame Streams content type.";
        operation = "Create the options, add the content type, and destroy the object.";
        expected = "The public API accepts the bounded value and clears the destroyed handle.";
        files."primary.c" = ''
          #include <stdio.h>
          #include <string.h>
          #include <fstrm.h>

          int main(void) {
              const char content_type[] = "application/aos-qualification";
              struct fstrm_writer_options *options = fstrm_writer_options_init();
              if (options == NULL) {
                  return 2;
              }
              if (fstrm_writer_options_add_content_type(
                      options, content_type, strlen(content_type)) != fstrm_res_success) {
                  fstrm_writer_options_destroy(&options);
                  return 3;
              }
              fstrm_writer_options_destroy(&options);
              if (options != NULL) {
                  return 4;
              }
              return puts("fstrm api passed") == EOF;
          }
        '';
        steps = [
          {
            argv = ["@cc@" "primary.c" "-I@out@/include" "-L@out@/lib" "-Wl,-rpath,@out@/lib" "-lfstrm" "-o" "primary"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@work@/primary/primary"];
            exit_code = 0;
            stdout.exact = "fstrm api passed\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "A content type one byte longer than Frame Streams permits.";
        operation = "Add the oversized value to a writer-options object.";
        expected = "The public API returns failure and does not accept the content type.";
        files."bad-input.c" = ''
          #include <stdio.h>
          #include <string.h>
          #include <fstrm.h>

          int main(void) {
              unsigned char content_type[FSTRM_CONTROL_FIELD_CONTENT_TYPE_LENGTH_MAX + 1];
              memset(content_type, 'x', sizeof(content_type));
              struct fstrm_writer_options *options = fstrm_writer_options_init();
              if (options == NULL) {
                  return 2;
              }
              fstrm_res result = fstrm_writer_options_add_content_type(
                  options, content_type, sizeof(content_type));
              fstrm_writer_options_destroy(&options);
              if (result != fstrm_res_failure) {
                  return 3;
              }
              fputs("fstrm rejected invalid input\n", stderr);
              return 7;
          }
        '';
        steps = [
          {
            argv = ["@cc@" "bad-input.c" "-I@out@/include" "-L@out@/lib" "-Wl,-rpath,@out@/lib" "-lfstrm" "-o" "bad-input"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@work@/bad-input/bad-input"];
            exit_code = 7;
            stdout.exact = "";
            stderr.exact = "fstrm rejected invalid input\n";
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };

  glibc = testing.mkQualificationPackageProbe {
    name = "glibc";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "glibc";
      primary = {
        input = "A C program sorting a fixed integer vector with libc qsort.";
        operation = "Compile it and execute it through the packaged dynamic loader and libc.";
        expected = "The AOS libc sorts the vector into the exact ascending sequence.";
        files."primary.c" = ''
          #include <stdio.h>
          #include <stdlib.h>

          static int compare(const void *left, const void *right) {
              int a = *(const int *)left;
              int b = *(const int *)right;
              return (a > b) - (a < b);
          }

          int main(void) {
              int values[] = {23, 5, 42, 17};
              qsort(values, 4, sizeof(values[0]), compare);
              return printf("%d,%d,%d,%d\n", values[0], values[1], values[2], values[3]) < 0;
          }
        '';
        steps = [
          {
            argv = ["@cc@" "primary.c" "-o" "primary"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@python@" "-c" ''
              import pathlib, subprocess
              loader = next(pathlib.Path("@out@/lib").glob("ld-linux*.so*"))
              result = subprocess.run([str(loader), "--library-path", "@out@/lib", "@work@/primary/primary"], capture_output=True, text=True)
              assert result.returncode == 0 and result.stderr == ""
              print(result.stdout, end="")
            ''];
            exit_code = 0;
            stdout.exact = "5,17,23,42\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "A request for a character-set conversion name that does not exist.";
        operation = "Call iconv_open through a program loaded by the packaged libc.";
        expected = "Glibc rejects the unknown conversion and sets EINVAL.";
        files."bad-input.c" = ''
          #include <errno.h>
          #include <iconv.h>
          #include <stdio.h>

          int main(void) {
              errno = 0;
              iconv_t conversion = iconv_open("AOS-NOT-A-CHARSET", "UTF-8");
              if (conversion != (iconv_t)-1 || errno != EINVAL) {
                  if (conversion != (iconv_t)-1) {
                      iconv_close(conversion);
                  }
                  return 2;
              }
              fputs("glibc rejected invalid input\n", stderr);
              return 7;
          }
        '';
        steps = [
          {
            argv = ["@cc@" "bad-input.c" "-o" "bad-input"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@python@" "-c" ''
              import pathlib, subprocess, sys
              loader = next(pathlib.Path("@out@/lib").glob("ld-linux*.so*"))
              result = subprocess.run([str(loader), "--library-path", "@out@/lib", "@work@/bad-input/bad-input"], capture_output=True)
              if result.returncode != 7 or result.stderr != b"glibc rejected invalid input\n":
                  raise SystemExit(2)
              sys.stderr.write("glibc rejected invalid input\n")
              raise SystemExit(7)
            ''];
            exit_code = 7;
            stdout.exact = "";
            stderr.exact = "glibc rejected invalid input\n";
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };

  glibc-locales = testing.mkQualificationPackageProbe {
    name = "glibc-locales";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "glibc-locales";
      primary = {
        input = "The packaged C.UTF-8 locale and a two-byte UTF-8 character.";
        operation = "Select the locale and convert the character with mbrtowc.";
        expected = "The locale is available and decodes U+00E9 from exactly two bytes.";
        files."primary.c" = ''
          #include <locale.h>
          #include <stdio.h>
          #include <wchar.h>

          int main(void) {
              wchar_t value = 0;
              mbstate_t state = {0};
              if (setlocale(LC_ALL, "C.UTF-8") == NULL) {
                  return 2;
              }
              size_t consumed = mbrtowc(&value, "\xC3\xA9", 2, &state);
              if (consumed != 2 || value != 0x00e9) {
                  return 3;
              }
              return puts("glibc-locales data passed") == EOF;
          }
        '';
        steps = [
          {
            argv = ["@cc@" "primary.c" "-o" "primary"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@python@" "-c" ''
              import os, subprocess
              environment = os.environ.copy()
              environment["LOCPATH"] = "@out@/lib/locale"
              result = subprocess.run(["@work@/primary/primary"], env=environment, capture_output=True, text=True)
              assert result.returncode == 0 and result.stderr == ""
              print(result.stdout, end="")
            ''];
            exit_code = 0;
            stdout.exact = "glibc-locales data passed\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "A locale name absent from the packaged locale tree.";
        operation = "Select the nonexistent locale with setlocale.";
        expected = "The C library rejects the unknown locale name.";
        files."bad-input.c" = ''
          #include <locale.h>
          #include <stdio.h>

          int main(void) {
              if (setlocale(LC_ALL, "aos_NONEXISTENT.UTF-8") != NULL) {
                  return 2;
              }
              fputs("glibc-locales rejected invalid input\n", stderr);
              return 7;
          }
        '';
        steps = [
          {
            argv = ["@cc@" "bad-input.c" "-o" "bad-input"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@python@" "-c" ''
              import os, subprocess, sys
              environment = os.environ.copy()
              environment["LOCPATH"] = "@out@/lib/locale"
              result = subprocess.run(["@work@/bad-input/bad-input"], env=environment, capture_output=True)
              if result.returncode != 7 or result.stderr != b"glibc-locales rejected invalid input\n":
                  raise SystemExit(2)
              sys.stderr.write("glibc-locales rejected invalid input\n")
              raise SystemExit(7)
            ''];
            exit_code = 7;
            stdout.exact = "";
            stderr.exact = "glibc-locales rejected invalid input\n";
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };
}
