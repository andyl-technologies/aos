##! Exercises sixth-slice A-G libraries through their public C APIs.
{testing}: let
  mkCProbe = {
    package,
    libraries,
    primaryInput,
    primaryOperation,
    primarySource,
    badInput,
    badOperation,
    badSource,
  }:
    testing.mkQualificationPackageProbe {
      name = package;
      spec = {
        schema_version = "aos.release.package-probe/v1";
        inherit package;
        primary = {
          input = primaryInput;
          operation = primaryOperation;
          expected = "The public API returns the expected value and the consumer prints the fixed success line.";
          files."primary.c" = primarySource;
          steps = [
            {
              argv = ["@cc@" "primary.c" "-I@out@/include" "-L@out@/lib" "-Wl,-rpath,@out@/lib"] ++ libraries ++ ["-o" "primary"];
              exit_code = 0;
              stdout.exact = "";
              stderr.exact = "";
            }
            {
              argv = ["@work@/primary/primary"];
              exit_code = 0;
              stdout.exact = "${package} api passed\n";
              stderr.exact = "";
            }
          ];
          artifacts = [];
        };
        bad_input = {
          input = badInput;
          operation = badOperation;
          expected = "The public API rejects the malformed boundary and the consumer returns the fixed rejection status.";
          files."bad-input.c" = badSource;
          steps = [
            {
              argv = ["@cc@" "bad-input.c" "-I@out@/include" "-L@out@/lib" "-Wl,-rpath,@out@/lib"] ++ libraries ++ ["-o" "bad-input"];
              exit_code = 0;
              stdout.exact = "";
              stderr.exact = "";
            }
            {
              argv = ["@work@/bad-input/bad-input"];
              exit_code = 7;
              stdout.exact = "";
              stderr.exact = "${package} rejected invalid input\n";
              observes_rejection = true;
            }
          ];
          artifacts = [];
        };
      };
    };
in {
  # This package intentionally exports compilation headers for consumers such
  # as OpenJDK. Qualify that surface without requiring an unshipped libcups.
  cups = testing.mkQualificationPackageProbe {
    name = "cups";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "cups";
      primary = {
        input = "A C translation unit using the declared CUPS HTTP URI interface.";
        operation = "Compile the typed API consumer against the installed headers.";
        expected = "The public declarations compile into a nonempty native object.";
        files."consumer.c" = ''
          #include <cups/http.h>

          http_uri_status_t qualification_uri(const char *uri) {
              char scheme[16], username[16], host[64], resource[64];
              int port = 0;
              return httpSeparateURI(HTTP_URI_CODING_ALL, uri,
                  scheme, sizeof(scheme), username, sizeof(username),
                  host, sizeof(host), &port, resource, sizeof(resource));
          }
        '';
        steps = [
          {
            argv = ["@cc@" "-I@out@/include" "-c" "consumer.c" "-o" "consumer.o"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@python@" "-c" "from pathlib import Path; data = Path('consumer.o').read_bytes(); assert len(data) > 64 and data[:4] in (bytes([127, 69, 76, 70]), bytes([207, 250, 237, 254]))"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "A C consumer omitting required arguments from httpSeparateURI.";
        operation = "Compile the invalid API call against the installed declaration.";
        expected = "The compiler diagnoses the argument mismatch for the CUPS interface.";
        files."invalid.c" = ''
          #include <cups/http.h>

          int main(void) {
              return httpSeparateURI(HTTP_URI_CODING_ALL);
          }
        '';
        steps = [
          {
            argv = [
              "@python@"
              "-c"
              ''
                import subprocess, sys
                result = subprocess.run(["@cc@", "-I@out@/include", "-c", "invalid.c", "-o", "invalid.o"], capture_output=True, text=True)
                assert result.returncode != 0 and result.stdout == ""
                assert "httpSeparateURI" in result.stderr and "too few arguments" in result.stderr
                sys.stderr.write("cups headers rejected invalid call\n")
                raise SystemExit(7)
              ''
            ];
            exit_code = 7;
            stdout.exact = "";
            stderr.exact = "cups headers rejected invalid call\n";
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };

  editline = mkCProbe {
    package = "editline";
    libraries = ["-leditline"];
    primaryInput = "Two fixed history entries and a writable history path.";
    primaryOperation = "Add the entries and serialize them through editline's history API.";
    primarySource = ''
      #include <stdio.h>
      #include <string.h>
      #include <editline.h>

      int main(void) {
          char buffer[128] = {0};
          rl_initialize();
          add_history("alpha");
          add_history("beta");
          if (write_history("history.txt") != 0) {
              rl_uninitialize();
              return 2;
          }
          FILE *history = fopen("history.txt", "r");
          if (history == NULL) {
              rl_uninitialize();
              return 3;
          }
          size_t length = fread(buffer, 1, sizeof(buffer) - 1, history);
          fclose(history);
          rl_uninitialize();
          buffer[length] = '\0';
          if (strstr(buffer, "alpha") == NULL || strstr(buffer, "beta") == NULL) {
              return 4;
          }
          return puts("editline api passed") == EOF;
      }
    '';
    badInput = "A history-file path that does not exist.";
    badOperation = "Read the missing history file through editline's history API.";
    badSource = ''
      #include <stdio.h>
      #include <editline.h>

      int main(void) {
          rl_initialize();
          int status = read_history("absent-history.txt");
          rl_uninitialize();
          if (status == 0) {
              return 2;
          }
          fputs("editline rejected invalid input\n", stderr);
          return 7;
      }
    '';
  };
}
