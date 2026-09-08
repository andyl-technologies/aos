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
  cups = mkCProbe {
    package = "cups";
    libraries = ["-lcups"];
    primaryInput = "An IPP printer URI containing a scheme, host, port, and resource.";
    primaryOperation = "Separate the URI into its components with libcups.";
    primarySource = ''
      #include <stdio.h>
      #include <string.h>
      #include <cups/http.h>

      int main(void) {
          char scheme[16], username[16], host[64], resource[64];
          int port = 0;
          http_uri_status_t status = httpSeparateURI(
              HTTP_URI_CODING_ALL,
              "ipp://printer.example:631/ipp/print",
              scheme, sizeof(scheme),
              username, sizeof(username),
              host, sizeof(host),
              &port,
              resource, sizeof(resource));
          if (status != HTTP_URI_STATUS_OK
              || strcmp(scheme, "ipp") != 0
              || strcmp(host, "printer.example") != 0
              || port != 631
              || strcmp(resource, "/ipp/print") != 0) {
              return 2;
          }
          return puts("cups api passed") == EOF;
      }
    '';
    badInput = "A valid IPP URI and a destination buffer too small for its host.";
    badOperation = "Separate the URI into the undersized component buffers with libcups.";
    badSource = ''
      #include <stdio.h>
      #include <cups/http.h>

      int main(void) {
          char scheme[16], username[16], host[2], resource[64];
          int port = 0;
          http_uri_status_t status = httpSeparateURI(
              HTTP_URI_CODING_ALL,
              "ipp://printer.example/ipp/print",
              scheme, sizeof(scheme),
              username, sizeof(username),
              host, sizeof(host),
              &port,
              resource, sizeof(resource));
          if (status == HTTP_URI_STATUS_OK) {
              return 2;
          }
          fputs("cups rejected invalid input\n", stderr);
          return 7;
      }
    '';
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
