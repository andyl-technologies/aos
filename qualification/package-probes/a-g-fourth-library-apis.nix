##! Exercises additional A-G libraries through self-contained public APIs.
{testing}: let
  mkCProbe = {
    package,
    compiler ? "@cc@",
    suffix ? "c",
    compileArguments,
    primaryInput,
    primaryOperation,
    primarySource,
    badInput,
    badInputOperation,
    badInputSource,
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
          files."primary.${suffix}" = primarySource;
          steps = [
            {
              argv = [compiler "primary.${suffix}"] ++ compileArguments ++ ["-o" "primary-consumer"];
              exit_code = 0;
              stdout.exact = "";
              stderr.exact = "";
            }
            {
              argv = ["@work@/primary/primary-consumer"];
              exit_code = 0;
              stdout.exact = "${package} api passed\n";
              stderr.exact = "";
            }
          ];
          artifacts = [];
        };
        bad_input = {
          input = badInput;
          operation = badInputOperation;
          expected = "The API reports the rejected boundary and the consumer returns the fixed rejection status.";
          files."bad-input.${suffix}" = badInputSource;
          steps = [
            {
              argv = [compiler "bad-input.${suffix}"] ++ compileArguments ++ ["-o" "bad-input-consumer"];
              exit_code = 0;
              stdout.exact = "";
              stderr.exact = "";
            }
            {
              argv = ["@work@/bad-input/bad-input-consumer"];
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
  fontconfig = mkCProbe {
    package = "fontconfig";
    compileArguments = ["-I@out@/include" "-L@out@/lib" "-Wl,-rpath,@out@/lib" "-lfontconfig"];
    primaryInput = "A font pattern containing a family and integer weight.";
    primaryOperation = "Parse the pattern with FcNameParse and retrieve its family field.";
    primarySource = ''
      #include <stdio.h>
      #include <string.h>
      #include <fontconfig/fontconfig.h>

      int main(void) {
          FcPattern *pattern = FcNameParse((const FcChar8 *)"monospace:weight=200");
          FcChar8 *family = NULL;
          if (pattern == NULL
              || FcPatternGetString(pattern, FC_FAMILY, 0, &family) != FcResultMatch
              || family == NULL || strcmp((const char *)family, "monospace") != 0) {
              if (pattern != NULL) FcPatternDestroy(pattern);
              return 2;
          }
          FcPatternDestroy(pattern);
          return puts("fontconfig api passed") == EOF;
      }
    '';
    badInput = "A request for a second family value from a pattern containing only one.";
    badInputOperation = "Query the out-of-range value index with FcPatternGetString.";
    badInputSource = ''
      #include <stdio.h>
      #include <fontconfig/fontconfig.h>

      int main(void) {
          FcPattern *pattern = FcNameParse((const FcChar8 *)"monospace");
          FcChar8 *family = NULL;
          if (pattern == NULL) {
              return 2;
          }
          FcResult result = FcPatternGetString(pattern, FC_FAMILY, 1, &family);
          FcPatternDestroy(pattern);
          if (result != FcResultNoId) {
              return 3;
          }
          fputs("fontconfig rejected invalid input\n", stderr);
          return 7;
      }
    '';
  };

  gc = mkCProbe {
    package = "gc";
    compileArguments = ["-I@out@/include" "-L@out@/lib" "-Wl,-rpath,@out@/lib" "-lgc" "-pthread"];
    primaryInput = "A managed byte buffer containing a fixed string.";
    primaryOperation = "Allocate the buffer with GC_malloc and recover its managed allocation base.";
    primarySource = ''
      #include <stdio.h>
      #include <string.h>
      #include <gc.h>

      int main(void) {
          GC_INIT();
          char *buffer = GC_malloc(32);
          if (buffer == NULL) {
              return 2;
          }
          strcpy(buffer, "managed allocation");
          if (GC_base(buffer + 4) != buffer || strcmp(buffer, "managed allocation") != 0) {
              return 3;
          }
          return puts("gc api passed") == EOF;
      }
    '';
    badInput = "An address that does not belong to a garbage-collected allocation.";
    badInputOperation = "Query the allocation base for the unmanaged address.";
    badInputSource = ''
      #include <stdint.h>
      #include <stdio.h>
      #include <gc.h>

      int main(void) {
          GC_INIT();
          if (GC_base((void *)(uintptr_t)42) != NULL) {
              return 2;
          }
          fputs("gc rejected invalid input\n", stderr);
          return 7;
      }
    '';
  };

  gcc-libs = mkCProbe {
    package = "gcc-libs";
    compiler = "@cxx@";
    suffix = "cc";
    compileArguments = ["-L@out@/lib" "-Wl,-rpath,@out@/lib" "-lstdc++"];
    primaryInput = "A C++ regular expression and a matching identifier.";
    primaryOperation = "Compile the expression with libstdc++ and match the complete string.";
    primarySource = ''
      #include <iostream>
      #include <regex>

      int main() {
          std::regex expression("[a-z]+[0-9]+");
          if (!std::regex_match("probe42", expression)) {
              return 2;
          }
          std::cout << "gcc-libs api passed\n";
      }
    '';
    badInput = "A C++ regular expression with an unmatched opening bracket.";
    badInputOperation = "Compile the malformed expression with libstdc++.";
    badInputSource = ''
      #include <iostream>
      #include <regex>

      int main() {
          try {
              std::regex expression("[");
              static_cast<void>(expression);
              return 2;
          } catch (const std::regex_error &) {
              std::cerr << "gcc-libs rejected invalid input\n";
              return 7;
          }
      }
    '';
  };

  gpgme = mkCProbe {
    package = "gpgme";
    compileArguments = ["-I@out@/include" "-L@out@/lib" "-Wl,-rpath,@out@/lib" "-lgpgme"];
    primaryInput = "A fixed memory buffer exposed as GPGME data.";
    primaryOperation = "Create a data object, seek it, and read back the exact bytes.";
    primarySource = ''
      #include <stdio.h>
      #include <string.h>
      #include <gpgme.h>

      int main(void) {
          const char source[] = "qualification";
          char recovered[sizeof(source)] = {0};
          gpgme_data_t data = NULL;
          if (gpgme_data_new_from_mem(&data, source, sizeof(source) - 1, 1) != 0
              || gpgme_data_seek(data, 0, SEEK_SET) != 0
              || gpgme_data_read(data, recovered, sizeof(source) - 1) != sizeof(source) - 1
              || memcmp(recovered, source, sizeof(source) - 1) != 0) {
              if (data != NULL) gpgme_data_release(data);
              return 2;
          }
          gpgme_data_release(data);
          return puts("gpgme api passed") == EOF;
      }
    '';
    badInput = "A protocol identifier outside GPGME's public protocol enumeration.";
    badInputOperation = "Assign the invalid protocol to a new GPGME context.";
    badInputSource = ''
      #include <stdio.h>
      #include <gpgme.h>

      int main(void) {
          gpgme_ctx_t context;
          if (gpgme_new(&context) != 0) {
              return 2;
          }
          gpgme_error_t status = gpgme_set_protocol(context, (gpgme_protocol_t)9999);
          gpgme_release(context);
          if (status == 0) {
              return 3;
          }
          fputs("gpgme rejected invalid input\n", stderr);
          return 7;
      }
    '';
  };
}
