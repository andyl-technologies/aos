##! Exercises A-G libraries through public parsing and transformation APIs.
{testing}: let
  mkLibraryProbe = {
    package,
    compiler ? "@cc@",
    sourceSuffix ? "c",
    compileArguments,
    primarySource,
    badInputSource,
    primaryInput,
    primaryOperation,
    badInput,
    badInputOperation,
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
          files."primary.${sourceSuffix}" = primarySource;
          steps = [
            {
              argv = [compiler "primary.${sourceSuffix}"] ++ compileArguments ++ ["-o" "primary-consumer"];
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
          expected = "The public API reports rejection and the consumer exits with the fixed rejection status and diagnostic.";
          files."bad-input.${sourceSuffix}" = badInputSource;
          steps = [
            {
              argv = [compiler "bad-input.${sourceSuffix}"] ++ compileArguments ++ ["-o" "bad-input-consumer"];
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
  abseil-cpp = mkLibraryProbe {
    package = "abseil-cpp";
    compiler = "@cxx@";
    sourceSuffix = "cc";
    compileArguments = ["-I@out@/include" "-L@out@/lib" "-Wl,-rpath,@out@/lib" "-labsl_strings" "-labsl_base"];
    primaryInput = "The decimal string 42.";
    primaryOperation = "Parse the string with absl::SimpleAtoi and verify the integer result.";
    primarySource = ''
      #include <iostream>
      #include "absl/strings/numbers.h"

      int main() {
          int value = 0;
          if (!absl::SimpleAtoi("42", &value) || value != 42) {
              return 2;
          }
          std::cout << "abseil-cpp api passed\n";
      }
    '';
    badInput = "A decimal string with trailing alphabetic data.";
    badInputOperation = "Parse the malformed integer with absl::SimpleAtoi.";
    badInputSource = ''
      #include <iostream>
      #include "absl/strings/numbers.h"

      int main() {
          int value = 0;
          if (absl::SimpleAtoi("42x", &value)) {
              return 2;
          }
          std::cerr << "abseil-cpp rejected invalid input\n";
          return 7;
      }
    '';
  };

  acl = mkLibraryProbe {
    package = "acl";
    compileArguments = ["-I@out@/include" "-L@out@/lib" "-Wl,-rpath,@out@/lib" "-lacl"];
    primaryInput = "A complete access ACL in the library's text notation.";
    primaryOperation = "Parse the ACL with acl_from_text and validate its structure.";
    primarySource = ''
      #include <stdio.h>
      #include <sys/acl.h>

      int main(void) {
          acl_t acl = acl_from_text("u::rw-,g::r--,o::---");
          if (acl == NULL || acl_valid(acl) != 0) {
              return 2;
          }
          acl_free(acl);
          return puts("acl api passed") == EOF;
      }
    '';
    badInput = "An ACL containing an unknown permission letter.";
    badInputOperation = "Parse the malformed ACL with acl_from_text.";
    badInputSource = ''
      #include <stdio.h>
      #include <sys/acl.h>

      int main(void) {
          acl_t acl = acl_from_text("u::rwx,g::r-z,o::---");
          if (acl != NULL) {
              acl_free(acl);
              return 2;
          }
          fputs("acl rejected invalid input\n", stderr);
          return 7;
      }
    '';
  };

  alsa-lib = mkLibraryProbe {
    package = "alsa-lib";
    compileArguments = ["-I@out@/include" "-L@out@/lib" "-Wl,-rpath,@out@/lib" "-lasound"];
    primaryInput = "The public PCM format name S16_LE.";
    primaryOperation = "Resolve the name with snd_pcm_format_value and verify the enum value.";
    primarySource = ''
      #include <stdio.h>
      #include <alsa/asoundlib.h>

      int main(void) {
          if (snd_pcm_format_value("S16_LE") != SND_PCM_FORMAT_S16_LE) {
              return 2;
          }
          return puts("alsa-lib api passed") == EOF;
      }
    '';
    badInput = "A PCM format name that ALSA does not define.";
    badInputOperation = "Resolve the unknown format with snd_pcm_format_value.";
    badInputSource = ''
      #include <stdio.h>
      #include <alsa/asoundlib.h>

      int main(void) {
          if (snd_pcm_format_value("AOS_NOT_A_PCM_FORMAT") != SND_PCM_FORMAT_UNKNOWN) {
              return 2;
          }
          fputs("alsa-lib rejected invalid input\n", stderr);
          return 7;
      }
    '';
  };

  boost = mkLibraryProbe {
    package = "boost";
    compiler = "@cxx@";
    sourceSuffix = "cc";
    compileArguments = ["-I@out@/include"];
    primaryInput = "The decimal string 42.";
    primaryOperation = "Convert the string to an integer with boost::lexical_cast.";
    primarySource = ''
      #include <iostream>
      #include <boost/lexical_cast.hpp>

      int main() {
          if (boost::lexical_cast<int>("42") != 42) {
              return 2;
          }
          std::cout << "boost api passed\n";
      }
    '';
    badInput = "A string containing no decimal integer.";
    badInputOperation = "Convert the string to an integer with boost::lexical_cast.";
    badInputSource = ''
      #include <iostream>
      #include <boost/lexical_cast.hpp>

      int main() {
          try {
              static_cast<void>(boost::lexical_cast<int>("forty-two"));
              return 2;
          } catch (const boost::bad_lexical_cast &) {
              std::cerr << "boost rejected invalid input\n";
              return 7;
          }
      }
    '';
  };

  c-ares = mkLibraryProbe {
    package = "c-ares";
    compileArguments = ["-I@out@/include" "-L@out@/lib" "-Wl,-rpath,@out@/lib" "-lcares"];
    primaryInput = "The IPv4 address 192.0.2.42.";
    primaryOperation = "Parse the address with ares_inet_pton.";
    primarySource = ''
      #include <stdio.h>
      #include <arpa/inet.h>
      #include <ares.h>

      int main(void) {
          unsigned char address[4];
          if (ares_inet_pton(AF_INET, "192.0.2.42", address) != 1
              || address[0] != 192 || address[3] != 42) {
              return 2;
          }
          return puts("c-ares api passed") == EOF;
      }
    '';
    badInput = "An IPv4 address containing an out-of-range octet.";
    badInputOperation = "Parse the malformed address with ares_inet_pton.";
    badInputSource = ''
      #include <stdio.h>
      #include <arpa/inet.h>
      #include <ares.h>

      int main(void) {
          unsigned char address[4];
          if (ares_inet_pton(AF_INET, "192.0.2.999", address) != 0) {
              return 2;
          }
          fputs("c-ares rejected invalid input\n", stderr);
          return 7;
      }
    '';
  };

  cairo = mkLibraryProbe {
    package = "cairo";
    compileArguments = ["-I@out@/include/cairo" "-L@out@/lib" "-Wl,-rpath,@out@/lib" "-lcairo"];
    primaryInput = "A two-by-two in-memory ARGB image surface.";
    primaryOperation = "Create the surface, paint it red, and validate the surface status.";
    primarySource = ''
      #include <stdio.h>
      #include <cairo.h>

      int main(void) {
          cairo_surface_t *surface = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, 2, 2);
          cairo_t *context = cairo_create(surface);
          cairo_set_source_rgb(context, 1.0, 0.0, 0.0);
          cairo_paint(context);
          cairo_surface_flush(surface);
          int failed = cairo_status(context) != CAIRO_STATUS_SUCCESS
              || cairo_surface_status(surface) != CAIRO_STATUS_SUCCESS;
          cairo_destroy(context);
          cairo_surface_destroy(surface);
          if (failed) {
              return 2;
          }
          return puts("cairo api passed") == EOF;
      }
    '';
    badInput = "An image surface request with an invalid pixel format.";
    badInputOperation = "Create the surface and inspect Cairo's error-object status.";
    badInputSource = ''
      #include <stdio.h>
      #include <cairo.h>

      int main(void) {
          cairo_surface_t *surface = cairo_image_surface_create((cairo_format_t)999, 2, 2);
          cairo_status_t status = cairo_surface_status(surface);
          cairo_surface_destroy(surface);
          if (status != CAIRO_STATUS_INVALID_FORMAT) {
              return 2;
          }
          fputs("cairo rejected invalid input\n", stderr);
          return 7;
      }
    '';
  };

  duktape = mkLibraryProbe {
    package = "duktape";
    compileArguments = ["-I@out@/include" "-L@out@/lib" "-Wl,-rpath,@out@/lib" "-lduktape" "-lm"];
    primaryInput = "A JavaScript expression reducing an integer array.";
    primaryOperation = "Evaluate the expression with Duktape and verify its numeric result.";
    primarySource = ''
      #include <stdio.h>
      #include <duktape.h>

      int main(void) {
          duk_context *context = duk_create_heap_default();
          if (context == NULL) {
              return 2;
          }
          if (duk_peval_string(context, "[19, 23].reduce(function(a, b) { return a + b; }, 0)") != 0
              || duk_get_int(context, -1) != 42) {
              duk_destroy_heap(context);
              return 3;
          }
          duk_destroy_heap(context);
          return puts("duktape api passed") == EOF;
      }
    '';
    badInput = "A JavaScript function declaration with an incomplete parameter list.";
    badInputOperation = "Evaluate the malformed source with protected Duktape evaluation.";
    badInputSource = ''
      #include <stdio.h>
      #include <duktape.h>

      int main(void) {
          duk_context *context = duk_create_heap_default();
          if (context == NULL) {
              return 2;
          }
          int status = duk_peval_string(context, "function broken( {");
          duk_destroy_heap(context);
          if (status == 0) {
              return 3;
          }
          fputs("duktape rejected invalid input\n", stderr);
          return 7;
      }
    '';
  };

  expat = mkLibraryProbe {
    package = "expat";
    compileArguments = ["-I@out@/include" "-L@out@/lib" "-Wl,-rpath,@out@/lib" "-lexpat"];
    primaryInput = "A well-formed XML document with nested elements.";
    primaryOperation = "Parse the complete document with XML_Parse.";
    primarySource = ''
      #include <stdio.h>
      #include <string.h>
      #include <expat.h>

      int main(void) {
          const char document[] = "<root><value>42</value></root>";
          XML_Parser parser = XML_ParserCreate(NULL);
          if (parser == NULL || XML_Parse(parser, document, (int)strlen(document), XML_TRUE) != XML_STATUS_OK) {
              XML_ParserFree(parser);
              return 2;
          }
          XML_ParserFree(parser);
          return puts("expat api passed") == EOF;
      }
    '';
    badInput = "An XML document whose closing tag does not match its opening tag.";
    badInputOperation = "Parse the malformed complete document with XML_Parse.";
    badInputSource = ''
      #include <stdio.h>
      #include <string.h>
      #include <expat.h>

      int main(void) {
          const char document[] = "<root><value>42</root>";
          XML_Parser parser = XML_ParserCreate(NULL);
          if (parser == NULL) {
              return 2;
          }
          enum XML_Status status = XML_Parse(parser, document, (int)strlen(document), XML_TRUE);
          XML_ParserFree(parser);
          if (status != XML_STATUS_ERROR) {
              return 3;
          }
          fputs("expat rejected invalid input\n", stderr);
          return 7;
      }
    '';
  };

  fmt = mkLibraryProbe {
    package = "fmt";
    compiler = "@cxx@";
    sourceSuffix = "cc";
    compileArguments = ["-I@out@/include" "-L@out@/lib" "-Wl,-rpath,@out@/lib" "-lfmt"];
    primaryInput = "A format string with a zero-padded integer field.";
    primaryOperation = "Format an integer with fmt::format and compare the resulting string.";
    primarySource = ''
      #include <iostream>
      #include <fmt/format.h>

      int main() {
          if (fmt::format("answer={:04d}", 42) != "answer=0042") {
              return 2;
          }
          std::cout << "fmt api passed\n";
      }
    '';
    badInput = "A runtime format string with an unmatched opening brace.";
    badInputOperation = "Format a value through fmt::runtime and catch the format_error.";
    badInputSource = ''
      #include <iostream>
      #include <fmt/format.h>

      int main() {
          try {
              static_cast<void>(fmt::format(fmt::runtime("{"), 42));
              return 2;
          } catch (const fmt::format_error &) {
              std::cerr << "fmt rejected invalid input\n";
              return 7;
          }
      }
    '';
  };

  gmp = mkLibraryProbe {
    package = "gmp";
    compileArguments = ["-I@out@/include" "-L@out@/lib" "-Wl,-rpath,@out@/lib" "-lgmp"];
    primaryInput = "Two integers larger than a native 64-bit value.";
    primaryOperation = "Parse and add the integers with GMP, then compare their decimal sum.";
    primarySource = ''
      #include <stdio.h>
      #include <stdlib.h>
      #include <string.h>
      #include <gmp.h>

      int main(void) {
          mpz_t left, right, sum;
          mpz_inits(left, right, sum, NULL);
          if (mpz_set_str(left, "100000000000000000000", 10) != 0
              || mpz_set_str(right, "23", 10) != 0) {
              return 2;
          }
          mpz_add(sum, left, right);
          char *text = mpz_get_str(NULL, 10, sum);
          int failed = text == NULL || strcmp(text, "100000000000000000023") != 0;
          free(text);
          mpz_clears(left, right, sum, NULL);
          if (failed) {
              return 3;
          }
          return puts("gmp api passed") == EOF;
      }
    '';
    badInput = "A supposed decimal integer containing an alphabetic character.";
    badInputOperation = "Parse the malformed integer with mpz_set_str.";
    badInputSource = ''
      #include <stdio.h>
      #include <gmp.h>

      int main(void) {
          mpz_t value;
          mpz_init(value);
          int status = mpz_set_str(value, "42x", 10);
          mpz_clear(value);
          if (status == 0) {
              return 2;
          }
          fputs("gmp rejected invalid input\n", stderr);
          return 7;
      }
    '';
  };
}
