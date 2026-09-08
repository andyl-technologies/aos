##! Exercises Q-through-Z libraries through public parsing and transformation APIs.
{testing}: let
  mkLibraryProbe = {
    package,
    compiler ? "@cc@",
    sourceSuffix ? "c",
    compileArguments,
    primaryInput,
    primaryOperation,
    primarySource,
    badInput,
    badInputOperation,
    badInputSource,
    badExpectedStderr ? "${package} rejected invalid input\n",
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
              stderr.exact = badExpectedStderr;
              observes_rejection = true;
            }
          ];
          artifacts = [];
        };
      };
    };
in {
  readline = mkLibraryProbe {
    package = "readline";
    compileArguments = ["-I@out@/include" "-L@out@/lib" "-Wl,-rpath,@out@/lib" "-lreadline"];
    primaryInput = "The documented vi value for Readline's editing-mode variable.";
    primaryOperation = "Bind the variable through Readline's public API and read its normalized value.";
    primarySource = ''
      #include <stdio.h>
      #include <string.h>
      #include <readline/readline.h>

      int main(void) {
          if (rl_variable_bind("editing-mode", "vi") != 0 ||
              strcmp(rl_variable_value("editing-mode"), "vi") != 0) {
              return 2;
          }
          return puts("readline api passed") == EOF;
      }
    '';
    badInput = "An editing-mode value that Readline does not support.";
    badInputOperation = "Attempt to bind an unsupported editing mode through rl_variable_bind.";
    badExpectedStderr = "readline: editing-mode: could not set value to `qualification-mode'\nreadline rejected invalid input\n";
    badInputSource = ''
      #include <stdio.h>
      #include <readline/readline.h>

      int main(void) {
          if (rl_variable_bind("editing-mode", "qualification-mode") == 0) {
              return 2;
          }
          fputs("readline rejected invalid input\n", stderr);
          return 7;
      }
    '';
  };

  snappy = mkLibraryProbe {
    package = "snappy";
    compileArguments = ["-I@out@/include" "-L@out@/lib" "-Wl,-rpath,@out@/lib" "-lsnappy"];
    primaryInput = "A fixed byte string passed through Snappy compression and decompression.";
    primaryOperation = "Compress the bytes with snappy_compress and recover them with snappy_uncompress.";
    primarySource = ''
      #include <stdio.h>
      #include <string.h>
      #include <snappy-c.h>

      int main(void) {
          const char input[] = "answer=42";
          char compressed[64];
          char output[64];
          size_t compressed_size = sizeof(compressed);
          size_t output_size = sizeof(output);

          if (snappy_compress(input, strlen(input), compressed, &compressed_size) != SNAPPY_OK ||
              snappy_uncompress(compressed, compressed_size, output, &output_size) != SNAPPY_OK ||
              output_size != strlen(input) || memcmp(input, output, output_size) != 0) {
              return 2;
          }
          return puts("snappy api passed") == EOF;
      }
    '';
    badInput = "A byte sequence that is not a valid Snappy stream.";
    badInputOperation = "Validate the malformed bytes through snappy_validate_compressed_buffer.";
    badInputSource = ''
      #include <stdio.h>
      #include <string.h>
      #include <snappy-c.h>

      int main(void) {
          const char invalid[] = "not a snappy stream";
          if (snappy_validate_compressed_buffer(invalid, strlen(invalid)) != SNAPPY_INVALID_INPUT) {
              return 2;
          }
          fputs("snappy rejected invalid input\n", stderr);
          return 7;
      }
    '';
  };

  toml11 = mkLibraryProbe {
    package = "toml11";
    compiler = "@cxx@";
    sourceSuffix = "cc";
    compileArguments = ["-std=c++17" "-I@out@/include"];
    primaryInput = "A TOML document containing an integer answer.";
    primaryOperation = "Parse the document with toml11 and retrieve the typed integer.";
    primarySource = ''
      #include <cstdint>
      #include <iostream>
      #include <sstream>
      #include <toml.hpp>

      int main() {
          std::istringstream input("answer = 42\n");
          const auto document = toml::parse(input, "answer.toml");
          if (toml::find<std::int64_t>(document, "answer") != 42) {
              return 2;
          }
          std::cout << "toml11 api passed\n";
      }
    '';
    badInput = "A TOML integer assignment with no value.";
    badInputOperation = "Parse the malformed document with toml11.";
    badInputSource = ''
      #include <iostream>
      #include <sstream>
      #include <toml.hpp>

      int main() {
          std::istringstream input("answer =\n");
          try {
              (void)toml::parse(input, "invalid.toml");
          } catch (const toml::syntax_error&) {
              std::cerr << "toml11 rejected invalid input\n";
              return 7;
          }
          return 2;
      }
    '';
  };

  "tpm2-tss" = mkLibraryProbe {
    package = "tpm2-tss";
    compileArguments = ["-I@out@/include" "-L@out@/lib" "-Wl,-rpath,@out@/lib" "-ltss2-mu"];
    primaryInput = "The 32-bit value 0x12345678.";
    primaryOperation = "Marshal the value into TPM wire order, then unmarshal it through the TSS MU API.";
    primarySource = ''
      #include <stdint.h>
      #include <stdio.h>
      #include <tss2/tss2_mu.h>

      int main(void) {
          uint8_t buffer[4];
          size_t offset = 0;
          UINT32 output = 0;

          if (Tss2_MU_UINT32_Marshal(0x12345678U, buffer, sizeof(buffer), &offset) != TSS2_RC_SUCCESS ||
              offset != sizeof(buffer)) {
              return 2;
          }
          offset = 0;
          if (Tss2_MU_UINT32_Unmarshal(buffer, sizeof(buffer), &offset, &output) != TSS2_RC_SUCCESS ||
              output != 0x12345678U) {
              return 2;
          }
          return puts("tpm2-tss api passed") == EOF;
      }
    '';
    badInput = "A three-byte destination buffer for a four-byte TPM UINT32.";
    badInputOperation = "Attempt to marshal the value into the undersized buffer.";
    badInputSource = ''
      #include <stdint.h>
      #include <stdio.h>
      #include <tss2/tss2_mu.h>

      int main(void) {
          uint8_t buffer[3];
          size_t offset = 0;
          if (Tss2_MU_UINT32_Marshal(42U, buffer, sizeof(buffer), &offset) !=
              TSS2_MU_RC_INSUFFICIENT_BUFFER) {
              return 2;
          }
          fputs("tpm2-tss rejected invalid input\n", stderr);
          return 7;
      }
    '';
  };

  utf8proc = mkLibraryProbe {
    package = "utf8proc";
    compileArguments = ["-I@out@/include" "-L@out@/lib" "-Wl,-rpath,@out@/lib" "-lutf8proc"];
    primaryInput = "The three-byte UTF-8 encoding of U+20AC EURO SIGN.";
    primaryOperation = "Decode the sequence through utf8proc_iterate and verify its code point and width.";
    primarySource = ''
      #include <stdio.h>
      #include <utf8proc.h>

      int main(void) {
          const utf8proc_uint8_t input[] = {0xe2, 0x82, 0xac};
          utf8proc_int32_t codepoint = 0;
          if (utf8proc_iterate(input, sizeof(input), &codepoint) != 3 || codepoint != 0x20ac) {
              return 2;
          }
          return puts("utf8proc api passed") == EOF;
      }
    '';
    badInput = "An overlong two-byte UTF-8 encoding.";
    badInputOperation = "Decode the malformed sequence through utf8proc_iterate.";
    badInputSource = ''
      #include <stdio.h>
      #include <utf8proc.h>

      int main(void) {
          const utf8proc_uint8_t input[] = {0xc0, 0xaf};
          utf8proc_int32_t codepoint = 0;
          if (utf8proc_iterate(input, sizeof(input), &codepoint) != UTF8PROC_ERROR_INVALIDUTF8) {
              return 2;
          }
          fputs("utf8proc rejected invalid input\n", stderr);
          return 7;
      }
    '';
  };

  "util-linux" = mkLibraryProbe {
    package = "util-linux";
    compileArguments = ["-I@out@/include" "-L@out@/lib" "-Wl,-rpath,@out@/lib" "-luuid"];
    primaryInput = "A canonical UUID string.";
    primaryOperation = "Parse and format the identifier through libuuid's public API.";
    primarySource = ''
      #include <stdio.h>
      #include <string.h>
      #include <uuid/uuid.h>

      int main(void) {
          const char expected[] = "12345678-1234-5678-9234-567812345678";
          char output[37];
          uuid_t value;

          if (uuid_parse(expected, value) != 0) {
              return 2;
          }
          uuid_unparse_lower(value, output);
          if (strcmp(output, expected) != 0) {
              return 2;
          }
          return puts("util-linux api passed") == EOF;
      }
    '';
    badInput = "A UUID string containing a non-hexadecimal digit.";
    badInputOperation = "Parse the malformed identifier through uuid_parse.";
    badInputSource = ''
      #include <stdio.h>
      #include <uuid/uuid.h>

      int main(void) {
          uuid_t value;
          if (uuid_parse("12345678-1234-5678-9234-56781234567z", value) == 0) {
              return 2;
          }
          fputs("util-linux rejected invalid input\n", stderr);
          return 7;
      }
    '';
  };
}
