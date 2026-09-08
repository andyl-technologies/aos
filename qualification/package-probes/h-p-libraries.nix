##! Exercises H-through-P library packages through their public data APIs.
{testing}: let
  mkCProbe = {
    package,
    primaryInput,
    primaryOperation,
    primaryExpected,
    primarySource,
    badInput,
    badOperation,
    badExpected,
    badSource,
    libraries,
    cxx ? false,
    extraArguments ? [],
  }:
    testing.mkQualificationPackageProbe {
      name = package;
      spec = {
        schema_version = "aos.release.package-probe/v1";
        inherit package;
        primary = {
          input = primaryInput;
          operation = primaryOperation;
          expected = primaryExpected;
          files."primary.${
            if cxx
            then "cc"
            else "c"
          }" =
            primarySource;
          steps = [
            {
              argv =
                [
                  (
                    if cxx
                    then "@cxx@"
                    else "@cc@"
                  )
                  "primary.${
                    if cxx
                    then "cc"
                    else "c"
                  }"
                  "-I@out@/include"
                  "-L@out@/lib"
                  "-Wl,-rpath,@out@/lib"
                ]
                ++ extraArguments
                ++ libraries
                ++ ["-o" "primary-check"];
              exit_code = 0;
              stdout.exact = "";
            }
            {
              argv = ["@work@/primary/primary-check"];
              exit_code = 0;
              stdout.exact = "${package} primary passed\n";
              stderr.exact = "";
            }
          ];
          artifacts = [];
        };
        bad_input = {
          input = badInput;
          operation = badOperation;
          expected = badExpected;
          files."bad-input.${
            if cxx
            then "cc"
            else "c"
          }" =
            badSource;
          steps = [
            {
              argv =
                [
                  (
                    if cxx
                    then "@cxx@"
                    else "@cc@"
                  )
                  "bad-input.${
                    if cxx
                    then "cc"
                    else "c"
                  }"
                  "-I@out@/include"
                  "-L@out@/lib"
                  "-Wl,-rpath,@out@/lib"
                ]
                ++ extraArguments
                ++ libraries
                ++ ["-o" "bad-input-check"];
              exit_code = 0;
              stdout.exact = "";
            }
            {
              argv = ["@work@/bad-input/bad-input-check"];
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

  report = package: body: ''
    #include <stdio.h>
    static int pass(void) { return puts("${package} primary passed") == EOF; }
    static int reject(void) {
        fputs("${package} rejected invalid input\n", stderr);
        return 7;
    }
    ${body}
  '';
in {
  jansson = mkCProbe {
    package = "jansson";
    primaryInput = "A JSON object containing an integer member.";
    primaryOperation = "Parse the object and read the member through Jansson's public API.";
    primaryExpected = "The parser returns an object whose answer member is the integer 42.";
    primarySource = report "jansson" ''
      #include <jansson.h>
      int main(void) {
          json_error_t error;
          json_t *root = json_loads("{\"answer\":42}", 0, &error);
          if (root == NULL) return 2;
          json_t *answer = json_object_get(root, "answer");
          int ok = json_is_integer(answer) && json_integer_value(answer) == 42;
          json_decref(root);
          return ok ? pass() : 3;
      }
    '';
    badInput = "A JSON object with a trailing comma.";
    badOperation = "Pass the malformed document to json_loads.";
    badExpected = "Jansson reports a parse error and does not return a JSON value.";
    badSource = report "jansson" ''
      #include <jansson.h>
      int main(void) {
          json_error_t error;
          json_t *root = json_loads("{\"answer\":42,}", 0, &error);
          if (root != NULL || error.line != 1) { json_decref(root); return 2; }
          return reject();
      }
    '';
    libraries = ["-ljansson"];
  };

  "json-c" = mkCProbe {
    package = "json-c";
    primaryInput = "A JSON array containing two integers.";
    primaryOperation = "Parse the array and sum its elements through json-c.";
    primaryExpected = "The parsed array contains two integers whose sum is 42.";
    primarySource = report "json-c" ''
      #include <json-c/json.h>
      int main(void) {
          struct json_object *root = json_tokener_parse("[19,23]");
          if (root == NULL || json_object_array_length(root) != 2) return 2;
          int sum = json_object_get_int(json_object_array_get_idx(root, 0))
              + json_object_get_int(json_object_array_get_idx(root, 1));
          json_object_put(root);
          return sum == 42 ? pass() : 3;
      }
    '';
    badInput = "A truncated JSON array.";
    badOperation = "Parse the malformed array with an explicit json_tokener.";
    badExpected = "json-c records an incomplete-input error instead of returning a value.";
    badSource = report "json-c" ''
      #include <json-c/json.h>
      int main(void) {
          struct json_tokener *tokener = json_tokener_new();
          struct json_object *root = json_tokener_parse_ex(tokener, "[1,", 3);
          enum json_tokener_error error = json_tokener_get_error(tokener);
          if (root != NULL || error == json_tokener_success) return 2;
          json_tokener_free(tokener);
          return reject();
      }
    '';
    libraries = ["-ljson-c"];
  };

  libcap = mkCProbe {
    package = "libcap";
    primaryInput = "The textual capability set cap_chown=ep.";
    primaryOperation = "Parse the text and render the capability set back through libcap.";
    primaryExpected = "The rendered set contains cap_chown with effective and permitted flags.";
    primarySource = report "libcap" ''
      #include <string.h>
      #include <sys/capability.h>
      int main(void) {
          cap_t capabilities = cap_from_text("cap_chown=ep");
          if (capabilities == NULL) return 2;
          char *text = cap_to_text(capabilities, NULL);
          int ok = text != NULL && strstr(text, "cap_chown") != NULL && strstr(text, "ep") != NULL;
          cap_free(text); cap_free(capabilities);
          return ok ? pass() : 3;
      }
    '';
    badInput = "A capability name that is not defined by Linux.";
    badOperation = "Parse the invalid name with cap_from_text.";
    badExpected = "libcap rejects the name by returning a null capability set.";
    badSource = report "libcap" ''
      #include <sys/capability.h>
      int main(void) {
          cap_t capabilities = cap_from_text("cap_definitely_not_real=ep");
          if (capabilities != NULL) { cap_free(capabilities); return 2; }
          return reject();
      }
    '';
    libraries = ["-lcap"];
  };

  libffi = mkCProbe {
    package = "libffi";
    primaryInput = "Two integer arguments for an indirectly invoked addition function.";
    primaryOperation = "Prepare a call interface and invoke the function through ffi_call.";
    primaryExpected = "The indirect call returns 42.";
    primarySource = report "libffi" ''
      #include <ffi.h>
      static int add(int left, int right) { return left + right; }
      int main(void) {
          ffi_cif cif; ffi_type *types[2] = {&ffi_type_sint, &ffi_type_sint};
          int left = 19, right = 23, result = 0; void *values[2] = {&left, &right};
          if (ffi_prep_cif(&cif, FFI_DEFAULT_ABI, 2, &ffi_type_sint, types) != FFI_OK) return 2;
          ffi_call(&cif, FFI_FN(add), &result, values);
          return result == 42 ? pass() : 3;
      }
    '';
    badInput = "An ABI selector outside libffi's supported ABI range.";
    badOperation = "Prepare a call interface using the invalid ABI.";
    badExpected = "ffi_prep_cif returns FFI_BAD_ABI.";
    badSource = report "libffi" ''
      #include <ffi.h>
      int main(void) {
          ffi_cif cif;
          if (ffi_prep_cif(&cif, (ffi_abi)9999, 0, &ffi_type_void, NULL) != FFI_BAD_ABI) return 2;
          return reject();
      }
    '';
    libraries = ["-lffi"];
  };

  libpng = mkCProbe {
    package = "libpng";
    primaryInput = "A request for libpng's compiled library version.";
    primaryOperation = "Read and validate the version through png_access_version_number.";
    primaryExpected = "The public API reports the same nonzero version encoded by the header.";
    primarySource = report "libpng" ''
      #include <png.h>
      int main(void) {
          return png_access_version_number() == PNG_LIBPNG_VER && PNG_LIBPNG_VER > 10000 ? pass() : 2;
      }
    '';
    badInput = "The eight-byte signature of a GIF file.";
    badOperation = "Ask png_sig_cmp to validate the foreign image signature.";
    badExpected = "libpng reports that the bytes are not a PNG signature.";
    badSource = report "libpng" ''
      #include <png.h>
      int main(void) {
          const png_byte signature[8] = {'G','I','F','8','9','a',0,0};
          if (png_sig_cmp(signature, 0, sizeof(signature)) == 0) return 2;
          return reject();
      }
    '';
    libraries = ["-lpng"];
  };

  libsodium = mkCProbe {
    package = "libsodium";
    primaryInput = "The ASCII string abc for SHA-256 hashing.";
    primaryOperation = "Hash the message through crypto_hash_sha256.";
    primaryExpected = "The digest matches the published SHA-256 test value.";
    primarySource = report "libsodium" ''
      #include <string.h>
      #include <sodium.h>
      int main(void) {
          static const unsigned char expected[32] = {0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
          unsigned char digest[32];
          if (sodium_init() < 0) return 2;
          crypto_hash_sha256(digest, (const unsigned char *)"abc", 3);
          return sodium_memcmp(digest, expected, sizeof(digest)) == 0 ? pass() : 3;
      }
    '';
    badInput = "A password-hash string outside libsodium's encoded format.";
    badOperation = "Verify the malformed hash with crypto_pwhash_str_verify.";
    badExpected = "libsodium returns failure instead of accepting the password.";
    badSource = report "libsodium" ''
      #include <sodium.h>
      int main(void) {
          if (sodium_init() < 0) return 2;
          if (crypto_pwhash_str_verify("not-a-password-hash", "secret", 6) == 0) return 3;
          return reject();
      }
    '';
    libraries = ["-lsodium"];
  };

  libxml2 = mkCProbe {
    package = "libxml2";
    primaryInput = "An XML document with a root element and text child.";
    primaryOperation = "Parse the document and inspect its root through libxml2.";
    primaryExpected = "The root element is named answer.";
    primarySource = report "libxml2" ''
      #include <libxml/parser.h>
      #include <libxml/tree.h>
      int main(void) {
          const char document[] = "<answer>42</answer>";
          xmlDocPtr parsed = xmlReadMemory(document, sizeof(document) - 1, "input.xml", NULL, XML_PARSE_NONET);
          if (parsed == NULL) return 2;
          xmlNodePtr root = xmlDocGetRootElement(parsed);
          int ok = root != NULL && xmlStrEqual(root->name, BAD_CAST "answer");
          xmlFreeDoc(parsed);
          return ok ? pass() : 3;
      }
    '';
    badInput = "An XML document with mismatched element tags.";
    badOperation = "Parse the malformed document with network access disabled.";
    badExpected = "libxml2 rejects the document and returns no parsed tree.";
    badSource = report "libxml2" ''
      #include <libxml/parser.h>
      int main(void) {
          const char document[] = "<open></closed>";
          xmlDocPtr parsed = xmlReadMemory(document, sizeof(document) - 1, "bad.xml", NULL, XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
          if (parsed != NULL) { xmlFreeDoc(parsed); return 2; }
          return reject();
      }
    '';
    libraries = ["-lxml2"];
    extraArguments = ["-I@out@/include/libxml2"];
  };

  libyaml = mkCProbe {
    package = "libyaml";
    primaryInput = "A YAML mapping whose answer value is 42.";
    primaryOperation = "Parse the stream and observe its scalar events.";
    primaryExpected = "The parser reaches stream end after observing the answer and 42 scalars.";
    primarySource = report "libyaml" ''
      #include <string.h>
      #include <yaml.h>
      int main(void) {
          const unsigned char input[] = "answer: 42\n"; int answer = 0, value = 0, done = 0;
          yaml_parser_t parser; yaml_event_t event;
          if (!yaml_parser_initialize(&parser)) return 2;
          yaml_parser_set_input_string(&parser, input, sizeof(input) - 1);
          while (!done && yaml_parser_parse(&parser, &event)) {
              if (event.type == YAML_SCALAR_EVENT && strcmp((char *)event.data.scalar.value, "answer") == 0) answer = 1;
              if (event.type == YAML_SCALAR_EVENT && strcmp((char *)event.data.scalar.value, "42") == 0) value = 1;
              done = event.type == YAML_STREAM_END_EVENT; yaml_event_delete(&event);
          }
          yaml_parser_delete(&parser);
          return answer && value && done ? pass() : 3;
      }
    '';
    badInput = "A YAML flow sequence with no closing bracket.";
    badOperation = "Parse events until libyaml reports a syntax failure.";
    badExpected = "The parser returns failure before stream end.";
    badSource = report "libyaml" ''
      #include <yaml.h>
      int main(void) {
          const unsigned char input[] = "answer: [1, 2\n"; int failed = 0, done = 0;
          yaml_parser_t parser; yaml_event_t event;
          if (!yaml_parser_initialize(&parser)) return 2;
          yaml_parser_set_input_string(&parser, input, sizeof(input) - 1);
          while (!done) {
              if (!yaml_parser_parse(&parser, &event)) { failed = 1; break; }
              done = event.type == YAML_STREAM_END_EVENT; yaml_event_delete(&event);
          }
          yaml_parser_delete(&parser);
          if (!failed) return 3;
          return reject();
      }
    '';
    libraries = ["-lyaml"];
  };

  lz4 = mkCProbe {
    package = "lz4";
    primaryInput = "A fixed string compressed into a bounded block.";
    primaryOperation = "Compress and decompress the bytes through the LZ4 block API.";
    primaryExpected = "The recovered bytes equal the original string.";
    primarySource = report "lz4" ''
      #include <string.h>
      #include <lz4.h>
      int main(void) {
          const char input[] = "AOS qualification"; char compressed[128], output[128];
          int size = LZ4_compress_default(input, compressed, sizeof(input), sizeof(compressed));
          if (size <= 0) return 2;
          int recovered = LZ4_decompress_safe(compressed, output, size, sizeof(output));
          return recovered == sizeof(input) && memcmp(input, output, sizeof(input)) == 0 ? pass() : 3;
      }
    '';
    badInput = "A truncated LZ4 block whose token declares missing literal bytes.";
    badOperation = "Decompress the invalid block with the safe decoder.";
    badExpected = "LZ4_decompress_safe returns a negative corruption status.";
    badSource = report "lz4" ''
      #include <lz4.h>
      int main(void) {
          const char invalid[] = {(char)0xf0}; char output[32];
          if (LZ4_decompress_safe(invalid, output, sizeof(invalid), sizeof(output)) >= 0) return 2;
          return reject();
      }
    '';
    libraries = ["-llz4"];
  };

  "nlohmann-json" = mkCProbe {
    package = "nlohmann-json";
    cxx = true;
    primaryInput = "A JSON object containing an integer answer.";
    primaryOperation = "Parse the document and read the value through nlohmann::json.";
    primaryExpected = "The answer field has integer value 42.";
    primarySource = report "nlohmann-json" ''
      #include <nlohmann/json.hpp>
      int main() {
          auto document = nlohmann::json::parse("{\"answer\":42}");
          return document.at("answer").get<int>() == 42 ? pass() : 2;
      }
    '';
    badInput = "A JSON object with a trailing comma.";
    badOperation = "Parse the malformed document while disabling exceptions.";
    badExpected = "The library returns its discarded sentinel.";
    badSource = report "nlohmann-json" ''
      #include <nlohmann/json.hpp>
      int main() {
          auto document = nlohmann::json::parse("{\"answer\":42,}", nullptr, false);
          if (!document.is_discarded()) return 2;
          return reject();
      }
    '';
    libraries = [];
  };

  pcre2 = mkCProbe {
    package = "pcre2";
    primaryInput = "A regular expression with a numeric capture and matching text.";
    primaryOperation = "Compile and match the expression through PCRE2's 8-bit API.";
    primaryExpected = "The engine reports the whole match and one capture.";
    primarySource = report "pcre2" ''
      #define PCRE2_CODE_UNIT_WIDTH 8
      #include <pcre2.h>
      int main(void) {
          int error; PCRE2_SIZE offset;
          pcre2_code *code = pcre2_compile((PCRE2_SPTR)"answer=([0-9]+)", PCRE2_ZERO_TERMINATED, 0, &error, &offset, NULL);
          if (code == NULL) return 2;
          pcre2_match_data *data = pcre2_match_data_create_from_pattern(code, NULL);
          int matches = pcre2_match(code, (PCRE2_SPTR)"answer=42", 9, 0, 0, data, NULL);
          pcre2_match_data_free(data); pcre2_code_free(code);
          return matches == 2 ? pass() : 3;
      }
    '';
    badInput = "A regular expression with an unclosed group.";
    badOperation = "Compile the malformed expression through PCRE2.";
    badExpected = "PCRE2 returns no compiled pattern and sets an error code.";
    badSource = report "pcre2" ''
      #define PCRE2_CODE_UNIT_WIDTH 8
      #include <pcre2.h>
      int main(void) {
          int error = 0; PCRE2_SIZE offset = 0;
          pcre2_code *code = pcre2_compile((PCRE2_SPTR)"(unclosed", PCRE2_ZERO_TERMINATED, 0, &error, &offset, NULL);
          if (code != NULL || error == 0) { pcre2_code_free(code); return 2; }
          return reject();
      }
    '';
    libraries = ["-lpcre2-8"];
  };

  popt = mkCProbe {
    package = "popt";
    primaryInput = "A --count=42 command-line option.";
    primaryOperation = "Parse the option through poptGetNextOpt.";
    primaryExpected = "The parser stores integer value 42 and reaches end of options.";
    primarySource = report "popt" ''
      #include <popt.h>
      int main(void) {
          int count = 0; const char *arguments[] = {"probe", "--count=42", NULL};
          struct poptOption options[] = {{"count", 'c', POPT_ARG_INT, &count, 0, "count", "N"}, POPT_TABLEEND};
          poptContext context = poptGetContext(NULL, 2, arguments, options, 0);
          int status = poptGetNextOpt(context); poptFreeContext(context);
          return status == -1 && count == 42 ? pass() : 2;
      }
    '';
    badInput = "A --count value that is not an integer.";
    badOperation = "Parse the malformed integer option through popt.";
    badExpected = "The parser returns POPT_ERROR_BADNUMBER.";
    badSource = report "popt" ''
      #include <popt.h>
      int main(void) {
          int count = 0; const char *arguments[] = {"probe", "--count=not-a-number", NULL};
          struct poptOption options[] = {{"count", 'c', POPT_ARG_INT, &count, 0, "count", "N"}, POPT_TABLEEND};
          poptContext context = poptGetContext(NULL, 2, arguments, options, 0);
          int status = poptGetNextOpt(context); poptFreeContext(context);
          if (status != POPT_ERROR_BADNUMBER) return 2;
          return reject();
      }
    '';
    libraries = ["-lpopt"];
  };

  inih = mkCProbe {
    package = "inih";
    primaryInput = "An INI section containing answer=42.";
    primaryOperation = "Parse the document and validate the callback's section, key, and value.";
    primaryExpected = "inih invokes the callback with the exact mapping and returns success.";
    primarySource = report "inih" ''
      #include <string.h>
      #include <ini.h>
      static int handler(void *seen, const char *section, const char *name, const char *value) {
          int *matched = seen;
          *matched = strcmp(section, "qualification") == 0
              && strcmp(name, "answer") == 0 && strcmp(value, "42") == 0;
          return 1;
      }
      int main(void) {
          int matched = 0;
          int status = ini_parse_string("[qualification]\nanswer=42\n", handler, &matched);
          return status == 0 && matched ? pass() : 2;
      }
    '';
    badInput = "An INI section header with no closing bracket.";
    badOperation = "Parse the malformed document through ini_parse_string.";
    badExpected = "inih reports the one-based line number of the syntax error.";
    badSource = report "inih" ''
      #include <ini.h>
      static int handler(void *unused, const char *section, const char *name, const char *value) {
          (void)unused; (void)section; (void)name; (void)value; return 1;
      }
      int main(void) {
          if (ini_parse_string("[unclosed\nanswer=42\n", handler, NULL) != 1) return 2;
          return reject();
      }
    '';
    libraries = ["-linih"];
  };

  jemalloc = mkCProbe {
    package = "jemalloc";
    primaryInput = "A request for a 64-byte allocation and its usable size.";
    primaryOperation = "Allocate, query, write, and free memory through jemalloc's public API.";
    primaryExpected = "The allocation succeeds and its usable size is at least 64 bytes.";
    primarySource = report "jemalloc" ''
      #include <string.h>
      #include <jemalloc/jemalloc.h>
      int main(void) {
          void *memory = mallocx(64, 0);
          if (memory == NULL || sallocx(memory, 0) < 64) return 2;
          memset(memory, 0x5a, 64); dallocx(memory, 0);
          return pass();
      }
    '';
    badInput = "An allocation request whose size is the maximum size_t value.";
    badOperation = "Request the impossible allocation through mallocx.";
    badExpected = "jemalloc rejects the overflowing request by returning a null pointer.";
    badSource = report "jemalloc" ''
      #include <stdint.h>
      #include <jemalloc/jemalloc.h>
      int main(void) {
          if (mallocx(SIZE_MAX, 0) != NULL) return 2;
          return reject();
      }
    '';
    libraries = ["-ljemalloc"];
  };

  libarchive = mkCProbe {
    package = "libarchive";
    primaryInput = "An in-memory tar archive containing one regular file.";
    primaryOperation = "Write the archive and read its entry back through libarchive.";
    primaryExpected = "The recovered entry has the declared pathname and size.";
    primarySource = report "libarchive" ''
      #include <archive.h>
      #include <archive_entry.h>
      #include <string.h>
      int main(void) {
          char buffer[4096]; size_t used = 0;
          struct archive *writer = archive_write_new();
          struct archive_entry *entry = archive_entry_new();
          archive_write_set_format_pax_restricted(writer);
          if (archive_write_open_memory(writer, buffer, sizeof(buffer), &used) != ARCHIVE_OK) return 2;
          archive_entry_set_pathname(entry, "answer.txt"); archive_entry_set_filetype(entry, AE_IFREG);
          archive_entry_set_perm(entry, 0644); archive_entry_set_size(entry, 2);
          if (archive_write_header(writer, entry) != ARCHIVE_OK || archive_write_data(writer, "42", 2) != 2) return 3;
          archive_entry_free(entry); archive_write_free(writer);
          struct archive *reader = archive_read_new(); archive_read_support_format_tar(reader);
          if (archive_read_open_memory(reader, buffer, used) != ARCHIVE_OK) return 4;
          if (archive_read_next_header(reader, &entry) != ARCHIVE_OK) return 5;
          int ok = strcmp(archive_entry_pathname(entry), "answer.txt") == 0 && archive_entry_size(entry) == 2;
          archive_read_free(reader);
          return ok ? pass() : 6;
      }
    '';
    badInput = "Bytes that do not encode a supported archive.";
    badOperation = "Open the bytes and request the first archive header.";
    badExpected = "libarchive returns an error status instead of an entry.";
    badSource = report "libarchive" ''
      #include <archive.h>
      int main(void) {
          const char invalid[] = "not an archive";
          struct archive *reader = archive_read_new();
          archive_read_support_filter_all(reader); archive_read_support_format_all(reader);
          int opened = archive_read_open_memory(reader, invalid, sizeof(invalid));
          struct archive_entry *entry = NULL;
          int status = opened == ARCHIVE_OK ? archive_read_next_header(reader, &entry) : opened;
          archive_read_free(reader);
          if (status >= ARCHIVE_OK) return 2;
          return reject();
      }
    '';
    libraries = ["-larchive"];
  };

  libevent = mkCProbe {
    package = "libevent";
    primaryInput = "The numeric socket address 127.0.0.1:42.";
    primaryOperation = "Parse the address and render its IPv4 host through libevent utilities.";
    primaryExpected = "The parsed port is 42 and the rendered address is 127.0.0.1.";
    primarySource = report "libevent" ''
      #include <arpa/inet.h>
      #include <string.h>
      #include <event2/util.h>
      int main(void) {
          struct sockaddr_storage address; int length = sizeof(address); char host[32];
          if (evutil_parse_sockaddr_port("127.0.0.1:42", (struct sockaddr *)&address, &length) != 0) return 2;
          struct sockaddr_in *ipv4 = (struct sockaddr_in *)&address;
          if (ntohs(ipv4->sin_port) != 42 || evutil_inet_ntop(AF_INET, &ipv4->sin_addr, host, sizeof(host)) == NULL) return 3;
          return strcmp(host, "127.0.0.1") == 0 ? pass() : 4;
      }
    '';
    badInput = "An IPv4 socket address whose port is above 65535.";
    badOperation = "Parse the out-of-range address with evutil_parse_sockaddr_port.";
    badExpected = "libevent rejects the address with a negative status.";
    badSource = report "libevent" ''
      #include <event2/util.h>
      int main(void) {
          struct sockaddr_storage address; int length = sizeof(address);
          if (evutil_parse_sockaddr_port("127.0.0.1:70000", (struct sockaddr *)&address, &length) == 0) return 2;
          return reject();
      }
    '';
    libraries = ["-levent"];
  };

  libgit2 = mkCProbe {
    package = "libgit2";
    primaryInput = "A forty-digit hexadecimal Git object identifier.";
    primaryOperation = "Parse the full identifier and render it through libgit2.";
    primaryExpected = "The round-tripped hexadecimal object name is unchanged.";
    primarySource = report "libgit2" ''
      #include <string.h>
      #include <git2.h>
      int main(void) {
          const char input[] = "0123456789abcdef0123456789abcdef01234567"; char output[GIT_OID_HEXSZ + 1]; git_oid oid;
          if (git_libgit2_init() < 0 || git_oid_fromstr(&oid, input) < 0) return 2;
          git_oid_tostr(output, sizeof(output), &oid); git_libgit2_shutdown();
          return strcmp(input, output) == 0 ? pass() : 3;
      }
    '';
    badInput = "A Git object identifier containing a non-hexadecimal letter.";
    badOperation = "Parse the malformed identifier with git_oid_fromstr.";
    badExpected = "libgit2 returns an error instead of an object identifier.";
    badSource = report "libgit2" ''
      #include <git2.h>
      int main(void) {
          git_oid oid; if (git_libgit2_init() < 0) return 2;
          int status = git_oid_fromstr(&oid, "g123456789abcdef0123456789abcdef01234567"); git_libgit2_shutdown();
          if (status >= 0) return 3;
          return reject();
      }
    '';
    libraries = ["-lgit2"];
  };

  libidn2 = mkCProbe {
    package = "libidn2";
    primaryInput = "The Unicode domain name bucher.example with an umlaut.";
    primaryOperation = "Convert the domain to its IDNA ASCII representation.";
    primaryExpected = "libidn2 returns xn--bcher-kva.example.";
    primarySource = report "libidn2" ''
      #include <string.h>
      #include <idn2.h>
      int main(void) {
          char *ascii = NULL;
          int status = idn2_to_ascii_8z("b\xc3\xbc" "cher.example", &ascii, 0);
          int ok = status == IDN2_OK && ascii != NULL && strcmp(ascii, "xn--bcher-kva.example") == 0;
          idn2_free(ascii);
          return ok ? pass() : 2;
      }
    '';
    badInput = "A domain containing an invalid UTF-8 byte sequence.";
    badOperation = "Pass the malformed name to the IDNA converter.";
    badExpected = "libidn2 returns a non-success status and no accepted domain.";
    badSource = report "libidn2" ''
      #include <idn2.h>
      int main(void) {
          char *ascii = NULL;
          int status = idn2_to_ascii_8z("bad\xff.example", &ascii, 0); idn2_free(ascii);
          if (status == IDN2_OK) return 2;
          return reject();
      }
    '';
    libraries = ["-lidn2"];
  };

  libpcap = mkCProbe {
    package = "libpcap";
    primaryInput = "The packet-filter expression tcp port 443.";
    primaryOperation = "Compile the filter for a dead Ethernet capture handle.";
    primaryExpected = "libpcap produces a nonempty BPF instruction program.";
    primarySource = report "libpcap" ''
      #include <pcap/pcap.h>
      int main(void) {
          pcap_t *capture = pcap_open_dead(DLT_EN10MB, 65535); struct bpf_program program;
          if (capture == NULL || pcap_compile(capture, &program, "tcp port 443", 1, PCAP_NETMASK_UNKNOWN) != 0) return 2;
          int ok = program.bf_len > 0; pcap_freecode(&program); pcap_close(capture);
          return ok ? pass() : 3;
      }
    '';
    badInput = "A packet-filter expression ending in an incomplete conjunction.";
    badOperation = "Compile the malformed expression through libpcap.";
    badExpected = "libpcap reports a filter syntax error.";
    badSource = report "libpcap" ''
      #include <pcap/pcap.h>
      int main(void) {
          pcap_t *capture = pcap_open_dead(DLT_EN10MB, 65535); struct bpf_program program;
          if (capture == NULL) return 2;
          int status = pcap_compile(capture, &program, "tcp and", 1, PCAP_NETMASK_UNKNOWN); pcap_close(capture);
          if (status == 0) { pcap_freecode(&program); return 3; }
          return reject();
      }
    '';
    libraries = ["-lpcap"];
  };

  libunistring = mkCProbe {
    package = "libunistring";
    primaryInput = "A valid UTF-8 sequence containing a two-byte umlaut.";
    primaryOperation = "Validate the complete byte sequence through u8_check.";
    primaryExpected = "libunistring returns a null error pointer for valid UTF-8.";
    primarySource = report "libunistring" ''
      #include <unistr.h>
      int main(void) {
          const uint8_t input[] = {'b', 0xc3, 0xbc, 'c', 'h', 'e', 'r'};
          return u8_check(input, sizeof(input)) == NULL ? pass() : 2;
      }
    '';
    badInput = "A truncated two-byte UTF-8 sequence.";
    badOperation = "Validate the malformed sequence through u8_check.";
    badExpected = "libunistring returns a pointer to the invalid byte.";
    badSource = report "libunistring" ''
      #include <unistr.h>
      int main(void) {
          const uint8_t input[] = {'a', 0xc3};
          if (u8_check(input, sizeof(input)) == NULL) return 2;
          return reject();
      }
    '';
    libraries = ["-lunistring"];
  };

  libuv = mkCProbe {
    package = "libuv";
    primaryInput = "The numeric IPv4 address 127.0.0.1 and port 42.";
    primaryOperation = "Parse and render the address through libuv's networking API.";
    primaryExpected = "The port and round-tripped host match the input.";
    primarySource = report "libuv" ''
      #include <arpa/inet.h>
      #include <string.h>
      #include <uv.h>
      int main(void) {
          struct sockaddr_in address; char host[32];
          if (uv_ip4_addr("127.0.0.1", 42, &address) != 0 || uv_ip4_name(&address, host, sizeof(host)) != 0) return 2;
          return ntohs(address.sin_port) == 42 && strcmp(host, "127.0.0.1") == 0 ? pass() : 3;
      }
    '';
    badInput = "An IPv4 address containing an octet above 255.";
    badOperation = "Parse the malformed address through uv_ip4_addr.";
    badExpected = "libuv returns UV_EINVAL.";
    badSource = report "libuv" ''
      #include <uv.h>
      int main(void) {
          struct sockaddr_in address;
          if (uv_ip4_addr("300.1.2.3", 42, &address) != UV_EINVAL) return 2;
          return reject();
      }
    '';
    libraries = ["-luv"];
  };

  nghttp2 = mkCProbe {
    package = "nghttp2";
    primaryInput = "A lowercase HTTP/2 header name.";
    primaryOperation = "Validate the bytes through nghttp2_check_header_name.";
    primaryExpected = "nghttp2 accepts the RFC-compatible header name.";
    primarySource = report "nghttp2" ''
      #include <string.h>
      #include <nghttp2/nghttp2.h>
      int main(void) {
          const uint8_t name[] = "content-type";
          return nghttp2_check_header_name(name, strlen((char *)name)) ? pass() : 2;
      }
    '';
    badInput = "An HTTP/2 header name containing an uppercase letter.";
    badOperation = "Validate the forbidden name through nghttp2_check_header_name.";
    badExpected = "nghttp2 rejects the header name.";
    badSource = report "nghttp2" ''
      #include <string.h>
      #include <nghttp2/nghttp2.h>
      int main(void) {
          const uint8_t name[] = "Content-Type";
          if (nghttp2_check_header_name(name, strlen((char *)name))) return 2;
          return reject();
      }
    '';
    libraries = ["-lnghttp2"];
  };

  oniguruma = mkCProbe {
    package = "oniguruma";
    primaryInput = "A regular expression with a numeric capture and matching text.";
    primaryOperation = "Compile and search the expression through Oniguruma.";
    primaryExpected = "The search matches the complete answer=42 string.";
    primarySource = report "oniguruma" ''
      #include <string.h>
      #include <oniguruma.h>
      int main(void) {
          const OnigUChar pattern[] = "answer=([0-9]+)"; const OnigUChar text[] = "answer=42";
          OnigRegex regex; OnigErrorInfo error; OnigRegion *region = onig_region_new();
          int status = onig_new(&regex, pattern, pattern + strlen((char *)pattern), ONIG_OPTION_NONE, ONIG_ENCODING_ASCII, ONIG_SYNTAX_DEFAULT, &error);
          if (status != ONIG_NORMAL) return 2;
          status = onig_search(regex, text, text + strlen((char *)text), text, text + strlen((char *)text), region, ONIG_OPTION_NONE);
          int ok = status == 0 && region->beg[0] == 0 && region->end[0] == 9;
          onig_region_free(region, 1); onig_free(regex); onig_end();
          return ok ? pass() : 3;
      }
    '';
    badInput = "A regular expression with an unclosed group.";
    badOperation = "Compile the malformed expression through Oniguruma.";
    badExpected = "The compiler returns a negative syntax-error code.";
    badSource = report "oniguruma" ''
      #include <string.h>
      #include <oniguruma.h>
      int main(void) {
          const OnigUChar pattern[] = "(unclosed"; OnigRegex regex; OnigErrorInfo error;
          int status = onig_new(&regex, pattern, pattern + strlen((char *)pattern), ONIG_OPTION_NONE, ONIG_ENCODING_ASCII, ONIG_SYNTAX_DEFAULT, &error);
          if (status >= 0) { onig_free(regex); return 2; }
          onig_end(); return reject();
      }
    '';
    libraries = ["-lonig"];
  };

  openssl = mkCProbe {
    package = "openssl";
    primaryInput = "The ASCII string abc for SHA-256 hashing.";
    primaryOperation = "Hash the bytes through OpenSSL's SHA256 API.";
    primaryExpected = "The digest matches the standard SHA-256 vector.";
    primarySource = report "openssl" ''
      #include <string.h>
      #include <openssl/sha.h>
      int main(void) {
          static const unsigned char expected[32] = {0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
          unsigned char digest[SHA256_DIGEST_LENGTH];
          if (SHA256((const unsigned char *)"abc", 3, digest) == NULL) return 2;
          return memcmp(digest, expected, sizeof(digest)) == 0 ? pass() : 3;
      }
    '';
    badInput = "A byte sequence that is not a DER-encoded X.509 certificate.";
    badOperation = "Decode the malformed bytes through d2i_X509.";
    badExpected = "OpenSSL returns no certificate object.";
    badSource = report "openssl" ''
      #include <openssl/x509.h>
      int main(void) {
          const unsigned char invalid[] = "not a certificate"; const unsigned char *cursor = invalid;
          X509 *certificate = d2i_X509(NULL, &cursor, sizeof(invalid));
          if (certificate != NULL) { X509_free(certificate); return 2; }
          return reject();
      }
    '';
    libraries = ["-lcrypto"];
  };

  pixman = mkCProbe {
    package = "pixman";
    primaryInput = "One opaque red source pixel composited over a blank destination.";
    primaryOperation = "Composite the pixel through pixman_image_composite32.";
    primaryExpected = "The destination becomes the exact source pixel.";
    primarySource = report "pixman" ''
      #include <pixman.h>
      int main(void) {
          uint32_t source_pixel = 0xffff0000, destination_pixel = 0;
          pixman_image_t *source = pixman_image_create_bits(PIXMAN_a8r8g8b8, 1, 1, &source_pixel, 4);
          pixman_image_t *destination = pixman_image_create_bits(PIXMAN_a8r8g8b8, 1, 1, &destination_pixel, 4);
          if (source == NULL || destination == NULL) return 2;
          pixman_image_composite32(PIXMAN_OP_SRC, source, NULL, destination, 0, 0, 0, 0, 0, 0, 1, 1);
          int ok = destination_pixel == source_pixel;
          pixman_image_unref(destination); pixman_image_unref(source);
          return ok ? pass() : 3;
      }
    '';
    badInput = "An image width above pixman's supported coordinate range.";
    badOperation = "Create the out-of-range image through pixman_image_create_bits.";
    badExpected = "pixman rejects the dimensions by returning a null image.";
    badSource = report "pixman" ''
      #include <pixman.h>
      int main(void) {
          pixman_image_t *image = pixman_image_create_bits(PIXMAN_a8r8g8b8, 0x7fffffff, 1, NULL, 4);
          if (image != NULL) { pixman_image_unref(image); return 2; }
          return reject();
      }
    '';
    libraries = ["-lpixman-1"];
    extraArguments = ["-I@out@/include/pixman-1"];
  };

  libpsl = mkCProbe {
    package = "libpsl";
    primaryInput = "The public suffix co.uk and the private domain example.co.uk.";
    primaryOperation = "Query both names through libpsl's built-in suffix context.";
    primaryExpected = "co.uk is public while example.co.uk is not itself a public suffix.";
    primarySource = report "libpsl" ''
      #include <libpsl.h>
      int main(void) {
          const psl_ctx_t *context = psl_builtin();
          if (context == NULL) return 2;
          return psl_is_public_suffix(context, "co.uk")
              && !psl_is_public_suffix(context, "example.co.uk") ? pass() : 3;
      }
    '';
    badInput = "A domain with an empty label between two dots.";
    badOperation = "Query the malformed domain through the public-suffix classifier.";
    badExpected = "libpsl does not classify the malformed name as a public suffix.";
    badSource = report "libpsl" ''
      #include <libpsl.h>
      int main(void) {
          const psl_ctx_t *context = psl_builtin();
          if (context == NULL || psl_is_public_suffix(context, "example..com")) return 2;
          return reject();
      }
    '';
    libraries = ["-lpsl"];
  };

  libseccomp = mkCProbe {
    package = "libseccomp";
    primaryInput = "The canonical x86_64 audit architecture name.";
    primaryOperation = "Resolve the name through libseccomp and compare its audit token.";
    primaryExpected = "The name resolves to the SCMP_ARCH_X86_64 token.";
    primarySource = report "libseccomp" ''
      #include <string.h>
      #include <seccomp.h>
      int main(void) {
          uint32_t architecture = seccomp_arch_resolve_name("x86_64");
          return architecture == SCMP_ARCH_X86_64 ? pass() : 2;
      }
    '';
    badInput = "An audit architecture name absent from libseccomp's registry.";
    badOperation = "Resolve the unknown name through seccomp_arch_resolve_name.";
    badExpected = "libseccomp returns its zero invalid-architecture token.";
    badSource = report "libseccomp" ''
      #include <seccomp.h>
      int main(void) {
          if (seccomp_arch_resolve_name("qualification_arch_does_not_exist") != 0) return 2;
          return reject();
      }
    '';
    libraries = ["-lseccomp"];
  };

  libxcrypt = mkCProbe {
    package = "libxcrypt";
    primaryInput = "A SHA-512 crypt prefix, round count, and fixed entropy bytes.";
    primaryOperation = "Generate a salt through crypt_gensalt_rn.";
    primaryExpected = "libxcrypt returns a SHA-512 salt beginning with the requested prefix.";
    primarySource = report "libxcrypt" ''
      #include <string.h>
      #include <crypt.h>
      int main(void) {
          const unsigned char entropy[16] = {0}; char salt[CRYPT_GENSALT_OUTPUT_SIZE];
          char *result = crypt_gensalt_rn("$6$", 5000, (const char *)entropy, sizeof(entropy), salt, sizeof(salt));
          return result == salt && strncmp(salt, "$6$", 3) == 0 ? pass() : 2;
      }
    '';
    badInput = "A password-hash prefix that names no supported method.";
    badOperation = "Generate a salt using the unsupported prefix.";
    badExpected = "libxcrypt rejects the request by returning a null pointer.";
    badSource = report "libxcrypt" ''
      #include <crypt.h>
      int main(void) {
          const unsigned char entropy[16] = {0}; char salt[CRYPT_GENSALT_OUTPUT_SIZE];
          if (crypt_gensalt_rn("$qualification$", 0, (const char *)entropy, sizeof(entropy), salt, sizeof(salt)) != NULL) return 2;
          return reject();
      }
    '';
    libraries = ["-lcrypt"];
  };

  icu = mkCProbe {
    package = "icu";
    primaryInput = "The UTF-8 bytes for b followed by u-umlaut.";
    primaryOperation = "Convert the bytes into UTF-16 through ICU's u_strFromUTF8 API.";
    primaryExpected = "ICU returns the two expected Unicode code units.";
    primarySource = report "icu" ''
      #include <unicode/ustring.h>
      int main(void) {
          const char input[3] = {'b', (char)0xc3, (char)0xbc}; UChar output[8]; int32_t length = 0;
          UErrorCode error = U_ZERO_ERROR;
          u_strFromUTF8(output, 8, &length, input, sizeof(input), &error);
          return U_SUCCESS(error) && length == 2 && output[0] == 0x62 && output[1] == 0xfc ? pass() : 2;
      }
    '';
    badInput = "A single continuation byte that cannot form a UTF-8 character.";
    badOperation = "Convert the malformed byte through u_strFromUTF8.";
    badExpected = "ICU returns U_INVALID_CHAR_FOUND.";
    badSource = report "icu" ''
      #include <unicode/ustring.h>
      int main(void) {
          const char input[1] = {(char)0x80}; UChar output[8]; int32_t length = 0;
          UErrorCode error = U_ZERO_ERROR;
          u_strFromUTF8(output, 8, &length, input, sizeof(input), &error);
          if (error != U_INVALID_CHAR_FOUND) return 2;
          return reject();
      }
    '';
    libraries = ["-licuuc"];
  };
}
