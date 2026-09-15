##! Exercises additional A-G libraries through their public data APIs.
{testing}: let
  mkCProbe = {
    package,
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
          expected = "The API returns the expected value and the consumer prints the fixed success line.";
          files."primary.c" = primarySource;
          steps = [
            {
              argv = ["@cc@" "primary.c"] ++ compileArguments ++ ["-o" "primary-consumer"];
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
          expected = "The API reports rejection and the consumer emits the fixed diagnostic and rejection status.";
          files."bad-input.c" = badInputSource;
          steps = [
            {
              argv = ["@cc@" "bad-input.c"] ++ compileArguments ++ ["-o" "bad-input-consumer"];
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
  audit = mkCProbe {
    package = "audit";
    compileArguments = ["-I@out@/include" "-L@out@/lib" "-Wl,-rpath,@out@/lib" "-laudit"];
    primaryInput = "The portable audit syscall name read and the detected machine type.";
    primaryOperation = "Resolve the syscall name to a machine-specific number and back to its canonical name.";
    primarySource = ''
      #include <stdio.h>
      #include <string.h>
      #include <libaudit.h>

      int main(void) {
          int machine = audit_detect_machine();
          int syscall = audit_name_to_syscall("read", machine);
          const char *name = audit_syscall_to_name(syscall, machine);
          if (machine < 0 || syscall < 0 || name == NULL || strcmp(name, "read") != 0) {
              return 2;
          }
          return puts("audit api passed") == EOF;
      }
    '';
    badInput = "A syscall name absent from the Linux audit tables.";
    badInputOperation = "Resolve the unknown name with audit_name_to_syscall.";
    badInputSource = ''
      #include <stdio.h>
      #include <libaudit.h>

      int main(void) {
          int machine = audit_detect_machine();
          if (machine < 0 || audit_name_to_syscall("aos_no_such_syscall", machine) != -1) {
              return 2;
          }
          fputs("audit rejected invalid input\n", stderr);
          return 7;
      }
    '';
  };

  boringssl = mkCProbe {
    package = "boringssl";
    compileArguments = ["-I@out@/include" "-L@out@/lib" "-lcrypto" "-lpthread"];
    primaryInput = "The Base64 text NDI=, which encodes the ASCII bytes 42.";
    primaryOperation = "Decode the text with EVP_DecodeBlock and verify the decoded prefix.";
    primarySource = ''
      #include <stdio.h>
      #include <string.h>
      #include <openssl/evp.h>

      int main(void) {
          unsigned char output[8] = {0};
          int length = EVP_DecodeBlock(output, (const unsigned char *)"NDI=", 4);
          if (length != 3 || memcmp(output, "42", 2) != 0) {
              return 2;
          }
          return puts("boringssl api passed") == EOF;
      }
    '';
    badInput = "A Base64 string containing characters outside the alphabet.";
    badInputOperation = "Decode the malformed text with EVP_DecodeBlock.";
    badInputSource = ''
      #include <stdio.h>
      #include <openssl/evp.h>

      int main(void) {
          unsigned char output[8] = {0};
          if (EVP_DecodeBlock(output, (const unsigned char *)"%%%?", 4) != -1) {
              return 2;
          }
          fputs("boringssl rejected invalid input\n", stderr);
          return 7;
      }
    '';
  };

  cyrus-sasl = mkCProbe {
    package = "cyrus-sasl";
    compileArguments = ["-I@out@/include" "-L@out@/lib" "-Wl,-rpath,@out@/lib" "-lsasl2"];
    primaryInput = "The ASCII bytes 42.";
    primaryOperation = "Encode and decode the bytes with the SASL Base64 utility API.";
    primarySource = ''
      #include <stdio.h>
      #include <string.h>
      #include <sasl/saslutil.h>

      int main(void) {
          char encoded[16];
          char decoded[16];
          unsigned encoded_length = 0;
          unsigned decoded_length = 0;
          if (sasl_encode64("42", 2, encoded, sizeof(encoded), &encoded_length) != SASL_OK
              || encoded_length != 4 || strcmp(encoded, "NDI=") != 0
              || sasl_decode64(encoded, encoded_length, decoded, sizeof(decoded), &decoded_length) != SASL_OK
              || decoded_length != 2 || memcmp(decoded, "42", 2) != 0) {
              return 2;
          }
          return puts("cyrus-sasl api passed") == EOF;
      }
    '';
    badInput = "A Base64 string containing characters outside the alphabet.";
    badInputOperation = "Decode the malformed text with sasl_decode64.";
    badInputSource = ''
      #include <stdio.h>
      #include <sasl/saslutil.h>

      int main(void) {
          char output[16];
          unsigned output_length = 0;
          if (sasl_decode64("%%%?", 4, output, sizeof(output), &output_length) == SASL_OK) {
              return 2;
          }
          fputs("cyrus-sasl rejected invalid input\n", stderr);
          return 7;
      }
    '';
  };

  efivar = mkCProbe {
    package = "efivar";
    compileArguments = ["-I@out@/include" "-L@out@/lib" "-Wl,-rpath,@out@/lib" "-lefivar"];
    primaryInput = "The canonical EFI global-variable GUID string.";
    primaryOperation = "Parse the string with efi_str_to_guid and compare it to EFI_GLOBAL_GUID.";
    primarySource = ''
      #include <stdio.h>
      #include <string.h>
      #include <efivar/efivar.h>

      int main(void) {
          efi_guid_t parsed;
          efi_guid_t expected = EFI_GLOBAL_GUID;
          if (efi_str_to_guid("8be4df61-93ca-11d2-aa0d-00e098032b8c", &parsed) < 0
              || memcmp(&parsed, &expected, sizeof(parsed)) != 0) {
              return 2;
          }
          return puts("efivar api passed") == EOF;
      }
    '';
    badInput = "A GUID string containing a non-hexadecimal character.";
    badInputOperation = "Parse the malformed identifier with efi_str_to_guid.";
    badInputSource = ''
      #include <stdio.h>
      #include <efivar/efivar.h>

      int main(void) {
          efi_guid_t parsed;
          if (efi_str_to_guid("8be4df6z-93ca-11d2-aa0d-00e098032b8c", &parsed) >= 0) {
              return 2;
          }
          fputs("efivar rejected invalid input\n", stderr);
          return 7;
      }
    '';
  };

  elfutils = mkCProbe {
    package = "elfutils";
    compileArguments = ["-I@out@/include" "-L@out@/lib" "-Wl,-rpath,@out@/lib" "-lelf"];
    primaryInput = "A complete in-memory ELF64 file header.";
    primaryOperation = "Open the bytes with elf_memory and verify that libelf recognizes an ELF object.";
    primarySource = ''
      #include <stdio.h>
      #include <string.h>
      #include <elf.h>
      #include <libelf.h>

      int main(void) {
          Elf64_Ehdr header = {0};
          memcpy(header.e_ident, ELFMAG, SELFMAG);
          header.e_ident[EI_CLASS] = ELFCLASS64;
          header.e_ident[EI_DATA] = ELFDATA2LSB;
          header.e_ident[EI_VERSION] = EV_CURRENT;
          header.e_version = EV_CURRENT;
          header.e_ehsize = sizeof(header);
          if (elf_version(EV_CURRENT) == EV_NONE) {
              return 2;
          }
          Elf *object = elf_memory((char *)&header, sizeof(header));
          if (object == NULL || elf_kind(object) != ELF_K_ELF) {
              if (object != NULL) elf_end(object);
              return 3;
          }
          elf_end(object);
          return puts("elfutils api passed") == EOF;
      }
    '';
    badInput = "A byte buffer without the ELF magic number.";
    badInputOperation = "Open the malformed bytes with elf_memory and inspect their object kind.";
    badInputSource = ''
      #include <stdio.h>
      #include <libelf.h>

      int main(void) {
          char invalid[64] = "not an ELF object";
          if (elf_version(EV_CURRENT) == EV_NONE) {
              return 2;
          }
          Elf *object = elf_memory(invalid, sizeof(invalid));
          if (object == NULL) {
              fputs("elfutils rejected invalid input\n", stderr);
              return 7;
          }
          Elf_Kind kind = elf_kind(object);
          elf_end(object);
          if (kind != ELF_K_NONE) {
              return 3;
          }
          fputs("elfutils rejected invalid input\n", stderr);
          return 7;
      }
    '';
  };

  freetype = mkCProbe {
    package = "freetype";
    compileArguments = ["-I@out@/include/freetype2" "-L@out@/lib" "-Wl,-rpath,@out@/lib" "-lfreetype"];
    primaryInput = "A request to initialize FreeType and query its linked version.";
    primaryOperation = "Initialize a library handle and read the major, minor, and patch version.";
    primarySource = ''
      #include <stdio.h>
      #include <ft2build.h>
      #include FT_FREETYPE_H

      int main(void) {
          FT_Library library;
          FT_Int major = 0, minor = 0, patch = 0;
          if (FT_Init_FreeType(&library) != 0) {
              return 2;
          }
          FT_Library_Version(library, &major, &minor, &patch);
          FT_Done_FreeType(library);
          if (major < 2 || minor < 0 || patch < 0) {
              return 3;
          }
          return puts("freetype api passed") == EOF;
      }
    '';
    badInput = "A four-byte buffer that is not a font file.";
    badInputOperation = "Create a memory face from the invalid bytes.";
    badInputSource = ''
      #include <stdio.h>
      #include <ft2build.h>
      #include FT_FREETYPE_H

      int main(void) {
          const FT_Byte invalid[] = {'n', 'o', 'p', 'e'};
          FT_Library library;
          FT_Face face;
          if (FT_Init_FreeType(&library) != 0) {
              return 2;
          }
          FT_Error status = FT_New_Memory_Face(library, invalid, sizeof(invalid), 0, &face);
          if (status == 0) {
              FT_Done_Face(face);
              FT_Done_FreeType(library);
              return 3;
          }
          FT_Done_FreeType(library);
          fputs("freetype rejected invalid input\n", stderr);
          return 7;
      }
    '';
  };

  gdbm = mkCProbe {
    package = "gdbm";
    compileArguments = ["-I@out@/include" "-L@out@/lib" "-Wl,-rpath,@out@/lib" "-lgdbm"];
    primaryInput = "A key and value to persist in a new GDBM database.";
    primaryOperation = "Store the record, fetch it, and compare the returned bytes.";
    primarySource = ''
      #include <stdio.h>
      #include <stdlib.h>
      #include <string.h>
      #include <gdbm.h>

      int main(void) {
          GDBM_FILE database = gdbm_open("probe.gdbm", 0, GDBM_NEWDB, 0600, NULL);
          datum key = {.dptr = "answer", .dsize = 6};
          datum value = {.dptr = "42", .dsize = 2};
          if (database == NULL || gdbm_store(database, key, value, GDBM_INSERT) != 0) {
              return 2;
          }
          datum fetched = gdbm_fetch(database, key);
          int failed = fetched.dptr == NULL || fetched.dsize != 2 || memcmp(fetched.dptr, "42", 2) != 0;
          free(fetched.dptr);
          gdbm_close(database);
          if (failed) {
              return 3;
          }
          return puts("gdbm api passed") == EOF;
      }
    '';
    badInput = "A request to open a nonexistent database read-only.";
    badInputOperation = "Open the missing path with GDBM_READER.";
    badInputSource = ''
      #include <stdio.h>
      #include <gdbm.h>

      int main(void) {
          GDBM_FILE database = gdbm_open("missing.gdbm", 0, GDBM_READER, 0, NULL);
          if (database != NULL) {
              gdbm_close(database);
              return 2;
          }
          fputs("gdbm rejected invalid input\n", stderr);
          return 7;
      }
    '';
  };

  glib = mkCProbe {
    package = "glib";
    compileArguments = [
      "-I@output:dev@/include/glib-2.0"
      "-I@output:dev@/lib/glib-2.0/include"
      "-L@out@/lib"
      "-Wl,-rpath,@out@/lib"
      "-lglib-2.0"
    ];
    primaryInput = "A regular expression and a matching alphanumeric record.";
    primaryOperation = "Compile the expression with GRegex and match the complete record.";
    primarySource = ''
      #include <stdio.h>
      #include <glib.h>

      int main(void) {
          GError *error = NULL;
          GRegex *regex = g_regex_new("^(alpha|beta)[0-9]+$", 0, 0, &error);
          if (regex == NULL || error != NULL || !g_regex_match(regex, "beta42", 0, NULL)) {
              g_clear_error(&error);
              if (regex != NULL) g_regex_unref(regex);
              return 2;
          }
          g_regex_unref(regex);
          return puts("glib api passed") == EOF;
      }
    '';
    badInput = "A regular expression with an unmatched opening parenthesis.";
    badInputOperation = "Compile the malformed expression with GRegex.";
    badInputSource = ''
      #include <stdio.h>
      #include <glib.h>

      int main(void) {
          GError *error = NULL;
          GRegex *regex = g_regex_new("(", 0, 0, &error);
          if (regex != NULL || error == NULL) {
              if (regex != NULL) g_regex_unref(regex);
              g_clear_error(&error);
              return 2;
          }
          g_clear_error(&error);
          fputs("glib rejected invalid input\n", stderr);
          return 7;
      }
    '';
  };

  gnutls = mkCProbe {
    package = "gnutls";
    compileArguments = ["-I@out@/include" "-L@out@/lib" "-Wl,-rpath,@out@/lib" "-lgnutls"];
    primaryInput = "The hexadecimal text 3432, which represents the ASCII bytes 42.";
    primaryOperation = "Decode the text with gnutls_hex_decode2 and compare the returned datum.";
    primarySource = ''
      #include <stdio.h>
      #include <string.h>
      #include <gnutls/gnutls.h>

      int main(void) {
          gnutls_datum_t input = {(unsigned char *)"3432", 4};
          gnutls_datum_t output = {0};
          if (gnutls_hex_decode2(&input, &output) < 0
              || output.size != 2 || memcmp(output.data, "42", 2) != 0) {
              gnutls_free(output.data);
              return 2;
          }
          gnutls_free(output.data);
          return puts("gnutls api passed") == EOF;
      }
    '';
    badInput = "Hexadecimal text containing a non-hexadecimal letter.";
    badInputOperation = "Decode the malformed text with gnutls_hex_decode2.";
    badInputSource = ''
      #include <stdio.h>
      #include <gnutls/gnutls.h>

      int main(void) {
          gnutls_datum_t input = {(unsigned char *)"34xz", 4};
          gnutls_datum_t output = {0};
          if (gnutls_hex_decode2(&input, &output) >= 0) {
              gnutls_free(output.data);
              return 2;
          }
          fputs("gnutls rejected invalid input\n", stderr);
          return 7;
      }
    '';
  };
}
