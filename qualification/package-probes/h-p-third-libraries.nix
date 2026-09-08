##! Exercises a third H-through-P library slice through deterministic public APIs.
{testing}: let
  mkLibraryProbe = {
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
    includeArguments ? [],
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
          files."primary.c" = primarySource;
          steps = [
            {
              argv = ["@cc@" "primary.c" "-I@out@/include" "-L@out@/lib" "-Wl,-rpath,@out@/lib"] ++ includeArguments ++ libraries ++ ["-o" "primary-check"];
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
          files."bad-input.c" = badSource;
          steps = [
            {
              argv = ["@cc@" "bad-input.c" "-I@out@/include" "-L@out@/lib" "-Wl,-rpath,@out@/lib"] ++ includeArguments ++ libraries ++ ["-o" "bad-input-check"];
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

  program = package: body: ''
    #include <stdio.h>
    static int pass(void) { return puts("${package} primary passed") == EOF; }
    static int reject(void) {
        fputs("${package} rejected invalid input\n", stderr);
        return 7;
    }
    ${body}
  '';
in {
  libmetalink = mkLibraryProbe {
    package = "libmetalink";
    primaryInput = "A Metalink 4 document describing answer.txt with a size of 42 bytes.";
    primaryOperation = "Parse the in-memory XML document through metalink_parse_memory.";
    primaryExpected = "The parser returns one Metalink 4 file with the declared name and size.";
    primarySource = program "libmetalink" ''
      #include <string.h>
      #include <metalink/metalink.h>
      int main(void) {
          const char *document = "<metalink xmlns='urn:ietf:params:xml:ns:metalink'><file name='answer.txt'><size>42</size></file></metalink>";
          metalink_t *metalink = NULL;
          int status = metalink_parse_memory(document, strlen(document), &metalink);
          int valid = status == 0 && metalink != NULL && metalink->version == METALINK_VERSION_4
              && metalink->files != NULL && metalink->files[0] != NULL
              && strcmp(metalink->files[0]->name, "answer.txt") == 0
              && metalink->files[0]->size == 42;
          metalink_delete(metalink);
          return valid ? pass() : 2;
      }
    '';
    badInput = "Plain text that is not an XML document.";
    badOperation = "Parse the malformed document through metalink_parse_memory.";
    badExpected = "The Metalink parser returns a nonzero syntax error.";
    badSource = program "libmetalink" ''
      #include <string.h>
      #include <metalink/metalink.h>
      int main(void) {
          const char *document = "not XML";
          metalink_t *metalink = NULL;
          int status = metalink_parse_memory(document, strlen(document), &metalink);
          if (status == 0) {
              metalink_delete(metalink);
              return 2;
          }
          return reject();
      }
    '';
    libraries = ["-lmetalink"];
  };

  libssh2 = mkLibraryProbe {
    package = "libssh2";
    primaryInput = "An OpenSSH known-host line for an Ed25519 key.";
    primaryOperation = "Load the line and match its host and key through the known-host API.";
    primaryExpected = "The known-host collection reports an exact match.";
    primarySource = program "libssh2" ''
      #include <string.h>
      #include <libssh2.h>
      int main(void) {
          const char *key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
          const char *line = "example.test ssh-ed25519 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n";
          LIBSSH2_SESSION *session = libssh2_session_init();
          LIBSSH2_KNOWNHOSTS *hosts = session == NULL ? NULL : libssh2_knownhost_init(session);
          if (hosts == NULL) return 2;
          int loaded = libssh2_knownhost_readline(hosts, line, strlen(line), LIBSSH2_KNOWNHOST_FILE_OPENSSH);
          int matched = libssh2_knownhost_check(
              hosts, "example.test", key, 0,
              LIBSSH2_KNOWNHOST_TYPE_PLAIN | LIBSSH2_KNOWNHOST_KEYENC_BASE64 | LIBSSH2_KNOWNHOST_KEY_ED25519,
              NULL);
          libssh2_knownhost_free(hosts);
          libssh2_session_free(session);
          return loaded == 0 && matched == LIBSSH2_KNOWNHOST_CHECK_MATCH ? pass() : 3;
      }
    '';
    badInput = "A known-host line without a key type or encoded key.";
    badOperation = "Load the malformed line through libssh2_knownhost_readline.";
    badExpected = "Libssh2 returns a negative parse error.";
    badSource = program "libssh2" ''
      #include <string.h>
      #include <libssh2.h>
      int main(void) {
          const char *line = "invalid line\n";
          LIBSSH2_SESSION *session = libssh2_session_init();
          LIBSSH2_KNOWNHOSTS *hosts = session == NULL ? NULL : libssh2_knownhost_init(session);
          if (hosts == NULL) return 2;
          int status = libssh2_knownhost_readline(hosts, line, strlen(line), LIBSSH2_KNOWNHOST_FILE_OPENSSH);
          libssh2_knownhost_free(hosts);
          libssh2_session_free(session);
          return status < 0 ? reject() : 3;
      }
    '';
    libraries = ["-lssh2"];
  };

  liburing = mkLibraryProbe {
    package = "liburing";
    primaryInput = "A request for an io_uring queue containing one entry.";
    primaryOperation = "Initialize and release the queue through liburing.";
    primaryExpected = "Liburing creates a usable kernel ring and releases it successfully.";
    primarySource = program "liburing" ''
      #include <liburing.h>
      int main(void) {
          struct io_uring ring = {0};
          if (io_uring_queue_init(1, &ring, 0) != 0) return 2;
          io_uring_queue_exit(&ring);
          return pass();
      }
    '';
    badInput = "A request for an io_uring queue containing zero entries.";
    badOperation = "Submit the invalid queue size through io_uring_queue_init.";
    badExpected = "Liburing rejects the zero-sized queue with EINVAL.";
    badSource = program "liburing" ''
      #include <errno.h>
      #include <liburing.h>
      int main(void) {
          struct io_uring ring = {0};
          int status = io_uring_queue_init(0, &ring, 0);
          return status == -EINVAL ? reject() : 2;
      }
    '';
    libraries = ["-luring"];
  };

  libusb1 = mkLibraryProbe {
    package = "libusb1";
    primaryInput = "A libusb context configured to skip device discovery.";
    primaryOperation = "Initialize and release the context through libusb_init_context.";
    primaryExpected = "Libusb creates the isolated context without accessing USB devices.";
    primarySource = program "libusb1" ''
      #include <libusb.h>
      int main(void) {
          libusb_context *context = NULL;
          struct libusb_init_option option = {.option = LIBUSB_OPTION_NO_DEVICE_DISCOVERY};
          int status = libusb_init_context(&context, &option, 1);
          if (status != LIBUSB_SUCCESS || context == NULL) return 2;
          libusb_exit(context);
          return pass();
      }
    '';
    badInput = "An option identifier at the exclusive upper bound of libusb's option enum.";
    badOperation = "Apply the unsupported option through libusb_set_option.";
    badExpected = "Libusb returns LIBUSB_ERROR_INVALID_PARAM.";
    badSource = program "libusb1" ''
      #include <libusb.h>
      int main(void) {
          libusb_context *context = NULL;
          if (libusb_init_context(&context, NULL, 0) != LIBUSB_SUCCESS) return 2;
          int status = libusb_set_option(context, (enum libusb_option)LIBUSB_OPTION_MAX);
          libusb_exit(context);
          return status == LIBUSB_ERROR_INVALID_PARAM ? reject() : 3;
      }
    '';
    includeArguments = ["-I@out@/include/libusb-1.0"];
    libraries = ["-lusb-1.0"];
  };
}
