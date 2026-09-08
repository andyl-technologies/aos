##! Exercises a seventh H-through-P C library slice through public APIs.
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
    primaryFiles ? {},
    badFiles ? {},
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
          files = primaryFiles // {"primary.c" = primarySource;};
          steps = [
            {
              argv = ["@python@" "-c" (compile "primary.c" "primary-check" libraries)];
              exit_code = 0;
              stdout.exact = "";
              stderr.exact = "";
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
          files = badFiles // {"bad-input.c" = badSource;};
          steps = [
            {
              argv = ["@python@" "-c" (compile "bad-input.c" "bad-input-check" libraries)];
              exit_code = 0;
              stdout.exact = "";
              stderr.exact = "";
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

  compile = source: output: libraries: ''
    import json, os, pathlib, subprocess
    closure = json.loads(os.environ["AOS_QUALIFICATION_PACKAGE_CLOSURE"])
    command = ["@cc@", ${builtins.toJSON source}]
    for root_text in closure:
        root = pathlib.Path(root_text)
        include = root / "include"
        library = root / "lib"
        if include.is_dir():
            command.append("-I" + str(include))
        for nested in (root / "include/glib-2.0", root / "lib/glib-2.0/include"):
            if nested.is_dir():
                command.append("-I" + str(nested))
        if library.is_dir():
            command.extend(["-L" + str(library), "-Wl,-rpath," + str(library)])
    command.extend(${builtins.toJSON libraries} + ["-o", ${builtins.toJSON output}])
    result = subprocess.run(command, capture_output=True, text=True)
    assert result.returncode == 0, (result.returncode, result.stdout, result.stderr)
  '';

  program = package: body: ''
    #include <stdio.h>

    static int pass(void) {
        return puts("${package} primary passed") == EOF;
    }

    static int reject(void) {
        fputs("${package} rejected invalid input\n", stderr);
        return 7;
    }

    ${body}
  '';
in {
  libassuan = mkLibraryProbe {
    package = "libassuan";
    primaryInput = "A newly allocated Assuan context.";
    primaryOperation = "Create and release it through the public context API.";
    primaryExpected = "Libassuan returns a usable context without an error.";
    primarySource = program "libassuan" ''
      #include <assuan.h>

      int main(void) {
          assuan_context_t context = NULL;
          gpg_error_t status = assuan_new(&context);
          int valid = status == 0 && context != NULL;
          if (context != NULL) assuan_release(context);
          return valid ? pass() : 2;
      }
    '';
    badInput = "A request to connect to a Unix socket path that does not exist.";
    badOperation = "Open the missing endpoint through assuan_socket_connect.";
    badExpected = "Libassuan returns an error instead of establishing a connection.";
    badSource = program "libassuan" ''
      #include <assuan.h>

      int main(void) {
          assuan_context_t context = NULL;
          if (assuan_new(&context) != 0 || context == NULL) return 2;
          gpg_error_t status = assuan_socket_connect(
              context,
              "missing-qualification.sock",
              ASSUAN_INVALID_PID,
              0
          );
          assuan_release(context);
          return status != 0 ? reject() : 3;
      }
    '';
    libraries = ["-lassuan" "-lgpg-error"];
  };

  libksba = mkLibraryProbe {
    package = "libksba";
    primaryInput = "An in-memory KSBA reader containing the bytes answer=42.";
    primaryOperation = "Create the reader, assign its memory, and read the bytes back.";
    primaryExpected = "KSBA returns the exact eight-byte payload.";
    primarySource = program "libksba" ''
      #include <string.h>
      #include <ksba.h>

      int main(void) {
          const char input[] = "answer=42";
          char output[sizeof(input)] = {0};
          size_t read_count = 0;
          ksba_reader_t reader = NULL;
          if (ksba_reader_new(&reader) != 0 || reader == NULL) return 2;
          if (ksba_reader_set_mem(reader, input, sizeof(input) - 1) != 0) return 3;
          gpg_error_t status = ksba_reader_read(reader, output, sizeof(input) - 1, &read_count);
          int valid = status == 0
              && read_count == sizeof(input) - 1
              && memcmp(input, output, read_count) == 0;
          ksba_reader_release(reader);
          return valid ? pass() : 4;
      }
    '';
    badInput = "A short text payload that is not a DER certificate.";
    badOperation = "Read it through KSBA's DER certificate parser.";
    badExpected = "KSBA returns a parse error for the malformed certificate.";
    badSource = program "libksba" ''
      #include <stdio.h>
      #include <unistd.h>
      #include <ksba.h>

      int main(void) {
          const char input[] = "not DER";
          ksba_reader_t reader = NULL;
          ksba_cert_t certificate = NULL;
          if (ksba_reader_new(&reader) != 0 || reader == NULL) return 2;
          if (ksba_reader_set_mem(reader, input, sizeof(input) - 1) != 0) return 3;
          if (ksba_cert_new(&certificate) != 0 || certificate == NULL) return 4;

          int saved_stderr = dup(fileno(stderr));
          FILE *discard = fopen("/dev/null", "w");
          if (saved_stderr < 0 || discard == NULL) return 5;
          if (dup2(fileno(discard), fileno(stderr)) < 0) return 6;
          gpg_error_t status = ksba_cert_read_der(certificate, reader);
          fflush(stderr);
          if (dup2(saved_stderr, fileno(stderr)) < 0) return 8;
          close(saved_stderr);
          fclose(discard);

          ksba_cert_release(certificate);
          ksba_reader_release(reader);
          return status != 0 ? reject() : 9;
      }
    '';
    libraries = ["-lksba" "-lgpg-error"];
  };

  libnetfilter_conntrack = mkLibraryProbe {
    package = "libnetfilter_conntrack";
    primaryInput = "A connection-tracking object with IPv4 source 192.0.2.1 and TCP source port 4242.";
    primaryOperation = "Set and retrieve both attributes through libnetfilter_conntrack.";
    primaryExpected = "The object preserves the exact address and port values.";
    primarySource = program "libnetfilter_conntrack" ''
      #include <arpa/inet.h>
      #include <stdint.h>
      #include <libnetfilter_conntrack/libnetfilter_conntrack.h>

      int main(void) {
          struct nf_conntrack *connection = nfct_new();
          if (connection == NULL) return 2;
          uint32_t address = inet_addr("192.0.2.1");
          uint16_t port = htons(4242);
          nfct_set_attr_u32(connection, ATTR_IPV4_SRC, address);
          nfct_set_attr_u16(connection, ATTR_PORT_SRC, port);
          int valid = nfct_get_attr_u32(connection, ATTR_IPV4_SRC) == address
              && nfct_get_attr_u16(connection, ATTR_PORT_SRC) == port;
          nfct_destroy(connection);
          return valid ? pass() : 3;
      }
    '';
    badInput = "An object-option selector beyond libnetfilter_conntrack's public range.";
    badOperation = "Apply the unsupported option through nfct_setobjopt.";
    badExpected = "Libnetfilter_conntrack returns a negative option-validation status.";
    badSource = program "libnetfilter_conntrack" ''
      #include <libnetfilter_conntrack/libnetfilter_conntrack.h>

      int main(void) {
          struct nf_conntrack *connection = nfct_new();
          if (connection == NULL) return 2;
          int status = nfct_setobjopt(connection, NFCT_SOPT_MAX + 1);
          nfct_destroy(connection);
          return status < 0 ? reject() : 3;
      }
    '';
    libraries = ["-lnetfilter_conntrack" "-lmnl"];
  };

  libnetfilter_cttimeout = mkLibraryProbe {
    package = "libnetfilter_cttimeout";
    primaryInput = "A TCP timeout policy named qualification with IPv4 protocol metadata.";
    primaryOperation = "Populate and render it through libnetfilter_cttimeout.";
    primaryExpected = "The rendered policy contains the declared name and protocol values.";
    primarySource = program "libnetfilter_cttimeout" ''
      #include <netinet/in.h>
      #include <string.h>
      #include <libnetfilter_cttimeout/libnetfilter_cttimeout.h>

      int main(void) {
          struct nfct_timeout *timeout = nfct_timeout_alloc();
          char output[256] = {0};
          if (timeout == NULL) return 2;
          int status = nfct_timeout_attr_set(timeout, NFCT_TIMEOUT_ATTR_NAME, "qualification");
          status |= nfct_timeout_attr_set_u16(timeout, NFCT_TIMEOUT_ATTR_L3PROTO, AF_INET);
          status |= nfct_timeout_attr_set_u8(timeout, NFCT_TIMEOUT_ATTR_L4PROTO, IPPROTO_TCP);
          int written = nfct_timeout_snprintf(output, sizeof(output), timeout, NFCT_TIMEOUT_O_DEFAULT, 0);
          int valid = status == 0
              && written > 0
              && strstr(output, ".qualification") != NULL
              && strstr(output, ".l3proto = 2") != NULL
              && strstr(output, ".l4proto = 6") != NULL;
          nfct_timeout_free(timeout);
          return valid ? pass() : 3;
      }
    '';
    badInput = "A timeout-state lookup using the unsupported transport protocol zero.";
    badOperation = "Resolve the state through nfct_timeout_policy_attr_to_name.";
    badExpected = "Libnetfilter_cttimeout rejects the protocol by returning null.";
    badSource = program "libnetfilter_cttimeout" ''
      #include <stdio.h>
      #include <unistd.h>
      #include <libnetfilter_cttimeout/libnetfilter_cttimeout.h>

      int main(void) {
          int saved_stderr = dup(fileno(stderr));
          int saved_stdout = dup(fileno(stdout));
          FILE *discard = fopen("/dev/null", "w");
          if (saved_stderr < 0 || saved_stdout < 0 || discard == NULL) return 2;
          if (dup2(fileno(discard), fileno(stderr)) < 0) return 3;
          if (dup2(fileno(discard), fileno(stdout)) < 0) return 4;
          const char *name = nfct_timeout_policy_attr_to_name(0, 0);
          fflush(stderr);
          fflush(stdout);
          if (dup2(saved_stderr, fileno(stderr)) < 0) return 5;
          if (dup2(saved_stdout, fileno(stdout)) < 0) return 6;
          close(saved_stderr);
          close(saved_stdout);
          fclose(discard);
          return name == NULL ? reject() : 8;
      }
    '';
    libraries = ["-lnetfilter_cttimeout" "-lmnl"];
  };

  libsemanage = mkLibraryProbe {
    package = "libsemanage";
    primaryInput = "A disconnected SELinux management handle and module priority 42.";
    primaryOperation = "Set and retrieve the default priority through libsemanage.";
    primaryExpected = "The handle preserves priority 42.";
    primarySource = program "libsemanage" ''
      #include <semanage/handle.h>

      int main(void) {
          semanage_handle_t *handle = semanage_handle_create();
          if (handle == NULL) return 2;
          int status = semanage_set_default_priority(handle, 42);
          int valid = status == 0 && semanage_get_default_priority(handle) == 42;
          semanage_handle_destroy(handle);
          return valid ? pass() : 3;
      }
    '';
    badInput = "Module priority zero, outside libsemanage's supported range.";
    badOperation = "Set the invalid default priority.";
    badExpected = "Libsemanage rejects the out-of-range priority.";
    badSource = program "libsemanage" ''
      #include <stdio.h>
      #include <unistd.h>
      #include <semanage/handle.h>

      int main(void) {
          semanage_handle_t *handle = semanage_handle_create();
          if (handle == NULL) return 2;

          int saved_stderr = dup(fileno(stderr));
          FILE *discard = fopen("/dev/null", "w");
          if (saved_stderr < 0 || discard == NULL) return 3;
          if (dup2(fileno(discard), fileno(stderr)) < 0) return 4;
          int status = semanage_set_default_priority(handle, 0);
          fflush(stderr);
          if (dup2(saved_stderr, fileno(stderr)) < 0) return 5;
          close(saved_stderr);
          fclose(discard);

          semanage_handle_destroy(handle);
          return status < 0 ? reject() : 6;
      }
    '';
    libraries = ["-lsemanage" "-lsepol"];
  };

  liburcu = mkLibraryProbe {
    package = "liburcu";
    primaryInput = "Two initialized nodes pushed onto a lock-free stack.";
    primaryOperation = "Push and pop them through liburcu's blocking stack API.";
    primaryExpected = "The stack returns the nodes in last-in, first-out order.";
    primarySource = program "liburcu" ''
      #include <urcu/lfstack.h>

      int main(void) {
          struct cds_lfs_stack stack;
          struct cds_lfs_node first;
          struct cds_lfs_node second;
          cds_lfs_init(&stack);
          cds_lfs_node_init(&first);
          cds_lfs_node_init(&second);
          cds_lfs_push(&stack, &first);
          cds_lfs_push(&stack, &second);
          struct cds_lfs_node *popped_second = cds_lfs_pop_blocking(&stack);
          struct cds_lfs_node *popped_first = cds_lfs_pop_blocking(&stack);
          int valid = popped_second == &second && popped_first == &first;
          cds_lfs_destroy(&stack);
          return valid ? pass() : 2;
      }
    '';
    badInput = "A pop request on an empty initialized stack.";
    badOperation = "Pop the absent node through the blocking stack API.";
    badExpected = "Liburcu rejects the empty input by returning null.";
    badSource = program "liburcu" ''
      #include <stddef.h>
      #include <urcu/lfstack.h>

      int main(void) {
          struct cds_lfs_stack stack;
          cds_lfs_init(&stack);
          struct cds_lfs_node *node = cds_lfs_pop_blocking(&stack);
          cds_lfs_destroy(&stack);
          return node == NULL ? reject() : 2;
      }
    '';
    libraries = ["-lurcu-cds" "-lurcu-common" "-lpthread"];
  };

  lksctp-tools = mkLibraryProbe {
    package = "lksctp-tools";
    primaryInput = "The IPv4 and IPv6 address-family selectors.";
    primaryOperation = "Resolve their socket address lengths through sctp_getaddrlen.";
    primaryExpected = "Lksctp reports the platform's sockaddr_in and sockaddr_in6 sizes.";
    primarySource = program "lksctp-tools" ''
      #include <sys/socket.h>
      #include <netinet/in.h>
      #include <netinet/sctp.h>

      int main(void) {
          int ipv4_length = sctp_getaddrlen(AF_INET);
          int ipv6_length = sctp_getaddrlen(AF_INET6);
          return ipv4_length == sizeof(struct sockaddr_in)
              && ipv6_length == sizeof(struct sockaddr_in6) ? pass() : 2;
      }
    '';
    badInput = "The unspecified address family, which cannot identify an SCTP socket address.";
    badOperation = "Resolve its address length through sctp_getaddrlen.";
    badExpected = "Lksctp rejects the unsupported family by returning zero.";
    badSource = program "lksctp-tools" ''
      #include <sys/socket.h>
      #include <netinet/sctp.h>

      int main(void) {
          return sctp_getaddrlen(AF_UNSPEC) == 0 ? reject() : 2;
      }
    '';
    libraries = ["-lsctp"];
  };

  mpfr = mkLibraryProbe {
    package = "mpfr";
    primaryInput = "The decimal value 42.5 at 128-bit precision.";
    primaryOperation = "Parse and compare it through MPFR.";
    primaryExpected = "MPFR stores a value exactly equal to 42.5.";
    primarySource = program "mpfr" ''
      #include <mpfr.h>

      int main(void) {
          mpfr_t value;
          mpfr_init2(value, 128);
          int status = mpfr_set_str(value, "42.5", 10, MPFR_RNDN);
          int valid = status == 0 && mpfr_cmp_d(value, 42.5) == 0;
          mpfr_clear(value);
          return valid ? pass() : 2;
      }
    '';
    badInput = "The text not-a-number.";
    badOperation = "Parse it through mpfr_set_str.";
    badExpected = "MPFR returns a nonzero conversion status.";
    badSource = program "mpfr" ''
      #include <mpfr.h>

      int main(void) {
          mpfr_t value;
          mpfr_init2(value, 128);
          int status = mpfr_set_str(value, "not-a-number", 10, MPFR_RNDN);
          mpfr_clear(value);
          return status != 0 ? reject() : 2;
      }
    '';
    libraries = ["-lmpfr" "-lgmp"];
  };
}
