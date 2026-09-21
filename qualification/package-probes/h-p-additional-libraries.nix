##! Exercises additional H-through-P libraries through deterministic public APIs.
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
  libatomic_ops = mkLibraryProbe {
    package = "libatomic_ops";
    primaryInput = "An atomic word initialized to 41.";
    primaryOperation = "Increment the word through AO_fetch_and_add1 and load it atomically.";
    primaryExpected = "The operation returns the prior value 41 and stores 42.";
    primarySource = program "libatomic_ops" ''
      #include <atomic_ops.h>
      int main(void) {
          volatile AO_t value;
          AO_store(&value, 41);
          AO_t previous = AO_fetch_and_add1(&value);
          return previous == 41 && AO_load(&value) == 42 ? pass() : 2;
      }
    '';
    badInput = "A compare-and-swap whose expected old value differs from the atomic word.";
    badOperation = "Attempt the conditional update through AO_compare_and_swap.";
    badExpected = "The operation reports failure and leaves the word unchanged.";
    badSource = program "libatomic_ops" ''
      #include <atomic_ops.h>
      int main(void) {
          volatile AO_t value;
          AO_store(&value, 42);
          if (AO_compare_and_swap(&value, 41, 99) || AO_load(&value) != 42) return 2;
          return reject();
      }
    '';
    libraries = ["-latomic_ops"];
  };

  "libcap-ng" = mkLibraryProbe {
    package = "libcap-ng";
    primaryInput = "The canonical Linux capability name chown.";
    primaryOperation = "Resolve the name through capng_name_to_capability.";
    primaryExpected = "The API returns the CAP_CHOWN capability number.";
    primarySource = program "libcap-ng" ''
      #include <linux/capability.h>
      #include <cap-ng.h>
      int main(void) {
          return capng_name_to_capability("chown") == CAP_CHOWN ? pass() : 2;
      }
    '';
    badInput = "A capability name absent from Linux's capability registry.";
    badOperation = "Resolve the unknown name through capng_name_to_capability.";
    badExpected = "libcap-ng rejects the name with a negative result.";
    badSource = program "libcap-ng" ''
      #include <cap-ng.h>
      int main(void) {
          if (capng_name_to_capability("qualification_capability_does_not_exist") >= 0) return 2;
          return reject();
      }
    '';
    libraries = ["-lcap-ng"];
  };

  libedit = mkLibraryProbe {
    package = "libedit";
    primaryInput = "A command line containing a quoted two-word argument.";
    primaryOperation = "Tokenize the line through libedit's tok_str interface.";
    primaryExpected = "The tokenizer returns three arguments and preserves the quoted space.";
    primarySource = program "libedit" ''
      #include <string.h>
      #include <histedit.h>
      int main(void) {
          Tokenizer *tokenizer = tok_init(NULL); int count = 0; const char **words = NULL;
          if (tokenizer == NULL) return 2;
          int status = tok_str(tokenizer, "run 'answer 42' now", &count, &words);
          int ok = status == 0 && count == 3 && strcmp(words[1], "answer 42") == 0;
          tok_end(tokenizer);
          return ok ? pass() : 3;
      }
    '';
    badInput = "A command line containing an unterminated single quote.";
    badOperation = "Tokenize the malformed line through tok_str.";
    badExpected = "libedit returns its unmatched-quote status.";
    badSource = program "libedit" ''
      #include <histedit.h>
      int main(void) {
          Tokenizer *tokenizer = tok_init(NULL); int count = 0; const char **words = NULL;
          if (tokenizer == NULL) return 2;
          int status = tok_str(tokenizer, "run 'unterminated", &count, &words);
          tok_end(tokenizer);
          if (status == 0) return 3;
          return reject();
      }
    '';
    libraries = ["-ledit"];
  };

  liblinear = mkLibraryProbe {
    package = "liblinear";
    cxx = true;
    primaryInput = "Two labeled one-dimensional training samples on opposite sides of zero.";
    primaryOperation = "Train a logistic-regression model and classify both samples.";
    primaryExpected = "The fitted model predicts each sample's original label.";
    primarySource = program "liblinear" ''
      #include <linear.h>
      static void discard_training_output(const char *) {}
      int main() {
          feature_node positive[] = {{1, 1.0}, {-1, 0.0}};
          feature_node negative[] = {{1, -1.0}, {-1, 0.0}};
          feature_node *samples[] = {positive, negative};
          double labels[] = {1.0, -1.0};
          problem training = {2, 1, labels, samples, -1.0};
          parameter settings = {};
          settings.solver_type = L2R_LR;
          settings.eps = 0.01;
          settings.C = 1.0;
          settings.p = 0.1;
          settings.nu = 0.5;
          settings.regularize_bias = 1;
          if (check_parameter(&training, &settings) != NULL) return 2;
          set_print_string_function(discard_training_output);
          model *fitted = train(&training, &settings);
          if (fitted == NULL) return 3;
          int ok = predict(fitted, positive) == 1.0 && predict(fitted, negative) == -1.0;
          free_and_destroy_model(&fitted);
          return ok ? pass() : 4;
      }
    '';
    badInput = "A training parameter set with a negative regularization cost.";
    badOperation = "Validate the parameter set through check_parameter.";
    badExpected = "liblinear returns a diagnostic instead of accepting the parameters.";
    badSource = program "liblinear" ''
      #include <linear.h>
      int main() {
          feature_node sample[] = {{1, 1.0}, {-1, 0.0}}; feature_node *samples[] = {sample}; double labels[] = {1.0};
          problem training = {1, 1, labels, samples, -1.0};
          parameter settings = {};
          settings.solver_type = L2R_LR;
          settings.eps = 0.01;
          settings.C = -1.0;
          settings.p = 0.1;
          settings.nu = 0.5;
          settings.regularize_bias = 1;
          if (check_parameter(&training, &settings) == NULL) return 2;
          return reject();
      }
    '';
    libraries = ["-llinear"];
  };

  libmd = mkLibraryProbe {
    package = "libmd";
    primaryInput = "The ASCII string abc for SHA-256 hashing.";
    primaryOperation = "Hash the bytes through libmd's SHA256Data interface.";
    primaryExpected = "The hexadecimal digest matches the standard SHA-256 vector.";
    primarySource = program "libmd" ''
      #include <string.h>
      #include <sha256.h>
      int main(void) {
          char digest[SHA256_DIGEST_STRING_LENGTH];
          const char *result = SHA256Data((const unsigned char *)"abc", 3, digest);
          return result != NULL && strcmp(digest, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0 ? pass() : 2;
      }
    '';
    badInput = "A pathname that does not exist.";
    badOperation = "Hash the missing file through SHA256File.";
    badExpected = "libmd returns a null result instead of a digest.";
    badSource = program "libmd" ''
      #include <sha256.h>
      int main(void) {
          char digest[SHA256_DIGEST_STRING_LENGTH];
          if (SHA256File("missing-qualification-file", digest) != NULL) return 2;
          return reject();
      }
    '';
    libraries = ["-lmd"];
  };

  libmnl = mkLibraryProbe {
    package = "libmnl";
    primaryInput = "A buffer for one Netlink request header.";
    primaryOperation = "Construct the header and validate its declared message length.";
    primaryExpected = "libmnl recognizes the complete header as a valid message.";
    primarySource = program "libmnl" ''
      #include <linux/netlink.h>
      #include <libmnl/libmnl.h>
      int main(void) {
          char buffer[4096] = {0};
          struct nlmsghdr *header = mnl_nlmsg_put_header(buffer);
          header->nlmsg_type = 42;
          return header->nlmsg_len == NLMSG_HDRLEN && mnl_nlmsg_ok(header, header->nlmsg_len) ? pass() : 2;
      }
    '';
    badInput = "A Netlink buffer one byte shorter than its declared header.";
    badOperation = "Validate the truncated length through mnl_nlmsg_ok.";
    badExpected = "libmnl rejects the incomplete message.";
    badSource = program "libmnl" ''
      #include <linux/netlink.h>
      #include <libmnl/libmnl.h>
      int main(void) {
          char buffer[4096] = {0};
          struct nlmsghdr *header = mnl_nlmsg_put_header(buffer);
          if (mnl_nlmsg_ok(header, NLMSG_HDRLEN - 1)) return 2;
          return reject();
      }
    '';
    libraries = ["-lmnl"];
  };

  libnl = mkLibraryProbe {
    package = "libnl";
    primaryInput = "The numeric IPv4 address 127.0.0.1.";
    primaryOperation = "Parse and render the address through libnl's address API.";
    primaryExpected = "The round-tripped address remains 127.0.0.1.";
    primarySource = program "libnl" ''
      #include <arpa/inet.h>
      #include <string.h>
      #include <netlink/addr.h>
      int main(void) {
          struct nl_addr *address = NULL; char output[64];
          if (nl_addr_parse("127.0.0.1", AF_INET, &address) != 0 || address == NULL) return 2;
          const char *rendered = nl_addr2str(address, output, sizeof(output));
          int ok = rendered != NULL && strcmp(rendered, "127.0.0.1") == 0;
          nl_addr_put(address);
          return ok ? pass() : 3;
      }
    '';
    badInput = "An IPv4 address containing an octet above 255.";
    badOperation = "Parse the malformed address through nl_addr_parse.";
    badExpected = "libnl returns a negative parse status and no address.";
    badSource = program "libnl" ''
      #include <arpa/inet.h>
      #include <netlink/addr.h>
      int main(void) {
          struct nl_addr *address = NULL;
          int status = nl_addr_parse("300.1.2.3", AF_INET, &address);
          if (address != NULL) nl_addr_put(address);
          if (status >= 0) return 2;
          return reject();
      }
    '';
    libraries = ["-lnl-3"];
    extraArguments = ["-I@out@/include/libnl3"];
  };

  libtirpc = mkLibraryProbe {
    package = "libtirpc";
    primaryInput = "The unsigned integer 42 encoded into an in-memory XDR stream.";
    primaryOperation = "Encode and decode the value through xdrmem_create and xdr_u_int32_t.";
    primaryExpected = "The decoded integer equals the original value.";
    primarySource = program "libtirpc" ''
      #include <stdint.h>
      #include <rpc/xdr.h>
      int main(void) {
          char buffer[16] = {0}; uint32_t input = 42, output = 0; XDR stream;
          xdrmem_create(&stream, buffer, sizeof(buffer), XDR_ENCODE);
          if (!xdr_u_int32_t(&stream, &input)) return 2;
          unsigned int used = xdr_getpos(&stream); xdr_destroy(&stream);
          xdrmem_create(&stream, buffer, used, XDR_DECODE);
          int ok = xdr_u_int32_t(&stream, &output) && output == input; xdr_destroy(&stream);
          return ok ? pass() : 3;
      }
    '';
    badInput = "An XDR buffer shorter than one encoded 32-bit integer.";
    badOperation = "Decode the truncated stream through xdr_u_int32_t.";
    badExpected = "libtirpc reports decoding failure.";
    badSource = program "libtirpc" ''
      #include <stdint.h>
      #include <rpc/xdr.h>
      int main(void) {
          char buffer[3] = {0}; uint32_t output = 0; XDR stream;
          xdrmem_create(&stream, buffer, sizeof(buffer), XDR_DECODE);
          int accepted = xdr_u_int32_t(&stream, &output); xdr_destroy(&stream);
          if (accepted) return 2;
          return reject();
      }
    '';
    libraries = ["-ltirpc"];
    extraArguments = ["-I@out@/include/tirpc"];
  };

  lmdb = mkLibraryProbe {
    package = "lmdb";
    primaryInput = "The key answer and value 42 in a fresh local LMDB environment.";
    primaryOperation = "Create the database, commit the pair, and read it in a new transaction.";
    primaryExpected = "LMDB returns the exact committed two-byte value.";
    primarySource = program "lmdb" ''
      #include <string.h>
      #include <lmdb.h>
      int main(void) {
          MDB_env *environment = NULL; MDB_txn *transaction = NULL; MDB_dbi database;
          MDB_val key = {6, (void *)"answer"}, value = {2, (void *)"42"}, observed;
          if (mdb_env_create(&environment) != 0 || mdb_env_set_mapsize(environment, 1048576) != 0) return 2;
          if (mdb_env_open(environment, ".", 0, 0600) != 0) return 3;
          if (mdb_txn_begin(environment, NULL, 0, &transaction) != 0 || mdb_dbi_open(transaction, NULL, 0, &database) != 0) return 4;
          if (mdb_put(transaction, database, &key, &value, 0) != 0 || mdb_txn_commit(transaction) != 0) return 5;
          if (mdb_txn_begin(environment, NULL, MDB_RDONLY, &transaction) != 0 || mdb_get(transaction, database, &key, &observed) != 0) return 6;
          int ok = observed.mv_size == 2 && memcmp(observed.mv_data, "42", 2) == 0;
          mdb_txn_abort(transaction); mdb_env_close(environment);
          return ok ? pass() : 8;
      }
    '';
    badInput = "A read-only environment path that does not exist.";
    badOperation = "Open the missing path through mdb_env_open.";
    badExpected = "LMDB returns a nonzero filesystem error.";
    badSource = program "lmdb" ''
      #include <lmdb.h>
      int main(void) {
          MDB_env *environment = NULL;
          if (mdb_env_create(&environment) != 0) return 2;
          int status = mdb_env_open(environment, "missing-qualification-directory", MDB_RDONLY, 0);
          mdb_env_close(environment);
          if (status == 0) return 3;
          return reject();
      }
    '';
    libraries = ["-llmdb"];
  };

  lzo = mkLibraryProbe {
    package = "lzo";
    primaryInput = "A fixed byte string compressed into a bounded LZO1X block.";
    primaryOperation = "Compress and safely decompress the bytes through LZO.";
    primaryExpected = "The recovered bytes equal the original string.";
    primarySource = program "lzo" ''
      #include <string.h>
      #include <lzo/lzo1x.h>
      int main(void) {
          const unsigned char input[] = "AOS qualification"; unsigned char compressed[128], output[128];
          lzo_uint compressed_size = sizeof(compressed), output_size = sizeof(output);
          unsigned char work[LZO1X_1_MEM_COMPRESS];
          if (lzo_init() != LZO_E_OK || lzo1x_1_compress(input, sizeof(input), compressed, &compressed_size, work) != LZO_E_OK) return 2;
          if (lzo1x_decompress_safe(compressed, compressed_size, output, &output_size, NULL) != LZO_E_OK) return 3;
          return output_size == sizeof(input) && memcmp(output, input, sizeof(input)) == 0 ? pass() : 4;
      }
    '';
    badInput = "A truncated LZO block with no complete token sequence.";
    badOperation = "Decode the malformed block through lzo1x_decompress_safe.";
    badExpected = "LZO returns a non-success corruption status.";
    badSource = program "lzo" ''
      #include <lzo/lzo1x.h>
      int main(void) {
          const unsigned char invalid[] = {0xff}; unsigned char output[32]; lzo_uint output_size = sizeof(output);
          if (lzo_init() != LZO_E_OK) return 2;
          if (lzo1x_decompress_safe(invalid, sizeof(invalid), output, &output_size, NULL) == LZO_E_OK) return 3;
          return reject();
      }
    '';
    libraries = ["-llzo2"];
  };

  nettle = mkLibraryProbe {
    package = "nettle";
    primaryInput = "The ASCII string abc for SHA-256 hashing.";
    primaryOperation = "Hash the bytes through Nettle's SHA-256 context API.";
    primaryExpected = "The digest matches the standard SHA-256 vector.";
    primarySource = program "nettle" ''
      #include <string.h>
      #include <nettle/sha2.h>
      int main(void) {
          static const unsigned char expected[32] = {0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
          struct sha256_ctx context; unsigned char digest[32];
          sha256_init(&context); sha256_update(&context, 3, (const uint8_t *)"abc"); sha256_digest(&context, digest);
          return memcmp(digest, expected, sizeof(digest)) == 0 ? pass() : 2;
      }
    '';
    badInput = "A base64 input containing a character outside the alphabet.";
    badOperation = "Decode the malformed bytes through base64_decode_update.";
    badExpected = "Nettle returns false instead of producing decoded bytes.";
    badSource = program "nettle" ''
      #include <nettle/base64.h>
      int main(void) {
          struct base64_decode_ctx context; uint8_t output[8]; size_t output_size = sizeof(output);
          base64_decode_init(&context);
          if (base64_decode_update(&context, &output_size, output, 1, (const uint8_t *)"!")) return 2;
          return reject();
      }
    '';
    libraries = ["-lnettle"];
  };
}
