##! Exercises a fourth H-through-P library slice through deterministic public APIs.
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
    badStderr ? "${package} rejected invalid input\n",
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
              argv = ["@cc@" "primary.c" "-I@out@/include" "-L@out@/lib" "-Wl,-rpath,@out@/lib"] ++ libraries ++ ["-o" "primary-check"];
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
              argv = ["@cc@" "bad-input.c" "-I@out@/include" "-L@out@/lib" "-Wl,-rpath,@out@/lib"] ++ libraries ++ ["-o" "bad-input-check"];
              exit_code = 0;
              stdout.exact = "";
            }
            {
              argv = ["@work@/bad-input/bad-input-check"];
              exit_code = 7;
              stdout.exact = "";
              stderr.exact = badStderr;
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
  libbpf = mkLibraryProbe {
    package = "libbpf";
    primaryInput = "The EINVAL error number and libbpf's compiled version constants.";
    primaryOperation = "Resolve the error text and query the linked library version.";
    primaryExpected = "Libbpf reports Invalid argument and matches its public version constants.";
    primarySource = program "libbpf" ''
      #include <errno.h>
      #include <string.h>
      #include <bpf/libbpf.h>
      #include <bpf/libbpf_version.h>
      int main(void) {
          char message[64] = {0};
          int status = libbpf_strerror(-EINVAL, message, sizeof(message));
          int valid = status == 0 && strcmp(message, "Invalid argument") == 0
              && libbpf_major_version() == LIBBPF_MAJOR_VERSION
              && libbpf_minor_version() == LIBBPF_MINOR_VERSION;
          return valid ? pass() : 2;
      }
    '';
    badInput = "A byte sequence that is not an ELF object.";
    badOperation = "Open the malformed bytes through bpf_object__open_mem.";
    badExpected = "Libbpf returns an error pointer instead of constructing a BPF object.";
    badSource = program "libbpf" ''
      #include <stdarg.h>
      #include <bpf/libbpf.h>
      static int quiet(enum libbpf_print_level level, const char *format, va_list arguments) {
          (void)level; (void)format; (void)arguments;
          return 0;
      }
      int main(void) {
          const char bytes[] = "not an ELF object";
          libbpf_set_print(quiet);
          struct bpf_object *object = bpf_object__open_mem(bytes, sizeof(bytes), NULL);
          long error = libbpf_get_error(object);
          if (error == 0) {
              bpf_object__close(object);
              return 2;
          }
          return reject();
      }
    '';
    libraries = ["-lbpf"];
  };

  libselinux = mkLibraryProbe {
    package = "libselinux";
    primaryInput = "The SELinux context system_u:system_r:init_t:s0.";
    primaryOperation = "Parse the context and inspect each component through the context API.";
    primaryExpected = "Libselinux returns the declared user, role, type, range, and canonical context.";
    primarySource = program "libselinux" ''
      #include <string.h>
      #include <selinux/context.h>
      int main(void) {
          context_t context = context_new("system_u:system_r:init_t:s0");
          if (context == NULL) return 2;
          int valid = strcmp(context_user_get(context), "system_u") == 0
              && strcmp(context_role_get(context), "system_r") == 0
              && strcmp(context_type_get(context), "init_t") == 0
              && strcmp(context_range_get(context), "s0") == 0
              && strcmp(context_str(context), "system_u:system_r:init_t:s0") == 0;
          context_free(context);
          return valid ? pass() : 3;
      }
    '';
    badInput = "A security context containing only one field.";
    badOperation = "Parse the incomplete context through context_new.";
    badExpected = "Libselinux rejects the context by returning null.";
    badSource = program "libselinux" ''
      #include <selinux/context.h>
      int main(void) {
          context_t context = context_new("missing-fields");
          if (context != NULL) {
              context_free(context);
              return 2;
          }
          return reject();
      }
    '';
    libraries = ["-lselinux"];
  };

  libsepol = mkLibraryProbe {
    package = "libsepol";
    primaryInput = "A new policy database configured for the minimum supported kernel policy version.";
    primaryOperation = "Create the database and set its type and version through libsepol.";
    primaryExpected = "Libsepol accepts the kernel policy type and supported version.";
    primarySource = program "libsepol" ''
      #include <sepol/policydb.h>
      int main(void) {
          sepol_policydb_t *policy = NULL;
          if (sepol_policydb_create(&policy) != 0 || policy == NULL) return 2;
          int minimum = sepol_policy_kern_vers_min();
          int maximum = sepol_policy_kern_vers_max();
          int valid = minimum > 0 && maximum >= minimum
              && sepol_policydb_set_typevers(policy, SEPOL_POLICY_KERN) == 0
              && sepol_policydb_set_vers(policy, (unsigned int)minimum) == 0;
          sepol_policydb_free(policy);
          return valid ? pass() : 3;
      }
    '';
    badInput = "A policy database type outside libsepol's declared type set.";
    badOperation = "Apply the unsupported type through sepol_policydb_set_typevers.";
    badExpected = "Libsepol rejects the type with status -1.";
    badSource = program "libsepol" ''
      #include <sepol/policydb.h>
      int main(void) {
          sepol_policydb_t *policy = NULL;
          if (sepol_policydb_create(&policy) != 0 || policy == NULL) return 2;
          int status = sepol_policydb_set_typevers(policy, 99);
          sepol_policydb_free(policy);
          return status == -1 ? reject() : 3;
      }
    '';
    libraries = ["-lsepol"];
  };

  numactl = mkLibraryProbe {
    package = "numactl";
    primaryInput = "An eight-bit NUMA mask with bits one and four selected.";
    primaryOperation = "Allocate, update, and inspect the mask through libnuma.";
    primaryExpected = "Libnuma reports exactly two selected bits at the requested positions.";
    primarySource = program "numactl" ''
      #include <numa.h>
      int main(void) {
          struct bitmask *mask = numa_bitmask_alloc(8);
          if (mask == NULL) return 2;
          numa_bitmask_setbit(mask, 1);
          numa_bitmask_setbit(mask, 4);
          int valid = numa_bitmask_weight(mask) == 2
              && numa_bitmask_isbitset(mask, 1) == 1
              && numa_bitmask_isbitset(mask, 4) == 1;
          numa_bitmask_free(mask);
          return valid ? pass() : 3;
      }
    '';
    badInput = "A NUMA node expression containing words instead of a node range.";
    badOperation = "Parse the malformed expression through numa_parse_nodestring.";
    badExpected = "Libnuma rejects the expression by returning null.";
    badSource = program "numactl" ''
      #include <numa.h>
      int main(void) {
          struct bitmask *mask = numa_parse_nodestring("qualification-invalid");
          if (mask != NULL) {
              numa_bitmask_free(mask);
              return 2;
          }
          return reject();
      }
    '';
    badStderr = "libnuma: Warning: unparseable node description `qualification-invalid'\n\nnumactl rejected invalid input\n";
    libraries = ["-lnuma"];
  };

  openpam = mkLibraryProbe {
    package = "openpam";
    primaryInput = "A PAM configuration line containing a quoted two-word argument and a comment.";
    primaryOperation = "Tokenize the line through openpam_readlinev.";
    primaryExpected = "OpenPAM returns the three logical arguments without the comment.";
    primarySource = program "openpam" ''
      #include <stdlib.h>
      #include <string.h>
      #include <security/pam_appl.h>
      #include <security/openpam.h>
      int main(void) {
          FILE *input = tmpfile();
          if (input == NULL) return 2;
          fputs("alpha 'two words' beta # ignored\n", input);
          rewind(input);
          int line = 0, count = 0;
          char **words = openpam_readlinev(input, &line, &count);
          int valid = words != NULL && line == 1 && count == 3
              && strcmp(words[0], "alpha") == 0
              && strcmp(words[1], "two words") == 0
              && strcmp(words[2], "beta") == 0;
          if (words != NULL) {
              for (int index = 0; index < count; ++index) free(words[index]);
              free(words);
          }
          fclose(input);
          return valid ? pass() : 3;
      }
    '';
    badInput = "A PAM configuration line with an unterminated quoted argument.";
    badOperation = "Tokenize the malformed line through openpam_readlinev.";
    badExpected = "OpenPAM rejects the line by returning null and no arguments.";
    badSource = program "openpam" ''
      #include <stdlib.h>
      #include <security/pam_appl.h>
      #include <security/openpam.h>
      int main(void) {
          FILE *input = tmpfile();
          if (input == NULL) return 2;
          fputs("alpha 'unterminated\n", input);
          rewind(input);
          int line = 0, count = 0;
          char **words = openpam_readlinev(input, &line, &count);
          fclose(input);
          if (words != NULL) {
              for (int index = 0; index < count; ++index) free(words[index]);
              free(words);
              return 3;
          }
          return line == 1 && count == 0 ? reject() : 4;
      }
    '';
    libraries = ["-lpam"];
  };
}
