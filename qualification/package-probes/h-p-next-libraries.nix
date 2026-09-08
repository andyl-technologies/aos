##! Exercises a second H-through-P library slice through deterministic public APIs.
{testing}: let
  mkLibraryProbe = {
    package,
    primaryInput,
    primaryOperation,
    primaryExpected,
    primarySource,
    primaryFiles ? {},
    badInput,
    badOperation,
    badExpected,
    badSource,
    badFiles ? {},
    libraries,
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
          files = primaryFiles // {"primary.c" = primarySource;};
          steps = [
            {
              argv = ["@cc@" "primary.c" "-I@out@/include" "-L@out@/lib" "-Wl,-rpath,@out@/lib"] ++ extraArguments ++ libraries ++ ["-o" "primary-check"];
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
          files = badFiles // {"bad-input.c" = badSource;};
          steps = [
            {
              argv = ["@cc@" "bad-input.c" "-I@out@/include" "-L@out@/lib" "-Wl,-rpath,@out@/lib"] ++ extraArguments ++ libraries ++ ["-o" "bad-input-check"];
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
  krb5 = mkLibraryProbe {
    package = "krb5";
    primaryInput = "The Kerberos principal user/admin in the EXAMPLE.TEST realm.";
    primaryOperation = "Parse and unparse the principal through the krb5 context API.";
    primaryExpected = "The canonical principal text round-trips unchanged.";
    primarySource = program "krb5" ''
      #include <stdlib.h>
      #include <string.h>
      #include <krb5.h>
      int main(void) {
          krb5_context context = NULL; krb5_principal principal = NULL; char *text = NULL;
          if (krb5_init_context(&context) != 0) return 2;
          if (krb5_parse_name(context, "user/admin@EXAMPLE.TEST", &principal) != 0) return 3;
          if (krb5_unparse_name(context, principal, &text) != 0) return 4;
          int ok = strcmp(text, "user/admin@EXAMPLE.TEST") == 0;
          krb5_free_unparsed_name(context, text); krb5_free_principal(context, principal); krb5_free_context(context);
          return ok ? pass() : 5;
      }
    '';
    badInput = "A Kerberos principal with an empty realm.";
    badOperation = "Parse the malformed principal through krb5_parse_name.";
    badExpected = "The Kerberos parser returns a nonzero parse error.";
    badSource = program "krb5" ''
      #include <krb5.h>
      int main(void) {
          krb5_context context = NULL; krb5_principal principal = NULL;
          if (krb5_init_context(&context) != 0) return 2;
          int status = krb5_parse_name(context, "user\\", &principal);
          if (principal != NULL) krb5_free_principal(context, principal);
          krb5_free_context(context);
          if (status == 0) return 3;
          return reject();
      }
    '';
    libraries = ["-lkrb5" "-lk5crypto" "-lcom_err"];
  };

  libaio = mkLibraryProbe {
    package = "libaio";
    primaryInput = "A request for one empty Linux asynchronous-I/O context.";
    primaryOperation = "Create and destroy the context through io_setup and io_destroy.";
    primaryExpected = "The kernel-backed context is created and released successfully.";
    primarySource = program "libaio" ''
      #include <libaio.h>
      int main(void) {
          io_context_t context = 0;
          if (io_setup(1, &context) != 0 || context == 0) return 2;
          return io_destroy(context) == 0 ? pass() : 3;
      }
    '';
    badInput = "A request for an asynchronous-I/O context with zero events.";
    badOperation = "Submit the invalid capacity through io_setup.";
    badExpected = "libaio returns EINVAL without creating a context.";
    badSource = program "libaio" ''
      #include <errno.h>
      #include <libaio.h>
      int main(void) {
          io_context_t context = 0;
          int status = io_setup(0, &context);
          if (status != -EINVAL || context != 0) return 2;
          return reject();
      }
    '';
    libraries = ["-laio"];
  };

  libapparmor = mkLibraryProbe {
    package = "libapparmor";
    primaryInput = "An AppArmor confinement string containing an enforce mode suffix.";
    primaryOperation = "Split the label and mode through aa_splitcon.";
    primaryExpected = "The parser returns the qualification label and enforce mode.";
    primarySource = program "libapparmor" ''
      #include <string.h>
      #include <sys/apparmor.h>
      int main(void) {
          char confinement[] = "qualification (enforce)"; char *mode = NULL;
          char *label = aa_splitcon(confinement, &mode);
          return label != NULL && mode != NULL
              && strcmp(label, "qualification") == 0 && strcmp(mode, "enforce") == 0 ? pass() : 2;
      }
    '';
    badInput = "A feature-directory pathname that does not exist.";
    badOperation = "Open the missing feature description through aa_features_new.";
    badExpected = "Libapparmor rejects the pathname with a nonzero filesystem error.";
    badSource = program "libapparmor" ''
      #include <fcntl.h>
      #include <sys/apparmor.h>
      int main(void) {
          aa_features *features = NULL;
          int status = aa_features_new(&features, AT_FDCWD, "missing-qualification-features");
          if (features != NULL) aa_features_unref(features);
          if (status == 0) return 2;
          return reject();
      }
    '';
    libraries = ["-lapparmor"];
  };

  libbsd = mkLibraryProbe {
    package = "libbsd";
    primaryInput = "The decimal text 42 constrained to the range 0 through 100.";
    primaryOperation = "Parse and range-check the value through strtonum.";
    primaryExpected = "strtonum returns 42 with no diagnostic.";
    primarySource = program "libbsd" ''
      #include <bsd/stdlib.h>
      int main(void) {
          const char *error = NULL;
          long long value = strtonum("42", 0, 100, &error);
          return value == 42 && error == NULL ? pass() : 2;
      }
    '';
    badInput = "A decimal value above the permitted maximum.";
    badOperation = "Parse and range-check the value through strtonum.";
    badExpected = "strtonum rejects the value with the too-large diagnostic.";
    badSource = program "libbsd" ''
      #include <string.h>
      #include <bsd/stdlib.h>
      int main(void) {
          const char *error = NULL;
          (void)strtonum("101", 0, 100, &error);
          if (error == NULL || strcmp(error, "too large") != 0) return 2;
          return reject();
      }
    '';
    libraries = ["-l:libbsd.so.0"];
  };

  "libgpg-error" = mkLibraryProbe {
    package = "libgpg-error";
    primaryInput = "The base64 text NDI= representing the bytes 42.";
    primaryOperation = "Decode the text incrementally through gpgrt's base64 decoder.";
    primaryExpected = "The decoder returns the exact two decoded bytes.";
    primarySource = program "libgpg-error" ''
      #include <string.h>
      #include <gpgrt.h>
      int main(void) {
          char buffer[] = "NDI="; size_t size = 0;
          gpgrt_b64state_t state = gpgrt_b64dec_start(NULL);
          if (state == NULL || gpgrt_b64dec_proc(state, buffer, 4, &size) != 0) return 2;
          if (gpgrt_b64dec_finish(state) != 0) return 3;
          return size == 2 && memcmp(buffer, "42", 2) == 0 ? pass() : 4;
      }
    '';
    badInput = "Base64 text containing characters outside the encoding alphabet.";
    badOperation = "Decode the malformed text through gpgrt's base64 decoder.";
    badExpected = "The decoder reports invalid encoded data.";
    badSource = program "libgpg-error" ''
      #include <gpgrt.h>
      int main(void) {
          char buffer[] = "!!!!"; size_t size = 0;
          gpgrt_b64state_t state = gpgrt_b64dec_start(NULL);
          if (state == NULL) return 2;
          gpg_err_code_t status = gpgrt_b64dec_proc(state, buffer, 4, &size);
          if (status == 0) status = gpgrt_b64dec_finish(state);
          if (status == 0) return 3;
          return reject();
      }
    '';
    libraries = ["-lgpg-error"];
  };

  libtasn1 = mkLibraryProbe {
    package = "libtasn1";
    primaryInput = "An ASN.1 module declaring one integer type.";
    primaryOperation = "Parse the module through asn1_parser2tree.";
    primaryExpected = "libtasn1 builds and releases the definition tree.";
    primaryFiles."schema.asn" = ''
      QUALIFICATION DEFINITIONS EXPLICIT TAGS ::= BEGIN
      Answer ::= INTEGER
      END
    '';
    primarySource = program "libtasn1" ''
      #include <libtasn1.h>
      int main(void) {
          asn1_node definitions = NULL; char error[ASN1_MAX_ERROR_DESCRIPTION_SIZE] = {0};
          int status = asn1_parser2tree("schema.asn", &definitions, error);
          if (status != ASN1_SUCCESS || definitions == NULL) return 2;
          asn1_delete_structure(&definitions);
          return pass();
      }
    '';
    badInput = "An ASN.1 module missing its terminating END declaration.";
    badOperation = "Parse the incomplete module through asn1_parser2tree.";
    badExpected = "libtasn1 returns a syntax error and no usable tree.";
    badFiles."invalid.asn" = ''
      QUALIFICATION DEFINITIONS ::= BEGIN
      Answer ::= INTEGER
    '';
    badSource = program "libtasn1" ''
      #include <libtasn1.h>
      int main(void) {
          asn1_node definitions = NULL; char error[ASN1_MAX_ERROR_DESCRIPTION_SIZE] = {0};
          int status = asn1_parser2tree("invalid.asn", &definitions, error);
          if (definitions != NULL) asn1_delete_structure(&definitions);
          if (status == ASN1_SUCCESS) return 2;
          return reject();
      }
    '';
    libraries = ["-ltasn1"];
  };

  openldap = mkLibraryProbe {
    package = "openldap";
    primaryInput = "An LDAP URL containing a base DN, subtree scope, and equality filter.";
    primaryOperation = "Parse the URL through ldap_url_parse.";
    primaryExpected = "The parsed descriptor preserves the host, DN, scope, and filter.";
    primarySource = program "openldap" ''
      #include <string.h>
      #include <ldap.h>
      int main(void) {
          LDAPURLDesc *description = NULL;
          int status = ldap_url_parse("ldap://example.test/dc=aos,dc=test??sub?(uid=42)", &description);
          int ok = status == LDAP_SUCCESS && description != NULL
              && strcmp(description->lud_host, "example.test") == 0
              && strcmp(description->lud_dn, "dc=aos,dc=test") == 0
              && description->lud_scope == LDAP_SCOPE_SUBTREE
              && strcmp(description->lud_filter, "(uid=42)") == 0;
          if (description != NULL) ldap_free_urldesc(description);
          return ok ? pass() : 2;
      }
    '';
    badInput = "An LDAP URL containing an invalid scope token.";
    badOperation = "Parse the malformed URL through ldap_url_parse.";
    badExpected = "OpenLDAP returns LDAP_URL_ERR_BADSCOPE.";
    badSource = program "openldap" ''
      #include <ldap.h>
      int main(void) {
          LDAPURLDesc *description = NULL;
          int status = ldap_url_parse("ldap://example.test/dc=aos??qualification-scope", &description);
          if (description != NULL) ldap_free_urldesc(description);
          if (status != LDAP_URL_ERR_BADSCOPE) return 2;
          return reject();
      }
    '';
    libraries = ["-lldap" "-llber"];
  };

  npth = mkLibraryProbe {
    package = "npth";
    primaryInput = "A newly initialized NPTH mutex.";
    primaryOperation = "Initialize, lock, unlock, and destroy the mutex.";
    primaryExpected = "Every NPTH synchronization operation succeeds.";
    primarySource = program "npth" ''
      #include <npth.h>
      int main(void) {
          npth_mutex_t mutex;
          if (npth_init() != 0 || npth_mutex_init(&mutex, NULL) != 0) return 2;
          if (npth_mutex_lock(&mutex) != 0 || npth_mutex_unlock(&mutex) != 0) return 3;
          return npth_mutex_destroy(&mutex) == 0 ? pass() : 4;
      }
    '';
    badInput = "A thread detach-state value outside the pthread API's enumeration.";
    badOperation = "Apply the invalid state through npth_attr_setdetachstate.";
    badExpected = "The NPTH attribute API returns EINVAL.";
    badSource = program "npth" ''
      #include <errno.h>
      #include <npth.h>
      int main(void) {
          npth_attr_t attributes;
          if (npth_attr_init(&attributes) != 0) return 2;
          int status = npth_attr_setdetachstate(&attributes, 999999);
          npth_attr_destroy(&attributes);
          if (status != EINVAL) return 3;
          return reject();
      }
    '';
    libraries = ["-lnpth" "-lpthread"];
  };
}
