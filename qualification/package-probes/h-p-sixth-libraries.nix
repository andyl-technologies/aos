##! Exercises Linux-PAM state handling through its deterministic public API.
{testing}: let
  program = body: ''
    #include <stdio.h>
    #include <string.h>
    #include <security/pam_appl.h>

    static int conversation(
        int message_count,
        const struct pam_message **messages,
        struct pam_response **responses,
        void *data
    ) {
        (void)message_count;
        (void)messages;
        (void)responses;
        (void)data;
        return PAM_CONV_ERR;
    }

    static int pass(void) {
        return puts("linux-pam primary passed") == EOF;
    }

    static int reject(void) {
        fputs("linux-pam rejected invalid input\n", stderr);
        return 7;
    }

    ${body}
  '';
in {
  linux-pam = testing.mkQualificationPackageProbe {
    name = "linux-pam";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "linux-pam";
      primary = {
        input = "A PAM transaction with the environment entry ANSWER=42.";
        operation = "Create the transaction, store the entry, and retrieve it through the application API.";
        expected = "Linux-PAM preserves the exact environment value.";
        files."primary.c" = program ''
          int main(void) {
              struct pam_conv callback = {conversation, NULL};
              pam_handle_t *handle = NULL;
              int start_status = pam_start("qualification", "user", &callback, &handle);
              if (start_status != PAM_SUCCESS || handle == NULL) return 2;

              int put_status = pam_putenv(handle, "ANSWER=42");
              const char *value = pam_getenv(handle, "ANSWER");
              int valid = put_status == PAM_SUCCESS
                  && value != NULL
                  && strcmp(value, "42") == 0;

              pam_end(handle, PAM_SUCCESS);
              return valid ? pass() : 3;
          }
        '';
        steps = [
          {
            argv = ["@cc@" "primary.c" "-I@out@/include" "-L@out@/lib" "-Wl,-rpath,@out@/lib" "-lpam" "-o" "primary-check"];
            exit_code = 0;
            stdout.exact = "";
          }
          {
            argv = ["@work@/primary/primary-check"];
            exit_code = 0;
            stdout.exact = "linux-pam primary passed\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "A PAM environment assignment whose variable name is empty.";
        operation = "Store the malformed assignment through pam_putenv.";
        expected = "Linux-PAM rejects the entry with PAM_BAD_ITEM.";
        files."bad-input.c" = program ''
          int main(void) {
              struct pam_conv callback = {conversation, NULL};
              pam_handle_t *handle = NULL;
              int start_status = pam_start("qualification", "user", &callback, &handle);
              if (start_status != PAM_SUCCESS || handle == NULL) return 2;

              int status = pam_putenv(handle, "=invalid");
              pam_end(handle, PAM_SUCCESS);
              return status == PAM_BAD_ITEM ? reject() : 3;
          }
        '';
        steps = [
          {
            argv = ["@cc@" "bad-input.c" "-I@out@/include" "-L@out@/lib" "-Wl,-rpath,@out@/lib" "-lpam" "-o" "bad-input-check"];
            exit_code = 0;
            stdout.exact = "";
          }
          {
            argv = ["@work@/bad-input/bad-input-check"];
            exit_code = 7;
            stdout.exact = "";
            stderr.exact = "linux-pam rejected invalid input\n";
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };
}
