##! Exercises additional A-G system libraries without requiring running daemons.
{testing}: let
  mkLibraryProbe = {
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
          expected = "The public API returns the expected result and the consumer prints the fixed success line.";
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
          expected = "The public API reports rejection and the consumer returns the fixed rejection status.";
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
              observes_rejection = true;
            }
          ];
          artifacts = [];
        };
      };
    };
in {
  attr = mkLibraryProbe {
    package = "attr";
    compileArguments = ["-I@out@/include" "-L@out@/lib" "-Wl,-rpath,@out@/lib" "-lattr"];
    primaryInput = "A user extended-attribute name and two-byte value on a regular file.";
    primaryOperation = "Store the attribute with attr_set and retrieve it with attr_get.";
    primarySource = ''
      #include <fcntl.h>
      #include <stdio.h>
      #include <string.h>
      #include <unistd.h>
      #include <attr/attributes.h>

      int main(void) {
          int descriptor = open("target", O_CREAT | O_WRONLY, 0600);
          if (descriptor < 0 || close(descriptor) != 0) {
              return 2;
          }
          if (attr_set("target", "user.aos_probe", "42", 2, 0) != 0) {
              return 3;
          }
          char value[8] = {0};
          int length = sizeof(value);
          if (attr_get("target", "user.aos_probe", value, &length, 0) != 0
              || length != 2 || memcmp(value, "42", 2) != 0) {
              return 4;
          }
          return puts("attr api passed") == EOF;
      }
    '';
    badInput = "An empty extended-attribute name.";
    badInputOperation = "Store a value under the invalid name with attr_set.";
    badInputSource = ''
      #include <fcntl.h>
      #include <stdio.h>
      #include <unistd.h>
      #include <attr/attributes.h>

      int main(void) {
          int descriptor = open("target", O_CREAT | O_WRONLY, 0600);
          if (descriptor < 0 || close(descriptor) != 0) {
              return 2;
          }
          if (attr_set("target", "", "42", 2, 0) == 0) {
              return 3;
          }
          fputs("attr rejected invalid input\n", stderr);
          return 7;
      }
    '';
  };

  dbus = mkLibraryProbe {
    package = "dbus";
    compileArguments = [
      "-I@out@/include/dbus-1.0"
      "-I@out@/lib/dbus-1.0/include"
      "-L@out@/lib"
      "-Wl,-rpath,@out@/lib"
      "-ldbus-1"
    ];
    primaryInput = "A valid bus name, object path, interface, and method name.";
    primaryOperation = "Construct a method-call message and read its routing metadata back.";
    primarySource = ''
      #include <stdio.h>
      #include <string.h>
      #include <dbus/dbus.h>

      int main(void) {
          DBusMessage *message = dbus_message_new_method_call(
              "org.aos.Qualification", "/org/aos/Qualification",
              "org.aos.Qualification", "Probe");
          if (message == NULL
              || strcmp(dbus_message_get_path(message), "/org/aos/Qualification") != 0
              || strcmp(dbus_message_get_member(message), "Probe") != 0) {
              if (message != NULL) dbus_message_unref(message);
              return 2;
          }
          dbus_message_unref(message);
          return puts("dbus api passed") == EOF;
      }
    '';
    badInput = "An object path without the required leading slash.";
    badInputOperation = "Validate the malformed path with dbus_validate_path.";
    badInputSource = ''
      #include <stdio.h>
      #include <dbus/dbus.h>

      int main(void) {
          DBusError error;
          dbus_error_init(&error);
          dbus_bool_t valid = dbus_validate_path("org/aos/invalid", &error);
          if (valid || !dbus_error_is_set(&error)) {
              dbus_error_free(&error);
              return 2;
          }
          dbus_error_free(&error);
          fputs("dbus rejected invalid input\n", stderr);
          return 7;
      }
    '';
  };

  device-mapper = mkLibraryProbe {
    package = "device-mapper";
    compileArguments = ["-I@out@/include" "-L@out@/lib" "-Wl,-rpath,@out@/lib" "-ldevmapper"];
    primaryInput = "A syntactically valid device-mapper name.";
    primaryOperation = "Create an information task and assign the name without contacting the kernel.";
    primarySource = ''
      #include <stdio.h>
      #include <libdevmapper.h>

      int main(void) {
          struct dm_task *task = dm_task_create(DM_DEVICE_INFO);
          if (task == NULL || !dm_task_set_name(task, "aos-qualification")) {
              if (task != NULL) dm_task_destroy(task);
              return 2;
          }
          dm_task_destroy(task);
          return puts("device-mapper api passed") == EOF;
      }
    '';
    badInput = "A device-mapper name containing a slash.";
    badInputOperation = "Assign the invalid name to an information task.";
    badInputSource = ''
      #include <stdio.h>
      #include <libdevmapper.h>

      int main(void) {
          struct dm_task *task = dm_task_create(DM_DEVICE_INFO);
          if (task == NULL) {
              return 2;
          }
          int accepted = dm_task_set_name(task, "invalid/name");
          dm_task_destroy(task);
          if (accepted) {
              return 3;
          }
          fputs("device-mapper rejected invalid input\n", stderr);
          return 7;
      }
    '';
  };

  fuse3 = mkLibraryProbe {
    package = "fuse3";
    compileArguments = ["-I@out@/include/fuse3" "-L@out@/lib" "-Wl,-rpath,@out@/lib" "-lfuse3" "-pthread"];
    primaryInput = "A FUSE-style integer option with value 42.";
    primaryOperation = "Parse the option into an application structure with fuse_opt_parse.";
    primarySource = ''
      #define FUSE_USE_VERSION 35
      #include <stddef.h>
      #include <stdio.h>
      #include <fuse_opt.h>

      struct options { int answer; };

      int main(void) {
          char *arguments[] = {"probe", "--answer=42"};
          int count = 2;
          struct fuse_args args = FUSE_ARGS_INIT(count, arguments);
          struct options options = {0};
          const struct fuse_opt specification[] = {
              {"--answer=%d", offsetof(struct options, answer), 0},
              FUSE_OPT_END,
          };
          if (fuse_opt_parse(&args, &options, specification, NULL) != 0 || options.answer != 42) {
              fuse_opt_free_args(&args);
              return 2;
          }
          fuse_opt_free_args(&args);
          return puts("fuse3 api passed") == EOF;
      }
    '';
    badInput = "An option rejected by the application's FUSE option callback.";
    badInputOperation = "Parse the option with a callback that rejects that token.";
    badInputSource = ''
      #define FUSE_USE_VERSION 35
      #include <stdio.h>
      #include <string.h>
      #include <fuse_opt.h>

      static int reject_option(void *data, const char *argument, int key, struct fuse_args *outargs) {
          (void)data;
          (void)key;
          (void)outargs;
          return strcmp(argument, "--reject") == 0 ? -1 : 1;
      }

      int main(void) {
          char *arguments[] = {"probe", "--reject"};
          int count = 2;
          struct fuse_args args = FUSE_ARGS_INIT(count, arguments);
          int status = fuse_opt_parse(&args, NULL, NULL, reject_option);
          fuse_opt_free_args(&args);
          if (status == 0) {
              return 2;
          }
          fputs("fuse3 rejected invalid input\n", stderr);
          return 7;
      }
    '';
  };
}
