##! fuse3 — Filesystem in Userspace library and mount helper
{
  lib,
  mkDerivation,
  fetchurl,
  meson,
  ninja,
  pkg-config,
  python3,
  util-linux,
}: let
  version = "3.17.4";
in
  mkDerivation {
    pname = "fuse3";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The public API returns the expected result and the consumer prints the fixed success line.";
        "files" = {
          "primary.c" = "#define FUSE_USE_VERSION 35\n#include <stddef.h>\n#include <stdio.h>\n#include <fuse_opt.h>\n\nstruct options { int answer; };\n\nint main(void) {\n    char *arguments[] = {\"probe\", \"--answer=42\"};\n    int count = 2;\n    struct fuse_args args = FUSE_ARGS_INIT(count, arguments);\n    struct options options = {0};\n    const struct fuse_opt specification[] = {\n        {\"--answer=%d\", offsetof(struct options, answer), 0},\n        FUSE_OPT_END,\n    };\n    if (fuse_opt_parse(&args, &options, specification, NULL) != 0 || options.answer != 42) {\n        fuse_opt_free_args(&args);\n        return 2;\n    }\n    fuse_opt_free_args(&args);\n    return puts(\"fuse3 api passed\") == EOF;\n}\n";
        };
        "input" = "A FUSE-style integer option with value 42.";
        "operation" = "Parse the option into an application structure with fuse_opt_parse.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include/fuse3"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lfuse3"
              "-pthread"
              "-o"
              "primary-consumer"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@work@/primary/primary-consumer"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "fuse3 api passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The public API reports rejection and the consumer returns the fixed rejection status.";
        "files" = {
          "bad-input.c" = "#define FUSE_USE_VERSION 35\n#include <stdio.h>\n#include <string.h>\n#include <fuse_opt.h>\n\nstatic int reject_option(void *data, const char *argument, int key, struct fuse_args *outargs) {\n    (void)data;\n    (void)key;\n    (void)outargs;\n    return strcmp(argument, \"--reject\") == 0 ? -1 : 1;\n}\n\nint main(void) {\n    char *arguments[] = {\"probe\", \"--reject\"};\n    int count = 2;\n    struct fuse_args args = FUSE_ARGS_INIT(count, arguments);\n    int status = fuse_opt_parse(&args, NULL, NULL, reject_option);\n    fuse_opt_free_args(&args);\n    if (status == 0) {\n        return 2;\n    }\n    fputs(\"fuse3 rejected invalid input\\n\", stderr);\n    return 7;\n}\n";
        };
        "input" = "An option rejected by the application's FUSE option callback.";
        "operation" = "Parse the option with a callback that rejects that token.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include/fuse3"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lfuse3"
              "-pthread"
              "-o"
              "bad-input-consumer"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@work@/bad-input/bad-input-consumer"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = ["https://github.com/libfuse/libfuse/archive/refs/tags/fuse-${version}.tar.gz"];
      hash = "sha256-3SHRVFwF5zraWUuT/lkzUbfb8QlA/ZO5NLk5VRMQizQ=";
    };

    buildDeps = [meson ninja pkg-config python3];
    runtimeDeps = [util-linux];
    propagatedDeps = [];
    mesonFlags = builtins.concatStringsSep " " [
      "-Duseroot=false"
      "-Dinitscriptdir="
      "-Dexamples=false"
      "-Dtests=false"
      "-Dudevrulesdir=${builtins.placeholder "out"}/lib/udev/rules.d"
    ];

    postPatch = ''
      sed -i         -e "s|/bin/mount|${util-linux}/bin/mount|g"         -e "s|/bin/umount|${util-linux}/bin/umount|g"         lib/mount_util.c
      sed -i "s|/bin/sh|$CONFIG_SHELL|g" util/mount.fuse.c
    '';

    preBuild = ''export PYTHONPATH="${meson}/lib/python3/site-packages"'';
    preInstall = ''export PYTHONPATH="${meson}/lib/python3/site-packages"'';

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "link-fuse3";
        library = self;
        libs = ["-lfuse3"];
        testSource = ''
          #define FUSE_USE_VERSION 35
          #include <fuse3/fuse.h>
          int main(void) {
            return fuse_version() > 0 ? 0 : 1;
          }
        '';
      };
      tool = testing.mkToolCheck {
        pname = "tool-fuse3";
        tool = self;
        command = "fusermount3 --version";
      };
    };

    meta = {
      description = "Reference library and tools for Filesystem in Userspace";
      homepage = "https://github.com/libfuse/libfuse";
      license = "GPL-2.0-only AND LGPL-2.1-only";
    };
  }
