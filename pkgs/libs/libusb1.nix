##! libusb1 — userspace USB device access library
{
  lib,
  mkDerivation,
  mkGithubUpstream,
  gnumake,
  stdenv,
}: let
  upstream = mkGithubUpstream {
    unitId = "libusb-1";
    family = "libusb";
    member = "libusb1";
    stream = "1";
    owner = "pkgs/libs/libusb1.nix";
    version = "1.0.30";
    upstreamId = "v1.0.30";
    repository = "libusb/libusb";
    provider = "github-releases";
    tagPrefix = "v";
    major = 1;
    source = {
      authority = "github.com";
      path = [
        "libusb"
        "libusb"
        "releases"
        "download"
        {
          parts = [
            {literal = "v";}
            {
              componentField = {
                component = "main";
                field = "comparisonVersion";
              };
            }
          ];
        }
        {
          parts = [
            {literal = "libusb-";}
            {
              componentField = {
                component = "main";
                field = "comparisonVersion";
              };
            }
            {literal = ".tar.bz2";}
          ];
        }
      ];
      hash = "sha256-/qNvNPkVZAAglZXjAIQHZ6saOF7eHcfuiTAVrqnG268=";
    };
  };
  inherit (upstream) version;
in
  mkDerivation {
    pname = "libusb1";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Libusb creates the isolated context without accessing USB devices.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libusb1 primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libusb1 rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <libusb.h>\nint main(void) {\n    libusb_context *context = NULL;\n    struct libusb_init_option option = {.option = LIBUSB_OPTION_NO_DEVICE_DISCOVERY};\n    int status = libusb_init_context(&context, &option, 1);\n    if (status != LIBUSB_SUCCESS || context == NULL) return 2;\n    libusb_exit(context);\n    return pass();\n}\n\n";
        };
        "input" = "A libusb context configured to skip device discovery.";
        "operation" = "Initialize and release the context through libusb_init_context.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-I@out@/include/libusb-1.0"
              "-lusb-1.0"
              "-o"
              "primary-check"
            ];
            "exit_code" = 0;
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@work@/primary/primary-check"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "libusb1 primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Libusb returns LIBUSB_ERROR_INVALID_PARAM.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libusb1 primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libusb1 rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <libusb.h>\nint main(void) {\n    libusb_context *context = NULL;\n    if (libusb_init_context(&context, NULL, 0) != LIBUSB_SUCCESS) return 2;\n    int status = libusb_set_option(context, (enum libusb_option)LIBUSB_OPTION_MAX);\n    libusb_exit(context);\n    return status == LIBUSB_ERROR_INVALID_PARAM ? reject() : 3;\n}\n\n";
        };
        "input" = "An option identifier at the exclusive upper bound of libusb's option enum.";
        "operation" = "Apply the unsupported option through libusb_set_option.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-I@out@/include/libusb-1.0"
              "-lusb-1.0"
              "-o"
              "bad-input-check"
            ];
            "exit_code" = 0;
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@work@/bad-input/bad-input-check"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "libusb1 rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;

    src = upstream.components.main.sources.source;
    update = upstream.update;

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf $src
            cd libusb-${version}
          '';
        }
      ]
      ++ (
        if stdenv.isCross && stdenv.hostPlatform.isDarwin
        then [
          {
            name = "darwin-build-paths";
            script = ''
              export CFLAGS="$CFLAGS \
                -ffile-prefix-map=$PWD=. \
                -fdebug-prefix-map=$PWD=."
            '';
          }
        ]
        else []
      )
      ++ [
        {
          # --disable-udev: we don't link libudev, so hotplug notifications are
          # unavailable, but device enumeration via sysfs still works — which is
          # all GnuPG's scdaemon internal CCID driver needs to find a card reader.
          name = "configure";
          script = ''
            ./configure \
              $configureFlags \
              --prefix=$out \
              --disable-static \
              --disable-udev
          '';
        }
        {
          name = "build";
          script = ''
            make -j$NIX_BUILD_CORES
          '';
        }
        {
          name = "install";
          script = ''
            make install
          '';
        }
      ];

    meta = {
      description = "Userspace library for accessing USB devices";
      homepage = "https://libusb.info/";
      license = "LGPL-2.1-or-later";
    };
  }
