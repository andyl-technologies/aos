##! libpciaccess — Generic PCI access library
{
  lib,
  mkDerivation,
  fetchurl,
  meson,
  ninja,
  pkg-config,
  hwdata,
  zlib,
}: let
  version = "0.19";
in
  mkDerivation {
    pname = "libpciaccess";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Libpciaccess discovers the platform without an initialization error.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libpciaccess primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libpciaccess rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <pciaccess.h>\nint main(void) {\n    int status = pci_system_init();\n    if (status != 0) return 2;\n    pci_system_cleanup();\n    return pass();\n}\n\n";
        };
        "input" = "The PCI devices exposed by the qualification kernel through sysfs.";
        "operation" = "Initialize and clean up libpciaccess's system backend.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lpciaccess"
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
              "exact" = "libpciaccess primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Libpciaccess reports that no device occupies the address by returning null.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libpciaccess primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libpciaccess rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <pciaccess.h>\nint main(void) {\n    if (pci_system_init() != 0) return 2;\n    struct pci_device *device = pci_device_find_by_slot(0xffff, 0xff, 0x1f, 7);\n    pci_system_cleanup();\n    return device == NULL ? reject() : 3;\n}\n\n";
        };
        "input" = "The impossible PCI address ffff:ff:1f.7.";
        "operation" = "Look up the absent slot through pci_device_find_by_slot.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lpciaccess"
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
              "exact" = "libpciaccess rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = [
        "https://www.x.org/releases/individual/lib/libpciaccess-${version}.tar.xz"
      ];
      hash = "sha256-PFWqhsguVKTjEJeG8EY1MNU7NrbRz9FGFkVPmF3SqkM=";
    };

    buildDeps = [meson ninja pkg-config];
    runtimeDeps = [hwdata zlib];
    propagatedDeps = [zlib];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd libpciaccess-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          meson setup build \
            $mesonFlags \
            --prefix="$out" \
            --libdir=lib \
            -Dzlib=enabled \
            -Dpci-ids="${hwdata}/share/hwdata"
        '';
      }
      {
        name = "build";
        script = ''
          PYTHONPATH="${meson}/lib/python3/site-packages" \
            ninja -C build -j"$NIX_BUILD_CORES"
        '';
      }
      {
        name = "install";
        script = ''
          PYTHONPATH="${meson}/lib/python3/site-packages" \
            ninja -C build install
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-libpciaccess";
        library = self;
        libs = ["-lpciaccess"];
        testSource = ''
          #include <errno.h>
          #include <pciaccess.h>

          int main(void) {
              int status = pci_system_init();
              if (status == 0) pci_system_cleanup();
              return status == 0 || status == EACCES || status == ENOENT ? 0 : 1;
          }
        '';
      };
    };

    meta = {
      description = "Generic PCI access library";
      homepage = "https://gitlab.freedesktop.org/xorg/lib/libpciaccess";
      license = "MIT AND ISC";
    };
  }
