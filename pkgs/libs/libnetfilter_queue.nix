##! libnetfilter_queue — Userspace API to packets queued by the kernel packet filter
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  libmnl,
  libnfnetlink,
}: let
  version = "1.0.5";
in
  mkDerivation {
    pname = "libnetfilter_queue";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The packet buffer records the replacement and its mangled state.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libnetfilter_queue primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libnetfilter_queue rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <stdbool.h>\n#include <stdint.h>\n#include <sys/socket.h>\n#include <libnetfilter_queue/pktbuff.h>\nint main(void) {\n    unsigned char packet[20] = {0x45};\n    struct pkt_buff *buffer = pktb_alloc(AF_INET, packet, sizeof(packet), 8);\n    if (buffer == NULL) return 2;\n    int status = pktb_mangle(buffer, 0, 1, 1, \"Z\", 1);\n    int valid = status == 1 && pktb_data(buffer)[1] == 'Z' && pktb_mangled(buffer);\n    pktb_free(buffer);\n    return valid ? pass() : 3;\n}\n\n";
        };
        "input" = "A minimal IPv4 packet buffer whose second byte is replaced with Z.";
        "operation" = "Allocate and modify the packet through pktb_mangle.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lnetfilter_queue"
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
              "exact" = "libnetfilter_queue primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The packet buffer rejects the replacement with status 0.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libnetfilter_queue primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libnetfilter_queue rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <stdbool.h>\n#include <stdint.h>\n#include <sys/socket.h>\n#include <libnetfilter_queue/pktbuff.h>\nint main(void) {\n    unsigned char packet[20] = {0x45};\n    char replacement[100] = {0};\n    struct pkt_buff *buffer = pktb_alloc(AF_INET, packet, sizeof(packet), 8);\n    if (buffer == NULL) return 2;\n    int status = pktb_mangle(buffer, 0, 1, 1, replacement, sizeof(replacement));\n    pktb_free(buffer);\n    return status == 0 ? reject() : 3;\n}\n\n";
        };
        "input" = "A packet replacement larger than the buffer's available tail room.";
        "operation" = "Apply the oversized replacement through pktb_mangle.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lnetfilter_queue"
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
              "exact" = "libnetfilter_queue rejected invalid input\n";
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
        "https://www.netfilter.org/projects/libnetfilter_queue/files/libnetfilter_queue-${version}.tar.bz2"
      ];
      hash = "sha256-+f88ETBdbgPYFAWVe9wRrqGODTFcPj9I2lOiS6JRufU=";
    };

    buildDeps = [
      gnumake
      pkg-config
    ];
    runtimeDeps = [
      libmnl
      libnfnetlink
    ];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libnetfilter_queue-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out \
            --disable-static \
            --enable-shared
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
      description = "libnetfilter_queue — userspace API to packets queued by the kernel packet filter";
      homepage = "https://www.netfilter.org/projects/libnetfilter_queue/";
      license = "GPL-2.0-only";
    };
  }
