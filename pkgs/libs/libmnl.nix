##! libmnl — Minimalistic Netlink library
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "1.0.5";
in
  mkDerivation {
    pname = "libmnl";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "libmnl recognizes the complete header as a valid message.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libmnl primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libmnl rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <linux/netlink.h>\n#include <libmnl/libmnl.h>\nint main(void) {\n    char buffer[4096] = {0};\n    struct nlmsghdr *header = mnl_nlmsg_put_header(buffer);\n    header->nlmsg_type = 42;\n    return header->nlmsg_len == NLMSG_HDRLEN && mnl_nlmsg_ok(header, header->nlmsg_len) ? pass() : 2;\n}\n\n";
        };
        "input" = "A buffer for one Netlink request header.";
        "operation" = "Construct the header and validate its declared message length.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lmnl"
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
              "exact" = "libmnl primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "libmnl rejects the incomplete message.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libmnl primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libmnl rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <linux/netlink.h>\n#include <libmnl/libmnl.h>\nint main(void) {\n    char buffer[4096] = {0};\n    struct nlmsghdr *header = mnl_nlmsg_put_header(buffer);\n    if (mnl_nlmsg_ok(header, NLMSG_HDRLEN - 1)) return 2;\n    return reject();\n}\n\n";
        };
        "input" = "A Netlink buffer one byte shorter than its declared header.";
        "operation" = "Validate the truncated length through mnl_nlmsg_ok.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lmnl"
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
              "exact" = "libmnl rejected invalid input\n";
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
        "https://www.netfilter.org/projects/libmnl/files/libmnl-${version}.tar.bz2"
      ];
      hash = "sha256-J0ubkZ7zFSv7PaOhPJUN1g1uK81UIw/+yimNA7QNBSU=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libmnl-${version}
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

    checks = {
      testing,
      self,
      pkgs,
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-libmnl";
        library = self;
        libs = ["-lmnl"];
        testSource = ''
          #include <libmnl/libmnl.h>
          #include <stdio.h>
          int main() {
            /* mnl_socket_open may fail in sandbox; we test symbol resolution */
            struct mnl_socket *nl = mnl_socket_open(0);
            if (nl) mnl_socket_close(nl);
            printf("libmnl: PASS\n");
            return 0;
          }
        '';
      };
    };

    meta = {
      description = "libmnl — minimalistic Netlink communication library";
      homepage = "https://www.netfilter.org/projects/libmnl/";
      license = "LGPL-2.1-or-later";
    };
  }
