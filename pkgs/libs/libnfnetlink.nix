##! libnfnetlink — Low-level netfilter netlink communication library
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "1.0.2";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "libnfnetlink";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Libnfnetlink appends the aligned attribute and increases the message length.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libnfnetlink primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libnfnetlink rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <string.h>\n#include <linux/netlink.h>\n#include <libnfnetlink/libnfnetlink.h>\nint main(void) {\n    char storage[64] = {0};\n    struct nlmsghdr *header = (struct nlmsghdr *)storage;\n    header->nlmsg_len = NLMSG_LENGTH(0);\n    int status = nfnl_addattr32(header, sizeof(storage), 1, 42);\n    return status == 0 && header->nlmsg_len == 24 ? pass() : 2;\n}\n\n";
        };
        "input" = "A netlink message buffer with room for one 32-bit attribute.";
        "operation" = "Append attribute type 1 with value 42 through nfnl_addattr32.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lnfnetlink"
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
              "exact" = "libnfnetlink primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Libnfnetlink rejects the attribute with status -1 and preserves the header length.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libnfnetlink primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libnfnetlink rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <string.h>\n#include <linux/netlink.h>\n#include <libnfnetlink/libnfnetlink.h>\nint main(void) {\n    char storage[16] = {0};\n    struct nlmsghdr *header = (struct nlmsghdr *)storage;\n    header->nlmsg_len = NLMSG_LENGTH(0);\n    int status = nfnl_addattr32(header, sizeof(storage), 1, 42);\n    return status == -1 && header->nlmsg_len == 16 ? reject() : 2;\n}\n\n";
        };
        "input" = "A netlink buffer with no room beyond its initial header.";
        "operation" = "Append a 32-bit attribute through nfnl_addattr32.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lnfnetlink"
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
              "exact" = "libnfnetlink rejected invalid input\n";
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
        "https://www.netfilter.org/projects/libnfnetlink/files/libnfnetlink-${version}.tar.bz2"
      ];
      hash = "sha256-sGTHw9Qm77R4bmCo5oWbgu4vLF5J/+6mQM/k/jPLw3Y=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libnfnetlink-${version}
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
        pname = "lib-libnfnetlink";
        library = self;
        libs = ["-lnfnetlink"];
        testSource = ''
          #include <libnfnetlink/libnfnetlink.h>
          #include <stdio.h>
          int main() {
            /* nfnl_open may fail in sandbox; we test symbol resolution */
            struct nfnl_handle *h = nfnl_open();
            if (h) nfnl_close(h);
            printf("libnfnetlink: PASS\n");
            return 0;
          }
        '';
      };
    };

    meta = {
      description = "libnfnetlink — low-level library for netfilter kernel/userspace communication";
      homepage = "https://www.netfilter.org/projects/libnfnetlink/";
      license = "GPL-2.0-only";
    };
  }
