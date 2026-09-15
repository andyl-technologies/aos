##! libnl — Linux Netlink protocol library suite
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  flex,
  bison,
}: let
  version = "3.12.0";
in
  mkDerivation {
    pname = "libnl";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The round-tripped address remains 127.0.0.1.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libnl primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libnl rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <arpa/inet.h>\n#include <string.h>\n#include <netlink/addr.h>\nint main(void) {\n    struct nl_addr *address = NULL; char output[64];\n    if (nl_addr_parse(\"127.0.0.1\", AF_INET, &address) != 0 || address == NULL) return 2;\n    const char *rendered = nl_addr2str(address, output, sizeof(output));\n    int ok = rendered != NULL && strcmp(rendered, \"127.0.0.1\") == 0;\n    nl_addr_put(address);\n    return ok ? pass() : 3;\n}\n\n";
        };
        "input" = "The numeric IPv4 address 127.0.0.1.";
        "operation" = "Parse and render the address through libnl's address API.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-I@out@/include/libnl3"
              "-lnl-3"
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
              "exact" = "libnl primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "libnl returns a negative parse status and no address.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libnl primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libnl rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <arpa/inet.h>\n#include <netlink/addr.h>\nint main(void) {\n    struct nl_addr *address = NULL;\n    int status = nl_addr_parse(\"300.1.2.3\", AF_INET, &address);\n    if (address != NULL) nl_addr_put(address);\n    if (status >= 0) return 2;\n    return reject();\n}\n\n";
        };
        "input" = "An IPv4 address containing an octet above 255.";
        "operation" = "Parse the malformed address through nl_addr_parse.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-I@out@/include/libnl3"
              "-lnl-3"
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
              "exact" = "libnl rejected invalid input\n";
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
        "https://github.com/thom311/libnl/releases/download/libnl${
          builtins.replaceStrings ["."] ["_"] version
        }/libnl-${version}.tar.gz"
      ];
      hash = "sha256-/FHKcZbxo/X99v/ThktQ9PnAIzO+KL5O7KBX4QPA3Rg=";
    };

    buildDeps = [
      gnumake
      pkg-config
      flex
      bison
    ];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libnl-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out \
            --sysconfdir=$out/etc \
            --enable-shared \
            --disable-static
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
        pname = "lib-libnl";
        library = self;
        includes = ["${self}/include/libnl3"];
        libs = ["-lnl-3"];
        testSource = ''
          #include <netlink/netlink.h>
          #include <netlink/socket.h>
          #include <stdio.h>
          int main() {
            struct nl_sock *sk = nl_socket_alloc();
            if (!sk) return 1;
            nl_socket_free(sk);
            printf("libnl: PASS\n");
            return 0;
          }
        '';
      };
    };

    meta = {
      description = "libnl — Linux Netlink protocol library suite";
      homepage = "https://github.com/thom311/libnl";
      license = "LGPL-2.1-only";
    };
  }
