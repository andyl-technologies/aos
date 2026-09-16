##! libnftnl — Netfilter nf_tables userspace library
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  libmnl,
}: let
  version = "1.3.2";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "libnftnl";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The table object preserves its family and name attributes.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libnftnl primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libnftnl rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <string.h>\n#include <libnftnl/table.h>\nint main(void) {\n    struct nftnl_table *table = nftnl_table_alloc();\n    if (table == NULL) return 2;\n    nftnl_table_set_u32(table, NFTNL_TABLE_FAMILY, 2);\n    int status = nftnl_table_set_str(table, NFTNL_TABLE_NAME, \"qualification\");\n    int valid = status == 0 && nftnl_table_get_u32(table, NFTNL_TABLE_FAMILY) == 2\n        && strcmp(nftnl_table_get_str(table, NFTNL_TABLE_NAME), \"qualification\") == 0;\n    nftnl_table_free(table);\n    return valid ? pass() : 3;\n}\n\n";
        };
        "input" = "An nftables table named qualification in the IPv4 family.";
        "operation" = "Set and retrieve table attributes through libnftnl.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lnftnl"
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
              "exact" = "libnftnl primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Libnftnl returns a negative parse status.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libnftnl primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libnftnl rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <libnftnl/table.h>\nint main(void) {\n    struct nftnl_table *table = nftnl_table_alloc();\n    struct nftnl_parse_err *error = nftnl_parse_err_alloc();\n    if (table == NULL || error == NULL) return 2;\n    int status = nftnl_table_parse(table, NFTNL_PARSE_JSON, \"not JSON\", error);\n    nftnl_parse_err_free(error);\n    nftnl_table_free(table);\n    return status < 0 ? reject() : 3;\n}\n\n";
        };
        "input" = "Text that is not an nftables JSON document.";
        "operation" = "Parse the malformed text through nftnl_table_parse.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lnftnl"
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
              "exact" = "libnftnl rejected invalid input\n";
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
        "https://www.netfilter.org/projects/libnftnl/files/libnftnl-${version}.tar.xz"
      ];
      hash = "sha256-yXq8NAn4+jlrRGKyu38UejpHpN3JfPoLLxiJDJz96LA=";
    };

    buildDeps = [
      gnumake
      pkg-config
    ];
    runtimeDeps = [libmnl];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libnftnl-${version}
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
        pname = "lib-libnftnl";
        library = self;
        libs = [
          "-lnftnl"
          "-lmnl"
        ];
        extraDeps = [pkgs.libmnl];
        testSource = ''
          #include <libnftnl/table.h>
          #include <stdio.h>
          int main() {
            struct nftnl_table *t = nftnl_table_alloc();
            if (!t) return 1;
            nftnl_table_free(t);
            printf("libnftnl: PASS\n");
            return 0;
          }
        '';
      };
    };

    meta = {
      description = "libnftnl — userspace library for nf_tables Netlink communication";
      homepage = "https://www.netfilter.org/projects/libnftnl/";
      license = "GPL-2.0-or-later";
    };
  }
