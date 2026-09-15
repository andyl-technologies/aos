##! libnetfilter_conntrack — Userspace library for in-kernel connection tracking
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  libmnl,
  libnfnetlink,
}: let
  version = "1.1.1";
in
  mkDerivation {
    pname = "libnetfilter_conntrack";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The object preserves the exact address and port values.";
        "files" = {
          "primary.c" = "#include <stdio.h>\n\nstatic int pass(void) {\n    return puts(\"libnetfilter_conntrack primary passed\") == EOF;\n}\n\nstatic int reject(void) {\n    fputs(\"libnetfilter_conntrack rejected invalid input\\n\", stderr);\n    return 7;\n}\n\n#include <arpa/inet.h>\n#include <stdint.h>\n#include <libnetfilter_conntrack/libnetfilter_conntrack.h>\n\nint main(void) {\n    struct nf_conntrack *connection = nfct_new();\n    if (connection == NULL) return 2;\n    uint32_t address = inet_addr(\"192.0.2.1\");\n    uint16_t port = htons(4242);\n    nfct_set_attr_u32(connection, ATTR_IPV4_SRC, address);\n    nfct_set_attr_u16(connection, ATTR_PORT_SRC, port);\n    int valid = nfct_get_attr_u32(connection, ATTR_IPV4_SRC) == address\n        && nfct_get_attr_u16(connection, ATTR_PORT_SRC) == port;\n    nfct_destroy(connection);\n    return valid ? pass() : 3;\n}\n\n";
        };
        "input" = "A connection-tracking object with IPv4 source 192.0.2.1 and TCP source port 4242.";
        "operation" = "Set and retrieve both attributes through libnetfilter_conntrack.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, os, pathlib, subprocess\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ncommand = [\"@cc@\", \"primary.c\"]\nfor root_text in closure:\n    root = pathlib.Path(root_text)\n    include = root / \"include\"\n    library = root / \"lib\"\n    if include.is_dir():\n        command.append(\"-I\" + str(include))\n    for nested in (root / \"include/glib-2.0\", root / \"lib/glib-2.0/include\"):\n        if nested.is_dir():\n            command.append(\"-I\" + str(nested))\n    if library.is_dir():\n        command.extend([\"-L\" + str(library), \"-Wl,-rpath,\" + str(library)])\ncommand.extend([\"-lnetfilter_conntrack\",\"-lmnl\"] + [\"-o\", \"primary-check\"])\nresult = subprocess.run(command, capture_output=True, text=True)\nassert result.returncode == 0, (result.returncode, result.stdout, result.stderr)\n"
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
              "@work@/primary/primary-check"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "libnetfilter_conntrack primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Libnetfilter_conntrack returns a negative option-validation status.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\n\nstatic int pass(void) {\n    return puts(\"libnetfilter_conntrack primary passed\") == EOF;\n}\n\nstatic int reject(void) {\n    fputs(\"libnetfilter_conntrack rejected invalid input\\n\", stderr);\n    return 7;\n}\n\n#include <libnetfilter_conntrack/libnetfilter_conntrack.h>\n\nint main(void) {\n    struct nf_conntrack *connection = nfct_new();\n    if (connection == NULL) return 2;\n    int status = nfct_setobjopt(connection, NFCT_SOPT_MAX + 1);\n    nfct_destroy(connection);\n    return status < 0 ? reject() : 3;\n}\n\n";
        };
        "input" = "An object-option selector beyond libnetfilter_conntrack's public range.";
        "operation" = "Apply the unsupported option through nfct_setobjopt.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, os, pathlib, subprocess\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ncommand = [\"@cc@\", \"bad-input.c\"]\nfor root_text in closure:\n    root = pathlib.Path(root_text)\n    include = root / \"include\"\n    library = root / \"lib\"\n    if include.is_dir():\n        command.append(\"-I\" + str(include))\n    for nested in (root / \"include/glib-2.0\", root / \"lib/glib-2.0/include\"):\n        if nested.is_dir():\n            command.append(\"-I\" + str(nested))\n    if library.is_dir():\n        command.extend([\"-L\" + str(library), \"-Wl,-rpath,\" + str(library)])\ncommand.extend([\"-lnetfilter_conntrack\",\"-lmnl\"] + [\"-o\", \"bad-input-check\"])\nresult = subprocess.run(command, capture_output=True, text=True)\nassert result.returncode == 0, (result.returncode, result.stdout, result.stderr)\n"
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
              "@work@/bad-input/bad-input-check"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "libnetfilter_conntrack rejected invalid input\n";
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
        "https://netfilter.org/projects/libnetfilter_conntrack/files/libnetfilter_conntrack-${version}.tar.xz"
      ];
      hash = "sha256-dp0+r1f6T72wXdEoc7bLmlvnhE2JN+Iitkc4HUQoSCA=";
    };

    buildDeps = [
      gnumake
      pkg-config
    ];
    runtimeDeps = [libmnl];
    propagatedDeps = [libnfnetlink];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libnetfilter_conntrack-${version}
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
        pname = "lib-libnetfilter-conntrack";
        library = self;
        libs = [
          "-lnetfilter_conntrack"
          "-lnfnetlink"
          "-lmnl"
        ];
        extraDeps = [
          pkgs.libnfnetlink
          pkgs.libmnl
        ];
        testSource = ''
          #include <libnetfilter_conntrack/libnetfilter_conntrack.h>
          #include <stdio.h>
          int main() {
            struct nf_conntrack *ct = nfct_new();
            if (!ct) return 1;
            nfct_destroy(ct);
            printf("libnetfilter_conntrack: PASS\n");
            return 0;
          }
        '';
      };
    };

    meta = {
      description = "libnetfilter_conntrack — userspace library for in-kernel connection tracking";
      homepage = "https://netfilter.org/projects/libnetfilter_conntrack/";
      license = "GPL-2.0-or-later";
    };
  }
