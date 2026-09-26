##! lksctp-tools — Linux SCTP userspace library and tools
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  autoconf,
  automake,
  libtool,
  m4,
}: let
  version = "1.0.21";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "lksctp-tools";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Lksctp reports the platform's sockaddr_in and sockaddr_in6 sizes.";
        "files" = {
          "primary.c" = "#include <stdio.h>\n\nstatic int pass(void) {\n    return puts(\"lksctp-tools primary passed\") == EOF;\n}\n\nstatic int reject(void) {\n    fputs(\"lksctp-tools rejected invalid input\\n\", stderr);\n    return 7;\n}\n\n#include <sys/socket.h>\n#include <netinet/in.h>\n#include <netinet/sctp.h>\n\nint main(void) {\n    int ipv4_length = sctp_getaddrlen(AF_INET);\n    int ipv6_length = sctp_getaddrlen(AF_INET6);\n    return ipv4_length == sizeof(struct sockaddr_in)\n        && ipv6_length == sizeof(struct sockaddr_in6) ? pass() : 2;\n}\n\n";
        };
        "input" = "The IPv4 and IPv6 address-family selectors.";
        "operation" = "Resolve their socket address lengths through sctp_getaddrlen.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, os, pathlib, subprocess\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ncommand = [\"@cc@\", \"primary.c\"]\nfor root_text in closure:\n    root = pathlib.Path(root_text)\n    include = root / \"include\"\n    library = root / \"lib\"\n    if include.is_dir():\n        command.append(\"-I\" + str(include))\n    for nested in (root / \"include/glib-2.0\", root / \"lib/glib-2.0/include\"):\n        if nested.is_dir():\n            command.append(\"-I\" + str(nested))\n    if library.is_dir():\n        command.extend([\"-L\" + str(library), \"-Wl,-rpath,\" + str(library)])\ncommand.extend([\"-lsctp\"] + [\"-o\", \"primary-check\"])\nresult = subprocess.run(command, capture_output=True, text=True)\nassert result.returncode == 0, (result.returncode, result.stdout, result.stderr)\n"
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
              "exact" = "lksctp-tools primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Lksctp rejects the unsupported family by returning zero.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\n\nstatic int pass(void) {\n    return puts(\"lksctp-tools primary passed\") == EOF;\n}\n\nstatic int reject(void) {\n    fputs(\"lksctp-tools rejected invalid input\\n\", stderr);\n    return 7;\n}\n\n#include <sys/socket.h>\n#include <netinet/sctp.h>\n\nint main(void) {\n    return sctp_getaddrlen(AF_UNSPEC) == 0 ? reject() : 2;\n}\n\n";
        };
        "input" = "The unspecified address family, which cannot identify an SCTP socket address.";
        "operation" = "Resolve its address length through sctp_getaddrlen.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, os, pathlib, subprocess\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ncommand = [\"@cc@\", \"bad-input.c\"]\nfor root_text in closure:\n    root = pathlib.Path(root_text)\n    include = root / \"include\"\n    library = root / \"lib\"\n    if include.is_dir():\n        command.append(\"-I\" + str(include))\n    for nested in (root / \"include/glib-2.0\", root / \"lib/glib-2.0/include\"):\n        if nested.is_dir():\n            command.append(\"-I\" + str(nested))\n    if library.is_dir():\n        command.extend([\"-L\" + str(library), \"-Wl,-rpath,\" + str(library)])\ncommand.extend([\"-lsctp\"] + [\"-o\", \"bad-input-check\"])\nresult = subprocess.run(command, capture_output=True, text=True)\nassert result.returncode == 0, (result.returncode, result.stdout, result.stderr)\n"
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
              "exact" = "lksctp-tools rejected invalid input\n";
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
        "https://github.com/sctp/lksctp-tools/archive/refs/tags/v${version}.tar.gz"
      ];
      hash = "sha256-hzi/F+z/u+JECm4v+vHLzrtjP8mdY9iHYa81wCpXGJM=";
    };

    buildDeps = [gnumake autoconf automake libtool m4];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd lksctp-tools-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          export ACLOCAL_PATH="${libtool}/share/aclocal''${ACLOCAL_PATH:+:$ACLOCAL_PATH}"
          autoreconf -fi
          ./configure \
            $configureFlags \
            --prefix="$out" \
            --enable-shared \
            --enable-static
        '';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "install";
        script = ''make install'';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-sctp";
        library = self;
        libs = ["-lsctp"];
        testSource = ''
          #include <netinet/sctp.h>

          int main(void) {
              return sctp_getaddrlen(AF_INET) > 0 ? 0 : 1;
          }
        '';
      };
    };

    meta = {
      description = "Linux SCTP userspace library and tools";
      homepage = "https://github.com/sctp/lksctp-tools";
      license = "LGPL-2.1-only AND GPL-2.0-or-later";
    };
  }
