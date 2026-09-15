##! c-ares — Asynchronous DNS request library
{
  lib,
  mkDerivation,
  fetchurl,
  cmake,
  ninja,
}: let
  version = "1.34.8";
in
  mkDerivation {
    pname = "c-ares";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The public API returns the expected value and the consumer prints the fixed success line.";
        "files" = {
          "primary.c" = "#include <stdio.h>\n#include <arpa/inet.h>\n#include <ares.h>\n\nint main(void) {\n    unsigned char address[4];\n    if (ares_inet_pton(AF_INET, \"192.0.2.42\", address) != 1\n        || address[0] != 192 || address[3] != 42) {\n        return 2;\n    }\n    return puts(\"c-ares api passed\") == EOF;\n}\n";
        };
        "input" = "The IPv4 address 192.0.2.42.";
        "operation" = "Parse the address with ares_inet_pton.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lcares"
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
              "exact" = "c-ares api passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The public API reports rejection and the consumer exits with the fixed rejection status and diagnostic.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\n#include <arpa/inet.h>\n#include <ares.h>\n\nint main(void) {\n    unsigned char address[4];\n    if (ares_inet_pton(AF_INET, \"192.0.2.999\", address) != 0) {\n        return 2;\n    }\n    fputs(\"c-ares rejected invalid input\\n\", stderr);\n    return 7;\n}\n";
        };
        "input" = "An IPv4 address containing an out-of-range octet.";
        "operation" = "Parse the malformed address with ares_inet_pton.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lcares"
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
            "stderr" = {
              "exact" = "c-ares rejected invalid input\n";
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
        "https://github.com/c-ares/c-ares/releases/download/v${version}/c-ares-${version}.tar.gz"
      ];
      hash = "sha256-wiK21oEJb5RE0sSGPSwRdAGeJ8rMoKSlwRTTbdfXv3g=";
    };

    buildDeps = [cmake ninja];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd c-ares-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          cmake -S . -B build -G Ninja \
            $cmakeFlags \
            -DCMAKE_BUILD_TYPE=Release \
            -DCMAKE_INSTALL_PREFIX="$out" \
            -DCMAKE_INSTALL_LIBDIR=lib \
            -DCARES_SHARED=ON \
            -DCARES_STATIC=ON \
            -DCARES_BUILD_TOOLS=ON \
            -DCARES_BUILD_TESTS=OFF
        '';
      }
      {
        name = "build";
        script = ''ninja -C build -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "install";
        script = ''ninja -C build install'';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-c-ares";
        library = self;
        libs = ["-lcares"];
        testSource = ''
          #include <ares.h>

          int main(void) {
              return ares_library_init(ARES_LIB_INIT_ALL);
          }
        '';
      };
      tool = testing.mkToolCheck {
        pname = "tool-c-ares";
        tool = self;
        command = "adig --help >/dev/null";
      };
    };

    meta = {
      description = "Asynchronous DNS request library";
      homepage = "https://c-ares.org/";
      license = "MIT";
    };
  }
