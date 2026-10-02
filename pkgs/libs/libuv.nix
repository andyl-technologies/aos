##! libuv — Portable asynchronous I/O library
{
  lib,
  mkDerivation,
  fetchurl,
  cmake,
  ninja,
}: let
  version = "1.52.1";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "libuv";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The port and round-tripped host match the input.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libuv primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libuv rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <arpa/inet.h>\n#include <string.h>\n#include <uv.h>\nint main(void) {\n    struct sockaddr_in address; char host[32];\n    if (uv_ip4_addr(\"127.0.0.1\", 42, &address) != 0 || uv_ip4_name(&address, host, sizeof(host)) != 0) return 2;\n    return ntohs(address.sin_port) == 42 && strcmp(host, \"127.0.0.1\") == 0 ? pass() : 3;\n}\n\n";
        };
        "input" = "The numeric IPv4 address 127.0.0.1 and port 42.";
        "operation" = "Parse and render the address through libuv's networking API.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-luv"
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
              "exact" = "libuv primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "libuv returns UV_EINVAL.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libuv primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libuv rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <uv.h>\nint main(void) {\n    struct sockaddr_in address;\n    if (uv_ip4_addr(\"300.1.2.3\", 42, &address) != UV_EINVAL) return 2;\n    return reject();\n}\n\n";
        };
        "input" = "An IPv4 address containing an octet above 255.";
        "operation" = "Parse the malformed address through uv_ip4_addr.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-luv"
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
              "exact" = "libuv rejected invalid input\n";
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
        "https://dist.libuv.org/dist/v${version}/libuv-v${version}.tar.gz"
      ];
      hash = "sha256-ZtURuebjNMDmInnrI0+/srMRCxR5wJuVtEx6/KjP+ec=";
    };

    buildDeps = [cmake ninja];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd libuv-v${version}
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
            -DBUILD_TESTING=OFF \
            -DLIBUV_BUILD_SHARED=ON \
            -DLIBUV_BUILD_TESTS=OFF \
            -DLIBUV_BUILD_BENCH=OFF
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
        pname = "lib-libuv";
        library = self;
        libs = ["-luv"];
        testSource = ''
          #include <uv.h>
          #include <stdio.h>

          int main(void) {
              printf("%s\n", uv_version_string());
              return uv_version() == 0 ? 1 : 0;
          }
        '';
      };
    };

    meta = {
      description = "Portable asynchronous I/O library";
      homepage = "https://libuv.org/";
      license = "MIT AND ISC AND BSD-2-Clause AND BSD-3-Clause AND CC-BY-4.0";
    };
  }
