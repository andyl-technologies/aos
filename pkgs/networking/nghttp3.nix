##! nghttp3 — HTTP/3 and QPACK library
{
  lib,
  mkDerivation,
  fetchurl,
  cmake,
  ninja,
}: let
  version = "1.18.0";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "nghttp3";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The linked library reports the compiled nghttp3 version.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"nghttp3 primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"nghttp3 rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <string.h>\n#include <nghttp3/nghttp3.h>\nint main(void) {\n    const nghttp3_info *info = nghttp3_version(0);\n    int valid = info != NULL && info->version_num == NGHTTP3_VERSION_NUM\n        && strcmp(info->version_str, NGHTTP3_VERSION) == 0;\n    return valid ? pass() : 2;\n}\n\n";
        };
        "input" = "A runtime version query with no minimum version.";
        "operation" = "Query nghttp3_version and compare it with the public header constants.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lnghttp3"
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
              "exact" = "nghttp3 primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Nghttp3 rejects the requirement by returning null.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"nghttp3 primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"nghttp3 rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <nghttp3/nghttp3.h>\nint main(void) {\n    return nghttp3_version(0xffffff) == NULL ? reject() : 2;\n}\n\n";
        };
        "input" = "A minimum nghttp3 version greater than any 24-bit release.";
        "operation" = "Query nghttp3_version with the unsupported minimum.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lnghttp3"
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
              "exact" = "nghttp3 rejected invalid input\n";
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
      urls = ["https://github.com/ngtcp2/nghttp3/releases/download/v${version}/nghttp3-${version}.tar.bz2"];
      hash = "sha256-yiMmaLlKXh+1S0FjLMVkc6tIImSDgUQQ72KnBilOZAI=";
    };

    buildDeps = [cmake ninja];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd nghttp3-${version}
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
            -DENABLE_SHARED_LIB=ON \
            -DENABLE_STATIC_LIB=OFF
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
        pname = "lib-nghttp3";
        library = self;
        libs = ["-lnghttp3"];
        testSource = ''
          #include <nghttp3/nghttp3.h>

          int main(void) {
              return nghttp3_version(0) != 0 ? 0 : 1;
          }
        '';
      };
    };

    meta = {
      description = "HTTP/3 mapping and QPACK implementation";
      homepage = "https://github.com/ngtcp2/nghttp3";
      license = "MIT";
    };
  }
