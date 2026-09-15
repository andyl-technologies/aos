##! ngtcp2 — QUIC protocol library
{
  lib,
  mkDerivation,
  fetchurl,
  cmake,
  ninja,
  pkg-config,
  boringssl,
  nghttp3,
}: let
  version = "1.25.0";
in
  mkDerivation {
    pname = "ngtcp2";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The linked library reports the compiled ngtcp2 version.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"ngtcp2 primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"ngtcp2 rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <string.h>\n#include <ngtcp2/ngtcp2.h>\nint main(void) {\n    const ngtcp2_info *info = ngtcp2_version(0);\n    int valid = info != NULL && info->version_num == NGTCP2_VERSION_NUM\n        && strcmp(info->version_str, NGTCP2_VERSION) == 0;\n    return valid ? pass() : 2;\n}\n\n";
        };
        "input" = "A runtime version query with no minimum version.";
        "operation" = "Query ngtcp2_version and compare it with the public header constants.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lngtcp2"
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
              "exact" = "ngtcp2 primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Ngtcp2 rejects the requirement by returning null.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"ngtcp2 primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"ngtcp2 rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <ngtcp2/ngtcp2.h>\nint main(void) {\n    return ngtcp2_version(0xffffff) == NULL ? reject() : 2;\n}\n\n";
        };
        "input" = "A minimum ngtcp2 version greater than any 24-bit release.";
        "operation" = "Query ngtcp2_version with the unsupported minimum.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lngtcp2"
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
              "exact" = "ngtcp2 rejected invalid input\n";
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
      urls = ["https://github.com/ngtcp2/ngtcp2/releases/download/v${version}/ngtcp2-${version}.tar.bz2"];
      hash = "sha256-jAy3gz62wLj0Eoh27ecxHuykmBLtP05xokPtiAPRttc=";
    };

    buildDeps = [cmake ninja pkg-config];
    runtimeDeps = [boringssl nghttp3];
    propagatedDeps = [nghttp3];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd ngtcp2-${version}
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
            -DENABLE_LIB_ONLY=ON \
            -DENABLE_OPENSSL=OFF \
            -DENABLE_BORINGSSL=ON \
            -DBORINGSSL_INCLUDE_DIR="${boringssl}/include" \
            -DBORINGSSL_LIBRARIES="${boringssl}/lib/libssl.a;${boringssl}/lib/libcrypto.a" \
            -DENABLE_SHARED_LIB=ON \
            -DENABLE_STATIC_LIB=ON
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
        pname = "lib-ngtcp2";
        library = self;
        libs = ["-lngtcp2"];
        testSource = ''
          #include <ngtcp2/ngtcp2.h>

          int main(void) {
              return ngtcp2_version(0) != 0 ? 0 : 1;
          }
        '';
      };
    };

    meta = {
      description = "QUIC protocol implementation";
      homepage = "https://github.com/ngtcp2/ngtcp2";
      license = "MIT";
    };
  }
