##! BoringSSL — Google TLS implementation for private static linking
{
  lib,
  mkDerivation,
  fetchurl,
  cmake,
  ninja,
  perl,
  buildPackages,
  stdenv,
}: let
  version = "0.20260803.0";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "boringssl";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The API returns the expected value and the consumer prints the fixed success line.";
        "files" = {
          "primary.c" = "#include <stdio.h>\n#include <string.h>\n#include <openssl/evp.h>\n\nint main(void) {\n    unsigned char output[8] = {0};\n    int length = EVP_DecodeBlock(output, (const unsigned char *)\"NDI=\", 4);\n    if (length != 3 || memcmp(output, \"42\", 2) != 0) {\n        return 2;\n    }\n    return puts(\"boringssl api passed\") == EOF;\n}\n";
        };
        "input" = "The Base64 text NDI=, which encodes the ASCII bytes 42.";
        "operation" = "Decode the text with EVP_DecodeBlock and verify the decoded prefix.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-lcrypto"
              "-lpthread"
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
              "exact" = "boringssl api passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The API reports rejection and the consumer emits the fixed diagnostic and rejection status.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\n#include <openssl/evp.h>\n\nint main(void) {\n    unsigned char output[8] = {0};\n    if (EVP_DecodeBlock(output, (const unsigned char *)\"%%%?\", 4) != -1) {\n        return 2;\n    }\n    fputs(\"boringssl rejected invalid input\\n\", stderr);\n    return 7;\n}\n";
        };
        "input" = "A Base64 string containing characters outside the alphabet.";
        "operation" = "Decode the malformed text with EVP_DecodeBlock.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-lcrypto"
              "-lpthread"
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
              "exact" = "boringssl rejected invalid input\n";
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
      urls = ["https://github.com/google/boringssl/archive/refs/tags/${version}.tar.gz"];
      hash = "sha256-WFyReC/AZRum8jdrZyrNwwQ3cF2KULSWfCDmKT4xiWk=";
    };

    buildDeps =
      [cmake ninja perl]
      ++ (
        if stdenv.hostPlatform.isDarwin
        then [buildPackages.llvm]
        else []
      );
    runtimeDeps = [];
    propagatedDeps = [];
    # CMake cannot discover this Darwin tool from the Linux-hosted wrapper.
    cmakeFlags =
      if stdenv.hostPlatform.isDarwin
      then "-DCMAKE_INSTALL_NAME_TOOL=${buildPackages.llvm}/bin/llvm-install-name-tool"
      else "";

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd boringssl-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          cmake -S . -B build -G Ninja \
            $cmakeFlags \
            -DCMAKE_BUILD_TYPE=Release \
            -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
            -DCMAKE_CXX_FLAGS=${
            if stdenv.hostPlatform.isDarwin
            then "-Wno-error=uninitialized"
            else "-Wno-error=maybe-uninitialized"
          } \
            -DBUILD_SHARED_LIBS=OFF
        '';
      }
      {
        name = "build";
        script = ''ninja -C build -j"$NIX_BUILD_CORES" crypto ssl bssl'';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin" "$out/include" "$out/lib"
          cp build/bssl "$out/bin/"
          cp build/libcrypto.a build/libssl.a "$out/lib/"
          cp -R include/openssl "$out/include/"
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-boringssl";
        tool = self;
        command = "bssl ciphers DEFAULT >/dev/null";
      };
    };

    meta = {
      description = "TLS implementation for private static linking";
      homepage = "https://boringssl.googlesource.com/boringssl/";
      license = "Apache-2.0 AND ISC AND MIT AND BSD-3-Clause";
      mainProgram = "bssl";
    };
  }
