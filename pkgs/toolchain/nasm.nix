##! nasm — Netwide Assembler (x86/x86-64)
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "3.02";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      role = "public-package";
    };
    pname = "nasm";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [
          {
            "path" = "answer.bin";
            "text" = "answer=42\n";
          }
        ];
        "expected" = "NASM emits the exact declared byte sequence.";
        "files" = {
          "answer.asm" = "bits 64\ndb \"answer=42\", 10\n";
        };
        "input" = "A flat-binary assembly source declaring the bytes answer=42.";
        "operation" = "Assemble the source into a raw binary.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/nasm"
              "-f"
              "bin"
              "answer.asm"
              "-o"
              "answer.bin"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "NASM rejects the source with its assembly-error status.";
        "files" = {
          "invalid.asm" = "bits 64\nrax, rbx\n";
        };
        "input" = "An assembly source with an operand but no instruction mnemonic.";
        "operation" = "Assemble the malformed source as a flat binary.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/nasm"
              "-f"
              "bin"
              "invalid.asm"
              "-o"
              "invalid.bin"
            ];
            "exit_code" = 1;
            "observes_rejection" = true;
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = [
        "https://www.nasm.us/pub/nasm/releasebuilds/${version}/nasm-${version}.tar.xz"
      ];
      hash = "sha256-hzNuulO0rP6RdCSrXVANKwBU2fUUjTXCJzzPLPtxLw0=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd nasm-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out
        '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES nasm ndisasm
        '';
      }
      {
        name = "install";
        script = ''
          make install
        '';
      }
    ];

    meta = {
      description = "nasm — Netwide Assembler for x86/x86-64";
      homepage = "https://www.nasm.us/";
      license = "BSD-2-Clause";
    };
  }
