# Build-only validation for Linux-produced Darwin compiler and runtime tools.
{pkgs}: let
  buildSystem = pkgs.stdenv.buildPlatform.system;
  x86 = import ../.. {
    system = buildSystem;
    crossSystem = "x86_64-darwin";
  };
  arm = import ../.. {
    system = buildSystem;
    crossSystem = "aarch64-darwin";
  };
in
  pkgs.mkDerivation {
    pname = "darwin-interpreters-check";
    version = "0";
    src = null;
    buildDeps = [pkgs.llvm];

    phases = [
      {
        name = "verify";
        script = ''
          verify_output() {
            output=$1
            platform=$2
            test "$(cat "$output/nix-support/aos-target-platform")" = "$platform"
          }

          verify_macho() {
            executable=$1
            expected_cpu=$2
            header=$(llvm-objdump --macho --private-header "$executable")
            if ! printf '%s\n' "$header" | grep -q "$expected_cpu"; then
              echo "unexpected Mach-O architecture in $executable: expected $expected_cpu" >&2
              printf '%s\n' "$header" >&2
              exit 1
            fi
          }

          verify_output ${x86.pkgs.llvm} x86_64-darwin
          verify_output ${x86.pkgs.nodejs} x86_64-darwin
          verify_output ${x86.pkgs.perl} x86_64-darwin
          verify_output ${x86.pkgs.python3} x86_64-darwin
          verify_output ${x86.pkgs.python3-3_12} x86_64-darwin
          verify_macho ${x86.pkgs.llvm}/bin/clang X86_64
          verify_macho ${x86.pkgs.nodejs}/bin/node X86_64
          verify_macho ${x86.pkgs.perl}/bin/perl X86_64
          verify_macho ${x86.pkgs.python3}/bin/python3 X86_64
          verify_macho ${x86.pkgs.python3-3_12}/bin/python3 X86_64

          verify_output ${arm.pkgs.llvm} aarch64-darwin
          verify_output ${arm.pkgs.nodejs} aarch64-darwin
          verify_output ${arm.pkgs.perl} aarch64-darwin
          verify_output ${arm.pkgs.python3} aarch64-darwin
          verify_output ${arm.pkgs.python3-3_12} aarch64-darwin
          verify_macho ${arm.pkgs.llvm}/bin/clang ARM64
          verify_macho ${arm.pkgs.nodejs}/bin/node ARM64
          verify_macho ${arm.pkgs.perl}/bin/perl ARM64
          verify_macho ${arm.pkgs.python3}/bin/python3 ARM64
          verify_macho ${arm.pkgs.python3-3_12}/bin/python3 ARM64

          mkdir -p "$out"
          printf 'PASS\n' > "$out/result"
        '';
      }
    ];
  }
