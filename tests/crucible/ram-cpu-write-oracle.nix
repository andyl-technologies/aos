{pkgs}: let
  profiles = [
    "scalar8"
    "scalar16"
    "scalar32"
    "unaligned32"
    "cross-page32"
    "exchange8"
    "exchange16"
    "exchange32"
    "unaligned-exchange32"
    "cross-page-exchange32"
    "compare-exchange64"
    "failed-compare-exchange32"
    "vector128"
    "unaligned-vector128"
    "cross-page-vector128"
    "locked-add8"
    "locked-add16"
    "locked-add32"
    "unaligned-locked-add32"
    "cross-page-locked-add32"
    "locked-xadd32"
    "unaligned-locked-xadd32"
    "cross-page-locked-xadd32"
    "successful-compare-exchange32"
    "cross-page-successful-compare-exchange32"
    "unaligned-compare-exchange64"
    "cross-page-compare-exchange64"
    "compound-two-store32"
  ];
in
  pkgs.mkDerivation {
    pname = "crucible-ram-cpu-write-oracle";
    version = "1";
    src = null;
    buildDeps = [pkgs.binutils pkgs.coreutils pkgs.python3];
    phases = [
      {
        name = "build-closed-cpu-writer-profiles";
        script = ''
          set -eu
          mkdir -p "$out"
          cat > writer.ld <<'LINKER'
          OUTPUT_FORMAT(elf32-i386)
          ENTRY(_start)
          SECTIONS {
            . = 0;
            .text : { *(.text*) }
            . = 0xffd0;
            .identity : { *(.identity*) }
            . = 0xfff0;
            .reset : { *(.reset*) }
            . = 0xffff;
            .last : { BYTE(0) }
            /DISCARD/ : { *(.note*) *(.comment*) }
          }
          LINKER
          build_rom() {
            name="$1"
            shift
            as --32 --defsym CASE="$case_number" "$@" ${./ram-cpu-write-oracle.S} -o "$out/$name.o"
            ld -m elf_i386 -nostdlib -T writer.ld -o "$out/$name.elf" "$out/$name.o"
            objcopy -O binary "$out/$name.elf" "$out/$name.bin"
            objdump -d -w -M i8086 "$out/$name.elf" > "$out/$name.instructions"
            test "$(stat -c %s "$out/$name.bin")" -eq 65536
          }
          case_number=0
          for profile in ${builtins.concatStringsSep " " profiles}; do
            build_rom "$profile"
            build_rom "$profile-missing-operation" --defsym OMIT_OPERATION=1
            if test "$case_number" -eq 11; then
              build_rom "$profile-forced-success" --defsym FORCE_FAILED_CAS_SUCCESS=1
            fi
            case_number=$((case_number + 1))
          done
          python3 ${./ram-cpu-write-oracle-inventory.py} "$out"
          python3 ${./ram-cpu-write-oracle-inventory-tests.py} \
            --inventory-tool ${./ram-cpu-write-oracle-inventory.py} --artifacts "$out"
        '';
      }
    ];
  }
