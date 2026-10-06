# One-byte modeled service timing under genuine resident and cold RAM placement.
{
  pkgs,
  lib,
  attrPath,
  nativeQemu ? pkgs.qemu-crucible,
  nativePlugin ? pkgs.crucible-qemu-plugin,
}: let
  guest = pkgs.mkDerivation {
    pname = "crucible-byte-service-benchmark";
    version = "0";
    src = null;
    buildDeps = [pkgs.binutils pkgs.coreutils pkgs.llvm pkgs.python3];
    phases = [
      {
        name = "assemble-unchanged-byte-benchmark";
        script = ''
          set -eu
          ${pkgs.llvm}/bin/clang --target=i386-none-elf -c -Wa,-defsym,TEST_MODE=1 \
            ${./phase2-qemu-memory-access-guest.S} -o benchmark.o
          ${pkgs.llvm}/bin/ld.lld -m elf_i386 -T ${./phase2-qemu-memory-access-guest.ld} \
            benchmark.o -o benchmark.elf
          nm -an benchmark.elf > symbols.txt
          objdump -d -m i386:x86-64 --insn-width=16 --disassemble=long_mode benchmark.elf \
            > instructions.txt
          python3 ${./ram-byte-service-asset.py} symbols.txt instructions.txt > coordinates.env
          mkdir -p "$out"
          install -m 444 benchmark.elf symbols.txt instructions.txt coordinates.env "$out/"
        '';
      }
    ];
  };
in
  import ./ram-native-flight.nix {
    inherit pkgs lib attrPath nativeQemu nativePlugin;
    pname = "crucible-managed-byte-service-flight";
    gateId = "gate:ram-native-byte-service";
    testName = "packaged_qemu_executor::tests::paging_native::byte_service::production_byte_service_latency_is_placement_independent";
    successMarker = "BYTE_SERVICE_NATIVE_PASS";
    lanes = [
      "byte-discovery"
      "byte-resident-7"
      "byte-cold-7"
      "byte-resident-42"
      "byte-cold-42"
      "byte-resident-991"
      "byte-cold-991"
    ];
    # The live target-discovery owner remains charged during each seeded lane.
    outerCpuSlots = 10;
    outerMemoryMiB = 8192;
    writableMiB = 8192;
    innerTimeoutSeconds = 10500;
    outerTimeoutSeconds = 10800;
    evidencePrefix = "byte_service";
    extraRootfsDeps = [guest];
    innerPreparation = ''
      export CRUCIBLE_BYTE_KERNEL=${guest}/benchmark.elf
      . ${guest}/coordinates.env
    '';
    innerEvidence = _: ''
      for evidence in \
        byte_service_seed_count=3 \
        byte_service_state_identity=true \
        byte_service_ram_root_identity=true \
        byte_service_modeled_time_identity=true \
        byte_service_actual_guest_entry=true \
        byte_service_one_byte_access=true \
        byte_service_native_latency_variation=true \
        byte_service_native_service_ledger_identity=true; do
        test "$(${pkgs.grep}/bin/grep -Fxc "$evidence" "$log")" -eq 1
      done
      for counter in \
        byte_service_missing_installs \
        byte_service_cold_discards; do
        test "$(${pkgs.grep}/bin/grep -Ec "^$counter=[1-9][0-9]*$" "$log")" -eq 1
      done
    '';
    outerEvidence = _: ''
      ${pkgs.grep}/bin/grep '^byte_service_' "$out/serial.log" \
        > "$out/byte-service-evidence.txt"
      cp ${guest}/symbols.txt ${guest}/instructions.txt "$out/"
    '';
  }
