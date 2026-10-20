{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
  pluginPackage ? pkgs.crucible-qemu-plugin,
}: let
  driver = import ./tcg-production-performance-driver.nix {inherit pkgs lib;};
  guest = import ./phase2-qemu-live-plugin-quantum-guest.nix {inherit pkgs;};
  kernel = pkgs.linux-crucible;
in
  pkgs.mkDerivation {
    pname = "crucible-tcg-linux-boot-performance-determinism";
    version = "0";
    src = null;

    buildDeps = [pkgs.coreutils pkgs.python3 driver guest kernel qemuPackage pluginPackage];

    phases = [
      {
        name = "check-authenticated-linux-boot-state";
        script = ''
          set -eu
          mkdir -p "$out/evidence"
          for image in ${kernel}/boot/vmlinuz-*; do kernel_image="$image"; done
          cpu=$(${pkgs.python3}/bin/python3 -c 'import os; print(min(os.sched_getaffinity(0)))')

          ${pkgs.python3}/bin/python3 ${./tcg-linux-boot-performance.py} \
            --driver ${driver}/bin/crucible-production-performance \
            --qemu packaged=${qemuPackage}/bin/qemu-system-x86_64 \
            --plugin packaged=${pluginPackage}/lib/libcrucible_qemu_plugin.so \
            --kernel "$kernel_image" --initrd ${guest}/initrd.img \
            --output "$out/evidence" --cpu "$cpu" --ram-mib 256 \
            --repetitions 2 > "$out/samples.jsonl"

          # Exact hashes and coordinates retain the comparison evidence without
          # keeping two full memory images in this qualification store output.
          rm "$out"/evidence/linux-*/ram.bin

          cat > "$out/result" <<'RESULT'
          PASS
          authenticated_selectable=flight.ready
          exact_doorbell_instruction_stop=true
          stock_linux_kernel=true
          guest_determinism_shaping=false
          stopped_registers_identical=true
          stopped_full_physical_memory_range_identical=true
          marker_coordinates_identical=true
          launch_and_boot_timings_retained_without_portable_threshold=true
          RESULT
        '';
      }
    ];
  }
