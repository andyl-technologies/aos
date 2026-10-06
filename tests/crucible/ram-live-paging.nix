# Real userfaultfd qualification runs inside an ephemeral AOS kernel namespace.
{
  pkgs,
  lib,
  attrPath,
  nativeQemu ? pkgs.qemu-crucible,
  nativePlugin ? pkgs.crucible-qemu-plugin,
}:
import ./ram-native-flight.nix {
  inherit pkgs lib attrPath nativeQemu nativePlugin;
  pname = "crucible-managed-ram-kernel-flight";
  gateId = "gate:ram-live-paging";
  testName = "packaged_qemu_executor::tests::paging_native::production_managed_paging_preserves_guest_state_and_cold_writes";
  successMarker = "MANAGED_PAGING_NATIVE_PASS";
  lanes = ["resident" "paged"];
  outerCpuSlots = 4;
  outerMemoryMiB = 4096;
  evidencePrefix = "managed_paging";
  innerEvidence = _: ''
    for evidence in \
      managed_paging_guest_state_identity=true \
      managed_paging_scheduler_and_clock_identity=true \
      managed_paging_published_ram_root_identity=true \
      managed_paging_full_execution_peak_retained=true \
      managed_paging_public_unqualified_policy_refused=true; do
      test "$(${pkgs.grep}/bin/grep -Fxc "$evidence" "$log")" -eq 1
    done
    for counter in \
      managed_paging_missing_installs \
      managed_paging_missing_read_installs \
      managed_paging_missing_write_installs \
      managed_paging_write_protect_transitions \
      managed_paging_preservation_reads \
      managed_paging_preservation_writes \
      managed_paging_physical_discards; do
      test "$(${pkgs.grep}/bin/grep -Ec "^$counter=[1-9][0-9]*$" "$log")" -eq 1
    done
  '';
  outerEvidence = {buildGraph}: ''
    kernel_build_id=$(
      ${pkgs.binutils}/bin/readelf -n ${pkgs.linux.vmlinux} \
        | ${pkgs.gawk}/bin/gawk '$1 == "Build" && $2 == "ID:" { print $3 }'
    )
    test "$(${pkgs.coreutils}/bin/printf '%s\n' "$kernel_build_id" \
      | ${pkgs.grep}/bin/grep -Ec '^[0-9a-f]{32,128}$')" -eq 1
    ${pkgs.grep}/bin/grep -Fxq \
      "managed_paging_host_kernel_build_id=$kernel_build_id" "$out/serial.log"
    ${pkgs.grep}/bin/grep -Fxq \
      'managed_paging_build_graph=${buildGraph}' "$out/serial.log"
    test "$(${pkgs.grep}/bin/grep -c '^managed_paging_receipt=' "$out/serial.log")" -eq 1
    ${pkgs.gawk}/bin/gawk '/^managed_paging_receipt=/ {
      sub(/^managed_paging_receipt=/, ""); print
    }' "$out/serial.log" > "$out/qualification.json"
    test "$(${pkgs.coreutils}/bin/wc -c < "$out/qualification.json")" -le 16384
    ${pkgs.jq}/bin/jq -e \
      --arg kernel_build_id "$kernel_build_id" --arg graph '${buildGraph}' '
      .edition == 1 and .host_kernel_build_id == $kernel_build_id
      and .build_graph_sha256 == $graph
      and ([.host_kernel_blake3, .qemu_blake3, .plugin_blake3, .topology_blake3]
        | all(test("^[0-9a-f]{64}$")))
      and .profile == {
        machine: "pc-q35-9.2", accelerator: "sim", thread_mode: "single",
        architecture: "x86_64", guest_ram_bytes: 67108864,
        vcpu_count: 1, page_bytes: 4096
      }
      and .operations == {
        full_peak_paused_reclamation: true, read_first_faults: true,
        write_first_faults: true, authenticated_spill: true,
        logical_state_unchanged: true, strict_low_peak: false,
        hot_fork: false, lazy_restore: false, transfer: false
      }
      and (.activity | length == 7 and all(. > 0))
    ' "$out/qualification.json" > /dev/null
  '';
}
