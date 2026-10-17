# Genuine accepted promotion, CAS-backed restore and native RAM child staging.
{
  pkgs,
  lib,
  attrPath,
  nativeQemu ? pkgs.qemu-crucible,
  nativePlugin ? pkgs.crucible-qemu-plugin,
}:
import ./ram-native-flight.nix {
  inherit pkgs lib attrPath nativeQemu nativePlugin;
  pname = "crucible-managed-ram-hot-fork-flight";
  gateId = "gate:ram-native-hot-fork";
  testName = "packaged_qemu_executor::tests::hot_fork_native::production_managed_hot_fork_preserves_ram_and_reaps_fresh_child";
  successMarker = "MANAGED_HOT_FORK_CHILD_NATIVE_PASS";
  lanes = ["fork" "fork-child"];
  outerCpuSlots = 6;
  outerMemoryMiB = 8192;
  writableMiB = 8192;
  innerTimeoutSeconds = 5700;
  outerTimeoutSeconds = 6000;
  evidencePrefix = "managed_hot_fork";
  outerEvidence = {buildGraph}: ''
    kernel_build_id=$(
      ${pkgs.binutils}/bin/readelf -n ${pkgs.linux.vmlinux} \
        | ${pkgs.gawk}/bin/gawk '$1 == "Build" && $2 == "ID:" { print $3 }'
    )
    test "$(${pkgs.coreutils}/bin/printf '%s\n' "$kernel_build_id" \
      | ${pkgs.grep}/bin/grep -Ec '^[0-9a-f]{32,128}$')" -eq 1
    test "$(${pkgs.grep}/bin/grep -c '^managed_hot_fork_receipt=' "$out/serial.log")" -eq 1
    ${pkgs.gawk}/bin/gawk '/^managed_hot_fork_receipt=/ {
      sub(/^managed_hot_fork_receipt=/, ""); print
    }' "$out/serial.log" > "$out/qualification.json"
    test "$(${pkgs.coreutils}/bin/wc -c < "$out/qualification.json")" -le 16384
    ${pkgs.jq}/bin/jq -e \
      --arg kernel_build_id "$kernel_build_id" --arg graph '${buildGraph}' '
      .edition == 1 and .host_kernel_build_id == $kernel_build_id
      and .build_graph_sha256 == $graph
      and ([.host_kernel_blake3, .qemu_blake3, .plugin_blake3, .topology_blake3,
            .source_ram_root, .changed_child_ram_root]
        | all(test("^[0-9a-f]{64}$")))
      and .source_ram_root != .changed_child_ram_root
      and .profile == {
        machine: "pc-q35-9.2", accelerator: "sim", thread_mode: "single",
        architecture: "x86_64", guest_ram_bytes: 67108864,
        vcpu_count: 1, page_bytes: 4096, outer_cpu_slots: 6
      }
      and .operations == {
        accepted_promotion: true, cas_lazy_restore: true, hot_fork: true,
        initial_ram_identity: true, child_cow_separation: true,
        source_ram_preserved: true, independent_full_peaks_retained: true,
        cleanup_before_discharge: true, strict_low_peak: false, transfer: false
      }
      and (.activity | length == 2 and all(. > 0))
    ' "$out/qualification.json" > /dev/null
  '';
}
