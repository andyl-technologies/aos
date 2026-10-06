# Real quota-backed storage indexing and bounded collection; no guest claims.
{
  pkgs,
  lib,
  attrPath,
}:
import ./ram-native-flight.nix {
  inherit pkgs lib attrPath;
  pname = "crucible-ram-storage-scale-flight";
  gateId = "gate:ram-storage-scale";
  testName = "packaged_qemu_executor::tests::paging_native::storage_scale::production_ram_storage_scales_past_packed_index_limit";
  successMarker = "RAM_STORAGE_SCALE_PASS";
  lanes = ["storage-scale"];
  outerCpuSlots = 4;
  outerMemoryMiB = 8192;
  # The outer writable filesystem contains the complete 32 GiB ext4 image.
  writableMiB = 36864;
  storageImageBytes = 34359738368;
  innerTimeoutSeconds = 14400;
  outerTimeoutSeconds = 14700;
  evidencePrefix = "ram_storage_scale";
  outerEvidence = _: ''
    for expected in \
      distinct_pages=131072 distinct_tree_objects=262143 \
      logical_bytes=536870912 gc_deleted_objects=393216 \
      rooted_graph_retained=true final_reader_release_before_collection=true \
      complete_vector_restored=true; do
      ${pkgs.grep}/bin/grep -qx "ram_storage_scale_$expected" "$out/serial.log"
    done
    ${pkgs.gawk}/bin/gawk -F= '
      /^ram_storage_scale_gc_batches=/ {
        if ($2 <= 1 || $2 > 8) exit 1; batches = 1
      }
      /^ram_storage_scale_verified_object_reads=/ {
        if ($2 < 393215) exit 1; reads = 1
      }
      /^ram_storage_scale_encoded_bytes=/ {
        if ($2 <= 536870912) exit 1; bytes = 1
      }
      /^ram_storage_scale_(capture|first_read|repeated_read)_ns=/ {
        if ($2 <= 0) exit 1; durations++
      }
      END { if (!batches || !reads || !bytes || durations != 3) exit 1 }
    ' "$out/serial.log"
  '';
}
