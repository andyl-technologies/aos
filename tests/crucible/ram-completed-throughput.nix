# Measures real completed attempts under a declared disposable-VM profile.
{
  pkgs,
  lib,
  attrPath ? "checks.crucible.ram.completedThroughput",
}:
import ./ram-native-flight.nix {
  inherit pkgs lib attrPath;
  pname = "crucible-completed-campaign-throughput";
  gateId = "gate:ram-completed-throughput";
  testName = "packaged_qemu_executor::tests::paging_native::throughput::completed_campaign_throughput_matrix";
  successMarker = "COMPLETED_CAMPAIGN_THROUGHPUT_MATRIX_NATIVE_PASS";
  lanes = ["campaign-throughput"];
  outerCpuSlots = 10;
  # The actor's complete 16 GiB resident envelope has independent kernel room.
  outerMemoryMiB = 20480;
  writableMiB = 69632;
  storageImageBytes = 68719476736;
  innerTimeoutSeconds = 3600;
  outerTimeoutSeconds = 3900;
  evidencePrefix = "completed_campaign_throughput";
  innerPreparation = ''
    export CRUCIBLE_THROUGHPUT_HOST='disposable source-built x86_64 TCG VM; 10 vCPUs; 20 GiB outer RAM; 16 GiB actor resident envelope'
    export CRUCIBLE_THROUGHPUT_STORAGE='virtio-backed 64 GiB ext4 project-quota image; 8 GiB independent catalog; host cache uncontrolled'
    export CRUCIBLE_THROUGHPUT_CPU_AFFINITY="$(${pkgs.sed}/bin/sed -n 's/^Cpus_allowed_list:[[:space:]]*//p' /proc/self/status)"
    test -n "$CRUCIBLE_THROUGHPUT_CPU_AFFINITY"
  '';
  extraRootfsDeps = [pkgs.sed];
  outerEvidence = _: ''
    ${pkgs.gawk}/bin/gawk '
      /^COMPLETED_CAMPAIGN_THROUGHPUT_ROW=/ { rows++ }
      /^COMPLETED_CAMPAIGN_THROUGHPUT_RECEIPT=/ { receipts++ }
      END { if (rows != 27 || receipts != 1) exit 1 }
    ' "$out/serial.log"
  '';
}
