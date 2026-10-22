# Genuine managed virtqueue completion with its original native RAM maps retained.
{
  pkgs,
  lib,
  attrPath,
  nativeQemu ? pkgs.qemu-crucible,
  nativePlugin ? pkgs.crucible-qemu-plugin,
}: let
  trafficGuest = import ./_nginx-curl-http-200-guest.nix {inherit pkgs;};
  scenario = pkgs.writeTextFile {
    name = "crucible-managed-dma-traffic-scenario";
    destination = "/scenario.toml";
    text = builtins.readFile ./fixtures/e2e-determinism.scenario.toml;
  };
in
  import ./ram-native-flight.nix {
    inherit pkgs lib attrPath nativeQemu nativePlugin;
    pname = "crucible-managed-dma-borrower-flight";
    gateId = "gate:ram-dma-borrowers";
    testName = "qemu_hot_fork_world_factory::tests::native_acceptance::production_managed_dma_maps_block_reclaim_until_real_completion";
    successMarker = "MANAGED_DMA_BORROWERS_NATIVE_PASS";
    lanes = ["dma-reference" "dma-held"];
    outerCpuSlots = 14;
    outerMemoryMiB = 36864;
    writableMiB = 81920;
    storageImageBytes = 68719476736;
    innerTimeoutSeconds = 5700;
    outerTimeoutSeconds = 6000;
    evidencePrefix = "dma_borrowers";
    extraRootfsDeps = [trafficGuest scenario];
    innerPreparation = ''
      mkdir -p /var/paging-history/dma-artifacts /var/paging-history/dma-run-state
      for kernel in ${pkgs.linux}/boot/vmlinuz-*; do
        export CRUCIBLE_ATOMIC_WORLD_KERNEL="$kernel"
      done
      export CRUCIBLE_ATOMIC_WORLD_QEMU=${nativeQemu}/bin/qemu-system-x86_64
      export CRUCIBLE_ATOMIC_WORLD_PLUGIN=${nativePlugin}/lib/libcrucible_qemu_plugin.so
      export CRUCIBLE_ATOMIC_WORLD_ROOT=${trafficGuest}/root.ext4
      export CRUCIBLE_ATOMIC_WORLD_SCENARIO=${scenario}/scenario.toml
      export CRUCIBLE_ATOMIC_WORLD_ARTIFACTS=/var/paging-history/dma-artifacts
      export CRUCIBLE_ATOMIC_WORLD_CGROUP=/sys/fs/cgroup/crucible-paging
      export CRUCIBLE_ATOMIC_WORLD_STORAGE=/var/paging-storage
      export CRUCIBLE_ATOMIC_WORLD_RUN_STATE=/var/paging-history/dma-run-state
      export CRUCIBLE_ATOMIC_WORLD_UID=65534
      export CRUCIBLE_ATOMIC_WORLD_GID=65534
    '';
    innerEvidence = _: ''
      for evidence in \
        dma_borrowers_actual_mapped_virtqueue_retained=true \
        dma_borrowers_policy_pending_without_cut_until_completion=true \
        dma_borrowers_real_completion_zero_maps_and_convergence=true \
        dma_borrowers_canonical_guest_boundary_and_full_cleanup=true; do
        ${pkgs.grep}/bin/grep -Fx "$evidence" /tmp/paging-native.log
      done
    '';
    outerEvidence = _: ''
      test -s "$out/serial.log"
    '';
  }
