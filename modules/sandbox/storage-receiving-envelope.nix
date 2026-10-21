# Keeps selected Storage main and its closed physical helpers within one paid envelope.
{
  config,
  lib,
  ...
}: let
  policy = config.aos.sandbox.resourceBank.policy;
  receiving =
    if policy == null
    then null
    else policy.storageReceiving;
  selected = config.aos.sandbox.storageBroker.enable && receiving != null;

  # The real initial receiver prepays main plus one joined property observer.
  # Preserve those two task slots during effect, rollback and owed posts.
  workerTasks = name:
    lib.min (
      if name == "aos-sandbox-held-snapshot-reader@"
      then 4
      else 16
    ) (receiving.pids - 2);

  # This fixed roster contains the existing worker services. Selecting their
  # aggregate preserves their executable, privilege, timeout, socket and
  # framing. Existing resource maxima remain upper bounds; the selected task
  # limit also leaves the actual paid main/observer roster available.
  services = [
    "aos-storaged"
    "aos-sandbox-zfs-ready"
    "aos-sandbox-zfs-worker@"
    "aos-sandbox-held-snapshot-reader@"
    "aos-sandbox-workspace-pin-worker@"
    "aos-sandbox-workspace-pin-observer@"
    "aos-sandbox-workspace-root-initializer@"
    "aos-sandbox-guest-root-publisher@"
  ];
in {
  config = lib.mkIf selected {
    assertions = [
      {
        assertion = receiving.pids >= 4;
        message = "Selected Storage receiving needs main, observer, worker and one child task.";
      }
      {
        assertion = config.aos.sandbox.storageWorker.enable;
        message = "Selected Storage receiving requires its actual fixed physical worker roster.";
      }
    ];

    # PID1 installs this aggregate before admitting any main or worker job.
    # The same original Storage F pays this rate once. Per-service ceilings
    # remain additional restrictions and cannot sum into a larger entitlement.
    systemd.slices.aos-control-storage = {
      description = "Original Storage main and fixed physical workers";
      sliceConfig = {
        CPUAccounting = true;
        CPUQuotaPeriodSec = "100ms";
        CPUQuota = "${toString (receiving.cpu-micros-per-period / 1000)}%";
        MemoryMax = receiving.memory-bytes;
        MemorySwapMax = 0;
        TasksMax = receiving.pids;
      };
    };

    systemd.services = lib.genAttrs services (name: {
      serviceConfig = {
        Slice = lib.mkForce "aos-control-storage.slice";

        # GuestRoot keeps its installed 1 GiB/16-task recipe. The aggregate and
        # same-F admission must fit it; selecting this roster adds no capacity.

        # PID1 delivers the same readonly aggregate directory on the existing
        # fixed worker launch. Recipients compare its kernel identity with the
        # compiled aggregate; the descriptor is never a payer or effect grant.
        # The readiness helper and main do not consume a worker protocol.
        # Unit provenance also inspects nested properties before rendering.
        # Keep this optional envelope's guard next to its dependent value.
        TasksMax = lib.mkIf (selected
          && name
          != "aos-storaged"
          && name != "aos-sandbox-zfs-ready"
          && name != "aos-sandbox-guest-root-publisher@") (lib.mkForce (workerTasks name));
        OpenFile = lib.mkIf (selected && name != "aos-storaged" && name != "aos-sandbox-zfs-ready") [
          "/sys/fs/cgroup/aos.slice/aos-control.slice/aos-control-storage.slice:aos-storage-worker-aggregate-v1:read-only"
        ];
      };
    });
  };
}
