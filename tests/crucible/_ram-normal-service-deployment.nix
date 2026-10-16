# Explicit managed-VM request vectors; genuine Main/Services must admit them.
{
  pkgs,
  lib,
  nativePluginFlight ? null,
}: let
  native = nativePluginFlight != null;
  baseCatalog = {
    resident_peak_bytes = 134217728;
    backing_peak_bytes = 536870912;
    metadata_bytes = 67108864;
    staging_bytes = 8388608;
    paging_io_slots = 1;
    cpu_slots = 1;
    task_slots = 1;
    file_descriptors = 128;
  };
  catalog =
    if native
    then
      baseCatalog
      // {
        resident_peak_bytes = 402653184;
        backing_peak_bytes = 1073741824;
        metadata_bytes = 268435456;
      }
    else baseCatalog;
  registry =
    baseCatalog
    // {
      backing_peak_bytes = 16777216;
    };
  # Two retained native process shares and their host controls are requested
  # from the single Main purpose. This declaration is not installed eligibility.
  baseAssignment = {
    resident_peak_bytes = 1879048192;
    backing_peak_bytes = 2147483648;
    metadata_bytes = 536870912;
    staging_bytes = 16777216;
    paging_io_slots = 2;
    cpu_slots = 2;
    task_slots = 133;
    file_descriptors = 2112;
  };
  assignment =
    if native
    then
      baseAssignment
      // {
        resident_peak_bytes = 2147483648;
        backing_peak_bytes = 4294967296;
        staging_bytes = 33554432;
        cpu_slots = 4;
        task_slots = 141;
      }
    else baseAssignment;
  aggregate = lib.mapAttrs (dimension: value:
    value + catalog.${dimension} + registry.${dimension})
  assignment;
  table = name: vector: ''
    [${name}]
    ${lib.concatStringsSep "\n" (lib.mapAttrsToList (name: value: "${name} = ${toString value}") vector)}
  '';
  operations = [
    "setup"
    "quantum"
    "page_in"
    "writeback"
    "fingerprint_initialization"
    "fingerprint_update"
    "quiescence"
    "checkpoint_capture"
    "checkpoint_publication"
    "restore"
    "fork_rearm"
    "transfer"
    "preparation"
    "cleanup"
  ];
in
  pkgs.writeTextFile {
    name = "normal-ram-executor.toml";
    text = ''
      schema = "crucible.campaign-packaged-executor"
      version = 3
      cgroup_root = "/sys/fs/cgroup/system.slice/crucible-campaign.service/workload"
      run_root = "/var/paging-storage/run"
      attempt_namespace = "normal-ram"
      first_project_id = 36200
      project_id_count = 4
      child_user_id = 65534
      child_group_id = 29000
      maximum_tasks = ${
        if native
        then "128"
        else "64"
      }
      maximum_file_descriptors = ${
        if native
        then "2048"
        else "1024"
      }
      maximum_locked_bytes = 0
      maximum_node_host_service_tasks = ${
        if native
        then "12"
        else "4"
      }
      maximum_node_host_service_file_descriptors = ${
        if native
        then "64"
        else "32"
      }
      maximum_node_host_service_resident_bytes = ${
        if native
        then "33554432"
        else "8388608"
      }
      watcher_service_resident_bytes = 1048576
      maximum_inodes = 4096
      finish_timeout_ms = 15000
      maximum_slots = 1
      maximum_paging_io_slots = ${toString aggregate.paging_io_slots}
      maximum_host_task_slots = ${toString aggregate.task_slots}
      maximum_host_file_descriptors = ${toString aggregate.file_descriptors}
      maximum_host_metadata_bytes = ${toString aggregate.metadata_bytes}
      maximum_host_staging_bytes = ${toString aggregate.staging_bytes}
      maximum_vcpus = ${toString aggregate.cpu_slots}
      maximum_resident_bytes = ${toString aggregate.resident_peak_bytes}
      maximum_disk_bytes = ${toString aggregate.backing_peak_bytes}
      maximum_execution_quanta = 150000
      maximum_checkpoint_bytes = 1073741824
      worker_count = 1
      host_architecture = "x86_64"
      qemu_profile = "deterministic-tcg-v1"
      ram_catalog_root = "/var/paging-storage/ram-catalogs"
      ram_catalog_project_id = 36000
      maximum_ram_catalog_inodes = 262144
      maximum_ram_catalog_sqlite_heap_bytes = 8388608
      operational_registry_root = "/var/paging-storage/executor-ledger"
      operational_registry_project_id = 36001
      operational_registry_maximum_inodes = 65536

      ${table "operational_registry_resources" registry}
      ${table "ram_catalog_resources" catalog}
      ${table "assignment_resources" assignment}
      ${table "retained_template_resources" assignment}

      ${lib.optionalString native ''
        [native_plugin_flight]
        kind = "${nativePluginFlight.kind}"
        kernel = "${nativePluginFlight.kernel}"
        initrd = "${nativePluginFlight.initrd}"
        firmware = "${nativePluginFlight.firmware}"
      ''}

      [assignment_limits]
      vcpus = ${
        if native
        then "4"
        else "1"
      }
      resident_bytes = 536870912
      disk_bytes = 1073741824
      execution_quanta = ${
        if native
        then "50000"
        else "150000"
      }

      [operations]
      listener_workers = 4
      pending_connections = 16
      requests_per_connection = 4096
      accept_poll_interval_ms = 10
      exchange_read_timeout_ms = 30000
      exchange_write_timeout_ms = 30000
      runtime_poll_interval_ms = 100
      planner_scan_limit = 1024
      planner_input_bytes = 16777216
      planner_fuel = 1025
      executor_scan_limit = 1024
      worker_slots_per_campaign = 1

      ${lib.concatMapStringsSep "\n" (name: ''
          [host_operation_budgets.${name}]
          poll_interval_ms = 10
          total_timeout_ms = 2700000
        '')
        operations}
    '';
  }
