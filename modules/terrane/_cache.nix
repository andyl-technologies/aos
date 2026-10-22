##! Explicit finite native cache resources and their TOML representation.
{lib}: let
  types = lib.types;
  positive = types.addCheck types.int (value: value > 0);
  nonnegative = types.addCheck types.int (value: value >= 0);
  required = type: description: lib.mkOption {inherit type description;};
  portableType = types.submodule {
    options = {
      maxFileBytes = required positive "Maximum bytes read from one existing portable file.";
      maxInputBytes = required positive "Maximum distinct portable input bytes.";
      maxFiles = required positive "Maximum portable input files and retained recipes.";
      maxSelectedBytes = required positive "Maximum retained selected key and value bytes.";
    };
  };
  lowerType = types.submodule {
    options = {
      budgetMs = required (types.addCheck positive (value: value <= 300000)) "Total verified lower-read budget in milliseconds.";
      failureThreshold = required (types.addCheck positive (value: value <= 1000)) "Consecutive failures before opening the lower circuit.";
      probeIntervalMs = required (types.addCheck positive (value: value <= 300000)) "Interval between open-circuit probes in milliseconds.";
    };
  };
  repairType = types.submodule {
    options = {
      maxIndexBytes = required positive "Maximum derived detached-index payload bytes.";
      futureHoldBytes = required positive "Explicit future hold covering index payload and metadata synchronization.";
    };
  };
  surfaceIndexType = types.submodule {
    options = {
      maxEntries = required (types.addCheck positive (value: value <= 4294967295)) "Maximum expanded entries in one canonical projection.";
      maxNodeBytes = required (types.addCheck positive (value: value >= 32)) "Maximum combined canonical node bodies and digest keys per request.";
      maxIndexBytes = required positive "Maximum compiled payload bytes in one FUSE metadata index.";
      capacityBytes = required positive "Separate allocation cap, conservatively checked against full project charge including retained mappings and verity data.";
      futureHoldBytes = required positive "Explicit future hold covering index payload and metadata synchronization.";
    };
  };
in {
  type = types.submodule {
    options = {
      stateGid = required (types.addCheck positive (value: value < 4294967295)) "Private cache-state group excluding the publisher.";
      capacityBytes = required positive "Maximum measured allocation plus logical future holds for this domain.";
      lowWatermarkBytes = required nonnegative "Target allocation after high-watermark eviction.";
      probationBytes = required nonnegative "Maximum probationary allocation before unread entries are preferred.";
      releaseGraceSeconds = required nonnegative "Protection interval following the final consumer release.";
      scanLimit = required positive "Maximum eviction queue visits in one attempt.";
      maxReadBytes = required positive "Maximum individual encoded read allocation.";
      stateBytes = required positive "Maximum serialized durable policy snapshot length.";
      stateRecords = required positive "Maximum records in a durable policy snapshot.";
      inventoryEntries = required positive "Maximum entries in a complete native recovery inventory.";
      queuedCommands = required (types.addCheck positive (value: value <= 1024)) "Maximum queued physical commands, excluding the active command.";
      metadataSyncHoldBytes = required positive "Logical future hold for metadata and snapshot synchronization.";
      publisherWaitBudgetMs = required (types.addCheck positive (value: value <= 300000)) "Finite publisher request wait in milliseconds.";
      consumerLeaseSeconds = required (types.addCheck positive (value: value <= 300)) "Whole-second consumer grant duration.";
      lower = lib.mkOption {
        type = types.nullOr lowerType;
        default = null;
        description = "Explicit lower-read policy required by native SDK read-through.";
      };
      portable = required portableType "Explicit complete portable-validation limits.";
      indexRepair = lib.mkOption {
        type = types.nullOr repairType;
        default = null;
        description = "Optional explicit funded detached-index repair policy.";
      };
      surfaceIndex = lib.mkOption {
        type = types.nullOr surfaceIndexType;
        default = null;
        description = "Optional explicit funded FUSE metadata-index policy; requires compiled surface-fuse support.";
      };
    };
  };

  checks = {
    domains,
    tierBudget,
    hasPublisher,
    hasQuota,
  }:
    lib.mapAttrsToList (name: domain: let
      cache = domain.cache;
    in {
      assertion =
        cache
        == null
        || (
          hasPublisher
          && hasQuota
          && domain.publisher != null
          && cache.stateGid == 844
          && cache.capacityBytes <= tierBudget
          && cache.lowWatermarkBytes <= cache.capacityBytes
          && cache.probationBytes <= cache.capacityBytes
          && cache.metadataSyncHoldBytes >= 2 * cache.stateBytes
          && cache.metadataSyncHoldBytes <= cache.capacityBytes
          && cache.portable.maxInputBytes >= cache.portable.maxFileBytes
          && (cache.indexRepair
            == null
            || (
              cache.indexRepair.futureHoldBytes
              >= cache.metadataSyncHoldBytes + cache.indexRepair.maxIndexBytes
              && cache.indexRepair.futureHoldBytes <= cache.capacityBytes
            ))
          && (cache.surfaceIndex
            == null
            || (
              cache.surfaceIndex.capacityBytes
              >= cache.surfaceIndex.maxIndexBytes
              && cache.surfaceIndex.capacityBytes <= cache.capacityBytes
              && cache.surfaceIndex.futureHoldBytes
              >= cache.metadataSyncHoldBytes + cache.surfaceIndex.maxIndexBytes
              && cache.surfaceIndex.futureHoldBytes <= cache.capacityBytes
            ))
        );
      message = "Terrane native cache ${name} requires explicit publisher/quota inputs, private state group and consistent finite resource bounds.";
    })
    domains;

  render = cache:
    if cache == null
    then null
    else {
      state_gid = cache.stateGid;
      capacity_bytes = cache.capacityBytes;
      low_watermark_bytes = cache.lowWatermarkBytes;
      probation_bytes = cache.probationBytes;
      release_grace_seconds = cache.releaseGraceSeconds;
      scan_limit = cache.scanLimit;
      max_read_bytes = cache.maxReadBytes;
      state_bytes = cache.stateBytes;
      state_records = cache.stateRecords;
      inventory_entries = cache.inventoryEntries;
      queued_commands = cache.queuedCommands;
      metadata_sync_hold_bytes = cache.metadataSyncHoldBytes;
      publisher_wait_budget_ms = cache.publisherWaitBudgetMs;
      consumer_lease_seconds = cache.consumerLeaseSeconds;
      lower =
        if cache.lower == null
        then null
        else {
          budget_ms = cache.lower.budgetMs;
          failure_threshold = cache.lower.failureThreshold;
          probe_interval_ms = cache.lower.probeIntervalMs;
        };
      portable = {
        max_file_bytes = cache.portable.maxFileBytes;
        max_input_bytes = cache.portable.maxInputBytes;
        max_files = cache.portable.maxFiles;
        max_selected_bytes = cache.portable.maxSelectedBytes;
      };
      index_repair =
        if cache.indexRepair == null
        then null
        else {
          max_index_bytes = cache.indexRepair.maxIndexBytes;
          future_hold_bytes = cache.indexRepair.futureHoldBytes;
        };
      surface_index =
        if cache.surfaceIndex == null
        then null
        else {
          max_entries = cache.surfaceIndex.maxEntries;
          max_node_bytes = cache.surfaceIndex.maxNodeBytes;
          max_index_bytes = cache.surfaceIndex.maxIndexBytes;
          capacity_bytes = cache.surfaceIndex.capacityBytes;
          future_hold_bytes = cache.surfaceIndex.futureHoldBytes;
        };
    };
}
