# Existing-owner fixture birth policy; immutable tools are built before runtime.
{
  pkgs,
  parentFixture,
  process,
}: let
  controller = parentFixture.passthru.controller;
  source = parentFixture.passthru.externalSource;
  fields = [
    "memoryMaxBytes"
    "tasksMax"
    "fileDescriptors"
    "runtimeSeconds"
    "startupTimeoutSeconds"
    "mainThreadStackBytes"
    "cpuQuotaPercent"
    "baselineResidentBytes"
    "metadataBytes"
    "sqliteBootstrapBytes"
    "sqliteHeapBytes"
    "sqliteConnections"
    "workerThreads"
    "blockingThreads"
    "threadStackBytes"
  ];
  valid = builtins.all (name:
    process ? ${name} && builtins.isInt process.${name} && process.${name} > 0)
  fields;
  policy = pkgs.writeText "crucible-existing-parent-process.toml" ''
    schema = "crucible.campaign-process.v1"
    unit = "crucible-campaign.service"
    executable = "${controller}/bin/crucible"
    memory_max_bytes = ${toString process.memoryMaxBytes}
    tasks_max = ${toString process.tasksMax}
    file_descriptors = ${toString process.fileDescriptors}
    runtime_seconds = ${toString process.runtimeSeconds}
    startup_timeout_seconds = ${toString process.startupTimeoutSeconds}
    main_thread_stack_bytes = ${toString process.mainThreadStackBytes}
    cpu_quota_percent = ${toString process.cpuQuotaPercent}
    baseline_resident_bytes = ${toString process.baselineResidentBytes}
    metadata_bytes = ${toString process.metadataBytes}
    sqlite_bootstrap_bytes = ${toString process.sqliteBootstrapBytes}
    sqlite_heap_bytes = ${toString process.sqliteHeapBytes}
    sqlite_connections = ${toString process.sqliteConnections}
    worker_threads = ${toString process.workerThreads}
    blocking_threads = ${toString process.blockingThreads}
    thread_stack_bytes = ${toString process.threadStackBytes}
  '';
  createWorkload = pkgs.writeTextFile {
    name = "crucible-existing-parent-workload";
    destination = "/bin/create-workload";
    executable = true;
    text = ''
      #!${pkgs.bash}/bin/bash
      set -eu
      # This persistent delegation belongs to owner startup, before any attempt.
      # Every attempt's controller, files, VM births and cleanup remain later.
      ${pkgs.coreutils}/bin/mkdir /sys/fs/cgroup/system.slice/crucible-campaign.service/workload
    '';
  };
in
  assert valid;
  assert source.totalMetadataBytes <= process.metadataBytes;
  assert source.tasks <= process.tasksMax;
  assert source.descriptors <= process.fileDescriptors;
  assert process.baselineResidentBytes + process.sqliteBootstrapBytes + process.sqliteHeapBytes + 21474836480 + source.residentBytes <= process.memoryMaxBytes; {
    policyFile = policy;
    environment.etc."crucible/campaign-process.toml".source = policy;
    systemd.services.crucible-campaign = {
      description = "Exclusive existing original Parent fixture owner";
      serviceConfig = {
        Type = "exec";
        Restart = "no";
        Delegate = "cpu memory pids";
        DelegateSubgroup = "guardian";
        ExecStartPre = "${createWorkload}/bin/create-workload";
        ExecStart = "${controller}/bin/crucible serve --production-qemu --listen 127.0.0.1:0 --trusted-unauthenticated-bind";
        MemoryMax = process.memoryMaxBytes;
        TasksMax = process.tasksMax;
        LimitNOFILE = "${toString process.fileDescriptors}:${toString process.fileDescriptors}";
        RuntimeMaxSec = process.runtimeSeconds;
        TimeoutStartSec = process.startupTimeoutSeconds;
        LimitSTACK = "${toString process.mainThreadStackBytes}:${toString process.mainThreadStackBytes}";
        CPUQuota = "${toString process.cpuQuotaPercent}%";
        CPUQuotaPeriodSec = "100ms";
      };
    };
    passthru = {
      privateFixture = true;
      runtimeAdmission = false;
      sourcePurposeComplete = false;
    };
  }
