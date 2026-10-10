# Local paired public-workflow experiment, with each revision's own protocol.
{
  pkgs,
  lib,
  baselineRoot,
  candidateSourceCommit,
  baselineSourceCommit,
  abbaBlocks ? 3,
  experimentId ? "paired-public-workflow-${candidateSourceCommit}",
}: let
  baseline = import baselineRoot {system = pkgs.stdenv.buildPlatform.system;};
  previousGate = baseline.checks.crucible.phase4.packagedCampaignVm;
  currentGate = import ./phase4-packaged-campaign-vm.nix {inherit pkgs lib;};
  previousFlight = previousGate.passthru.campaignFlight;
  currentFlight = currentGate.passthru.campaignFlight;
  previousTemplate = builtins.fromTOML previousGate.passthru.campaignDeploymentText;
  currentTemplate = builtins.fromTOML currentGate.passthru.campaignDeploymentText;
  toml = lib.formats.toml {inherit pkgs lib;};
  invocationCount = 2 * abbaBlocks;

  # A single 128 MiB / one-vCPU world retains the baseline 512 MiB and 2 GiB
  # initial native limits. The current owner's complete peak additionally owns
  # its 1 MiB watcher, 8 MiB source services, one 4 MiB CAS slot, and the
  # actual known_ram_launch_requirements(..., 1) staging of 4 MiB + 16 KiB.
  assignment =
    currentTemplate.assignment_resources
    // {
      resident_peak_bytes = 550502400;
      backing_peak_bytes = 2151694336;
      cpu_slots = 1;
    };
  registry = currentTemplate.operational_registry_resources;
  catalog = currentTemplate.ram_catalog_resources;
  aggregate =
    lib.foldl' (
      total: resources: lib.mapAttrs (dimension: value: value + resources.${dimension}) total
    )
    catalog [registry assignment assignment];
  rootFor = variant: index: "/var/workflow-storage/${variant}-${toString index}";
  cgroupFor = variant: index: "/sys/fs/cgroup/workflow/${variant}-${toString index}";

  # Every invocation has new actual ledger/catalog/attempt namespaces. A
  # previously completed request or retained catalog cannot shortcut a repeat.
  previousConfig = index:
    previousTemplate
    // {
      cgroup_root = cgroupFor "baseline" index;
      run_root = "${rootFor "baseline" index}/run";
      attempt_namespace = "baseline-${toString index}";
      first_project_id = 50000 + index * 10;
      maximum_vcpus = 1;
    };
  currentConfig = index:
    currentTemplate
    // {
      cgroup_root = cgroupFor "candidate" index;
      run_root = "${rootFor "candidate" index}/run";
      attempt_namespace = "candidate-${toString index}";
      first_project_id = 60000 + index * 10;
      ram_catalog_root = "${rootFor "candidate" index}/catalog";
      operational_registry_root = "${rootFor "candidate" index}/registry";
      ram_catalog_project_id = 80000 + index * 2;
      operational_registry_project_id = 80001 + index * 2;
      assignment_resources = assignment;
      retained_template_resources = assignment;
      assignment_limits = currentTemplate.assignment_limits // {vcpus = 1;};
      maximum_vcpus = aggregate.cpu_slots;
      maximum_resident_bytes = aggregate.resident_peak_bytes;
      maximum_disk_bytes = aggregate.backing_peak_bytes;
      maximum_host_metadata_bytes = aggregate.metadata_bytes;
      maximum_host_staging_bytes = aggregate.staging_bytes;
      maximum_paging_io_slots = aggregate.paging_io_slots;
      maximum_host_task_slots = aggregate.task_slots;
      maximum_host_file_descriptors = aggregate.file_descriptors;
    };
  deployment = variant: config: index:
    builtins.toFile "${variant}-workflow-${toString index}.toml" (toml.toTOML (config index));
  previousDeployments = builtins.genList (deployment "baseline" previousConfig) invocationCount;
  currentDeployments = builtins.genList (deployment "candidate" currentConfig) invocationCount;
  manifestPackage = pkgs.writeTextFile {
    name = "public-workflow-performance-manifest";
    destination = "/share/crucible/public-workflow-performance.json";
    text = builtins.toJSON {
      experiment_id = experimentId;
      abba_blocks = abbaBlocks;
      sample_timeout_seconds = 300;
      profile = {
        host = "one disposable source-built x86_64 TCG VM; 4 vCPUs; 4 GiB RAM";
        storage = "same virtio-backed 32 GiB ext4 project-quota image; host cache uncontrolled";
      };
      inputs = {
        kernel = "/var/workflow-kernel";
        root_image = "${currentFlight}/root.raw";
      };
      variants = {
        baseline = {
          source_commit = baselineSourceCommit;
          test_binary = "${previousFlight}/bin/campaign-process-flight";
          cli = "${previousFlight}/bin/crucible";
          qemu = "${baseline.pkgs.qemu-crucible}/bin/qemu-system-x86_64";
          plugin = "${baseline.pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so";
          deployments = map toString previousDeployments;
        };
        candidate = {
          source_commit = candidateSourceCommit;
          test_binary = "${currentFlight}/bin/campaign-process-flight";
          cli = "${currentFlight}/bin/crucible";
          qemu = "${pkgs.qemu-crucible}/bin/qemu-system-x86_64";
          plugin = "${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so";
          deployments = map toString currentDeployments;
        };
      };
    };
  };
  manifest = "${manifestPackage}/share/crucible/public-workflow-performance.json";
  catalogInstaller = import ./_catalog-quota-installer.nix {inherit pkgs lib;};
  setupInvocation = index: ''
    mkdir -m 700 ${rootFor "baseline" index} ${rootFor "candidate" index}
    mkdir -m 700 ${rootFor "baseline" index}/run ${rootFor "candidate" index}/run
    mkdir ${cgroupFor "baseline" index} ${cgroupFor "candidate" index}
    echo '+cpu +memory +pids' > ${cgroupFor "baseline" index}/cgroup.subtree_control
    echo '+cpu +memory +pids' > ${cgroupFor "candidate" index}/cgroup.subtree_control
    ${catalogInstaller}/bin/install-catalog-quota \
      /var/workflow-storage ${rootFor "candidate" index}/catalog \
      ${toString (80000 + index * 2)} ${toString catalog.backing_peak_bytes} \
      ${toString currentTemplate.maximum_ram_catalog_inodes}
    ${catalogInstaller}/bin/install-catalog-quota \
      /var/workflow-storage ${rootFor "candidate" index}/registry \
      ${toString (80001 + index * 2)} ${toString registry.backing_peak_bytes} \
      ${toString currentTemplate.operational_registry_maximum_inodes}
  '';
  rootfs = (import ../../lib/testing/firecracker.nix {inherit pkgs lib;}).mkFirecrackerRootfs {
    pname = "crucible-public-workflow-performance";
    extraWritableMiB = 36864;
    rootfsDeps =
      [
        previousFlight
        currentFlight
        baseline.pkgs.qemu-crucible
        baseline.pkgs.crucible-qemu-plugin
        pkgs.qemu-crucible
        pkgs.crucible-qemu-plugin
        pkgs.linux
        pkgs.python3
        pkgs.coreutils
        pkgs.util-linux
        pkgs.e2fsprogs
        pkgs.grep
        catalogInstaller
        manifestPackage
      ]
      ++ previousDeployments
      ++ currentDeployments;
    testScript = ''
      set -eu
      echo 1 > /proc/sys/vm/unprivileged_userfaultfd
      test "$(cat /proc/sys/vm/unprivileged_userfaultfd)" = 1
      mkdir -p /sys/fs/cgroup
      ${pkgs.util-linux}/bin/mount -t cgroup2 none /sys/fs/cgroup
      echo '+cpu +memory +pids' > /sys/fs/cgroup/cgroup.subtree_control
      mkdir /sys/fs/cgroup/workflow
      echo '+cpu +memory +pids' > /sys/fs/cgroup/workflow/cgroup.subtree_control
      ${pkgs.coreutils}/bin/truncate -s 34359738368 /var/workflow-storage.img
      ${pkgs.e2fsprogs}/sbin/mkfs.ext4 -F -O quota,project -E quotatype=prjquota /var/workflow-storage.img
      mkdir /var/workflow-storage
      ${pkgs.util-linux}/bin/mount -o loop,prjquota /var/workflow-storage.img /var/workflow-storage
      for kernel in ${pkgs.linux}/boot/vmlinuz-*; do
        ${pkgs.coreutils}/bin/ln -s "$kernel" /var/workflow-kernel
      done
      ${lib.concatStringsSep "\n" (builtins.genList setupInvocation invocationCount)}
      # The old process inherits these limits; the current process contract
      # independently sets the same native FD/memlock limits before execution.
      ulimit -n 1024
      ulimit -l 0
      set +e
      ${pkgs.python3}/bin/python3 ${./public-workflow-performance.py} \
        ${manifest} /var/workflow-results > /var/workflow-collector.log 2>&1
      status=$?
      set -e
      cat /var/workflow-collector.log
      for log in /var/workflow-results/*.log; do
        echo "public_workflow_sample_log=$log"
        cat "$log"
      done
      if test -f /var/workflow-results/report.json; then
        echo PUBLIC_WORKFLOW_REPORT_BEGIN
        cat /var/workflow-results/report.json
        echo PUBLIC_WORKFLOW_REPORT_END
      fi
      test "$status" -eq 0
      ${pkgs.util-linux}/bin/umount /var/workflow-storage
      echo PUBLIC_WORKFLOW_COMPARISON_PASS
    '';
  };
in
  assert previousTemplate.version == 2 && currentTemplate.version == 3;
  assert abbaBlocks >= 2 && abbaBlocks <= 3;
    pkgs.mkDerivation {
      pname = "crucible-public-workflow-performance";
      version = "0";
      src = null;
      buildDeps = [pkgs.qemu pkgs.coreutils pkgs.grep pkgs.gawk];
      phases = [
        {
          name = "compare-real-public-workflows";
          script = ''
              set -eu
              mkdir -p "$out"
              cp ${rootfs} rootfs.img
              chmod u+w rootfs.img
              for image in ${pkgs.linux}/boot/vmlinuz-*; do kernel="$image"; done
              ${pkgs.coreutils}/bin/timeout -k 30 4800 \
                ${pkgs.qemu}/bin/qemu-system-x86_64 \
                -machine q35,accel=tcg -cpu max -smp 4 -m 4096 \
                -nodefaults -display none -serial stdio -monitor none -no-reboot \
                -kernel "$kernel" \
                -append "console=ttyS0 reboot=k panic=1 root=/dev/vda rw init=/init net.ifnames=0" \
                -drive file=rootfs.img,format=raw,if=virtio > "$out/serial.raw.log" 2>&1
            ${pkgs.coreutils}/bin/tr -d '\r' < "$out/serial.raw.log" > "$out/serial.log"
            cat "$out/serial.log"
            ${pkgs.gawk}/bin/gawk '
              /^PUBLIC_WORKFLOW_REPORT_BEGIN$/ { begin++; copying=1; next }
              /^PUBLIC_WORKFLOW_REPORT_END$/ { end++; copying=0; next }
              copying { print }
              END { if (begin != 1 || end != 1) exit 1 }
            ' "$out/serial.log" > "$out/report.json"
            ${pkgs.grep}/bin/grep -Fxq PUBLIC_WORKFLOW_COMPARISON_PASS "$out/serial.log"
              ${pkgs.grep}/bin/grep -Fq TEST_RESULT:PASS "$out/serial.log"
              if ${pkgs.grep}/bin/grep -Fq TEST_RESULT:FAIL "$out/serial.log"; then exit 1; fi
          '';
        }
      ];
      passthru = {inherit rootfs manifest previousDeployments currentDeployments;};
    }
