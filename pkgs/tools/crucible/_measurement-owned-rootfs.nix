# Trusted private PID1 boot image; it carries identities, never Rust credits.
{
  pkgs,
  lib,
  installedImages,
  operatorPolicy,
  imageInventory,
  sourceManifest,
  workflow,
  imageBytes,
  operatorMode,
}: let
  imageFacts = installedImages.passthru;
  workflowFacts = workflow.passthru;
  actorMainStackBytes = workflowFacts.servicePolicy.actorMainStackBytes;
  actorMainStackKiB = builtins.div actorMainStackBytes 1024;
  registryBytes = workflowFacts.servicePolicy.registry.backingPeakBytes;
  registryInodes = workflowFacts.servicePolicy.registryMaximumInodes;
  catalogBytes = 8589934592;
  catalogInodes = 1048576;
  projectBytes = catalogBytes + registryBytes;
  projectInodes = catalogInodes + registryInodes;
  sqliteBootstrapProof = workflowFacts.sqliteBootstrapProof;
  campaignPolicy = workflowFacts.campaignPolicy;
  componentAuthorities = workflowFacts.componentAuthorities;
  swapBytes =
    if operatorMode == "kernelMeasurement"
    then 4294967296
    else 0;
  projectImageScript = import ./_measurement-project-image.nix {
    inherit pkgs imageBytes projectBytes projectInodes;
  };
  initExecutable = "${installedImages}/bin/crucible-measurement-init";
  actorExecutable = "${installedImages}/bin/crucible-measurement-actor";
  birth = pkgs.writeTextFile {
    name = "crucible-private-actor-birth";
    destination = "/bin/actor-birth";
    executable = true;
    text = ''
      #!${pkgs.bash}/bin/bash
      set -eu
      # This is the actual child PID. The fixed trusted leaf exists before birth.
      # No subshell or helper runs between placement and fresh actor exec.
      printf '%s\n' "$$" > /sys/fs/cgroup/crucible-measurement-actor/guardian/cgroup.procs
      ulimit -n 1024
      # Both limits use the same authored extent carried in the workflow digest.
      # The guest/actor original resident envelope retains this stack purpose.
      ulimit -S -s ${toString actorMainStackKiB}
      ulimit -H -s ${toString actorMainStackKiB}
      exec ${actorExecutable}
    '';
  };
  init = pkgs.writeTextFile {
    name = "crucible-private-parent-pid1";
    destination = "/init";
    executable = true;
    text = ''
      #!/bin/sh
      set -eu
      export PATH=${pkgs.coreutils}/bin:${pkgs.util-linux}/bin:${pkgs.util-linux}/sbin
      mount -t proc proc /proc
      mount -t sysfs sysfs /sys
      mount -t devtmpfs devtmpfs /dev
      # The installed ext4 image carries project quota records. PID1 installs
      # limits only after authenticating the externally held original purpose.
      mount -o remount,prjquota /
      # The native bootstrap proof is conditional on the no-THP birth case.
      # Failure refuses before PID1 can prepare or spawn the actor.
      printf 'never\n' > /sys/kernel/mm/transparent_hugepage/enabled
      mount -t tmpfs tmpfs /run
      mkdir -p /run/crucible
      mount -t tmpfs tmpfs /tmp
      mkdir -p /sys/fs/cgroup
      mount -t cgroup2 cgroup2 /sys/fs/cgroup
      # The complete twenty-GiB guest is externally contained from kernel birth.
      # This fresh actor leaf is a sixteen-GiB subdivision, not another grant.
      printf '+cpu +memory +pids\n' > /sys/fs/cgroup/cgroup.subtree_control
      mkdir /sys/fs/cgroup/crucible-measurement-actor
      printf '17179869184\n' > /sys/fs/cgroup/crucible-measurement-actor/memory.max
      printf '${toString swapBytes}\n' > /sys/fs/cgroup/crucible-measurement-actor/memory.swap.max
      printf '1000000 100000\n' > /sys/fs/cgroup/crucible-measurement-actor/cpu.max
      printf '4096\n' > /sys/fs/cgroup/crucible-measurement-actor/pids.max
      printf '+cpu +memory +pids\n' > /sys/fs/cgroup/crucible-measurement-actor/cgroup.subtree_control
      mkdir /sys/fs/cgroup/crucible-measurement-actor/guardian
      printf '0\n' > /sys/fs/cgroup/crucible-measurement-actor/guardian/memory.swap.max
      mkdir /sys/fs/cgroup/crucible-measurement-actor/workload
      printf '${toString swapBytes}\n' > /sys/fs/cgroup/crucible-measurement-actor/workload/memory.swap.max
      printf '+cpu +memory +pids\n' > /sys/fs/cgroup/crucible-measurement-actor/workload/cgroup.subtree_control
      exec ${initExecutable}
    '';
  };
  dependencies = [installedImages operatorPolicy imageInventory sourceManifest workflow sqliteBootstrapProof campaignPolicy componentAuthorities birth init pkgs.bash pkgs.coreutils pkgs.util-linux];
  closure = import ../../../lib/build/closure-info.nix {inherit pkgs lib;} {
    rootPaths = dependencies;
    pname = "crucible-private-parent-rootfs-closure";
  };
in
  assert builtins.elem operatorMode ["nativeOnly" "kernelMeasurement"];
  assert imageFacts.privateFixture;
  assert workflowFacts.privateFixture && !workflowFacts.runtimeAdmission;
  assert builtins.isInt actorMainStackBytes && actorMainStackBytes > 0 && actorMainStackBytes <= 17179869184;
  assert builtins.div actorMainStackBytes 4096 * 4096 == actorMainStackBytes;
  assert !imageFacts.runtimeAdmission;
  assert builtins.isInt registryBytes && registryBytes >= 1024;
  assert builtins.isInt registryInodes && registryInodes > 0 && registryInodes <= catalogInodes;
  assert builtins.isInt imageBytes && imageBytes > projectBytes && imageBytes <= 68719476736;
    pkgs.mkDerivation {
      pname = "crucible-private-parent-owned-rootfs";
      version = "0";
      src = null;
      outputs = ["out" "metadata"];
      buildDeps = [pkgs.coreutils pkgs.e2fsprogs pkgs.fakeroot pkgs.findutils pkgs.gawk];
      runtimeDeps = dependencies;
      phases = [
        {
          name = "assemble-immutable-owned-rootfs";
          script = ''
            mkdir -p rootfs/nix/store rootfs/etc/crucible rootfs/bin rootfs/proc rootfs/sys rootfs/dev rootfs/run/crucible rootfs/tmp rootfs/var/lib/crucible/measurement
            chmod 0755 rootfs/nix rootfs/nix/store
            chmod 0700 rootfs/var/lib/crucible/measurement
            while IFS= read -r store_path; do
              cp -a "$store_path" rootfs/nix/store/
            done < ${closure}/store-paths
            ln -s ${pkgs.bash}/bin/bash rootfs/bin/sh
            ln -s ${init}/init rootfs/init
            ln -s ${operatorPolicy} rootfs/etc/crucible/measurement-operator.json
            ln -s ${imageInventory} rootfs/etc/crucible/measurement-images.json
            ln -s ${sourceManifest} rootfs/etc/crucible/measurement-source.json
            ln -s ${workflow}/share/crucible/resident-workflow/workflow.json rootfs/etc/crucible/measurement-workflow.json
            ln -s ${workflow}/share/crucible/resident-workflow rootfs/etc/crucible/measurement-inputs
            # Ordinary policy loading rejects a final symlink. Copy exact bytes
            # with an immutable mode; the workflow carries their actual hashes.
            cp ${sqliteBootstrapProof}/share/crucible/sqlite-bootstrap/target.json rootfs/etc/crucible/sqlite-bootstrap-target.json
            cp ${campaignPolicy} rootfs/etc/crucible/measurement-service-policy.toml
            cp ${componentAuthorities} rootfs/etc/crucible/measurement-components.v1
            chmod 0600 rootfs/etc/crucible/measurement-components.v1
            cp ${workflow}/share/crucible/resident-workflow/campaign-policy.json rootfs/etc/crucible/measurement-service-policy.json
            chmod 0444 rootfs/etc/crucible/sqlite-bootstrap-target.json rootfs/etc/crucible/measurement-service-policy.toml rootfs/etc/crucible/measurement-service-policy.json
            ln -s ${birth}/bin/actor-birth rootfs/etc/crucible/measurement-actor-birth
            ${projectImageScript}
          '';
        }
      ];
      passthru = {
        inherit operatorPolicy imageInventory sourceManifest workflow installedImages birth init operatorMode projectBytes projectInodes;
        privateFixture = true;
        runtimeAdmission = false;
      };
    }
