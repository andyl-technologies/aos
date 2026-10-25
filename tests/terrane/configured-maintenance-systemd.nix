##! Runs the rendered Terrane units under the actual guest service manager.
{
  pkgs,
  lib,
  mkSystem,
  initialEnrollmentProof,
  configuredSdkProof,
}: let
  testing = import ../../lib/testing {inherit pkgs lib;};
  root = "/var/lib/terrane-enrollment-proof/data";
  repository = "${root}/configured-maintenance/repository";
  sdkOutput = "${root}/managed-sdk";
  image = initialEnrollmentProof.image;
  sdkImage = configuredSdkProof.image;
  launcher = pkgs.writeTextFile {
    name = "terrane-managed-proof-launcher";
    destination = "/bin/terrane";
    executable = true;
    text = ''
      #!${pkgs.bash}/bin/bash
      set -eu
      exec ${pkgs.python3}/bin/python3 ${image}/share/configured_maintenance_systemd_vm.py actor ${sdkImage} "$@"
    '';
  };
  cache = {
    stateGid = 844;
    capacityBytes = 25165824;
    lowWatermarkBytes = 16777216;
    probationBytes = 65536;
    releaseGraceSeconds = 1;
    scanLimit = 64;
    maxReadBytes = 2097152;
    stateBytes = 65536;
    stateRecords = 64;
    inventoryEntries = 128;
    queuedCommands = 4;
    metadataSyncHoldBytes = 262144;
    publisherWaitBudgetMs = 10000;
    consumerLeaseSeconds = 30;
    portable = {
      maxFileBytes = 67108864;
      maxInputBytes = 268435456;
      maxFiles = 4096;
      maxSelectedBytes = 33554432;
    };
    lower = {
      budgetMs = 10000;
      failureThreshold = 3;
      probeIntervalMs = 5000;
    };
    surfaceIndex = {
      maxEntries = 16;
      maxNodeBytes = 65536;
      maxIndexBytes = 65536;
      capacityBytes = 25165824;
      futureHoldBytes = 327680;
    };
  };
  domain = directory: {
    path = "${root}/positive/${directory}";
    administrativeRoot = "${root}/positive/${directory}-admin";
    quotaOwnerId = "fixture-${directory}";
    wipe = "none";
    inherit cache;
    publisher = {
      retirementGraceMs = 1000;
      chunkProfile = "cdc-1m";
      chunkSeed = lib.concatStrings (builtins.genList (_: "07") 32);
    };
  };
  # Host activation reconciles identities from retained policy rather than the
  # image's seed passwd database. Keep the module's exact Terrane declarations
  # in that policy, including supplementary groups, without rewriting passwd.
  roleIdentity = name: _: name == "terrane" || lib.hasPrefix "terrane-" name;
  identitySource = accounts: let
    policy = {
      users = lib.filterAttrs roleIdentity accounts.users;
      groups = lib.filterAttrs roleIdentity accounts.groups;
    };
  in
    builtins.toFile "terrane-managed-identities.nix" ''
      { ... }: {
        aos.users = builtins.fromJSON ${builtins.toJSON (builtins.toJSON policy)};
      }
    '';
  baseSystem = mkSystem {
    systemName = "terrane-managed-maintenance";
    modules = [
      ../../systems/server-test.nix
      ({config, ...}: {
        aos.activation.stages.host.configuration = [(identitySource config.aos.users)];
        aos.terrane = {
          enable = true;
          package = launcher;
          store = "bucket(file://${repository}/bucket)";
          roles.realize.enable = false;
          localRepository = {
            authorityDirectory = "${repository}/authority";
            issuer = "configured-sdk-fixture";
            keyId = "initial";
            ownerUid = 840;
            storeName = "fixture";
            domain = "public";
            defaultPrivateDomain = "private:fixture";
            currentReference = "refs/heads/_/main";
            policyAuthority = "refs/heads/_/main";
            acl = [
              {
                principal = "fixture-owner";
                verbs = ["read" "fork" "commit" "tag" "admin"];
              }
            ];
            timing = {
              maximumMs = 30000;
              graceMs = 60000;
              marginMs = 10000;
            };
          };
          sdkOutputRoots = [sdkOutput];
          exposures = map (id: {
            inherit id;
            view = "refs/heads/_/main";
            surface = "sdk";
            at = "${sdkOutput}/snapshot-${id}";
            token = "file:${repository}/${id}.cap";
            mode.reader = "pinned";
          }) ["first" "second"];
          hostTier = {
            path = "${root}/layout-admin";
            sizeBytes = 67108864;
            publisher = {
              socketPath = "/run/terrane-publish/publisher.sock";
              serveUid = 840;
              publishUid = 841;
              contentUid = 840;
              contentGid = 845;
              maxConnections = 8;
            };
            quota = {
              socketPath = "${root}/positive/quota.sock";
              configurationEpoch = "00000000000000000000000000000001";
            };
            domains = {
              public = domain "public";
              "private:fixture" = domain "private";
            };
            maintenance = {
              gcUid = 843;
              maxConnections = 2;
              maxRequests = 1;
              connectionTimeoutMs = 3000;
              requestTimeoutMs = 2000;
              sockets = {
                public = "/run/terrane-maintenance/public.sock";
                "private:fixture" = "/run/terrane-maintenance/private.sock";
              };
            };
          };
        };
        # Prepare the real enrollment and signing inputs before starting any role.
        # Unit identities, hardening and dependencies retain the module's values.
        systemd.services.terrane-serve.wantedBy = lib.mkForce [];
        systemd.services.terrane-publish.wantedBy = lib.mkForce [];
        systemd.timers.terrane-gc.wantedBy = lib.mkForce [];
        # The scripts retain the proof images by explicit store references.
        # They are evidence inputs, not installable package catalogs or PATH tools.
        environment.systemPackages = [guest pkgs.python3 pkgs.util-linux pkgs.e2fsprogs pkgs.coreutils pkgs.binutils];
        # Retained debug ELFs and their source belong only to this test image.
        aos.image.testArtifactRoots = [image sdkImage launcher];
        aos.image.rootPartitionMiB = lib.mkForce 3072;
        aos.image.budgets = {
          maxRootMiB = lib.mkForce 3072;
          maxDownloadMiB = lib.mkForce 4096;
        };
      })
    ];
  };
  # The direct-kernel harness boots an ext4 test disk without a UKI root hash.
  # Apply the selected platform's existing kernel-test policy in both retained
  # boot scopes, as fleet tests do, before building its disk and initrd.
  system = baseSystem.extendModules {
    modules = [
      (baseSystem.config.aos.image.platform.testMachineModule {
        bakeAgentUnit = false;
        bootMode = "kernel";
        varProvisioning = "baked";
        varSizeMiB = 256;
        defaultAgentPackage = pkgs.aos-test-agent;
        inherit (pkgs) writeTextFile;
        ip = "192.0.2.1";
        mac = "02:00:00:00:00:01";
        debugMac = "02:00:00:00:00:02";
      })
    ];
  };
  guest = pkgs.writeTextFile {
    name = "terrane-managed-maintenance-guest";
    destination = "/run-proof";
    text = ''
      set -eu
      # Completed-image verification inspects the actual ELF closure in the guest.
      export PATH=${pkgs.binutils}/bin:$PATH

      # Native host activation reconciles the fixture's accounts after early
      # boot tmpfiles. Apply only the module's runtime-directory rules now;
      # enrollment prepares the separate domain layout on the test disk.
      test "$(id -u terrane)" = 840
      test "$(id -u terrane-publish)" = 841
      test "$(id -u terrane-gc)" = 843
      ${pkgs.systemd}/bin/systemd-tmpfiles --create \
        --prefix=/run/terrane-publish --prefix=/run/terrane-maintenance \
        /etc/tmpfiles.d/terrane.conf
      test "$(stat -c '%u:%g:%a' /run/terrane-publish)" = 841:845:2750
      test "$(stat -c '%u:%g:%a' /run/terrane-maintenance)" = 840:846:2750

      mkdir -p /var/lib/terrane-enrollment-proof /var/lib/terrane-host
      chmod 700 /var/lib/terrane-host
      mkdir /var/lib/terrane-host/project-claims
      chmod 700 /var/lib/terrane-host/project-claims
      for directory in /var/lib/terrane-host /var/lib/terrane-host/project-claims; do
        test -d "$directory" && test ! -L "$directory"
        test "$(stat -c '%u:%g:%a' "$directory")" = 0:0:700
      done
      test -z "$(ls -A /var/lib/terrane-host/project-claims)"
      disk=/dev/vdb
      mounted=0
      cleanup() {
        systemctl stop terrane-serve.service terrane-publish.service || return
        if test "$mounted" = 1; then umount ${root} || return; fi
      }
      trap cleanup EXIT
      mkdir -p ${root}
      mkfs.ext4 -F -b 4096 -O project,quota,verity -E quotatype=prjquota "$disk"
      mount -t ext4 -o prjquota "$disk" ${root}
      mounted=1
      chmod 755 ${root}
      mkdir ${root}/scratch
      chmod 700 ${root}/scratch
      export TMPDIR=${root}/scratch
      export TERRANE_INITIAL_FIXTURE_ROOT=${root}
      export TERRANE_INITIAL_VM_IMAGE="$disk"
      export TERRANE_CONFIGURED_SDK_IMAGE=${sdkImage}
      export TERRANE_MANAGED_EXPECTED=/run/terrane-managed-expected.json
      export LD_LIBRARY_PATH="$(cat ${image}/share/runtime-library-path)"
      ${pkgs.python3}/bin/python3 ${image}/share/initial_enrollment_image.py verify ${image} ${pkgs.terrane.src}
      ${pkgs.python3}/bin/python3 ${image}/share/initial_enrollment_vm.py ${image} ${pkgs.terrane.src} maintenance-systemd
    '';
  };
  # Build this exact input in the native builder before running the manager
  # test on a KVM host. Provider checks keep their ordinary derivations.
  withBuildImage = test:
    test
    // {
      passthru =
        test.passthru
        // {
          systemDisk = testing.mkTestDisk {inherit system;};
        };
    };
  expected = {
    source = toString pkgs.terrane.src;
    configuration = system.config.environment.etc."terrane/terrane.toml".text;
    units = builtins.listToAttrs (map (role: {
      name = "terrane-${role}.service";
      value = system.config.system.build.systemdUnitBodies."terrane-${role}.service".text;
    }) ["serve" "publish" "gc"]);
  };
in
  withBuildImage (testing.mkVMTest {
    name = "terrane-native-configured-maintenance-systemd-ext4";
    inherit system;
    timeout = 300;
    memory = 4096;
    extraDisks = [{sizeMiB = 1024;}];
    testScript = ''
      import base64
      expected = ${builtins.toJSON (builtins.toJSON expected)}
      encoded = base64.b64encode(expected.encode()).decode()
      vm.wait_for_unit("multi-user.target", timeout=120)
      vm.succeed(f"printf '%s' {encoded} | base64 -d > /run/terrane-managed-expected.json")
      vm.succeed("${pkgs.bash}/bin/bash ${guest}/run-proof >/dev/console 2>&1", timeout=240)
      vm.succeed("test $(cat /proc/1/comm) = systemd")
    '';
  })
