# Installed-systemd proof for the public Storage Prepare, repair, and inventory boundary.
{
  lib,
  mkSystem,
  pkgs,
  seedInPrivateMountNamespace ? false,
  ...
}: let
  selectedFixture = "broker::tests::systemd_storage_rpc_vm_fixture";
  authorityDirectory = "/run/aos/sandbox-storage-authority";
  bootstrapDirectory = "/run/aos/sandbox-storage-bootstrap";
  resolverPolicyDirectory = "/run/aos/sandbox-storage-resolver-policy";
  fixtureDirectory = "/run/aos/storage-rpc-fixture";
  stateDirectory = "/var/lib/aos/sandbox-storage";
  credentialFixture = import ./_broker-session-credential-fixture.nix {inherit lib pkgs;};
  qualifyTpmFloorSeed = pkgs.stdenv.hostPlatform.isx86_64;
  floorTransportProbe = import ./_method46-tpm-transport-probe.nix {inherit pkgs;};
  seccompProbeChmodStatus =
    if pkgs.stdenv.hostPlatform.isx86_64
    then "chmod"
    else if pkgs.stdenv.hostPlatform.isAarch64
    then "chmod-unavailable"
    else throw "Storage broker seccomp probe does not support ${pkgs.stdenv.hostPlatform.system}";

  seccompProbe = pkgs.mkDerivation {
    pname = "aos-storage-broker-seccomp-probe";
    version = "0.1.0";
    src = null;
    buildDeps = [];
    runtimeDeps = [];
    phases = [
      {
        name = "build";
        script = ''
          mkdir -p "$out/bin"
          $CC -std=c11 -Wall -Wextra -Werror -O2 \
            ${../sandbox/storage-broker-seccomp-probe.c} \
            -o "$out/bin/storage-broker-seccomp-probe"
        '';
      }
    ];
  };

  fixture = pkgs.mkCargoPackage {
    pname = "aos-sandbox-storage-rpc-tests";
    version = "0.1.0";
    src = import ../../pkgs/tools/aos/_workspace-source.nix {inherit lib;};
    cargoDeps = pkgs.aos-storaged.passthru.cargoDeps;
    cargoRoot = "crates";
    buildType = "debug";
    cargoBuildCommands = [
      "test --no-run --lib --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-storage"
    ];
    doCheck = false;
    installBins = false;
    buildDeps = [pkgs.protobuf];
    runtimeDeps = [];
    cargoEnv.PROTOC = "${pkgs.protobuf}/bin/protoc";
    postBuild = ''
      mkdir fixture-bin
      cargo_target_dir="''${CARGO_TARGET_DIR:-target}"
      if [ -n "''${CARGO_BUILD_TARGET:-}" ]; then
        cargo_target_dir="$cargo_target_dir/$CARGO_BUILD_TARGET"
      fi
      count=0
      for candidate in "$cargo_target_dir"/debug/deps/aos_sandbox_storage-*; do
        if [ -f "$candidate" ] && [ -x "$candidate" ]; then
          install -m 0755 "$candidate" fixture-bin/aos-sandbox-storage-rpc-tests
          count=$((count + 1))
        fi
      done
      if [ "$count" -ne 1 ]; then
        echo "expected one Storage unit-test executable under $cargo_target_dir/debug/deps, found $count" >&2
        exit 1
      fi
    '';
    postInstall = ''
      mkdir -p "$out/bin"
      install -m 0755 \
        fixture-bin/aos-sandbox-storage-rpc-tests \
        "$out/bin/"
    '';
  };

  system = mkSystem [
    ../../systems/server-test.nix
    ({config, ...}: let
      zfs = pkgs.zfsForKernel config.system.build.kernel;
      fixtureCommand = role: ''
        ${pkgs.coreutils}/bin/env \
          RUST_MIN_STACK=33554432 \
          AOS_STORAGE_RPC_ROLE=${role} \
          AOS_STORAGE_RPC_CLIENT=${credentialFixture}/bin/broker-session-credential-fixture \
          ${fixture}/bin/aos-sandbox-storage-rpc-tests \
          --ignored --exact '${selectedFixture}' --test-threads=1 --nocapture
      '';
    in {
      # Selection-time fixture modules are not replayed as operator policy.
      # Retain the same identity in the native host activation input as well.
      aos.activation.stages.host.configuration = [
        (builtins.path {
          path = ./_sandbox-controller-identity.nix;
          name = "aos-sandbox-controller-identity.nix";
        })
        (builtins.path {
          path = ./_sandbox-storage-worker-identity.nix;
          name = "aos-sandbox-storage-worker-identity.nix";
        })
      ];
      aos.sandbox.storageWorker = {
        enable = true;
        inherit authorityDirectory;
      };
      aos.sandbox.storageBroker = {
        enable = true;
        inherit authorityDirectory bootstrapDirectory resolverPolicyDirectory;
        # Match the seed and audit binding: four minimum-size identity ranges.
        identityPoolStart = 65536;
        identityPoolSize = 262144;
      };

      # ExecStartPre inherits the exact production service confinement. This
      # test-only probe adds neither a privilege prefix nor a broker RPC.
      systemd.services.aos-storaged.serviceConfig.ExecStartPre = "${seccompProbe}/bin/storage-broker-seccomp-probe";

      aos.image.budgets = {
        maxRootMiB = 1024;
        maxDownloadMiB = 1152;
      };
      environment.systemPackages =
        [pkgs.coreutils pkgs.systemd zfs]
        ++ lib.optional qualifyTpmFloorSeed floorTransportProbe;

      # This fixture replaces the Controller unit without enabling its module.
      # Its real Storage journal still requires an explicit immutable mode pin.
      environment.etc."aos/method46-tpm-floor/controller-mode".text = "legacy-closed-v1\n";

      systemd.services.aos-sandboxd = {
        description = "Storage RPC controller fixture";
        serviceConfig = {
          Type = "simple";
          ExecStart = fixtureCommand "controller";
          User = "aos-sandboxd";
          Group = "aos-sandboxd";
          Slice = "aos-control.slice";
          RuntimeDirectory = "storage-rpc-controller";
          RuntimeDirectoryMode = "0700";
          StateDirectory = "aos/sandboxd/broker-session/storage";
          StateDirectoryMode = "0700";
          UMask = "0077";

          CapabilityBoundingSet = "";
          DevicePolicy = "closed";
          LimitCORE = 0;
          MemoryDenyWriteExecute = true;
          NoNewPrivileges = true;
          PrivateDevices = true;
          PrivateNetwork = true;
          PrivateTmp = true;
          # Match the production Controller: currentness reads the real boot ID.
          ProcSubset = "all";
          ProtectClock = true;
          ProtectControlGroups = true;
          ProtectHome = true;
          ProtectKernelLogs = true;
          ProtectKernelModules = true;
          ProtectKernelTunables = true;
          # Signed handshakes compare the peer pidfd with its real proc stat.
          ProtectProc = "default";
          ProtectSystem = "strict";
          RestrictAddressFamilies = ["AF_UNIX"];
          RestrictNamespaces = true;
          RestrictRealtime = true;
          RestrictSUIDSGID = true;
          TasksMax = 16;
        };
      };

      systemd.services.aos-storage-rpc-decoy = {
        description = "Wrong-cgroup Storage RPC peer fixture";
        serviceConfig = {
          Type = "oneshot";
          ExecStart = fixtureCommand "decoy";
          User = "aos-sandboxd";
          Group = "aos-sandboxd";
          Slice = "aos-control.slice";
          UMask = "0077";

          CapabilityBoundingSet = "";
          DevicePolicy = "closed";
          LimitCORE = 0;
          MemoryDenyWriteExecute = true;
          NoNewPrivileges = true;
          PrivateDevices = true;
          PrivateNetwork = true;
          PrivateTmp = true;
          ProcSubset = "pid";
          ProtectControlGroups = true;
          ProtectSystem = "strict";
          RestrictAddressFamilies = ["AF_UNIX"];
          RestrictNamespaces = true;
          RestrictSUIDSGID = true;
          TasksMax = 8;
        };
      };
    })
  ];
in {
  name =
    if seedInPrivateMountNamespace
    then "sandbox-storage-rpc-stale-scope"
    else "sandbox-storage-rpc";
  timeout = 900;
  bootTimeout = 180;

  # Each signed denial retains its own unresolved history. Independent guests
  # prevent a later positive case from overwriting or adopting that pending cut.
  machines = lib.genAttrs ["machine" "repairConflict" "applyClosed" "prepareConflict" "prepareClosed"] (name: {
    inherit system;
    tpm = qualifyTpmFloorSeed && name == "machine";
  });

  testScript = let
    qualification = ''
      COREUTILS = "${pkgs.coreutils}/bin"
      FINDMNT = "${pkgs.util-linux}/bin/findmnt"
      PIN_ROOT = "/run/aos/sandbox-pins/workspaces"
      SECCOMP_PROBE = "${stateDirectory}/seccomp-probe"
      SEED_IN_PRIVATE_SCOPE = ${
        if seedInPrivateMountNamespace
        then "True"
        else "False"
      }
      SECCOMP_PROBE_MARKER = (
          "AOS_STORAGE_BROKER_SECCOMP_PROBE_PASS "
          "no-setid io-uring-denied openat2-setid-denied "
          "boot-id-read-only openat2 ${seccompProbeChmodStatus} "
          "fchmod fchmodat fchmodat2"
      )
      STATE_JOURNAL = "${stateDirectory}/storage-state.journal"
      ZFS = "${pkgs.zfsForKernel system.config.system.build.kernel}/sbin/zfs"
      ZPOOL = "${pkgs.zfsForKernel system.config.system.build.kernel}/sbin/zpool"

      def socket_sample(unit):
          values = dict(
              line.split("=", 1) for line in machine.succeed(
                  f"systemctl show '{unit}' -p NAccepted -p InvocationID"
              ).splitlines()
          )
          assert values["InvocationID"], values
          return int(values["NAccepted"]), values["InvocationID"]

      def observer_after(previous, additional_calls):
          current = socket_sample("aos-sandbox-workspace-pin-observer.socket")
          assert current == (previous[0] + additional_calls, previous[1]), (
              previous, current, additional_calls,
          )
          return current

      def replay_claims():
          return int(machine.succeed(
              "find /var/lib/aos-sandbox-workspace-pin-worker "
              "-maxdepth 1 -type f -name 'attempt-*' 2>/dev/null | wc -l"
          ))

      def journal_hash():
          return machine.succeed(
              f"{COREUTILS}/sha256sum '{STATE_JOURNAL}'"
          ).split()[0]

      def dataset_snapshot():
          return machine.succeed(
              f"{ZFS} get -Hp -r -o name,property,value "
              "guid,mountpoint,canmount,quota,refquota,reservation,"
              "filesystem_limit,snapshot_limit aosproof/aos"
          )

      command_number = 0

      def controller(action, expected):
          nonlocal command_number
          command_number += 1
          command = f"{command_number} {action}"
          machine.succeed(
              f"printf '%s\\n' '{command}' > /run/storage-rpc-controller/command"
          )
          machine.wait_until_succeeds(
              f"grep -qx '{command_number} ok {expected}' "
              "/run/storage-rpc-controller/result",
              timeout=30,
          )

      def seccomp_probe_passes():
          return int(machine.succeed(
              "journalctl -u aos-storaged.service --no-pager -o cat "
              f"| grep -Fxc '{SECCOMP_PROBE_MARKER}' || true"
          ).strip())

      def storaged_diagnostics():
          for command in (
              "systemctl show aos-sandboxd.service "
              "-p ActiveState -p SubState -p Result -p MainPID "
              "-p ExecMainCode -p ExecMainStatus -p NRestarts",
              "systemctl status aos-sandboxd.service --no-pager -l",
              "journalctl -u aos-sandboxd.service --no-pager -n 200",
              "systemctl show aos-storaged.service "
              "-p ActiveState -p SubState -p Result -p MainPID "
              "-p ExecMainCode -p ExecMainStatus -p NRestarts",
              "systemctl status aos-storaged.service --no-pager -l",
              "journalctl -u aos-storaged.service --no-pager -n 200",
              "journalctl -b -u 'aos-sandbox-zfs-worker@*' "
              "-u 'aos-sandbox-workspace-pin-observer@*' "
              "-u 'aos-sandbox-workspace-pin-worker@*' "
              "-u 'aos-sandbox-guest-root-publisher@*' --no-pager -n 200",
          ):
              status, stdout, stderr = machine.execute(command)
              print(f"storaged diagnostic ({status}): {command}")
              print(stdout.decode("utf-8", errors="replace"))
              print(stderr.decode("utf-8", errors="replace"))

      def start_storaged(action, expected, expected_probe_passes):
          try:
              machine.succeed("systemctl start aos-storaged.service", timeout=150)
              controller(action, expected)
              machine.succeed("systemctl is-active --quiet aos-storaged.service")
              broker_pid = int(machine.succeed(
                  "systemctl show aos-storaged.service -p MainPID --value"
              ).strip())
              assert broker_pid > 1
              # The durable host pins must survive replacement of the broker's
              # confined namespace, rather than depending on that namespace.
              assert machine.succeed(f"readlink /proc/{broker_pid}/ns/mnt").strip() != (
                  machine.succeed("readlink /proc/1/ns/mnt").strip()
              )
              assert seccomp_probe_passes() == expected_probe_passes
          except Exception:
              try:
                  storaged_diagnostics()
              except Exception as diagnostic_error:
                  print(f"storaged diagnostics failed: {diagnostic_error}")
              raise

      def finish():
          controller("exit", "exit")
          machine.wait_until_fails(
              "systemctl is-active --quiet aos-sandboxd.service", timeout=15
          )
          machine.succeed("systemctl stop aos-storaged.service")
          machine.succeed(f"${pkgs.util-linux}/bin/umount -- '{pin}'")
          machine.succeed(f"{ZFS} destroy aosproof/aos/project/rpc-workspace")
          machine.succeed(f"{ZPOOL} destroy aosproof")

      def effect_state():
          return (
              journal_hash(), dataset_snapshot(), replay_claims(),
              socket_sample("aos-sandbox-workspace-pin-observer.socket"),
              socket_sample("aos-sandbox-workspace-pin-worker.socket"),
              socket_sample("aos-sandbox-zfs-worker.socket"),
              machine.succeed(f"{COREUTILS}/stat -c '%d:%i' '{PIN_ROOT}' '{pin}'"),
          )

      def reject_and_stop(action, expected):
          before = effect_state()
          controller(action, expected)
          assert effect_state() == before

          # A client reservation without a signed terminal remains unresolved.
          # A fresh Inventory must not replace it with a fabricated clean history.
          session_journals = (
              "/var/lib/aos/sandboxd/broker-session/storage/session.journal "
              "/var/lib/aos/sandbox-storage/broker-session/session.journal"
          )
          pending = machine.succeed(f"{COREUTILS}/sha256sum {session_journals}")
          controller("inventory-blocked", "inventory-blocked")
          assert machine.succeed(f"{COREUTILS}/sha256sum {session_journals}") == pending
          assert effect_state() == before
          finish()

      machine.wait_for_unit("multi-user.target", timeout=120)
      controller_account = machine.succeed("getent passwd aos-sandboxd").strip().split(":")
      assert controller_account[2:4] == ["811", "811"], controller_account
      machine.wait_for_unit("aos-sandbox-zfs-ready.service", timeout=30)
      machine.succeed("systemctl is-active --quiet aos-sandbox-zfs-ready.service")
      snapshot_metadata_custody = machine.succeed(
          "stat -c '%u:%g:%a' ${stateDirectory}/snapshot-metadata"
      ).strip()
      assert snapshot_metadata_custody == "0:0:700", snapshot_metadata_custody
      for unit in (
          "aos-sandbox-zfs-worker.socket",
          "aos-sandbox-workspace-pin-worker.socket",
          "aos-sandbox-workspace-pin-observer.socket",
          "aos-sandbox-workspace-root-initializer.socket",
          "aos-storaged.socket",
      ):
          try:
              machine.wait_for_unit(unit, timeout=30)
          except Exception:
              for command in (
                  f"systemctl status {unit} --no-pager -l",
                  f"journalctl -b -u {unit} -u systemd-tmpfiles-setup.service --no-pager -n 100",
                  "getent passwd aos-sandboxd",
              ):
                  status, stdout, stderr = machine.execute(command)
                  print(f"startup diagnostic ({status}): {command}")
                  print(stdout.decode("utf-8", errors="replace"))
                  print(stderr.decode("utf-8", errors="replace"))
              raise

      for executable in (
          "${system.config.aos.sandbox.storageBroker.package}/bin/aos-storaged",
          "${system.config.aos.sandbox.storageWorker.package}/bin/aos-sandbox-zfs-worker",
          "${system.config.aos.sandbox.storageWorker.package}/bin/aos-sandbox-workspace-pin-worker",
          "${system.config.aos.sandbox.storageWorker.package}/bin/aos-sandbox-workspace-pin-observer",
          "${system.config.aos.sandbox.storageWorker.package}/bin/aos-sandbox-workspace-root-initializer",
          "${system.config.aos.sandbox.storageWorker.package}/bin/aos-sandbox-guest-root-publisher",
      ):
          status, _, stderr = machine.execute(executable)
          assert status != 0 and b"PR_GET_AOS_NO_SETID" in stderr, (
              executable, status, stderr
          )

      machine.succeed(f"{COREUTILS}/truncate -s 512M /run/aos/storage-rpc-pool.img")
      machine.succeed(f"{ZPOOL} create -f -m none aosproof /run/aos/storage-rpc-pool.img")
      machine.succeed(f"{ZFS} create -o mountpoint=none aosproof/aos")
      machine.succeed(f"{ZFS} create -o mountpoint=none aosproof/aos/project")
      machine.succeed(
          f"{ZFS} create -o mountpoint=none -o canmount=off "
          "-o refquota=67108864 -o reservation=1048576 "
          "aosproof/aos/project/rpc-workspace"
      )
      # Match the complete authenticated ancestor policy before seeding the
      # ambiguous pin attempt; quota alone is not its physical postcondition.
      machine.succeed(
          f"{ZFS} set quota=268435456 filesystem_limit=8 snapshot_limit=16 "
          "aosproof/aos/project"
      )
      root_guid = machine.succeed(
          f"{ZFS} get -Hp -o value guid aosproof/aos"
      ).strip()
      ancestor_guid = machine.succeed(
          f"{ZFS} get -Hp -o value guid aosproof/aos/project"
      ).strip()
      dataset_guid = machine.succeed(
          f"{ZFS} get -Hp -o value guid aosproof/aos/project/rpc-workspace"
      ).strip()
      machine.succeed(
          f"{COREUTILS}/mkdir -p '{PIN_ROOT}' "
          "${authorityDirectory} ${bootstrapDirectory} ${fixtureDirectory} "
          "${stateDirectory}"
      )
      machine.succeed(
          f"{COREUTILS}/chmod 0700 '{PIN_ROOT}' "
          "${authorityDirectory} ${bootstrapDirectory} ${stateDirectory}"
      )
      machine.succeed(f"{COREUTILS}/chmod 0755 ${fixtureDirectory}")
      machine.succeed(f"{COREUTILS}/touch '{SECCOMP_PROBE}'")
      machine.succeed(f"{COREUTILS}/chown 0:0 '{SECCOMP_PROBE}'")
      machine.succeed(f"{COREUTILS}/chmod 0600 '{SECCOMP_PROBE}'")
      seed_command = (
          f"{COREUTILS}/env "
          "AOS_STORAGE_RPC_ROLE=seed "
          "AOS_STORAGE_AUTHORITY_DIRECTORY=${authorityDirectory} "
          "AOS_STORAGE_BOOTSTRAP_DIRECTORY=${bootstrapDirectory} "
          "AOS_STORAGE_RESOLVER_POLICY_DIRECTORY=${resolverPolicyDirectory} "
          "AOS_STORAGE_STATE_DIRECTORY=${stateDirectory} "
          f"AOS_STORAGE_ROOT_GUID={root_guid} "
          f"AOS_STORAGE_ANCESTOR_GUID={ancestor_guid} "
          f"AOS_STORAGE_DATASET_GUID={dataset_guid} "
          "${fixture}/bin/aos-sandbox-storage-rpc-tests "
          "--ignored --exact '${selectedFixture}' --test-threads=1 --nocapture"
      )
      # The alternate case retains a real now-dead mount namespace in the
      # authenticated ambiguous attempt. No boot ID or namespace inode is forged.
      seed_prefix = (
          "${pkgs.util-linux}/bin/unshare --mount --propagation private -- "
          if SEED_IN_PRIVATE_SCOPE else ""
      )
      machine.succeed(seed_prefix + seed_command, timeout=60)
      audit_command = seed_command.replace(
          "AOS_STORAGE_RPC_ROLE=seed", "AOS_STORAGE_RPC_ROLE=audit"
      )
      seeded_parent_identity = machine.succeed(
          f"{COREUTILS}/stat -c '%d:%i' '{PIN_ROOT}'"
      ).strip()

      assert machine.succeed("id -u aos-sandboxd").strip() == "811"
      assert machine.succeed("id -g aos-sandboxd").strip() == "811"
      # Generate the BSA pair after boot. Each side receives only its own keys,
      # at the fixed production custody root and with its actual service owner.
      session_seed = "/run/aos/storage-rpc-session-credentials"
      machine.succeed(
          f"AOS_BSA_QUALIFICATION_ROOT={session_seed} "
          "AOS_BSA_QUALIFICATION_NODE_FILE=${authorityDirectory}/node-id "
          "${credentialFixture}/bin/broker-session-credential-fixture "
          "--ignored --exact handshake::qualification_credentials::"
          "provision_controller_broker_credentials_after_boot "
          "--test-threads=1 --nocapture"
      )
      for role, owner, journal, key_names in (
          ("client", 811, "/var/lib/aos/sandboxd/broker-session/storage",
           ("client-hello-signing-key", "client-record-signing-key")),
          ("broker", 0, "${stateDirectory}/broker-session",
           ("broker-hello-signing-key", "broker-outcome-signing-key")),
      ):
          custody = f"{journal}/custody"
          machine.succeed(f"install -d -o {owner} -g {owner} -m 0700 {journal}")
          machine.succeed(f"install -d -o {owner} -g {owner} -m 0500 {custody}")
          for name in ("broker-session-manifest", *key_names):
              machine.succeed(
                  f"install -o {owner} -g {owner} -m 0400 "
                  f"{session_seed}/sessions/storage/{role}/{name} {custody}/{name}"
              )
      machine.succeed("systemctl start aos-sandboxd.service")
      machine.wait_until_succeeds(
          "systemctl is-active --quiet aos-sandboxd.service", timeout=15
      )
      controller_cgroup = machine.succeed(
          "systemctl show aos-sandboxd.service -p ControlGroup --value"
      ).strip()
      assert controller_cgroup == (
          "/aos.slice/aos-control.slice/aos-sandboxd.service"
      ), controller_cgroup

      observer_before = socket_sample("aos-sandbox-workspace-pin-observer.socket")
      worker_before = socket_sample("aos-sandbox-workspace-pin-worker.socket")
      claims_before = replay_claims()
      baseline_hash = journal_hash()
      assert seccomp_probe_passes() == 0
      # Pending pins cannot yield authoritative empty inventory. The isolated
      # Repair path stays reachable and rejects an unauthenticated request.
      start_storaged("missing-authority", "missing-authority", 1)
      observer_started = socket_sample("aos-sandbox-workspace-pin-observer.socket")
      worker_started = socket_sample("aos-sandbox-workspace-pin-worker.socket")
      # Historical scope cannot be probed through the current namespace. It
      # stays pending until the explicit fresh repair, with no ordinary observer.
      initial_observations = 0 if SEED_IN_PRIVATE_SCOPE else 1
      assert observer_started == (observer_before[0] + initial_observations, observer_before[1]), (
          observer_before,
          observer_started,
      )
      assert worker_started == worker_before, (worker_before, worker_started)
      assert replay_claims() == claims_before == 0
      assert machine.succeed(
          f"{COREUTILS}/stat -c '%d:%i' '{PIN_ROOT}'"
      ).strip() == seeded_parent_identity

      service_values = dict(
          line.split("=", 1) for line in machine.succeed(
              "systemctl show aos-storaged.service "
              "-p User -p Group -p Slice -p ControlGroup -p MainPID"
          ).splitlines()
      )
      assert service_values["User"] == "root", service_values
      assert service_values["Group"] == "root", service_values
      assert service_values["Slice"] == "aos-control.slice", service_values
      assert service_values["ControlGroup"] == (
          "/aos.slice/aos-control.slice/aos-storaged.service"
      ), service_values
      assert int(service_values["MainPID"]) > 1, service_values
      installed_service = machine.succeed("systemctl cat aos-storaged.service")
      exec_start_lines = installed_service.splitlines()
      exec_start_index = next(
          index for index, line in enumerate(exec_start_lines)
          if line.startswith("ExecStart=")
      )
      exec_start_pool = [
          line.strip().removesuffix("\\").strip()
          for line in exec_start_lines[exec_start_index + 3:exec_start_index + 5]
      ]
      assert exec_start_pool == ["65536", "262144"], exec_start_pool
      for setting in (
          "CapabilityBoundingSet=",
          "NoNewPrivileges=true",
          "PrivateDevices=true",
          "PrivateNetwork=true",
          "ProcSubset=all",
          "ProtectSystem=strict",
          "RestrictSUIDSGID=true",
          "RestrictAddressFamilies=AF_UNIX",
          "SystemCallArchitectures=native",
          "SystemCallErrorNumber=EPERM",
          "LimitSTACK=32M",
          "SystemCallFilter=~chmod",
          "SystemCallFilter=~fchmod",
          "SystemCallFilter=~fchmodat",
          "SystemCallFilter=~fchmodat2",
          "SystemCallFilter=~io_uring_setup",
          "SystemCallFilter=~io_uring_enter",
          "SystemCallFilter=~io_uring_register",
          "RuntimeDirectory=aos/sandbox-pins/workspaces",
          "RuntimeDirectoryMode=0700",
          "RuntimeDirectoryPreserve=yes",
          "RequiresMountsFor=${resolverPolicyDirectory}",
          "ReadOnlyPaths=${authorityDirectory}",
          "ReadOnlyPaths=${bootstrapDirectory}",
          "ReadOnlyPaths=-${resolverPolicyDirectory}",
          "ExecStartPre=${seccompProbe}/bin/storage-broker-seccomp-probe",
      ):
          assert setting in installed_service, (setting, installed_service)
      assert "ExecStartPre=+" not in installed_service, installed_service
      guest_root_unit = machine.succeed(
          "systemctl cat aos-sandbox-guest-root-publisher@.service"
      )
      for setting in (
          "RestrictSUIDSGID=true",
          "SystemCallFilter=~io_uring_setup",
          "SystemCallFilter=~io_uring_enter",
          "SystemCallFilter=~io_uring_register",
      ):
          assert setting in guest_root_unit, (setting, guest_root_unit)

      installed_socket = machine.succeed("systemctl cat aos-storaged.socket")
      for setting in (
          "ListenSequentialPacket=/run/aos/sandbox-storage/control.sock",
          "FileDescriptorName=aos-storaged",
          "Accept=false",
          "PassCredentials=true",
          "PassPIDFD=true",
          "SocketUser=aos-sandboxd",
          "SocketGroup=aos-sandboxd",
          "DefaultDependencies=false",
          "SocketMode=0600",
      ):
          assert setting in installed_socket, (setting, installed_socket)
      for property_name in ("After", "Requires"):
          dependencies = machine.succeed(
              f"systemctl show aos-storaged.socket --property={property_name} --value"
          ).split()
          assert "aos-activate.service" in dependencies, dependencies
      assert machine.succeed(
          f"{COREUTILS}/stat -c '%u:%g:%a' /run/aos/sandbox-storage"
      ).strip() == "0:811:710"
      assert machine.succeed(
          f"{COREUTILS}/stat -c '%u:%g:%a' "
          "/run/aos/sandbox-storage/control.sock"
      ).strip() == "811:811:600"
      assert machine.succeed(
          f"{COREUTILS}/stat -c '%u:%g:%a' '{PIN_ROOT}'"
      ).strip() == "0:0:700"

      broker_pid = int(machine.succeed(
          "systemctl show aos-storaged.service --property=MainPID --value"
      ).strip())
      assert broker_pid > 1
      broker_namespace = machine.succeed(f"{COREUTILS}/readlink /proc/{broker_pid}/ns/mnt").strip()
      host_namespace = machine.succeed(f"{COREUTILS}/readlink /proc/1/ns/mnt").strip()
      assert broker_namespace != host_namespace, (broker_namespace, host_namespace)

      assert journal_hash() == baseline_hash
      assert socket_sample("aos-sandbox-workspace-pin-observer.socket") == observer_started
      assert socket_sample("aos-sandbox-workspace-pin-worker.socket") == worker_started
      assert replay_claims() == 0

      controller("missing-authority", "missing-authority")
      assert journal_hash() == baseline_hash
      assert socket_sample("aos-sandbox-workspace-pin-observer.socket") == observer_started
      assert socket_sample("aos-sandbox-workspace-pin-worker.socket") == worker_started
      assert replay_claims() == 0

      controller("repair", "repair")
      observer_repaired = socket_sample("aos-sandbox-workspace-pin-observer.socket")
      worker_repaired = socket_sample("aos-sandbox-workspace-pin-worker.socket")
      # Repair independently observes admission before the effect and reconciles
      # the resulting catalog afterward. Both calls use the same socket lifetime.
      assert observer_repaired == (observer_started[0] + 2, observer_started[1]), (
          observer_started,
          observer_repaired,
      )
      assert worker_repaired == (worker_started[0] + 1, worker_started[1]), (
          worker_started,
          worker_repaired,
      )
      assert replay_claims() == 1
      assert journal_hash() != baseline_hash

      handle = machine.succeed(
          f"{COREUTILS}/od -An -tx1 -v ${fixtureDirectory}/workspace-handle "
          f"| {COREUTILS}/tr -d ' \\n'"
      ).strip()
      assert len(handle) == 64, handle
      pin = f"{PIN_ROOT}/{handle}"
      machine.succeed(f"test -d '{pin}'")
      assert machine.succeed(
          f"{FINDMNT} --raw --noheadings --mountpoint '{pin}' --output TARGET"
      ).splitlines() == [pin]
      controller("inventory-live", "inventory-live")
      # Inventory reobserves physical custody; it does not mutate workspace state.
      observer_current = observer_after(observer_repaired, 1)

      repair_hash = journal_hash()
      stable_parent_identity = machine.succeed(
          f"{COREUTILS}/stat -c '%d:%i' '{PIN_ROOT}'"
      ).strip()
      stable_pin_identity = machine.succeed(
          f"{COREUTILS}/stat -c '%d:%i' '{pin}'"
      ).strip()
      machine.succeed("systemctl stop aos-storaged.service")
      machine.succeed(f"test -d '{PIN_ROOT}'")
      machine.succeed(f"test -d '{pin}'")
      start_storaged("inventory-restarted", "inventory-live", 2)
      # Startup reconciliation and the subsequent Inventory each observe once.
      observer_current = observer_after(observer_current, 2)
      assert journal_hash() == repair_hash
      assert machine.succeed(
          f"{COREUTILS}/stat -c '%d:%i' '{PIN_ROOT}'"
      ).strip() == stable_parent_identity
      assert machine.succeed(
          f"{COREUTILS}/stat -c '%d:%i' '{pin}'"
      ).strip() == stable_pin_identity
      assert socket_sample("aos-sandbox-workspace-pin-observer.socket") == observer_current
      assert socket_sample("aos-sandbox-workspace-pin-worker.socket") == worker_repaired
      assert replay_claims() == 1

      if scenario == "repair-conflict":
          reject_and_stop("retry", "retry-rejected")
          return
      if scenario == "apply-closed":
          reject_and_stop("apply-unavailable", "apply-unavailable")
          return

      controller("inventory-live", "inventory-live")
      observer_current = observer_after(observer_current, 1)
      assert journal_hash() == repair_hash
      assert socket_sample("aos-sandbox-workspace-pin-observer.socket") == observer_current
      assert socket_sample("aos-sandbox-workspace-pin-worker.socket") == worker_repaired
      assert replay_claims() == 1

      prepare_observer = observer_current
      prepare_worker = socket_sample("aos-sandbox-workspace-pin-worker.socket")
      prepare_zfs_worker = socket_sample("aos-sandbox-zfs-worker.socket")
      prepare_claims = replay_claims()
      prepare_datasets = dataset_snapshot()
      prepare_before = journal_hash()
      controller("prepare-one-two-unavailable", "prepare-one-two-unavailable")
      controller("prepare", "prepare")
      prepare_after = journal_hash()
      assert prepare_after != prepare_before
      assert socket_sample("aos-sandbox-workspace-pin-observer.socket") == prepare_observer
      assert socket_sample("aos-sandbox-workspace-pin-worker.socket") == prepare_worker
      assert socket_sample("aos-sandbox-zfs-worker.socket") == prepare_zfs_worker
      assert replay_claims() == prepare_claims == 1
      assert dataset_snapshot() == prepare_datasets

      stable_hash = prepare_after
      machine.succeed("systemctl stop aos-storaged.service")
      machine.succeed(audit_command, timeout=60)
      assert journal_hash() == stable_hash
      machine.succeed(f"test -d '{PIN_ROOT}'")
      machine.succeed(f"test -d '{pin}'")
      assert machine.succeed(
          f"{COREUTILS}/stat -c '%d:%i' '{PIN_ROOT}'"
      ).strip() == stable_parent_identity
      assert machine.succeed(
          f"{COREUTILS}/stat -c '%d:%i' '{pin}'"
      ).strip() == stable_pin_identity

      start_storaged("inventory-restarted", "inventory-live", 3)
      observer_current = observer_after(observer_current, 2)
      assert machine.succeed(
          f"{COREUTILS}/stat -c '%d:%i' '{PIN_ROOT}'"
      ).strip() == stable_parent_identity
      assert machine.succeed(
          f"{COREUTILS}/stat -c '%d:%i' '{pin}'"
      ).strip() == stable_pin_identity
      assert journal_hash() == stable_hash
      assert socket_sample("aos-sandbox-workspace-pin-observer.socket") == observer_current
      assert socket_sample("aos-sandbox-workspace-pin-worker.socket") == worker_repaired
      assert socket_sample("aos-sandbox-zfs-worker.socket") == prepare_zfs_worker
      assert replay_claims() == 1
      assert dataset_snapshot() == prepare_datasets

      if scenario == "prepare-conflict":
          reject_and_stop("prepare-retry", "prepare-retry-rejected")
          return
      assert journal_hash() == stable_hash
      assert socket_sample("aos-sandbox-workspace-pin-observer.socket") == observer_current
      assert socket_sample("aos-sandbox-workspace-pin-worker.socket") == worker_repaired
      assert socket_sample("aos-sandbox-zfs-worker.socket") == prepare_zfs_worker
      assert replay_claims() == 1
      assert dataset_snapshot() == prepare_datasets

      controller("inventory-live", "inventory-live")
      observer_current = observer_after(observer_current, 1)
      assert journal_hash() == stable_hash

      machine.succeed("systemctl start aos-storage-rpc-decoy.service", timeout=20)
      assert journal_hash() == stable_hash
      assert socket_sample("aos-sandbox-workspace-pin-observer.socket") == observer_current
      assert socket_sample("aos-sandbox-workspace-pin-worker.socket") == worker_repaired
      assert replay_claims() == 1

      machine.succeed("systemctl stop aos-storaged.service")
      machine.succeed(audit_command, timeout=60)
      assert journal_hash() == stable_hash
      machine.succeed(
          "${pkgs.coreutils}/bin/mv ${resolverPolicyDirectory} "
          "${resolverPolicyDirectory}.missing"
      )
      start_storaged("inventory-restarted", "inventory-live", 4)
      observer_current = observer_after(observer_current, 2)
      machine.wait_until_succeeds(
          "journalctl -u aos-storaged.service --no-pager "
          "| grep -F 'Storage Prepare disabled: resolver policy is invalid'",
          timeout=20,
      )
      assert journal_hash() == stable_hash
      if scenario == "prepare-closed":
          reject_and_stop("prepare-unavailable", "prepare-unavailable")
          return

      controller("inventory-live", "inventory-live")
      observer_current = observer_after(observer_current, 1)
      assert journal_hash() == stable_hash
      assert socket_sample("aos-sandbox-workspace-pin-observer.socket") == observer_current
      assert socket_sample("aos-sandbox-workspace-pin-worker.socket") == worker_repaired
      assert replay_claims() == 1

      finish()

      ${lib.optionalString qualifyTpmFloorSeed ''
        # Offline provisioning consumes the real, fully replayed namespace-47 cut
        # on each installed endpoint. The offline installer runs only after the
        # external probe authenticates the exact initialized NV value. This grants
        # no method-46 readiness; Required-mode hook qualification is a separate gate.
        machine.succeed(
            "install -d -m 0711 /var/lib/method46-offline; "
            "install -d -m 0700 /var/lib/method46-external; "
            "head -c 16 /dev/urandom > /var/lib/method46-external/deployment-epoch"
        )
        transport = "${floorTransportProbe}/bin/method46-tpm-transport-probe"
        for index, role, owner in ((0, "client", 811), (1, "broker", 0)):
            directory = f"/var/lib/method46-offline/{role}"
            state = f"/var/lib/method46-external/endpoint-{index}"
            machine.succeed(f"install -d -o {owner} -g {owner} -m 0700 {directory}")
            machine.succeed(f"{transport} prepare {index} {state}")
            machine.succeed(
                f"dd if={state} of={directory}/salt-name bs=1 skip=32 count=34 status=none; "
                f"cp /var/lib/method46-external/deployment-epoch {directory}/deployment-epoch; "
                f"chown {owner}:{owner} {directory}/salt-name {directory}/deployment-epoch; "
                f"chmod 0400 {directory}/salt-name {directory}/deployment-epoch"
            )
            stage = (
                "${pkgs.util-linux}/bin/setpriv "
                f"--reuid={owner} --regid={owner} --clear-groups "
                "${pkgs.coreutils}/bin/env RUST_MIN_STACK=33554432 "
                f"AOS_FLOOR_SEED_ROLE={role} AOS_FLOOR_SEED_DIRECTORY={directory} "
                "${credentialFixture}/bin/broker-session-credential-fixture "
                "--ignored --exact recovery::journal::tpm_floor::qualification_seed::"
                "stage_installed_initial_floor --test-threads=1 --nocapture"
            )
            machine.succeed(stage, timeout=30)
            staged_files = " ".join(
                f"{directory}/{name}"
                for name in ("provision", "checkpoint", "extend-input", "expected-nv")
            )
            staged_hashes = machine.succeed(f"sha256sum {staged_files}")
            machine.succeed(f"{transport} initialize {index} {state} {directory}/extend-input")
            machine.succeed(f"{transport} read {index} {state}")
            machine.succeed(
                f"dd if={state} of={directory}/observed-nv bs=1 skip=66 count=32 status=none; "
                f"chown {owner}:{owner} {directory}/observed-nv; "
                f"chmod 0400 {directory}/observed-nv"
            )
            machine.succeed(f"cmp {directory}/expected-nv {directory}/observed-nv")
            machine.fail(stage, timeout=30)
            assert machine.succeed(f"sha256sum {staged_files}") == staged_hashes
            machine.fail(f"{transport} initialize {index} {state} {directory}/extend-input")
            machine.succeed(f"{transport} read {index} {state}")
            install = stage.replace("stage_installed_initial_floor", "install_installed_initial_floor")
            journal_root = (
                "/var/lib/aos/sandboxd/broker-session/storage"
                if role == "client" else "/var/lib/aos/sandbox-storage/broker-session"
            )
            sidecar = f"{journal_root}/session-floor.journal"
            machine.succeed(
                f"cp {directory}/observed-nv {directory}/observed-nv.saved; "
                f"head -c 32 /dev/zero > {directory}/observed-nv"
            )
            machine.fail(install, timeout=30)
            machine.succeed(f"test ! -e {sidecar}")
            machine.succeed(f"test ! -e {sidecar}.lock")
            machine.succeed(f"cat {directory}/observed-nv.saved > {directory}/observed-nv")
            machine.succeed(f"cmp {directory}/expected-nv {directory}/observed-nv")
            machine.succeed(install, timeout=30)
            sidecar_hash = machine.succeed(f"sha256sum {sidecar} {sidecar}.lock")
            machine.fail(install, timeout=30)
            assert machine.succeed(f"sha256sum {sidecar} {sidecar}.lock") == sidecar_hash
            assert machine.succeed(f"sha256sum {staged_files}") == staged_hashes
      ''}
    '';
  in ''
    def qualify(machine, scenario):
    ${lib.concatMapStringsSep "\n" (line: "    " + line) (lib.splitString "\n" qualification)}

    qualify(machine, "positive")
    qualify(repairConflict, "repair-conflict")
    qualify(applyClosed, "apply-closed")
    qualify(prepareConflict, "prepare-conflict")
    qualify(prepareClosed, "prepare-closed")
  '';
}
