# Installed-systemd proof for the public Storage repair and inventory boundary.
{
  lib,
  mkSystem,
  pkgs,
  ...
}: let
  selectedFixture = "broker::tests::systemd_storage_rpc_vm_fixture";
  authorityDirectory = "/run/aos/sandbox-storage-authority";
  bootstrapDirectory = "/run/aos/sandbox-storage-bootstrap";
  fixtureDirectory = "/run/aos/storage-rpc-fixture";
  stateDirectory = "/var/lib/aos/sandbox-storage";

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
      count=0
      for candidate in target/debug/deps/aos_sandbox_storage-*; do
        if [ -f "$candidate" ] && [ -x "$candidate" ]; then
          install -m 0755 "$candidate" fixture-bin/aos-sandbox-storage-rpc-tests
          count=$((count + 1))
        fi
      done
      test "$count" -eq 1
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
          AOS_STORAGE_RPC_ROLE=${role} \
          ${fixture}/bin/aos-sandbox-storage-rpc-tests \
          --ignored --exact '${selectedFixture}' --test-threads=1 --nocapture
      '';
    in {
      aos.sandbox.storageWorker = {
        enable = true;
        inherit authorityDirectory;
      };
      aos.sandbox.storageBroker = {
        enable = true;
        inherit authorityDirectory bootstrapDirectory;
      };

      aos.image.budgets = {
        maxRootMiB = 1024;
        maxDownloadMiB = 1152;
      };
      environment.systemPackages = [pkgs.coreutils pkgs.systemd zfs];

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
          ProtectClock = true;
          ProtectControlGroups = true;
          ProtectHome = true;
          ProtectKernelLogs = true;
          ProtectKernelModules = true;
          ProtectKernelTunables = true;
          ProtectProc = "invisible";
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
  name = "sandbox-storage-rpc";
  timeout = 420;
  bootTimeout = 180;

  machines.machine = {inherit system;};

  testScript = ''
    COREUTILS = "${pkgs.coreutils}/bin"
    FINDMNT = "${pkgs.util-linux}/bin/findmnt"
    PIN_ROOT = "/run/aos/sandbox-pins/workspaces"
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

    def replay_claims():
        return int(machine.succeed(
            "find /var/lib/aos-sandbox-workspace-pin-worker "
            "-maxdepth 1 -type f -name 'attempt-*' 2>/dev/null | wc -l"
        ))

    def journal_hash():
        return machine.succeed(
            f"{COREUTILS}/sha256sum '{STATE_JOURNAL}'"
        ).split()[0]

    command_number = 0

    def controller(action, expected):
        global command_number
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

    machine.wait_for_unit("multi-user.target", timeout=120)
    machine.wait_for_unit("aos-sandbox-zfs-ready.service", timeout=30)
    machine.succeed("systemctl is-active --quiet aos-sandbox-zfs-ready.service")
    for unit in (
        "aos-sandbox-zfs-worker.socket",
        "aos-sandbox-workspace-pin-worker.socket",
        "aos-sandbox-workspace-pin-observer.socket",
        "aos-storaged.socket",
    ):
        machine.wait_for_unit(unit, timeout=30)

    machine.succeed(f"{COREUTILS}/truncate -s 512M /run/aos/storage-rpc-pool.img")
    machine.succeed(f"{ZPOOL} create -f -m none aosproof /run/aos/storage-rpc-pool.img")
    machine.succeed(f"{ZFS} create -o mountpoint=none aosproof/aos")
    machine.succeed(f"{ZFS} create -o mountpoint=none aosproof/aos/project")
    machine.succeed(
        f"{ZFS} create -o mountpoint=none -o canmount=off "
        "-o refquota=67108864 -o reservation=1048576 "
        "aosproof/aos/project/rpc-workspace"
    )
    machine.succeed(f"{ZFS} set quota=268435456 aosproof/aos/project")
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
    seed_command = (
        f"{COREUTILS}/env "
        "AOS_STORAGE_RPC_ROLE=seed "
        "AOS_STORAGE_AUTHORITY_DIRECTORY=${authorityDirectory} "
        "AOS_STORAGE_BOOTSTRAP_DIRECTORY=${bootstrapDirectory} "
        "AOS_STORAGE_STATE_DIRECTORY=${stateDirectory} "
        f"AOS_STORAGE_ROOT_GUID={root_guid} "
        f"AOS_STORAGE_ANCESTOR_GUID={ancestor_guid} "
        f"AOS_STORAGE_DATASET_GUID={dataset_guid} "
        "${fixture}/bin/aos-sandbox-storage-rpc-tests "
        "--ignored --exact '${selectedFixture}' --test-threads=1 --nocapture"
    )
    machine.succeed(seed_command, timeout=60)
    seeded_parent_identity = machine.succeed(
        f"{COREUTILS}/stat -c '%d:%i' '{PIN_ROOT}'"
    ).strip()

    assert machine.succeed("id -u aos-sandboxd").strip() == "811"
    assert machine.succeed("id -g aos-sandboxd").strip() == "811"
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
    machine.succeed("systemctl start aos-storaged.service", timeout=150)
    machine.wait_until_succeeds(
        "systemctl is-active --quiet aos-storaged.service", timeout=20
    )
    observer_started = socket_sample("aos-sandbox-workspace-pin-observer.socket")
    worker_started = socket_sample("aos-sandbox-workspace-pin-worker.socket")
    assert observer_started == (observer_before[0] + 1, observer_before[1]), (
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
    for setting in (
        "CapabilityBoundingSet=",
        "NoNewPrivileges=true",
        "PrivateDevices=true",
        "PrivateNetwork=true",
        "ProtectSystem=strict",
        "RestrictAddressFamilies=AF_UNIX",
        "RuntimeDirectory=aos/sandbox-pins/workspaces",
        "RuntimeDirectoryMode=0700",
        "RuntimeDirectoryPreserve=yes",
        "ReadOnlyPaths=${authorityDirectory} ${bootstrapDirectory}",
    ):
        assert setting in installed_service, (setting, installed_service)
    installed_socket = machine.succeed("systemctl cat aos-storaged.socket")
    for setting in (
        "ListenSequentialPacket=/run/aos/sandbox-storage/control.sock",
        "FileDescriptorName=aos-storaged",
        "Accept=no",
        "PassCredentials=yes",
        "PassPIDFD=yes",
        "SocketUser=aos-sandboxd",
        "SocketGroup=aos-sandboxd",
        "SocketMode=0600",
    ):
        assert setting in installed_socket, (setting, installed_socket)
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

    baseline_hash = journal_hash()
    controller("inventory-empty", "inventory-empty")
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
    assert observer_repaired == (observer_started[0] + 1, observer_started[1]), (
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

    stable_hash = journal_hash()
    stable_parent_identity = machine.succeed(
        f"{COREUTILS}/stat -c '%d:%i' '{PIN_ROOT}'"
    ).strip()
    stable_pin_identity = machine.succeed(
        f"{COREUTILS}/stat -c '%d:%i' '{pin}'"
    ).strip()
    machine.succeed("systemctl stop aos-storaged.service")
    machine.succeed(f"test -d '{PIN_ROOT}'")
    machine.succeed(f"test -d '{pin}'")
    assert machine.succeed(
        f"{COREUTILS}/stat -c '%d:%i' '{PIN_ROOT}'"
    ).strip() == stable_parent_identity
    assert machine.succeed(
        f"{COREUTILS}/stat -c '%d:%i' '{pin}'"
    ).strip() == stable_pin_identity

    machine.succeed("systemctl start aos-storaged.service", timeout=150)
    machine.wait_until_succeeds(
        "systemctl is-active --quiet aos-storaged.service", timeout=20
    )
    assert machine.succeed(
        f"{COREUTILS}/stat -c '%d:%i' '{PIN_ROOT}'"
    ).strip() == stable_parent_identity
    assert machine.succeed(
        f"{COREUTILS}/stat -c '%d:%i' '{pin}'"
    ).strip() == stable_pin_identity
    assert journal_hash() == stable_hash
    assert socket_sample("aos-sandbox-workspace-pin-observer.socket") == observer_repaired
    assert socket_sample("aos-sandbox-workspace-pin-worker.socket") == worker_repaired
    assert replay_claims() == 1

    controller("retry", "retry-conflict")
    assert journal_hash() == stable_hash
    assert socket_sample("aos-sandbox-workspace-pin-observer.socket") == observer_repaired
    assert socket_sample("aos-sandbox-workspace-pin-worker.socket") == worker_repaired
    assert replay_claims() == 1
    controller("inventory-live", "inventory-live")
    assert journal_hash() == stable_hash

    machine.succeed("systemctl start aos-storage-rpc-decoy.service", timeout=20)
    assert journal_hash() == stable_hash
    assert socket_sample("aos-sandbox-workspace-pin-observer.socket") == observer_repaired
    assert socket_sample("aos-sandbox-workspace-pin-worker.socket") == worker_repaired
    assert replay_claims() == 1

    controller("exit", "exit")
    machine.wait_until_fails(
        "systemctl is-active --quiet aos-sandboxd.service", timeout=15
    )
    machine.succeed("systemctl stop aos-storaged.service")
    machine.succeed(f"${pkgs.util-linux}/bin/umount -- '{pin}'")
    machine.succeed(f"{ZFS} destroy aosproof/aos/project/rpc-workspace")
    machine.succeed(f"{ZPOOL} destroy aosproof")
  '';
}
