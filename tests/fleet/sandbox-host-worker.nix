# Real transient-unit compilation and payload verification, not readiness minting.
{
  lib,
  mkSystem,
  pkgs,
  ...
}: let
  incarnation = "61616161616161616161616161616161";
  runtimeUnit = "aos-sandbox-${incarnation}.service";
  guardian = "aos-lease-guard-${incarnation}";
  workspace = "/run/aos/sandbox-pins/workspaces/qualification";
  network = "/run/aos/sandbox-pins/netns/qualification";
  testName = "plan::kernel_tests::production_compiler_worker_launch_refresh_and_stop";

  fixture = pkgs.mkCargoPackage {
    pname = "aos-sandbox-host-worker-tests";
    version = "0.1.0";
    src = import ../../pkgs/tools/aos/_workspace-source.nix {inherit lib;};
    cargoDeps = pkgs.aos.passthru.cargoDeps;
    cargoRoot = "crates";
    buildType = "debug";
    cargoBuildCommands = [
      "test --no-run --lib --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-host --features kernel-tests"
    ];
    doCheck = true;
    cargoTestFlags = "-p aos-sandbox-host --lib";
    installBins = false;
    buildDeps = [pkgs.protobuf];
    runtimeDeps = [];
    cargoEnv.PROTOC = "${pkgs.protobuf}/bin/protoc";
    postBuild = ''
      mkdir worker-fixture
      count=0
      for candidate in target/debug/deps/aos_sandbox_host-*; do
        if [ -f "$candidate" ] && [ -x "$candidate" ]; then
          install -m 0755 "$candidate" worker-fixture/aos-sandbox-host-worker-tests
          count=$((count + 1))
        fi
      done
      test "$count" -eq 1
    '';
    postInstall = ''
      mkdir -p "$out/bin"
      install -m 0755 worker-fixture/aos-sandbox-host-worker-tests "$out/bin/"
    '';
  };

  payloadTarget = pkgs.writeTextFile {
    name = "aos-host-worker-payload-target";
    destination = "/default.target";
    text = ''
      [Unit]
      Description=Minimal payload for production worker qualification
      DefaultDependencies=no
      Requires=qualification.service
      After=qualification.service
    '';
  };
  payloadService = pkgs.writeTextFile {
    name = "aos-host-worker-payload-service";
    destination = "/qualification.service";
    text = ''
      [Unit]
      Description=Retain the qualified payload execution
      DefaultDependencies=no

      [Service]
      Type=simple
      ExecStart=${pkgs.coreutils}/bin/sleep infinity
    '';
  };
  root = pkgs.runCommand "aos-host-worker-payload-root" {} ''
    mkdir -p "$out/etc/systemd/system" "$out/sbin" "$out/nix/store" "$out/var"
    cp ${payloadTarget}/default.target "$out/etc/systemd/system/default.target"
    cp ${payloadService}/qualification.service "$out/etc/systemd/system/qualification.service"
    ln -s ${pkgs.systemd}/lib/systemd/systemd "$out/sbin/init"
    printf 'NAME=AOS-host-worker-qualification\nID=aos-host-worker-qualification\n' > "$out/etc/os-release"
    printf '${incarnation}\n' > "$out/etc/machine-id"
  '';

  system = mkSystem [
    ../../systems/server-test.nix
    {
      environment.systemPackages = [pkgs.systemd pkgs.iproute2 pkgs.nftables pkgs.util-linux];
      systemd.slices.aos-sandboxes.description = "Sandbox worker qualification runtimes";

      # The real guardian is a separate gate. This inert dependency permits the
      # production unit's BindsTo/After contract to be exercised without claiming
      # ownership-lease or network-expiry enforcement.
      systemd.services.${guardian} = {
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = "${pkgs.coreutils}/bin/true";
        };
      };

      systemd.services.aos-host-worker-qualification = {
        serviceConfig = {
          Type = "oneshot";
          TimeoutStartSec = 180;
          Environment = [
            "AOS_SANDBOX_WORKER_QUALIFICATION=1"
            "AOS_SANDBOX_QUALIFICATION_NSPAWN=${pkgs.systemd}/bin/systemd-nspawn"
          ];
        };
        script = ''
          set -eu
          mkdir -p ${workspace} /run/aos/sandbox-pins/netns
          cp -a ${root}/. ${workspace}/
          ${pkgs.util-linux}/bin/mount --bind /nix/store ${workspace}/nix/store
          ${pkgs.util-linux}/bin/mount -o remount,bind,ro ${workspace}/nix/store
          ${pkgs.iproute2}/sbin/ip netns add aos-host-worker-qualification
          ${pkgs.iproute2}/sbin/ip netns exec aos-host-worker-qualification \
            ${pkgs.nftables}/sbin/nft 'add table inet qualification'
          ${pkgs.iproute2}/sbin/ip netns exec aos-host-worker-qualification \
            ${pkgs.nftables}/sbin/nft 'add chain inet qualification input { type filter hook input priority 0; policy drop; }'
          ${pkgs.iproute2}/sbin/ip netns exec aos-host-worker-qualification \
            ${pkgs.nftables}/sbin/nft 'add chain inet qualification output { type filter hook output priority 0; policy drop; }'
          touch ${network}
          ${pkgs.util-linux}/bin/mount --bind /run/netns/aos-host-worker-qualification ${network}
          unset LD_LIBRARY_PATH
          ${fixture}/bin/aos-sandbox-host-worker-tests --ignored --exact '${testName}' --list \
            > /run/aos-host-worker-selected-tests
          ${pkgs.grep}/bin/grep -Fx '${testName}: test' /run/aos-host-worker-selected-tests
          exec ${fixture}/bin/aos-sandbox-host-worker-tests --ignored --exact '${testName}' \
            --test-threads=1 --nocapture
        '';
      };
    }
  ];
in {
  name = "sandbox-host-worker";
  timeout = 300;
  machines.vm = {inherit system;};
  testScript = ''
    vm.wait_for_unit("multi-user.target", timeout=120)
    try:
        vm.succeed("systemctl start aos-host-worker-qualification.service", timeout=200)
        vm.fail("systemctl is-active --quiet ${runtimeUnit}")
    finally:
        print(vm.execute("journalctl -u aos-host-worker-qualification.service -u ${runtimeUnit} --no-pager")[1])
        vm.execute("systemctl stop ${runtimeUnit} ${guardian}.service")
  '';
}
