# Qualifies the genuine funded Controller before admitting operation authority.
{
  lib,
  pkgs,
  systems,
  ...
} @ args: let
  base = import ./sandbox-root-startup.nix args;
  credentialFixture = import ./_broker-session-credential-fixture.nix {inherit lib pkgs;};
  system = base.machines.vm.system.extendModules {
    modules = [
      {
        # Exercise the ordinary Controller/Root profile first. Online Nix has
        # independent provisioned floors and a separate paired startup gate.
        aos.sandbox.nixBroker.enable = lib.mkForce false;
        aos.sandbox.ownershipAuthority.enable = lib.mkForce false;
        aos.sandbox.controllerService.credentials.brokerPlanSigningKey = lib.mkForce null;
        environment.systemPackages = [credentialFixture];
      }
    ];
  };
in
  base
  // {
    name = "sandbox-controller-startup";
    timeout = 3600;
    machines.vm = base.machines.vm // {inherit system;};

    testScript =
      base.testScript
      + ''
        unit = "aos-sandboxd.service"
        credential_root = "/run/controller-startup-credentials"
        node_file = "/run/controller-startup-node"
        fixture = "${credentialFixture}/bin/broker-session-credential-fixture"
        python = "${pkgs.python3}/bin/python3"

        # The external test provisioner chooses the image's declared node and
        # generates fresh, independent session keys after boot. No journal,
        # resource-bank receipt, Root grant or lifecycle state is synthesized.
        write_node = f"from pathlib import Path; Path({node_file!r}).write_bytes(bytes([0x11]) * 16)"
        vm.succeed(f"{python} -c {shlex.quote(write_node)}")
        vm.succeed(
            f"AOS_BSA_QUALIFICATION_ROOT={credential_root} "
            f"AOS_BSA_QUALIFICATION_NODE_FILE={node_file} {fixture} "
            "--ignored --exact handshake::qualification_credentials::"
            "provision_controller_broker_credentials_after_boot "
            "--test-threads=1 --nocapture"
        )
        vm.succeed(
            f"install -m 0400 {credential_root}/node-id "
            "/run/credentials/@system/qualification-node-id"
        )
        for endpoint in ("Host", "Storage", "Mount", "Network"):
            source = f"{credential_root}/sessions/{endpoint.lower()}/client"
            for suffix, filename in (
                ("Manifest", "broker-session-manifest"),
                ("HelloKey", "client-hello-signing-key"),
                ("RecordKey", "client-record-signing-key"),
            ):
                vm.succeed(
                    f"install -m 0400 {source}/{filename} "
                    f"/run/credentials/@system/qualification-{endpoint}-{suffix}"
                )

        try:
            vm.succeed(f"systemctl reset-failed {unit}")
            vm.succeed(f"systemctl start {unit}", timeout=180)
            vm.wait_for_unit(unit, timeout=180)
            vm.succeed("test -S /run/aos/sandboxd/diagnostics.sock")
            pid = int(vm.succeed(f"systemctl show {unit} -p MainPID --value"))
            assert pid > 1
            assert vm.succeed(f"readlink /proc/{pid}/exe").strip() == (
                "${system.config.aos.sandbox.controllerService.package}/bin/aos-sandboxd"
            )
            status = dict(
                line.split(":", 1) for line in vm.succeed(f"cat /proc/{pid}/status").splitlines()
                if ":" in line
            )
            assert status["Uid"].split() == ["811"] * 4, status["Uid"]
            assert status["PPid"].strip() == "1", status["PPid"]
            assert int(status["CapEff"].strip(), 16) == 0, status["CapEff"]
            assert status["NoNewPrivs"].strip() == "1", status["NoNewPrivs"]
            assert status["Seccomp"].strip() == "2", status["Seccomp"]
            assert vm.succeed(f"cat /proc/{pid}/attr/current").strip().split(":")[2] == "aos_sandbox_controller_t"
            vm.succeed("test -s /var/lib/aos/sandboxd/controller.journal")
            vm.succeed("test ! -S /run/aos/sandboxd/public.sock")
        except Exception:
            print(vm.execute(f"systemctl status {unit} --no-pager -l")[1].decode("utf-8", errors="replace"))
            print(vm.execute(f"journalctl -u {unit} --no-pager -n 100")[1].decode("utf-8", errors="replace"))
            raise
      '';
  }
