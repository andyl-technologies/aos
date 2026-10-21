# QEMU/vTPM qualification of the production device/HMAC transport. The probe
# has test-only hierarchy authority; this does not release daemon admission.
{
  pkgs,
  mkSystem,
  ...
}: let
  probe = import ./_method46-tpm-transport-probe.nix {inherit pkgs;};
  command = "${probe}/bin/method46-tpm-transport-probe";
  system = mkSystem [
    ../../systems/server-test.nix
    {
      environment.systemPackages = [probe pkgs.tpm2-tools];
    }
  ];
in {
  name = "sandbox-method46-tpm-transport";
  timeout = 900;
  bootTimeout = 240;
  machines.vm = {
    inherit system;
    tpm = true;
  };
  testScript = ''
    import time

    vm.wait_for_unit("multi-user.target", timeout=180)
    vm.succeed("test -c /dev/tpmrm0; mkdir -m 0700 /var/lib/method46-transport")

    for role in (0, 1):
        state = f"/var/lib/method46-transport/endpoint-{role}"
        vm.succeed(f"${command} provision {role} {state}")
        vm.fail(f"${command} provision {role} {state}")
        vm.succeed(f"${command} read {role} {state}")
        vm.succeed(f"${command} wrong-pin {role} {state}")
        vm.succeed(f"${command} wrong-auth {role} {state}")
        vm.fail(f"${command} read {1 - role} {state}")
        vm.succeed(f"cp {state} {state}.old")
        status, _, _ = vm.execute(f"${command} advance {role} {state}")
        assert status == 77, (role, status)
        vm.fail(f"${command} read {role} {state}.old")

    # A new guest boot creates new device connections and salted sessions.
    # Preserve the independently running swtpm, including its advanced NV.
    vm.reboot(timeout=240)
    vm.wait_for_unit("multi-user.target", timeout=180)
    for role in (0, 1):
        state = f"/var/lib/method46-transport/endpoint-{role}"
        vm.succeed(f"${command} recover {role} {state}")
        vm.fail(f"${command} recover {role} {state}")
        vm.succeed(f"${command} read {role} {state}")
        vm.fail(f"${command} read {role} {state}.old")

    for role in (0, 1):
        state = f"/var/lib/method46-transport/endpoint-{role}"
        status, _, _ = vm.execute(f"${command} advance {role} {state}")
        assert status == 77, (role, status)

    # SysRq resets the guest without syncing or stopping services. The vTPM
    # stays independent of the guest disk and retains the advanced indices.
    # This is an unclean guest reset, not a claim about swtpm power-loss media.
    vm.succeed("(sleep 1; echo b > /proc/sysrq-trigger) >/dev/null 2>&1 &")
    vm.agent.close()
    vm.agent.wait_down(time.monotonic() + 90)
    vm.agent.wait_ready(time.monotonic() + 240)
    vm.wait_for_unit("multi-user.target", timeout=180)
    for role in (0, 1):
        state = f"/var/lib/method46-transport/endpoint-{role}"
        vm.succeed(f"${command} recover {role} {state}")
        vm.fail(f"${command} recover {role} {state}")
        vm.succeed(f"${command} read {role} {state}")

    # Only the external test provisioner has hierarchy reset authority.
    vm.succeed("${pkgs.tpm2-tools}/bin/tpm2_clear -T device:/dev/tpmrm0")
    for role in (0, 1):
        state = f"/var/lib/method46-transport/endpoint-{role}"
        vm.fail(f"${command} read {role} {state}")
        vm.succeed(f"${command} provision {role} {state}.new")
        vm.succeed(f"${command} read {role} {state}.new")
        vm.fail(f"${command} read {role} {state}")
  '';
}
