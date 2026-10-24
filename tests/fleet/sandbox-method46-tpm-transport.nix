# QEMU/vTPM qualification of the production device/HMAC transport. The probe
# has test-only hierarchy authority; this does not release daemon admission.
{
  lib,
  pkgs,
  mkSystem,
  systems,
  ...
} @ args: let
  probe = import ./_method46-tpm-transport-probe.nix {inherit pkgs;};
  command = "${probe}/bin/method46-tpm-transport-probe";
  installedSystem = (import ./sandbox-root-startup.nix args).machines.vm.system;
  installedKernel = installedSystem.config.system.build.kernel;
  transportSystem = mkSystem [
    ../../systems/server-test.nix
    {
      environment.systemPackages = [probe pkgs.tpm2-tools];
      # Exercise the deployed TPM driver bytes. This lightweight userspace
      # still grants only transport-test provisioning, not installed custody.
      aos.kernel._extraConfigFragments = lib.mkForce installedSystem.config.aos.kernel._extraConfigFragments;
    }
  ];
  system =
    if toString transportSystem.config.system.build.kernel == toString installedKernel
    then transportSystem
    else throw "method46 transport must use the installed Root kernel";
in {
  name = "sandbox-method46-tpm-transport";
  timeout = 900;
  bootTimeout = 240;
  machines.vm = {
    inherit system;
    tpm = true;
  };
  testScript = ''
    import signal
    import time

    vm.wait_for_unit("multi-user.target", timeout=180)
    vm.succeed("test -c /dev/tpmrm0; mkdir -m 0700 /var/lib/method46-transport")

    for role in (0, 1):
        state = f"/var/lib/method46-transport/endpoint-{role}"
        if role == 0:
            # Exercise the two-stage offline interface. These are transport
            # component bytes; installed hooks must supply the canonical cut
            # from their actual authenticated journal and provisioned scope.
            seed = f"{state}.initial-cut"
            vm.succeed(f"${command} prepare {role} {state}")
            vm.succeed(f"cp {state} {state}.unwritten")
            vm.fail(f"${command} read {role} {state}")
            vm.succeed(f"printf short > {seed}")
            vm.fail(f"${command} initialize {role} {state} {seed}")
            vm.succeed(f"printf 0123456789abcdef0123456789abcdef > {seed}")
            vm.succeed(f"${command} initialize {role} {state} {seed}")
            vm.fail(f"${command} initialize {role} {state} {seed}")
            vm.fail(f"${command} initialize {role} {state}.unwritten {seed}")
        else:
            vm.succeed(f"${command} provision {role} {state}")
        vm.fail(f"${command} provision {role} {state}")
        vm.fail(f"${command} provision {role} {state}.occupied")
        vm.succeed(f"test ! -e {state}.occupied")
        vm.succeed(f"${command} read {role} {state}")
        vm.succeed(f"${command} wrong-pin {role} {state}")
        vm.succeed(f"${command} wrong-auth {role} {state}")
        vm.fail(f"${command} read {1 - role} {state}")
        vm.succeed(f"cp {state} {state}.old")
        status, stdout, stderr = vm.execute(f"${command} advance {role} {state}")
        assert status == 77, (role, status, stdout, stderr)
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
        status, stdout, stderr = vm.execute(f"${command} advance {role} {state}")
        assert status == 77, (role, status, stdout, stderr)

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

    for role in (0, 1):
        state = f"/var/lib/method46-transport/endpoint-{role}"
        status, stdout, stderr = vm.execute(f"${command} advance {role} {state}")
        assert status == 77, (role, status, stdout, stderr)

    # Kill both QEMU and swtpm without a clean TPM shutdown. The driver must
    # reuse the same disk and persistent TPM state, rather than a snapshot.
    vm.power_cycle(timeout=240)
    vm.wait_for_unit("multi-user.target", timeout=180)
    for role in (0, 1):
        state = f"/var/lib/method46-transport/endpoint-{role}"
        vm.succeed(f"${command} recover {role} {state}")
        vm.fail(f"${command} recover {role} {state}")
        vm.succeed(f"${command} read {role} {state}")
        vm.fail(f"${command} read {role} {state}.old")

    # Also cut power with preparation durable but the TPM unable to execute
    # the extend. An authenticated predecessor must not be mistaken for the
    # target or silently discard the pending operation.
    state = "/var/lib/method46-transport/endpoint-0"
    vm.succeed(
        f"${command} advance-paused 0 {state} > {state}.paused-log 2>&1 "
        f"& echo $! > {state}.paused-pid"
    )
    pid = int(vm.succeed(f"cat {state}.paused-pid").strip())
    vm.wait_until_succeeds(f"test $(cut -d ' ' -f 3 /proc/{pid}/stat) = T")
    pending = vm.succeed(f"od -v -An -tx1 -j98 -N32 {state}")
    assert "".join(pending.split()) == "51" * 32, pending
    assert vm.swtpm_proc is not None and vm.swtpm_proc.poll() is None
    vm.swtpm_proc.send_signal(signal.SIGSTOP)
    vm.succeed(f"kill -CONT {pid}")
    # The kernel TPM driver may wait uninterruptibly for the stopped device.
    vm.wait_until_succeeds(
        f"case $(cut -d ' ' -f 3 /proc/{pid}/stat) in S|D) exit 0;; *) exit 1;; esac"
    )
    vm.power_cycle(timeout=240)
    vm.wait_for_unit("multi-user.target", timeout=180)
    vm.fail(f"${command} recover 0 {state}")
    vm.succeed(f"${command} read 0 {state}")
    assert vm.succeed(f"od -v -An -tx1 -j98 -N32 {state}") == pending

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
