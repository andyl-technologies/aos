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
  timeout = 1200;
  bootTimeout = 240;
  machines.vm = {
    inherit system;
    tpm = true;
  };
  testScript = ''
    import hashlib
    import signal
    import time

    vm.wait_for_unit("multi-user.target", timeout=180)
    vm.succeed("test -c /dev/tpmrm0; mkdir -m 0700 /var/lib/method46-transport")

    for role in (0, 1):
        state = f"/var/lib/method46-transport/endpoint-{role}"
        # Exercise both endpoints' two-stage offline interface, including the
        # production encrypted initial Extend and authenticated WRITTEN Name.
        # These are transport component bytes; installed hooks must supply the
        # canonical cut from their actual journal and provisioned scope.
        seed = f"{state}.initial-cut"
        vm.succeed(f"${command} prepare {role} {state}")
        vm.succeed(f"cp {state} {state}.unwritten")
        vm.fail(f"${command} read {role} {state}")
        vm.succeed(f"printf short > {seed}")
        vm.fail(f"${command} initialize {role} {state} {seed}")
        vm.succeed(f"printf 0123456789abcdef0123456789abcdef > {seed}")
        vm.succeed(f"sync -f {seed}")
        vm.succeed(f"${command} initialize {role} {state} {seed}")
        vm.fail(f"${command} initialize {role} {state} {seed}")
        vm.fail(f"${command} initialize {role} {state}.unwritten {seed}")
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

    # Lose both owners after their first encrypted Extend and authenticated
    # readback, before either checkpoint reaches disk. The external provisioner
    # creates the indices; no ordinary retry may overwrite or adopt their NV.
    vm.succeed("${pkgs.tpm2-tools}/bin/tpm2_clear -T device:/dev/tpmrm0")
    uncheckpointed = []
    seed_bytes = b"0123456789abcdef0123456789abcdef"
    expected_nv = hashlib.sha256(bytes(32) + seed_bytes).hexdigest()
    for role in (0, 1):
        state = f"/var/lib/method46-transport/uncheckpointed-{role}"
        seed = f"{state}.initial-cut"
        vm.succeed(f"${command} prepare {role} {state}")
        vm.succeed(f"printf 0123456789abcdef0123456789abcdef > {seed}")
        vm.succeed(f"sync -f {seed}")
        retained_hash = vm.succeed(f"sha256sum {state} {seed}")
        vm.succeed(
            f"${command} initialize-paused {role} {state} {seed} "
            f"> {state}.paused-log 2>&1 & echo $! > {state}.paused-pid"
        )
        pid = int(vm.succeed(f"cat {state}.paused-pid").strip())
        vm.wait_until_succeeds(f"test $(cut -d ' ' -f 3 /proc/{pid}/stat) = T")
        assert vm.succeed(f"${command} observe {role} {state}").strip() == expected_nv
        assert vm.succeed(f"sha256sum {state} {seed}") == retained_hash
        uncheckpointed.append((role, state, seed, retained_hash))

    # Persist only the prepared inputs. The stopped callers still hold the
    # successful initialization results solely in their volatile originals.
    vm.succeed("sync")
    vm.power_cycle(timeout=240)
    vm.wait_for_unit("multi-user.target", timeout=180)
    for role, state, seed, retained_hash in uncheckpointed:
        assert vm.succeed(f"sha256sum {state} {seed}") == retained_hash
        assert vm.succeed(f"${command} observe {role} {state}").strip() == expected_nv
        vm.fail(f"${command} initialize {role} {state} {seed}")
        vm.fail(f"${command} read {role} {state}")
        vm.fail(f"${command} recover {role} {state}")
        assert vm.succeed(f"${command} observe {role} {state}").strip() == expected_nv
        assert vm.succeed(f"sha256sum {state} {seed}") == retained_hash

    # A separately retained initial intent permits exact cold reconciliation.
    # This exercises transport mechanics only: these test preimages carry no
    # production funding, approval or protected journal-cut authority.
    for cut in ("before", "after"):
        vm.succeed("${pkgs.tpm2-tools}/bin/tpm2_clear -T device:/dev/tpmrm0")
        retained = []
        for role in (0, 1):
            state = f"/var/lib/method46-transport/initial-intent-{cut}-{role}"
            seed = f"{state}.initial-cut"
            vm.succeed(f"${command} prepare {role} {state}")
            vm.succeed(f"printf 0123456789abcdef0123456789abcdef > {seed}")
            vm.succeed(f"sync -f {seed}")
            vm.succeed(
                f"${command} initialize-resumable-{cut} {role} {state} {seed} "
                f"> {state}.paused-log 2>&1 & echo $! > {state}.paused-pid"
            )
            pid = int(vm.succeed(f"cat {state}.paused-pid").strip())
            vm.wait_until_succeeds(f"test $(cut -d ' ' -f 3 /proc/{pid}/stat) = T")
            checkpoint = vm.succeed(f"od -v -An -tx1 -j66 -N32 {state}")
            pending = vm.succeed(f"od -v -An -tx1 -j98 -N32 {state}")
            assert "".join(checkpoint.split()) == "00" * 32, checkpoint
            assert "".join(pending.split()) == seed_bytes.hex(), pending
            if cut == "before":
                vm.fail(f"${command} observe {role} {state}")
            else:
                assert vm.succeed(f"${command} observe {role} {state}").strip() == expected_nv
            retained.append((role, state, seed, vm.succeed(f"sha256sum {state} {seed}")))

        vm.power_cycle(timeout=240)
        vm.wait_for_unit("multi-user.target", timeout=180)
        for role, state, seed, retained_hash in retained:
            assert vm.succeed(f"sha256sum {state} {seed}") == retained_hash
            vm.fail(f"${command} initialize {role} {state} {seed}")
            vm.fail(f"${command} initialize-resumable {role} {state} {seed}")
            vm.fail(f"${command} recover {role} {state}")
            vm.fail(f"${command} recover-initial {1 - role} {state}")
            assert vm.succeed(f"sha256sum {state} {seed}") == retained_hash

            if cut == "after":
                # A conflicting preimage cannot adopt an already-written NV.
                # Restore only this external test's DATA after the refusal.
                vm.succeed(f"cp {state} {state}.saved")
                vm.succeed(
                    "printf RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR | "
                    f"dd of={state} bs=1 seek=98 conv=notrunc status=none"
                )
                conflict_hash = vm.succeed(f"sha256sum {state}")
                vm.fail(f"${command} recover-initial {role} {state}")
                assert vm.succeed(f"sha256sum {state}") == conflict_hash
                assert vm.succeed(f"${command} observe {role} {state}").strip() == expected_nv
                vm.succeed(f"cp {state}.saved {state}")

            vm.succeed(f"${command} recover-initial {role} {state}")
            vm.succeed(f"${command} read {role} {state}")
            assert vm.succeed(f"${command} observe {role} {state}").strip() == expected_nv
            checkpoint = vm.succeed(f"od -v -An -tx1 -j66 -N32 {state}")
            pending = vm.succeed(f"od -v -An -tx1 -j98 -N32 {state}")
            assert "".join(checkpoint.split()) == expected_nv, checkpoint
            assert "".join(pending.split()) == "00" * 32, pending
            completed_hash = vm.succeed(f"sha256sum {state}")
            vm.fail(f"${command} recover-initial {role} {state}")
            vm.fail(f"${command} initialize-resumable {role} {state} {seed}")
            assert vm.succeed(f"sha256sum {state}") == completed_hash
            assert vm.succeed(f"${command} observe {role} {state}").strip() == expected_nv
  '';
}
