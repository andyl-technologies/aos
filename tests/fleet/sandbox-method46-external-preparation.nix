# Qualifies host-side setup against the production initial transport. The
# enforcing initial producer and its genuine Source remain separate gates.
{
  lib,
  pkgs,
  mkSystem,
  systems,
  ...
} @ args: let
  baseline = import ./sandbox-method46-tpm-transport.nix args;
  preparation = import ./_method46-external-tpm-prepare.nix {inherit pkgs;};
  transport = import ./_method46-tpm-transport-probe.nix {inherit pkgs;};
  command = "${transport}/bin/method46-tpm-transport-probe";
in {
  name = "sandbox-method46-external-preparation";
  timeout = 900;
  inherit (baseline) bootTimeout machines;

  testScript = ''
    import base64
    import hashlib
    import pathlib
    import shlex
    import struct
    import subprocess
    import tempfile
    import time

    vm.wait_for_unit("multi-user.target", timeout=180)
    vm.succeed("test -c /dev/tpmrm0; mkdir -m 0700 /var/lib/method46-external-preparation")
    original_boot = vm.succeed("cat /proc/sys/kernel/random/boot_id").strip()

    with tempfile.TemporaryDirectory(prefix="method46-external-") as scratch:
        scratch = pathlib.Path(scratch)
        state = scratch / "prepared"
        data = scratch / "tpm.sock"
        control = scratch / "tpm.sock.ctrl"

        # Stop and reap both owners before opening the same persistent TPM
        # state externally. No snapshot, reset or replacement state is used.
        vm._stop_runtime_for_relaunch(120)
        assert vm.qemu_proc.poll() is not None
        assert vm.swtpm_proc.poll() is not None
        with (scratch / "external-tpm.log").open("wb") as log:
            backend = subprocess.Popen([
                vm.swtpm_bin, "socket", "--tpm2", f"--tpmstate=dir={vm.tpm_state_dir}",
                f"--server=type=unixio,path={data}", f"--ctrl=type=unixio,path={control}",
                "--flags=not-need-init,startup-clear",
            ], stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 5
                while not data.exists() or not control.exists():
                    assert backend.poll() is None, "external TPM backend exited"
                    assert time.monotonic() < deadline, "external TPM socket timeout"
                    time.sleep(0.02)

                output = subprocess.check_output([
                    "${preparation}/bin/method46-external-tpm-prepare", str(data), str(state),
                ], text=True)
                assert "both indices remain unwritten" in output, output
                records = [state.joinpath(f"endpoint-{role}").read_bytes() for role in (0, 1)]
                assert all(len(record) == 130 and record[66:] == bytes(64) for record in records)
                assert all(record[:32] != bytes(32) and record[32:34] == b"\x00\x0b" for record in records)
                assert records[0][:32] != records[1][:32], "index auth must be independent"
                retained = [hashlib.sha256(record).digest() for record in records]

                # Both existing output and already occupied handles must refuse
                # without changing the original external credential records.
                for output_directory in (state, scratch / "occupied"):
                    refused = subprocess.run([
                        "${preparation}/bin/method46-external-tpm-prepare",
                        str(data), str(output_directory),
                    ], capture_output=True)
                    assert refused.returncode != 0
                assert retained == [
                    hashlib.sha256(state.joinpath(f"endpoint-{role}").read_bytes()).digest()
                    for role in (0, 1)
                ]
                assert list((scratch / "occupied").iterdir()) == []
                subprocess.run([
                    "${pkgs.tpm2-tools}/bin/tpm2_shutdown", "-T", f"swtpm:path={data}", "-c",
                ], check=True)
            finally:
                backend.terminate()
                try:
                    backend.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    backend.kill()
                    backend.wait(timeout=5)

        vm._launch()
        vm.agent.wait_ready(time.monotonic() + 240)
        vm.wait_for_unit("multi-user.target", timeout=180)
        assert vm.succeed("cat /proc/sys/kernel/random/boot_id").strip() != original_boot

        for role, record in enumerate(records):
            path = f"/var/lib/method46-external-preparation/endpoint-{role}"
            encoded = shlex.quote(base64.b64encode(record).decode())
            vm.succeed(f"umask 077; printf %s {encoded} | base64 -d > {path}; sync -f {path}")

            # The unchanged production ESYS reader authenticates these external
            # salts and auth values and reports NVUnwritten after cold restart.
            public = struct.pack(
                ">IHIHH", 0x0180a046 + role, 0x000b, 0x00040044, 0, 32,
            )
            name = "000b" + hashlib.sha256(public).hexdigest()
            expected = f"00040044 {name} {bytes(32).hex()}"
            observed = vm.succeed(f"${command} observe-initial {role} {path}").strip()
            assert observed == expected, (role, observed)
            vm.fail(f"${command} read {role} {path}")

        # A failed repeat of external setup must not invalidate either role's
        # authenticated unwritten observation or mutate the retained records.
        for role in (0, 1):
            path = f"/var/lib/method46-external-preparation/endpoint-{role}"
            digest = vm.succeed(f"sha256sum {path}").split()[0]
            assert digest == retained[role].hex()
  '';
}
