# Canonical request and independent-cut comparison; no installed authority claim.
{
  lib,
  pkgs,
  ...
}: let
  approver = import ../fleet/_method46-independent-approval.nix {inherit lib pkgs;};
in
  pkgs.runCommand "sandbox-method46-independent-approval-check" {
    buildDeps = [pkgs.python3 pkgs.openssl approver];
    passthru = {inherit approver;};
  } ''
    ${pkgs.python3}/bin/python3 - <<'PY'
    import hashlib
    import pathlib
    import struct
    import subprocess

    # These shape-only records are independent test vectors. They supply no
    # live main writer, Source, journal history or physical TPM observation.
    header = lambda magic: magic + struct.pack(">HH", 1, 0)
    public = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    salt = b"\x00\x0b" + bytes([0x61]) * 32

    for role, purpose in enumerate(("controller", "storage"), 1):
        root = pathlib.Path(purpose)
        root.mkdir(mode=0o700)
        paths = [root / name for name in (
            "provision", "checkpoint", "request", "seed", "public", "signature",
        )]
        provision, checkpoint, request, key, pin, output = paths
        profile = (
            header(b"AOSBTP01") + bytes([role, 0, 0, 0]) + bytes([1]) * 16
            + bytes([2]) * 16 + bytes([3]) * 32 + hashlib.sha256(salt).digest()
        )
        scope = hashlib.sha256(b"aos.sandbox.broker-session.tpm-floor.scope.v1\0" + profile).digest()
        cut = (
            header(b"AOSBTF01") + struct.pack(">Q", 1) + scope
            + struct.pack(">Q", 7) + bytes([4]) * 32 + bytes(64)
        )
        candidate = (
            header(b"AOSBIP01") + profile + salt
            + struct.pack(">II", 0x0180a045 + role, 0x8100a045 + role) + cut
        )
        provision.write_bytes(header(b"AOSBTD01") + profile + salt + bytes(2))
        checkpoint.write_bytes(cut)
        request.write_bytes(candidate)
        key.write_bytes(seed)
        key.chmod(0o600)
        pin.write_bytes(public)
        command = ["${approver}/bin/aos-method46-independent-approval", purpose, *map(str, paths)]

        subprocess.run(command, check=True)
        original = output.read_bytes()
        assert len(original) == 64 and output.stat().st_mode & 0o7777 == 0o600
        der = root / "public.der"
        der.write_bytes(bytes.fromhex("302a300506032b6570032100") + public)
        subprocess.run([
            "${pkgs.openssl}/bin/openssl", "pkeyutl", "-verify", "-pubin", "-keyform", "DER",
            "-inkey", str(der), "-rawin", "-in", str(request), "-sigfile", str(output),
        ], check=True)

        # Existing decisions cannot be overwritten, including by a valid retry.
        assert subprocess.run(command, capture_output=True).returncode != 0
        assert output.read_bytes() == original
        output.unlink()

        def refuses():
            result = subprocess.run(command, capture_output=True)
            assert result.returncode != 0
            assert not output.exists(), "refused input published a signature"

        for changed in (candidate[:-1], candidate + b"\0"):
            request.write_bytes(changed)
            refuses()
        request.write_bytes(candidate)
        checkpoint.write_bytes(cut[:-1] + b"\x01")
        refuses()
        checkpoint.write_bytes(cut)
        pin.write_bytes(bytes([1]) * 32)
        refuses()
        pin.write_bytes(public)
        key.chmod(0o644)
        refuses()
        key.chmod(0o600)

        linked = root / "linked-seed"
        linked.hardlink_to(key)
        refuses()
        linked.unlink()
        renamed = root / "original-seed"
        key.rename(renamed)
        key.symlink_to(renamed.name)
        refuses()
        key.unlink()
        renamed.rename(key)

        subprocess.run(command, check=True)
        assert output.read_bytes() == original
        assert key.read_bytes() == seed
    PY
    mkdir -p "$out"
    printf '%s\n' 'PASS: both fixed approvals, independent OpenSSL verification and refusal without publication; no installed authority proof' > "$out/result"
  ''
