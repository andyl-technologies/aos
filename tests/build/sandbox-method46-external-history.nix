# Prepares real native history and checks offline installation without mounts.
{
  lib,
  pkgs,
  ...
}: let
  history = import ../fleet/_method46-external-history.nix {inherit lib pkgs;};
in
  pkgs.runCommand "sandbox-method46-external-history-check" {
    buildDeps = [pkgs.python3 pkgs.e2fsprogs history];
    passthru = {inherit history;};
  } ''
    ${pkgs.python3}/bin/python3 - <<'PY'
    import hashlib
    import json
    import pathlib
    import re
    import subprocess

    tools = pathlib.Path("${pkgs.e2fsprogs}/sbin")
    root = pathlib.Path("prepared")
    command = ["${history}/bin/aos-method46-external-history", str(root)]
    subprocess.run(command, check=True)
    cut = json.loads((root / "expected-cut.json").read_bytes())
    assert cut["namespace"] == 47 and cut["live_records"] == 0
    assert cut["next_sequence"] == 7
    expected_head = hashlib.sha256(
        b"aos.sandbox.broker-session.tpm-floor.head.v1\0" + bytes([47])
        + (7).to_bytes(8, "big") + bytes(8)
    ).digest()
    assert bytes(cut["head"]) == expected_head
    assert root.stat().st_mode & 0o7777 == 0o700
    originals = {path.name: path.read_bytes() for path in root.iterdir()}
    assert set(originals) == {"session.journal", "session.journal.lock", "expected-cut.json"}
    assert originals["session.journal"]
    for path in root.iterdir():
        assert path.stat().st_mode & 0o7777 == 0o600
        assert path.stat().st_nlink == 1
    assert subprocess.run(command, capture_output=True).returncode != 0
    assert originals == {path.name: path.read_bytes() for path in root.iterdir()}

    # Exercise the pinned ext2fs filename offset option against the same raw
    # image, with sentinels on both sides. No loop device, mount or image copy.
    offset = 1024 * 1024
    size = 32 * 1024 * 1024
    image = pathlib.Path("disk.raw")
    prefix = b"partition-prefix\0" * 64
    suffix = b"partition-suffix\0" * 64
    with image.open("wb") as stream:
        stream.write(prefix)
        stream.seek(offset + size)
        stream.write(suffix)
    subprocess.run([
        str(tools / "mkfs.ext4"), "-q", "-F", "-b", "4096",
        "-E", f"offset={offset}", str(image), str(size // 4096),
    ], check=True, capture_output=True)

    def debug(command):
        result = subprocess.run([
            str(tools / "debugfs"), "-w", "-R", command,
            f"{image}?offset={offset}",
        ], check=True, capture_output=True, text=True)
        # debugfs can return success for a failed command; readbacks below are
        # the evidence for each mutation, rather than the process status.
        return result.stdout

    debug("mkdir /initial")
    debug("set_inode_field /initial mode 040700")
    for name in ("session.journal", "session.journal.lock"):
        destination = f"/initial/{name}"
        debug(f"write {root / name} {destination}")
        debug(f"set_inode_field {destination} mode 0100600")
        debug(f"set_inode_field {destination} uid 811")
        debug(f"set_inode_field {destination} gid 811")
        label = "aos_method46_controller_main_t" if name == "session.journal" else "aos_method46_controller_lock_t"
        debug(f"ea_set {destination} security.selinux system_u:object_r:{label}:s0")
        readback = pathlib.Path(f"readback-{name}")
        debug(f"dump {destination} {readback}")
        assert readback.read_bytes() == originals[name]
        stat = debug(f"stat {destination}")
        assert re.search(r"Mode:\s+0600", stat), stat
        assert re.search(r"User:\s+811\s+Group:\s+811", stat), stat
        assert re.search(r"Links:\s+1", stat), stat
        assert f"system_u:object_r:{label}:s0" in debug(f"ea_get {destination} security.selinux")
    with image.open("rb") as stream:
        assert stream.read(len(prefix)) == prefix
        stream.seek(offset + size)
        assert stream.read() == suffix
    PY
    mkdir -p "$out"
    printf '%s\n' 'PASS: native committed-deletion history, replay and exclusive output; offset ext4 byte/owner/mode/label readback; no installed Source authority' > "$out/result"
  ''
