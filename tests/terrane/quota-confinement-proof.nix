# Dedicated kernel evidence, outside gate discovery. This does not qualify the
# complete cache or host-quota-exact gate; the owning gate composes it explicitly.
{pkgs, lib, sourceGateWithInputs}: let
  testing = import ../../lib/testing {inherit pkgs lib;};
  image = sourceGateWithInputs {
    runtimeDeps = [pkgs.rust pkgs.rust.dev] ++ (pkgs.rust.runtimeDeps or []);
    nukeRefsKeep = [pkgs.terrane.src];
  } "quota-confinement-proof-image" ''
    cd crates
    cargo build --frozen --offline -p terrane-fs --features tokio \
      --message-format=json > "$TMPDIR/confinement-artifacts.jsonl"
    python3 - "$TMPDIR/confinement-artifacts.jsonl" "$TMPDIR/confinement-inputs" <<'PY'
    import json
    import pathlib
    import sys

    artifacts = {}
    for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
        item = json.loads(line)
        name = item.get("target", {}).get("name")
        if item.get("reason") == "compiler-artifact" and name in ("terrane_fs", "libc"):
            libraries = [path for path in item.get("filenames", []) if path.endswith(".rlib")]
            if len(libraries) == 1:
                artifacts[name] = libraries[0]
    if set(artifacts) != {"terrane_fs", "libc"}:
        raise SystemExit("missing standalone confinement fixture dependency")
    pathlib.Path(sys.argv[2]).write_text("\n".join(artifacts[name] for name in ("terrane_fs", "libc")) + "\n")
    PY
    terrane_rlib=$(sed -n '1p' "$TMPDIR/confinement-inputs")
    libc_rlib=$(sed -n '2p' "$TMPDIR/confinement-inputs")
    mkdir -p "$out/bin" "$out/lib"
    rustc --edition 2024 terrane-fs/tests/quota_confinement_fixture.rs \
      --extern "terrane_fs=$terrane_rlib" --extern "libc=$libc_rlib" \
      -L "dependency=$(dirname "$terrane_rlib")" \
      -o "$out/bin/quota-confinement-fixture"
    rustc --print target-libdir > "$TMPDIR/confinement-rust-libdir"
    python3 - "$TMPDIR/confinement-rust-libdir" "$out/lib" "$(dirname "$terrane_rlib")" <<'PY'
    import pathlib
    import shutil
    import sys

    for directory in (pathlib.Path(pathlib.Path(sys.argv[1]).read_text().strip()), pathlib.Path(sys.argv[3])):
        for library in directory.glob("*.so*"):
            if library.is_file():
                shutil.copy2(library, pathlib.Path(sys.argv[2]) / library.name)
    PY
  '';
  native = testing.mkVMTest {
    name = "terrane-quota-confinement-ext4";
    memory = 1024;
    rootfsDeps = [image pkgs.coreutils pkgs.util-linux pkgs.e2fsprogs];
    testScript = ''
      set -eu
      mount -o remount,rw /
      mkdir -p /var/lib/terrane-confinement-proof /mnt/terrane-confinement
      truncate -s 96M /var/lib/terrane-confinement-proof/quota.img
      mkfs.ext4 -F -O project,quota,verity -E quotatype=prjquota /var/lib/terrane-confinement-proof/quota.img
      mount -t ext4 -o loop,prjquota /var/lib/terrane-confinement-proof/quota.img /mnt/terrane-confinement
      trap 'umount /mnt/terrane-confinement; rm -f /var/lib/terrane-confinement-proof/quota.img; rmdir /mnt/terrane-confinement /var/lib/terrane-confinement-proof' EXIT
      export TERRANE_QUOTA_CONFINEMENT_VM=1
      export LD_LIBRARY_PATH="${image}/lib"
      ${image}/bin/quota-confinement-fixture owner /mnt/terrane-confinement/owner
    '';
  };
in {inherit image native;}
