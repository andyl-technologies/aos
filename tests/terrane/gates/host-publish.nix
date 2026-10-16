# Kernel proof is deliberately separate from portable fault-injection tests.
{
  pkgs,
  lib,
  sourceGateWithInputs,
  ...
}: let
  sourceGate = sourceGateWithInputs {
    runtimeDeps = [pkgs.rust pkgs.rust.dev] ++ (pkgs.rust.runtimeDeps or []);
    extraBuildDeps = [pkgs.coreutils];
  };
  portable = sourceGate "host-publication-ordering" ''
    cd crates
    cargo test --frozen --offline -p terrane --test host_publication \
      -- --test-threads=1 > "$out/ordering.log" 2>&1
    cat "$out/ordering.log"
  '';
  image = sourceGate "host-publication-kernel-image" ''
    cd crates
    cargo test --frozen --offline -p terrane-fs --features tokio --test host_publish_kernel \
      --no-run --message-format=json > "$TMPDIR/publication-build.jsonl"
    rustc --print target-libdir > "$TMPDIR/publication-rust-libdir"
    python3 - "$TMPDIR/publication-build.jsonl" "$TMPDIR/publication-rust-libdir" "$out" <<'PY'
    import json
    import pathlib
    import shutil
    import sys

    artifacts = [json.loads(line) for line in pathlib.Path(sys.argv[1]).read_text().splitlines()]
    binaries = [item["executable"] for item in artifacts
                if item.get("reason") == "compiler-artifact"
                and item.get("target", {}).get("name") == "host_publish_kernel"
                and item.get("profile", {}).get("test") is True
                and item.get("executable")]
    if len(binaries) != 1:
        raise SystemExit("expected exactly one publisher kernel test executable")
    output = pathlib.Path(sys.argv[3])
    (output / "bin").mkdir()
    (output / "lib").mkdir()
    shutil.copy2(binaries[0], output / "bin" / "terrane-publication-kernel-tests")
    for directory in [pathlib.Path(binaries[0]).parent,
                      pathlib.Path(pathlib.Path(sys.argv[2]).read_text().strip())]:
        for library in directory.glob("*.so*"):
            if library.is_file():
                shutil.copy2(library, output / "lib" / library.name)
    PY
  '';
  testing = import ../../../lib/testing {inherit pkgs lib;};
  native = testing.mkVMTest {
    name = "terrane-host-publication-ext4";
    memory = 1024;
    rootfsDeps = [image pkgs.coreutils pkgs.util-linux pkgs.e2fsprogs];
    testScript = ''
      mkdir -p /var/lib/terrane-publication /mnt/terrane-publication
      # The loop image lives on the guest's persistent root disk, never /tmp.
      truncate -s 96M /var/lib/terrane-publication/verity.img
      mkfs.ext4 -F -O verity /var/lib/terrane-publication/verity.img
      mount -t ext4 -o loop /var/lib/terrane-publication/verity.img /mnt/terrane-publication
      export TERRANE_PUBLISH_VM_ROOT=/mnt/terrane-publication
      export LD_LIBRARY_PATH="${image}/lib''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
      ${image}/bin/terrane-publication-kernel-tests \
        --ignored --exact disk_ext4_seal_noreplace_recovery_and_domain_isolation \
        --test-threads=1 --nocapture
      umount /mnt/terrane-publication
      rm /var/lib/terrane-publication/verity.img
    '';
  };
  combined = name:
    pkgs.mkDerivation {
      pname = "terrane-gate-${name}";
      version = "0.1.0";
      src = null;
      buildDeps = [pkgs.coreutils];
      phases = [{
        name = "qualify";
        script = ''
          mkdir -p "$out"
          test -e ${portable}/ordering.log
          test -e ${native}
          printf '%s\n' '${name}: portable ordering and disk-backed kernel proof passed' > "$out/result"
        '';
      }];
    };
in {
  host-publish-sequence = combined "host-publish-sequence";
  host-publish-no-replace = combined "host-publish-no-replace";
  host-sealed-immutable = combined "host-sealed-immutable";
  host-sealed-adopt = combined "host-sealed-adopt";
  host-sealed-before-serve = combined "host-sealed-before-serve";
}
