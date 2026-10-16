# Kernel proof is deliberately separate from portable fault-injection tests.
{
  pkgs,
  lib,
  sourceGateWithInputs,
  ...
}: let
  portableNames = [
    "publication_orders_close_seal_sync_link_parent_and_state"
    "invalid_plaintext_never_closes_seals_or_inserts"
    "prepublication_faults_leave_no_canonical_name"
    "parent_sync_failure_withholds_handle_and_rolls_back"
    "binding_failure_withholds_handle_and_rolls_back"
    "adoption_rejects_unsealed_and_conflicting_bindings"
    "lost_state_adoption_revalidates_plaintext_and_rewinds_handle"
    "manifest_identity_remains_distinct_from_all_verified_plaintext_hashes"
    "one_chunk_above_inline_threshold_retains_manifest_identity"
    "manifest_and_claim_domain_are_checked_before_plaintext"
  ];
  sourceGate = sourceGateWithInputs {
    runtimeDeps = [pkgs.rust pkgs.rust.dev] ++ (pkgs.rust.runtimeDeps or []);
    extraBuildDeps = [pkgs.coreutils];
  };
  portable = sourceGate "host-publication-ordering" ''
    cd crates
    cargo test --frozen --offline -p terrane --test host_publication \
      -- --list > "$TMPDIR/publication-tests.txt"
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$TMPDIR/publication-tests.txt" '${builtins.toJSON portableNames}'
    cargo test --frozen --offline -p terrane --test host_publication \
      -- --test-threads=1 > "$out/ordering.log" 2>&1
    python3 ../tests/terrane/check_native_gate.py execution \
      "$out/ordering.log" '${builtins.toJSON portableNames}'
    cat "$out/ordering.log"
  '';
  image = sourceGate "host-publication-kernel-image" ''
    cd crates
    cargo test --frozen --offline -p terrane-fs --features tokio --test host_publish_kernel \
      --no-run --message-format=json > "$TMPDIR/publication-build.jsonl"
    cargo test --frozen --offline -p terrane-fs --features tokio --lib \
      --no-run --message-format=json >> "$TMPDIR/publication-build.jsonl"
    rustc --print target-libdir > "$TMPDIR/publication-rust-libdir"
    python3 - "$TMPDIR/publication-build.jsonl" "$TMPDIR/publication-rust-libdir" "$out" <<'PY'
    import json
    import pathlib
    import shutil
    import sys

    artifacts = [json.loads(line) for line in pathlib.Path(sys.argv[1]).read_text().splitlines()]
    output = pathlib.Path(sys.argv[3])
    (output / "bin").mkdir()
    (output / "lib").mkdir()
    directories = {pathlib.Path(pathlib.Path(sys.argv[2]).read_text().strip())}
    for target, installed in [
            ("host_publish_kernel", "terrane-publication-kernel-tests"),
            ("terrane_fs", "terrane-publication-worker-tests")]:
        binaries = {item["executable"] for item in artifacts
                    if item.get("reason") == "compiler-artifact"
                    and item.get("target", {}).get("name") == target
                    and item.get("profile", {}).get("test") is True
                    and item.get("executable")}
        if len(binaries) != 1:
            raise SystemExit(f"expected exactly one {target} test executable")
        binary = pathlib.Path(next(iter(binaries)))
        shutil.copy2(binary, output / "bin" / installed)
        directories.add(binary.parent)
    for directory in directories:
        for library in directory.glob("*.so*"):
            if library.is_file():
                shutil.copy2(library, output / "lib" / library.name)
    PY
  '';
  testing = import ../../../lib/testing {inherit pkgs lib;};
  native = testing.mkVMTest {
    name = "terrane-host-publication-ext4";
    memory = 1024;
    rootfsDeps = [image pkgs.coreutils pkgs.grep pkgs.util-linux pkgs.e2fsprogs];
    testScript = ''
      mkdir -p /var/lib/terrane-publication /mnt/terrane-publication
      # The loop image lives on the guest's persistent root disk, never /tmp.
      truncate -s 96M /var/lib/terrane-publication/verity.img
      mkfs.ext4 -F -O verity /var/lib/terrane-publication/verity.img
      mount -t ext4 -o loop /var/lib/terrane-publication/verity.img /mnt/terrane-publication
      export TERRANE_PUBLISH_VM_ROOT=/mnt/terrane-publication
      export LD_LIBRARY_PATH="${image}/lib''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
      ${image}/bin/terrane-publication-kernel-tests --list \
        > /var/lib/terrane-publication/inventory.log
      grep -Fx 'disk_ext4_seal_noreplace_recovery_and_domain_isolation: test' \
        /var/lib/terrane-publication/inventory.log
      if ! ${image}/bin/terrane-publication-kernel-tests \
        --ignored --exact disk_ext4_seal_noreplace_recovery_and_domain_isolation \
        --test-threads=1 --nocapture > /var/lib/terrane-publication/result.log 2>&1; then
        cat /var/lib/terrane-publication/result.log
        exit 1
      fi
      cat /var/lib/terrane-publication/result.log
      grep -F 'test result: ok. 1 passed; 0 failed; 0 ignored;' \
        /var/lib/terrane-publication/result.log
      ${image}/bin/terrane-publication-worker-tests --list \
        > /var/lib/terrane-publication/worker-inventory.log
      for worker_case in \
        canceled_waiter_retains_owner_through_actual_binding_durability \
        startup_reports_actual_private_state_recovery_failure \
        pending_restart_rebuilds_lease_and_requires_canonical_adoption \
        pack_pair_reconciles_actual_partial_rename_without_replacing_collision \
        failed_second_unlink_recovers_orphan_index_without_pack_authority \
        prepared_roots_defer_staging_effects_and_retain_actual_exclusion \
        staged_writer_retains_root_exclusion_after_adapter_drop \
        actual_binding_path_failure_rolls_back_before_backing_acknowledgment; do
        worker_selector="publisher_io::worker::tests::$worker_case"
        grep -Fx "$worker_selector: test" /var/lib/terrane-publication/worker-inventory.log
        if ! ${image}/bin/terrane-publication-worker-tests --ignored --exact \
          "$worker_selector" --test-threads=1 --nocapture \
          > /var/lib/terrane-publication/worker-result.log 2>&1; then
          cat /var/lib/terrane-publication/worker-result.log
          exit 1
        fi
        cat /var/lib/terrane-publication/worker-result.log
        grep -F 'test result: ok. 1 passed; 0 failed; 0 ignored;' \
          /var/lib/terrane-publication/worker-result.log
      done
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
      phases = [
        {
          name = "qualify";
          script = ''
            mkdir -p "$out"
            test -e ${portable}/ordering.log
            test -e ${native}
            printf '%s\n' '${name}: portable ordering and disk-backed kernel proof passed' > "$out/result"
          '';
        }
      ];
    };
in {
  host-publish-sequence = combined "host-publish-sequence";
  host-publish-no-replace = combined "host-publish-no-replace";
  host-sealed-immutable = combined "host-sealed-immutable";
  host-sealed-adopt = combined "host-sealed-adopt";
  host-sealed-before-serve = combined "host-sealed-before-serve";
}
