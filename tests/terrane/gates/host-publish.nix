# Kernel proof is deliberately separate from portable fault-injection tests.
{
  pkgs,
  lib,
  sourceGateWithInputs,
  nativeSdkGate,
  publisherLocalProof,
  hostCacheProof,
  initialEnrollmentProof,
  moduleEval,
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
    "retained_descriptor_failure_precedes_canonical_publication"
    "retained_descriptor_failure_precedes_adoption_state_effects"
  ];
  nativeNames = [
    "disk_ext4_seal_noreplace_recovery_and_domain_isolation"
    "canceled_waiter_retains_owner_through_actual_binding_durability"
    "startup_reports_actual_private_state_recovery_failure"
    "unsupported_wipe_policy_is_refused_before_directory_effects"
    "pending_restart_rebuilds_lease_and_requires_canonical_adoption"
    "pack_pair_reconciles_actual_partial_rename_without_replacing_collision"
    "failed_second_unlink_recovers_orphan_index_without_pack_authority"
    "prepared_roots_defer_staging_effects_and_retain_actual_exclusion"
    "staged_writer_retains_root_exclusion_after_adapter_drop"
    "actual_binding_path_failure_rolls_back_before_backing_acknowledgment"
  ];
  sourceGate = sourceGateWithInputs {
    runtimeDeps = [pkgs.rust pkgs.rust.dev] ++ (pkgs.rust.runtimeDeps or []);
    extraBuildDeps = [pkgs.coreutils pkgs.binutils];
    nukeRefsKeep = [pkgs.terrane.src];
  };
  portable = sourceGate "host-publication-ordering" ''
    cd crates
    cargo test --frozen --offline -p terrane-sdk --test host_publication \
      -- --list > "$TMPDIR/publication-tests.txt"
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$TMPDIR/publication-tests.txt" '${builtins.toJSON portableNames}'
    cargo test --frozen --offline -p terrane-sdk --test host_publication \
      -- --test-threads=1 > "$out/ordering.log" 2>&1
    python3 ../tests/terrane/check_native_gate.py execution \
      "$out/ordering.log" '${builtins.toJSON portableNames}'
    cat "$out/ordering.log"
  '';
  image =
    sourceGateWithInputs {
      runtimeDeps = [pkgs.rust pkgs.rust.dev] ++ (pkgs.rust.runtimeDeps or []);
      extraBuildDeps = [pkgs.coreutils pkgs.binutils];
      nukeRefsKeep = [pkgs.terrane.src];
      # The owning gate compares the guest ELF with the exact bound Cargo SHA.
      preserveArtifactBytes = true;
    } "host-publication-kernel-image" ''
      cd crates
      cargo build --frozen --offline -p terrane-linux --features native-test-fixtures \
        --example publication_fixture --message-format=json > "$TMPDIR/publication-build.jsonl"
      rustc --print target-libdir > "$TMPDIR/publication-rust-libdir"
      cargo metadata --frozen --offline --no-deps --format-version=1 > "$TMPDIR/publication-packages.json"
      python3 ${../host_publish_image.py} ${../.}
      "$out/bin/terrane-publication-fixture" --list > "$out/all-selectors.txt"
      "$out/bin/terrane-publication-fixture" --fixture-inputs > "$TMPDIR/publication-inputs.txt"
      python3 - "$out" "$TMPDIR/publication-inputs.txt" '${builtins.toJSON nativeNames}' <<'PYASSETS'
      import json
      import pathlib
      import sys

      output = pathlib.Path(sys.argv[1])
      publication = json.loads(sys.argv[3])
      transport = ["transport:native-publisher", "transport:native-client"]
      if (output / "all-selectors.txt").read_text().splitlines() != publication + transport:
          raise SystemExit("complete native example selector inventory changed")
      # Transport has its own guest provisioning and gate. This image runs every
      # publication selector and retains the full inventory for composition review.
      (output / "selectors.txt").write_text("\n".join(publication) + "\n")
      expected = {f"{root}/objects/pack/{byte}/{byte * 16}.{extension}"
                  for root, byte in [("worker-pack-partial-rename", "31"),
                                     ("worker-pack-partial-unlink", "42")]
                  for extension in ["pack", "idx"]}
      expected.add("worker-pack-partial-rename/chunks/51/" + "51" * 32 + ".0")
      seen = set()
      for record in pathlib.Path(sys.argv[2]).read_text().splitlines():
          relative, encoded = record.split("\t")
          if relative not in expected or relative in seen:
              raise SystemExit("unexpected or duplicate fixture asset")
          if len(encoded) > 2097152 or len(encoded) % 2 or any(c not in "0123456789abcdef" for c in encoded):
              raise SystemExit("invalid bounded canonical fixture hex")
          destination = output / "fixtures" / relative
          destination.parent.mkdir(parents=True, exist_ok=True)
          destination.write_bytes(bytes.fromhex(encoded))
          seen.add(relative)
      if seen != expected:
          raise SystemExit("missing native fixture asset")
      PYASSETS
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
      # The production Merkle block is 4096 bytes and must fit one fs block.
      mkfs.ext4 -F -b 4096 -O project,quota,verity -E quotatype=prjquota /var/lib/terrane-publication/verity.img
      trap 'umount /mnt/terrane-publication || true; rm -f /var/lib/terrane-publication/verity.img' EXIT
      umask 077
      mount -t ext4 -o loop,prjquota /var/lib/terrane-publication/verity.img /mnt/terrane-publication
      # Actual projects are bound durably by the external root supervisor
      # while every fixed root is empty, before confined roles can allocate.
      TERRANE_PUBLISH_VM=1 TERRANE_PUBLISH_VM_ROOT=/mnt/terrane-publication \
        ${image}/bin/terrane-publication-fixture --provision-projects
      # All ownership and encoded fixture inputs are installed by the external
      # supervisor before the fresh publisher process drops credentials/caps.
      chown 841:845 /mnt/terrane-publication
      chmod 0700 /mnt/terrane-publication
      for fixture_root in \
        worker-cancellation worker-startup-failure worker-pending-restart \
        worker-pack-partial-rename worker-pack-partial-unlink \
        worker-prepared-roots worker-staged-root-retention worker-binding-path-failure; do
        root="/mnt/terrane-publication/$fixture_root"
        mkdir -p "$root/state/publication" "$root/sealed" "$root/staging" "$root/pending-delete" \
          "$root/chunks" "$root/objects" "$root/quarantine"
        chown 841:845 "$root" "$root/state" "$root/state/publication" \
          "$root/sealed" "$root/staging" "$root/pending-delete"
        chmod 0700 "$root" "$root/state/publication" "$root/sealed" "$root/staging" "$root/pending-delete"
        chmod 0755 "$root/state"
        chown 840:845 "$root/chunks" "$root/objects" "$root/quarantine"
        chmod 2770 "$root/chunks" "$root/objects" "$root/quarantine"
      done
      cp -R ${image}/fixtures/. /mnt/terrane-publication/
      for fixture_root in worker-pack-partial-rename worker-pack-partial-unlink; do
        case "$fixture_root" in
          worker-pack-partial-rename) byte=31 ;;
          worker-pack-partial-unlink) byte=42 ;;
        esac
        root="/mnt/terrane-publication/$fixture_root"
        pack_id="$byte$byte$byte$byte$byte$byte$byte$byte$byte$byte$byte$byte$byte$byte$byte$byte"
        chown 840:845 "$root/objects" "$root/objects/pack" "$root/objects/pack/$byte" \
          "$root/objects/pack/$byte/$pack_id.pack" "$root/objects/pack/$byte/$pack_id.idx"
        chmod 2770 "$root/objects" "$root/objects/pack" "$root/objects/pack/$byte"
        chmod 0640 "$root/objects/pack/$byte/$pack_id.pack" "$root/objects/pack/$byte/$pack_id.idx"
      done
      chunk_root=/mnt/terrane-publication/worker-pack-partial-rename/chunks/51
      chown -R 840:845 "$chunk_root"
      chmod 2770 "$chunk_root"
      chmod 0640 "$chunk_root"/*.0
      ln /mnt/terrane-publication/worker-pack-partial-unlink/objects/pack/42/42424242424242424242424242424242.idx \
        /mnt/terrane-publication/worker-pack-partial-unlink/index-survivor
      TERRANE_PUBLISH_VM=1 TERRANE_PUBLISH_VM_ROOT=/mnt/terrane-publication \
        ${image}/bin/terrane-publication-fixture --verify-projects
      # Each selector is a separate exec before Installed exists. The example
      # then installs the real fixed filter before creating its first runtime.
      while IFS= read -r selector; do
        if ! setpriv --reuid=841 --regid=845 --clear-groups \
          --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
          ${pkgs.coreutils}/bin/env TERRANE_PUBLISH_VM_ROOT=/mnt/terrane-publication \
          ${image}/bin/terrane-publication-fixture "$selector" \
          > /var/lib/terrane-publication/result.log 2>&1; then
          cat /var/lib/terrane-publication/result.log
          exit 1
        fi
        cat /var/lib/terrane-publication/result.log
        grep -Fx "PASS native-publication $selector" /var/lib/terrane-publication/result.log
      done < ${image}/selectors.txt
      umount /mnt/terrane-publication
      rm /var/lib/terrane-publication/verity.img
      trap - EXIT
    '';
  };
  combined = name:
    pkgs.mkDerivation {
      pname = "terrane-gate-${name}";
      version = "0.1.0";
      src = null;
      buildDeps = [pkgs.coreutils pkgs.python3];
      phases = [
        {
          name = "qualify";
          script = ''
            mkdir -p "$out"
            test -e ${portable}/ordering.log
            test -e ${native}
            # The original fixture proves kernel ordering. These separate VMs
            # also require real configured cache recovery and completed native
            # handoff for inline, multi-chunk and direct single-chunk objects.
            test -e ${initialEnrollmentProof.native}
            test -e ${initialEnrollmentProof.reassembly}
            python3 - ${image} ${pkgs.terrane.src} <<'PYIDENTITY'
            import hashlib
            import json
            import pathlib
            import sys

            image = pathlib.Path(sys.argv[1])
            source = pathlib.Path(sys.argv[2])
            identity = json.loads((image / "share/identity.json").read_text())
            profile = identity.get("profile", {})
            target = identity.get("target", {})
            if (identity.get("schema_version") != 1 or identity.get("cargo_profile") != "dev"
                    or identity.get("default_features") is not True
                    or identity.get("requested_features") != ["native-test-fixtures"]
                    or identity.get("features") != ["native-test-fixtures", "tokio"]
                    or identity.get("source") != str(source)
                    or target.get("name") != "publication_fixture" or target.get("kind") != ["example"]
                    or target.get("crate_types") != ["bin"]
                    or profile.get("test") is not False or profile.get("opt_level") != "0"
                    or profile.get("debuginfo") != 2 or profile.get("debug_assertions") is not True
                    or profile.get("overflow_checks") is not True):
                raise SystemExit("native publication image source/profile/features mismatch")
            actual_inputs = {}
            for path in sorted((source / "crates").rglob("*")):
                if path.is_file():
                    relative = path.relative_to(source / "crates").as_posix()
                    if relative != ".cargo/config.toml":
                        actual_inputs[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
            if actual_inputs != identity.get("input_sha256"):
                raise SystemExit("native publication image input hashes mismatch")
            binary = image / "libexec/terrane-publication-fixture"
            if hashlib.sha256(binary.read_bytes()).hexdigest() != identity.get("executable_sha256"):
                raise SystemExit("native publication guest ELF differs from bound Cargo bytes")
            libraries = identity.get("copied_runtime_sha256", {})
            if set(path.name for path in (image / "lib").iterdir()) != set(libraries):
                raise SystemExit("native publication runtime library inventory mismatch")
            for name, digest in libraries.items():
                if hashlib.sha256((image / "lib" / name).read_bytes()).hexdigest() != digest:
                    raise SystemExit("native publication runtime library hash mismatch")
            PYIDENTITY
            printf '%s\n' '${name}: portable ordering, kernel publication, configured recovery and native reassembly handoff passed' > "$out/result"
          '';
        }
      ];
    };
  wipeConfiguration = nativeSdkGate "host-wipe-configuration" ''
    cd crates
    selector=config::tests::sealed_host_tiers_reject_zero_wipe_for_every_role
    "$TERRANE_NATIVE_SDK_TEST_BINARY" --list > "$TMPDIR/wipe-inventory.txt"
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$TMPDIR/wipe-inventory.txt" "[\"$selector\"]"
    "$TERRANE_NATIVE_SDK_TEST_BINARY" "$selector" --exact \
      > "$out/configuration.log" 2>&1 || {
        cat "$out/configuration.log"
        exit 1
      }
    python3 ../tests/terrane/check_native_gate.py execution \
      "$out/configuration.log" "[\"$selector\"]"
  '';
in {
  host-publish-sequence = combined "host-publish-sequence";
  host-publish-no-replace = combined "host-publish-no-replace";
  host-sealed-immutable = combined "host-sealed-immutable";
  host-sealed-adopt = combined "host-sealed-adopt";
  host-sealed-before-serve = combined "host-sealed-before-serve";
  host-wipe-on-release = pkgs.mkDerivation {
    pname = "terrane-gate-host-wipe-on-release";
    version = "0.1.0";
    src = null;
    phases = [
      {
        name = "qualify";
        script = ''
          mkdir -p "$out"
          test -s ${wipeConfiguration}/configuration.log
          test -s ${moduleEval}/result.json
          test -s ${combined "host-publish-sequence"}/result
          printf '%s\n' 'PASS: sealed tiers refuse unsupported wipe policies before effects; explicit none retains kernel sealing (D-128)' > "$out/result"
        '';
      }
    ];
  };
  publisher-sole-writer = import ../publisher-ownership.nix {
    inherit pkgs publisherLocalProof hostCacheProof;
    publication = combined "host-publish-sequence";
  };
}
