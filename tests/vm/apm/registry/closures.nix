# Registry VM checks for closures workflows.
{
  testing,
  pkgs,
  fixtures,
  setupNixPublishEnv,
  closureLeafTool,
  closureRootTool,
  closureWorkflowDeps,
}: {
  # -------------------------------------------------------------------------
  # closure-generate — Closure files created and well-formed
  # -------------------------------------------------------------------------
  closure-generate = testing.mkVMTest {
    name = "apm-closure-generate";
    rootfsDeps = closureWorkflowDeps ++ [pkgs.jq];
    memory = 1024;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixPublishEnv}

      echo "==> Test: real APR closure file generation and structure"

      LEAF_STORE="${closureLeafTool}"
      ROOT_STORE="${closureRootTool}"
      LEAF_HASH=$(basename "$LEAF_STORE" | cut -d- -f1)
      ROOT_HASH=$(basename "$ROOT_STORE" | cut -d- -f1)

      assert_store_valid() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/closure-valid-$label.out" 2>&1; then
          pass "$label valid in store"
        else
          cat "/tmp/closure-valid-$label.out"
          fail "$label should be valid in store"
        fi
      }

      publish_closure_package() {
        store="$1"
        name="$2"
        version="$3"
        $APR publish "$store" \
          --name "$name" \
          --version "$version" \
          --description "Real closure fixture $name" \
          --license MIT \
          --maintainer closure@example.invalid \
          --registry test-reg \
          --no-commit > "/tmp/closure-publish-$name.out" 2>&1 || {
          cat "/tmp/closure-publish-$name.out"
          fail "apr publish $name succeeds"
          return 1
        }
        cat "/tmp/closure-publish-$name.out"
      }

      mount -o remount,rw / || true
      assert_store_valid "$LEAF_STORE" "closure-leaf"
      assert_store_valid "$ROOT_STORE" "closure-root"
      nix-store -q --references "$ROOT_STORE" > /tmp/closure-root-refs.out
      assert_file_contains /tmp/closure-root-refs.out "$LEAF_STORE" \
        "closure-root has a real Nix reference to closure-leaf"

      $APR create test-reg
      REG_DIR="$REG_STORAGE/test-reg"

      publish_closure_package "$LEAF_STORE" closure-leaf 1.0.0
      publish_closure_package "$ROOT_STORE" closure-root 1.0.0
      git -C "$REG_DIR" add -A
      git -C "$REG_DIR" commit -m "publish real closure packages"

      assert_file_exists "$REG_DIR/packages/c/closure-leaf.toml" \
        "published closure-leaf package metadata exists"
      assert_file_exists "$REG_DIR/packages/c/closure-root.toml" \
        "published closure-root package metadata exists"
      LEAF_FILE="$REG_DIR/store/$(printf %.2s "$LEAF_HASH")/$LEAF_HASH"
      ROOT_FILE="$REG_DIR/store/$(printf %.2s "$ROOT_HASH")/$ROOT_HASH"
      assert_file_exists "$LEAF_FILE" \
        "closure-leaf store record exists"
      assert_file_exists "$ROOT_FILE" \
        "closure-root store record exists"

      # Each store record opens with a realisation header — either a
      # content-addressed line ("ca:sha256:<ca> nar:sha256:<nar>:<size>") or,
      # for IA-only paths, a bare "nar:sha256:<nar>:<size>". The path's own
      # ia-hash is the filename, never part of the record body.
      LEAF_FIRST_TOKEN=$(head -1 "$LEAF_FILE" | cut -d' ' -f1)
      case "$LEAF_FIRST_TOKEN" in
        ca:sha256:* | nar:sha256:*)
          pass "closure-leaf store record starts with a realisation header" ;;
        *)
          fail "closure-leaf store record should start with a realisation header, got $LEAF_FIRST_TOKEN"
          cat "$LEAF_FILE" ;;
      esac

      ROOT_FIRST_TOKEN=$(head -1 "$ROOT_FILE" | cut -d' ' -f1)
      case "$ROOT_FIRST_TOKEN" in
        ca:sha256:* | nar:sha256:*)
          pass "closure-root store record starts with a realisation header" ;;
        *)
          fail "closure-root store record should start with a realisation header, got $ROOT_FIRST_TOKEN"
          cat "$ROOT_FILE" ;;
      esac

      # The leaf appears as an "ia:" dependency edge in the root record. Edge
      # lines are indented, so match the hash anywhere on the line (no anchor).
      if grep -q "$LEAF_HASH" "$ROOT_FILE"; then
        pass "closure-root store record lists closure-leaf as a dependency edge"
      else
        fail "closure-root store record missing closure-leaf dependency edge"
        cat "$ROOT_FILE"
      fi

      for ref_path in $(nix-store -q --references "$ROOT_STORE"); do
        ref_hash=$(basename "$ref_path" | cut -d- -f1)
        # Self-references are excluded from the edge set (the path's own hash
        # is the filename, not a record edge).
        if [ "$ref_hash" = "$ROOT_HASH" ]; then
          continue
        fi
        assert_file_contains "$ROOT_FILE" "$ref_hash" \
          "closure-root store record includes direct reference $ref_hash"
      done

      echo "==> Exercise APR store graph maintenance commands"
      $APR --json store verify --registry test-reg \
        > /tmp/store-verify.json
      ${pkgs.jq}/bin/jq -e '.action == "store_verify" and .errors == 0' \
        /tmp/store-verify.json >/dev/null
      $APR --json store verify --deep --registry test-reg \
        > /tmp/store-verify-deep.json
      ${pkgs.jq}/bin/jq -e \
        '.action == "store_verify" and .errors == 0 and .deep_checked > 0' \
        /tmp/store-verify-deep.json >/dev/null

      $APR --json store bless "$ROOT_STORE" --registry test-reg --no-commit \
        > /tmp/store-bless.json
      ${pkgs.jq}/bin/jq -e '.action == "store_bless" and .committed == false' \
        /tmp/store-bless.json >/dev/null
      $APR --json store revoke "$ROOT_STORE" --registry test-reg --no-commit \
        > /tmp/store-revoke.json
      ${pkgs.jq}/bin/jq -e '.action == "store_revoke" and .committed == false' \
        /tmp/store-revoke.json >/dev/null
      if $APR store verify --registry test-reg \
        > /tmp/store-verify-revoked.out 2>&1; then
        cat /tmp/store-verify-revoked.out
        fail "apr store verify should reject a revoked published root"
      else
        pass "apr store verify rejects a revoked published root"
      fi
      $APR store bless "$ROOT_STORE" --registry test-reg --no-commit \
        > /tmp/store-rebless.out
      $APR store verify --deep --registry test-reg \
        > /tmp/store-verify-reblessed.out

      rm -rf "$REG_DIR/store"
      $APR --json store backfill --registry test-reg --no-commit \
        > /tmp/store-backfill.json
      ${pkgs.jq}/bin/jq -e \
        '.action == "store_backfill" and .roots == 2 and .created > 0 and .committed == false' \
        /tmp/store-backfill.json >/dev/null
      $APR store verify --deep --registry test-reg \
        > /tmp/store-verify-backfilled.out

      echo "==> Exercise APR staged static-cache garbage collection"
      $APR cache generate --registry test-reg --no-commit \
        > /tmp/cache-generate-default.out
      $APR --json cache gc --registry test-reg --max-age 0 --dry-run \
        > /tmp/cache-gc-dry-run.json
      ${pkgs.jq}/bin/jq -e \
        '.action == "cache_gc" and .dry_run == true and .candidates > 0' \
        /tmp/cache-gc-dry-run.json >/dev/null
      $APR --json cache gc --registry test-reg --max-age 0 \
        > /tmp/cache-gc.json
      ${pkgs.jq}/bin/jq -e \
        '.action == "cache_gc" and .dry_run == false and .deleted_files > 0' \
        /tmp/cache-gc.json >/dev/null

      $APR verify --registry test-reg > /tmp/closure-verify-ok.out 2>&1 || {
        cat /tmp/closure-verify-ok.out
        fail "apr verify accepts real generated closure files"
      }
      cat /tmp/closure-verify-ok.out
      assert_file_contains /tmp/closure-verify-ok.out "no errors" \
        "apr verify reports generated closures are valid"

      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # closure-verify — apr verify validates closure consistency
  # -------------------------------------------------------------------------
  closure-verify = testing.mkVMTest {
    name = "apm-closure-verify";
    rootfsDeps = closureWorkflowDeps;
    memory = 1024;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixPublishEnv}

      echo "==> Test: apr verify rejects broken real closure metadata"

      LEAF_STORE="${closureLeafTool}"
      ROOT_STORE="${closureRootTool}"
      LEAF_HASH=$(basename "$LEAF_STORE" | cut -d- -f1)
      ROOT_HASH=$(basename "$ROOT_STORE" | cut -d- -f1)

      publish_closure_package() {
        store="$1"
        name="$2"
        version="$3"
        $APR publish "$store" \
          --name "$name" \
          --version "$version" \
          --description "Real closure verify fixture $name" \
          --license MIT \
          --maintainer closure@example.invalid \
          --registry test-reg \
          --no-commit > "/tmp/verify-publish-$name.out" 2>&1 || {
          cat "/tmp/verify-publish-$name.out"
          fail "apr publish $name succeeds"
          return 1
        }
        cat "/tmp/verify-publish-$name.out"
      }

      commit_registry_changes() {
        message="$1"
        git -C "$REG_DIR" add -A
        git -C "$REG_DIR" commit -m "$message" > /tmp/verify-commit.out 2>&1 || {
          cat /tmp/verify-commit.out
          fail "registry commit succeeds: $message"
          return 1
        }
        cat /tmp/verify-commit.out
      }

      expect_verify_success() {
        label="$1"
        if $APR verify --registry test-reg > "/tmp/verify-$label.out" 2>&1; then
          cat "/tmp/verify-$label.out"
          assert_file_contains "/tmp/verify-$label.out" "no errors" \
            "apr verify reports $label has no errors"
        else
          cat "/tmp/verify-$label.out"
          fail "apr verify should succeed for $label"
        fi
      }

      expect_verify_failure() {
        label="$1"
        pattern="$2"
        if $APR verify --registry test-reg > "/tmp/verify-$label.out" 2>&1; then
          cat "/tmp/verify-$label.out"
          fail "apr verify should fail for $label"
        else
          cat "/tmp/verify-$label.out"
          pass "apr verify fails for $label"
        fi
        assert_file_contains "/tmp/verify-$label.out" "$pattern" \
          "apr verify reports $label"
      }

      mount -o remount,rw / || true
      $APR create test-reg
      REG_DIR="$REG_STORAGE/test-reg"
      publish_closure_package "$LEAF_STORE" closure-leaf 1.0.0
      publish_closure_package "$ROOT_STORE" closure-root 1.0.0
      commit_registry_changes "publish real closure verify packages"

      ROOT_FILE="$REG_DIR/store/$(printf %.2s "$ROOT_HASH")/$ROOT_HASH"
      LEAF_FILE="$REG_DIR/store/$(printf %.2s "$LEAF_HASH")/$LEAF_HASH"

      cp "$ROOT_FILE" /tmp/root-store-good
      expect_verify_success valid-generated

      # Trimming a single dependency edge from a committed store record is now
      # tolerated: apr verify revalidates each path against the live Nix store
      # rather than trusting the recorded edge set, so a stale edge alone is
      # not an error.
      grep -v "$LEAF_HASH" "$ROOT_FILE" > /tmp/root-store-trimmed
      mv /tmp/root-store-trimmed "$ROOT_FILE"
      commit_registry_changes "trim root store dependency edge"
      expect_verify_success trimmed-edge-tolerated

      # Restore the good record before exercising the missing-record path.
      cp /tmp/root-store-good "$ROOT_FILE"
      commit_registry_changes "restore root store record"
      expect_verify_success restored-generated

      # Deleting the store record entirely is an error: a closure member then
      # has no store/ record to validate against.
      rm -f "$ROOT_FILE"
      commit_registry_changes "remove root store record"
      expect_verify_failure missing-store-record \
        "has no store/ record"

      $APR verify --registry test-reg --package closure-leaf \
        > /tmp/verify-filtered-leaf.out 2>&1 || {
        cat /tmp/verify-filtered-leaf.out
        fail "apr verify --package ignores unrelated broken store metadata"
      }
      cat /tmp/verify-filtered-leaf.out
      assert_file_contains /tmp/verify-filtered-leaf.out "no errors" \
        "apr verify --package validates only the requested package"

      $APR verify --registry test-reg --package closure-root --fix \
        > /tmp/verify-fix-missing-store.out 2>&1 || {
        cat /tmp/verify-fix-missing-store.out
        fail "apr verify --fix repairs missing root store metadata"
      }
      cat /tmp/verify-fix-missing-store.out
      assert_file_contains /tmp/verify-fix-missing-store.out \
        "Regenerated store/ records for" \
        "apr verify --fix reports missing store record repair"
      assert_file_contains /tmp/verify-fix-missing-store.out "no errors" \
        "apr verify --fix validates repaired missing store metadata"
      assert_file_exists "$ROOT_FILE" \
        "apr verify --fix recreates missing root store record"
      assert_file_contains "$ROOT_FILE" "$LEAF_HASH" \
        "apr verify --fix recreates root store dependency edge"
      commit_registry_changes "repair missing root store record with verify fix"
      expect_verify_success fixed-missing-store-record

      assert_file_exists "$LEAF_FILE" \
        "removing root store record leaves dependency record intact"

      check_fail
    '';
  };
}
