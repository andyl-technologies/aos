# Registry VM checks for validation bundles workflows.
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
  # registry-validate — Validate registry TOML structure
  # -------------------------------------------------------------------------
  registry-validate = testing.mkVMTest {
    name = "apm-registry-validate";
    rootfsDeps = closureWorkflowDeps;
    memory = 1024;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixPublishEnv}

      echo "==> Test: apr verify (TOML schema validation)"

      $APR create test-reg
      REG_DIR="$REG_STORAGE/test-reg"

      $APR publish "${closureLeafTool}" \
        --name validpkg \
        --version 1.0.0 \
        --description "Real verify schema fixture" \
        --license MIT \
        --maintainer verify@example.invalid \
        --registry test-reg \
        --no-commit > /tmp/validate-publish.out 2>&1 || {
        cat /tmp/validate-publish.out
        fail "apr publish creates valid package metadata"
      }
      cat /tmp/validate-publish.out
      git -C "$REG_DIR" add -A
      git -C "$REG_DIR" commit -m "publish validpkg 1.0.0"

      $APR verify --registry test-reg > /tmp/verify-valid.out 2>&1 || {
        cat /tmp/verify-valid.out
        fail "apr verify passes with real valid package"
      }
      cat /tmp/verify-valid.out
      assert_file_contains /tmp/verify-valid.out "no errors" \
        "apr verify reports real valid package has no errors"

      mkdir -p "$REG_DIR/packages/b"
      echo 'invalid = "no package section"' > "$REG_DIR/packages/b/badpkg.toml"
      git -C "$REG_DIR" add -A
      git -C "$REG_DIR" commit -m "add invalid package"

      if $APR verify --registry test-reg > /tmp/verify-invalid.out 2>&1; then
        cat /tmp/verify-invalid.out
        fail "apr verify should fail with invalid package TOML"
      else
        cat /tmp/verify-invalid.out
        pass "apr verify fails with invalid package TOML"
      fi
      assert_file_contains /tmp/verify-invalid.out "missing \\[package\\] section" \
        "apr verify reports invalid package TOML"

      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # registry-bundle — Signed tag, re-sign, and no-bundle clean break
  # -------------------------------------------------------------------------
  registry-bundle = testing.mkVMTest {
    name = "apm-registry-signed-tag-clean-break";
    rootfsDeps = closureWorkflowDeps ++ [pkgs.openssh];
    memory = 1024;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixPublishEnv}

      echo "==> Test: real APR signed tag, re-sign, and bundle clean break"

      TAG_STORE="${closureRootTool}"
      TAG_DEP_STORE="${closureLeafTool}"
      TAG_HASH=$(basename "$TAG_STORE" | cut -d- -f1)
      TAG_DEP_HASH=$(basename "$TAG_DEP_STORE" | cut -d- -f1)

      mount -o remount,rw / || true
      nix-store -q --references "$TAG_STORE" > /tmp/tagpkg-refs.out
      assert_file_contains /tmp/tagpkg-refs.out "$TAG_DEP_STORE" \
        "tagged package has a real Nix reference to its dependency"

      $APR create test-reg
      REG_DIR="$REG_STORAGE/test-reg"

      $APR publish "$TAG_STORE" \
        --name tagpkg \
        --version 1.0.0 \
        --description "Real signed tag fixture" \
        --license MIT \
        --maintainer tag@example.invalid \
        --registry test-reg \
        --no-commit > /tmp/tag-publish.out 2>&1 || {
        cat /tmp/tag-publish.out
        fail "apr publish creates real tag package"
      }
      cat /tmp/tag-publish.out
      git -C "$REG_DIR" add -A
      git -C "$REG_DIR" commit -m "publish tagpkg 1.0.0"

      assert_file_contains "$REG_DIR/packages/t/tagpkg.toml" "$TAG_HASH" \
        "package metadata records real tagged store hash"
      assert_file_exists "$REG_DIR/store/$(printf %.2s "$TAG_HASH")/$TAG_HASH" \
        "tagged package store record exists"
      assert_file_contains "$REG_DIR/store/$(printf %.2s "$TAG_HASH")/$TAG_HASH" "$TAG_DEP_HASH" \
        "tagged package store record lists dependency edge"
      $APR verify --registry test-reg > /tmp/tag-verify-before.out 2>&1 || {
        cat /tmp/tag-verify-before.out
        fail "apr verify accepts real package before tag"
      }
      assert_file_contains /tmp/tag-verify-before.out "no errors" \
        "apr verify validates real package before tag"

      ssh-keygen -q -t ed25519 -N "" -f /tmp/release-key
      $APR tag 1.0.0 --registry test-reg --key /tmp/release-key \
        > /tmp/tag-create.out 2>&1 || {
        cat /tmp/tag-create.out
        fail "apr tag creates signed release tag"
      }
      cat /tmp/tag-create.out
      assert_file_contains /tmp/tag-create.out "Created signed tag '1.0.0'" \
        "apr tag reports signed release tag creation"

      cd "$REG_DIR"
      assert_cmd_success "git rev-parse 1.0.0^{tag}" \
        "signed release tag object exists"
      git cat-file -p 1.0.0 > /tmp/tag-object.out
      assert_file_contains /tmp/tag-object.out \
        "BEGIN SSH SIGNATURE" "release tag object carries SSH signature"
      assert_file_contains /tmp/tag-object.out "tag 1.0.0" \
        "release tag object records release name"
      git show 1.0.0:packages/t/tagpkg.toml > /tmp/tagpkg-at-tag.toml
      git show "1.0.0:store/$(printf %.2s "$TAG_HASH")/$TAG_HASH" > /tmp/tag-closure-at-tag.out
      cd /tmp

      assert_file_contains /tmp/tagpkg-at-tag.toml "$TAG_HASH" \
        "signed tag captures real package metadata"
      assert_file_contains /tmp/tagpkg-at-tag.toml "Real signed tag fixture" \
        "signed tag captures maintainer package description"
      assert_file_contains /tmp/tag-closure-at-tag.out "$TAG_DEP_HASH" \
        "signed tag captures real package closure"

      INITIAL_TAG_OBJECT=$(git -C "$REG_DIR" rev-parse '1.0.0^{tag}')
      INITIAL_TAG_COMMIT=$(git -C "$REG_DIR" rev-parse '1.0.0^{commit}')

      ssh-keygen -q -t ed25519 -N "" -f /tmp/release-key-next
      NEXT_PUBLIC=$(cut -d ' ' -f2 < /tmp/release-key-next.pub)
      NEXT_TRUST_KEY="test-reg:Ed25519:$NEXT_PUBLIC"
      $APR keys add next "$NEXT_TRUST_KEY" --registry test-reg \
        > /tmp/sign-key-add.out 2>&1 || {
        cat /tmp/sign-key-add.out
        fail "apr keys add records replacement signing key"
      }
      cat /tmp/sign-key-add.out
      assert_file_contains "$REG_DIR/keys.toml" 'id = "next"' \
        "keys.toml records replacement signing key id"
      assert_file_contains "$REG_DIR/keys.toml" "$NEXT_TRUST_KEY" \
        "keys.toml records replacement signing key value"

      {
        printf '[registry]\n'
        printf 'name = "test-reg"\n'
        printf 'url = "file://%s"\n\n' "$REG_DIR"
        printf '[registry.signing_keys]\n'
        printf 'next = "/tmp/release-key-next"\n'
      } > "$APM_CONFIG/registries.d/test-reg.toml"

      if $APR sign --registry test-reg --key-id next \
        > /tmp/sign-missing-tag.out 2>&1; then
        cat /tmp/sign-missing-tag.out
        fail "apr sign should require an explicit tag name"
      else
        cat /tmp/sign-missing-tag.out
        pass "apr sign rejects missing tag name"
      fi
      assert_file_contains /tmp/sign-missing-tag.out \
        "pass the existing tag name to re-sign" \
        "apr sign explains required tag argument"

      $APR sign 1.0.0 --registry test-reg --key-id next \
        > /tmp/tag-resign.out 2>&1 || {
        cat /tmp/tag-resign.out
        fail "apr sign re-signs existing tag with configured key id"
      }
      cat /tmp/tag-resign.out
      assert_file_contains /tmp/tag-resign.out "Re-signed tag '1.0.0'" \
        "apr sign reports re-signed tag"
      RESIGNED_TAG_OBJECT=$(git -C "$REG_DIR" rev-parse '1.0.0^{tag}')
      RESIGNED_TAG_COMMIT=$(git -C "$REG_DIR" rev-parse '1.0.0^{commit}')
      if [ "$RESIGNED_TAG_COMMIT" = "$INITIAL_TAG_COMMIT" ]; then
        pass "apr sign keeps the release tag target commit"
      else
        fail "apr sign should keep commit $INITIAL_TAG_COMMIT, got $RESIGNED_TAG_COMMIT"
      fi
      if [ "$RESIGNED_TAG_OBJECT" != "$INITIAL_TAG_OBJECT" ]; then
        pass "apr sign replaces the annotated tag object"
      else
        fail "apr sign should replace annotated tag object"
      fi
      git -C "$REG_DIR" cat-file -p 1.0.0 > /tmp/tag-object-resigned.out
      assert_file_contains /tmp/tag-object-resigned.out \
        "BEGIN SSH SIGNATURE" "re-signed tag object carries SSH signature"
      assert_file_contains /tmp/tag-object-resigned.out "$INITIAL_TAG_COMMIT" \
        "re-signed tag object targets original release commit"

      assert_file_not_exists "$REG_DIR/bundle-list.toml" \
        "git-native registry does not emit bundle-list.toml"

      if $APR bundle --tag 1.0.0 --output /tmp/bundles --registry test-reg \
        > /tmp/bundle-out 2>&1; then
        fail "apr bundle should not exist after git-native cutover"
      elif grep -q "unrecognized subcommand" /tmp/bundle-out; then
        pass "apr bundle is removed with a clean CLI error"
      else
        fail "apr bundle failed with unexpected output"
        cat /tmp/bundle-out
      fi

      check_fail
    '';
  };
}
