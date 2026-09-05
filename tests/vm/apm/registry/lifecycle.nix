# Registry VM checks for lifecycle workflows.
{
  testing,
  fixtures,
}: {
  # -------------------------------------------------------------------------
  # registry-create — Initialize a new empty registry
  # -------------------------------------------------------------------------
  registry-create = testing.mkVMTest {
    name = "apm-registry-create";
    rootfsDeps = fixtures.commonDeps;
    memory = 512;
    testScript = ''
      ${fixtures.setupPreamble}

      echo "==> Test: apr create"
      $APR create test-reg

      REG_DIR="$REG_STORAGE/test-reg"

      # Verify git repo exists
      assert_dir_exists "$REG_DIR/.git" "git repo initialized"

      # Verify registry.toml exists
      assert_file_exists "$REG_DIR/registry.toml" "registry.toml exists"

      # Verify packages/ directory exists
      assert_dir_exists "$REG_DIR/packages" "packages/ directory exists"

      # Verify registry.toml contains the registry name
      assert_file_contains "$REG_DIR/registry.toml" "test-reg" "registry.toml contains name"

      # Verify git log shows initial commit
      cd "$REG_DIR"
      COMMIT_COUNT=$(git log --oneline | wc -l)
      if [ "$COMMIT_COUNT" -ge 1 ]; then
        pass "git log shows initial commit"
      else
        fail "git log shows no commits"
      fi
      cd /tmp

      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # registry-add-clone — Add a remote registry via clone
  # -------------------------------------------------------------------------
  registry-add-clone = testing.mkVMTest {
    name = "apm-registry-add-clone";
    rootfsDeps = fixtures.commonDeps;
    memory = 512;
    testScript = ''
      ${fixtures.setupPreamble}
      ${fixtures.mkRemoteRegistry}

      echo "==> Test: apr add (clone from local bare repo)"

      # Create a bare remote registry
      create_remote_registry /tmp/remote-registry.git
      git clone /tmp/remote-registry.git /tmp/remote-registry-tag
      cd /tmp/remote-registry-tag
      git tag 1.0.0
      git push origin 1.0.0
      cd /tmp
      rm -rf /tmp/remote-registry-tag

      # Use apm registry add to add the remote
      $APM registry add --no-verify file:///tmp/remote-registry.git --name test-remote

      # Verify config file was created
      assert_file_exists "$APM_CONFIG/registries.d/test-remote.toml" \
        "registry config file created"

      # Verify config contains URL
      assert_file_contains "$APM_CONFIG/registries.d/test-remote.toml" \
        "file:///tmp/remote-registry.git" "config contains URL"

      # apr add should sync the git repo and materialize authenticated metadata by default.
      assert_dir_exists "$HOME/.local/share/apm/remote/test-remote/repo.git" \
        "registry git cache created during add"
      assert_file_exists "$REG_STORAGE/test-remote/registry.toml" \
        "registry root metadata materialized during add"
      assert_dir_exists "$HOME/.local/share/apm/remote/test-remote/packages" \
        "registry package cache materialized during add"

      # Verify apr list shows the registry
      assert_cmd_output_contains "$APR list" "test-remote" "apr list shows registry"

      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # registry-add-no-clone-publish-hint — Config-only add has recovery hints
  # -------------------------------------------------------------------------
  registry-add-no-clone-publish-hint = testing.mkVMTest {
    name = "apm-registry-add-no-clone-publish-hint";
    rootfsDeps = fixtures.commonDeps;
    memory = 512;
    testScript = ''
      ${fixtures.setupPreamble}
      ${fixtures.mkRemoteRegistry}

      echo "==> Test: apr add --no-clone followed by update and apr publish"

      assert_file_not_contains() {
        if grep -q "$2" "$1" 2>/dev/null; then
          fail "$3 (pattern '$2' unexpectedly found in $1)"
          cat "$1" 2>/dev/null || true
        else
          pass "$3"
        fi
      }

      create_remote_registry /tmp/no-clone-registry.git

      $APM registry add --no-verify file:///tmp/no-clone-registry.git \
        --name no-clone-reg --no-clone > /tmp/add-no-clone.out 2>&1 || {
        cat /tmp/add-no-clone.out
        fail "apm registry add --no-clone succeeds"
      }
      cat /tmp/add-no-clone.out
      assert_file_contains /tmp/add-no-clone.out \
        "apm update --registry no-clone-reg" \
        "apm registry add --no-clone points to the valid update syntax"
      assert_file_not_contains /tmp/add-no-clone.out \
        "apm update no-clone-reg" \
        "apm registry add --no-clone does not suggest invalid positional update syntax"

      assert_file_exists "$APM_CONFIG/registries.d/no-clone-reg.toml" \
        "registry config file created"

      if [ -e "$REG_STORAGE/no-clone-reg" ]; then
        fail "apr add --no-clone should not create a local clone"
      else
        pass "apr add --no-clone leaves local clone absent"
      fi

      if $APR publish /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-dummy-1.0.0 \
        --name dummy --version 1.0.0 \
        --description "No-clone publish diagnostic fixture" \
        --license MIT --maintainer test@test \
        --registry no-clone-reg --no-commit \
        > /tmp/publish-no-clone.out 2>&1; then
        fail "apr publish should fail without a local clone"
      else
        cat /tmp/publish-no-clone.out
        assert_file_contains /tmp/publish-no-clone.out \
          "has no writable local clone" "apr publish reports missing writable clone"
        assert_file_contains /tmp/publish-no-clone.out \
          "only syncs consumer metadata" \
          "apr publish explains apm update cannot create a publishing worktree"
        assert_file_not_contains /tmp/publish-no-clone.out \
          "apm update no-clone-reg" \
          "apr publish does not suggest invalid positional update syntax"
        assert_file_contains /tmp/publish-no-clone.out \
          "apr create no-clone-reg" "apr publish points to apr create"
      fi

      $APM update --registry no-clone-reg > /tmp/update-no-clone.out 2>&1 || {
        cat /tmp/update-no-clone.out
        fail "apm update --registry syncs config-only registry metadata"
      }
      cat /tmp/update-no-clone.out
      assert_file_contains /tmp/update-no-clone.out \
        "Registry 'no-clone-reg': done" \
        "apm update --registry follows the no-clone recovery hint for consumers"
      assert_dir_exists "$HOME/.local/share/apm/remote/no-clone-reg/repo.git" \
        "apm update materializes consumer git cache"
      assert_file_exists "$REG_STORAGE/no-clone-reg/registry.toml" \
        "apm update materializes authenticated registry root metadata"
      if [ -d "$REG_STORAGE/no-clone-reg/.git" ]; then
        fail "apm update should not create an APR publishing worktree"
      else
        pass "apm update leaves APR publishing worktree absent"
      fi

      if $APR publish /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-dummy-1.0.0 \
        --name dummy --version 1.0.0 \
        --description "No-clone publish diagnostic fixture" \
        --license MIT --maintainer test@test \
        --registry no-clone-reg --no-commit \
        > /tmp/publish-after-update.out 2>&1; then
        fail "apr publish should still fail after consumer metadata update"
      else
        cat /tmp/publish-after-update.out
        assert_file_contains /tmp/publish-after-update.out \
          "has no writable local clone" \
          "apr publish still reports missing writable clone after apm update"
        assert_file_contains /tmp/publish-after-update.out \
          "only syncs consumer metadata" \
          "apr publish distinguishes consumer metadata from publishing worktree"
        assert_file_not_contains /tmp/publish-after-update.out \
          "not a git repository" \
          "apr publish does not fall through to a raw git error"
        assert_file_not_contains /tmp/publish-after-update.out \
          "store path" \
          "apr publish validates writable clone before store introspection"
      fi

      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # registry-remove — Remove a registry
  # -------------------------------------------------------------------------
  registry-remove = testing.mkVMTest {
    name = "apm-registry-remove";
    rootfsDeps = fixtures.commonDeps;
    memory = 512;
    testScript = ''
      ${fixtures.setupPreamble}

      echo "==> Test: apr remove"

      # Add a registry first
      $APM registry add --no-verify file:///tmp/fake-remote --name removable-reg

      # Verify it exists
      assert_file_exists "$APM_CONFIG/registries.d/removable-reg.toml" \
        "registry config exists before remove"

      # Remove it
      $APM registry remove removable-reg

      # Verify config file is gone
      assert_file_not_exists "$APM_CONFIG/registries.d/removable-reg.toml" \
        "registry config removed"

      # Verify apr list no longer shows it
      $APR list > /tmp/list-output 2>&1 || true
      if grep -q "removable-reg" /tmp/list-output 2>/dev/null; then
        fail "apr list still shows removed registry"
      else
        pass "apr list no longer shows removed registry"
      fi

      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # registry-remove-unprivileged — Remove without profile write access
  # -------------------------------------------------------------------------
  registry-remove-unprivileged = testing.mkVMTest {
    name = "apm-registry-remove-unprivileged";
    rootfsDeps = fixtures.commonDeps;
    memory = 512;
    testScript = ''
      ${fixtures.setupPreamble}

      echo "==> Test: unprivileged apr remove does not touch package profile"

      USER_HOME=/tmp/apr-user
      mkdir -p "$USER_HOME/.config/apm/registries.d"
      mkdir -p "$USER_HOME/.local/share/apm/registries/unpriv-reg"
      mkdir -p "$USER_HOME/.local/share/apm/remote/unpriv-reg"
      mkdir -p /var/lib/profiles
      chmod 755 /var/lib/profiles

      cat > "$USER_HOME/.config/apm/registries.d/unpriv-reg.toml" << 'EOF'
      [registry]
      name = "unpriv-reg"
      url = "file:///tmp/unpriv-reg"
      priority = 500
      enabled = true
      EOF

      chown -R 1000:1000 "$USER_HOME"

      if env HOME="$USER_HOME" USER=aprtest chroot --userspec=1000:1000 / \
        "$APR" remove unpriv-reg > /tmp/unpriv-remove.out 2>&1; then
        cat /tmp/unpriv-remove.out
        pass "unprivileged apr remove succeeds"
      else
        cat /tmp/unpriv-remove.out
        fail "unprivileged apr remove should not require profile write access"
      fi

      assert_file_not_exists "$USER_HOME/.config/apm/registries.d/unpriv-reg.toml" \
        "registry config removed by unprivileged apr"

      if [ -e /var/lib/profiles/per-user/aprtest ]; then
        fail "apr remove should not create the package profile"
      else
        pass "apr remove leaves package profile untouched"
      fi

      check_fail
    '';
  };
}
