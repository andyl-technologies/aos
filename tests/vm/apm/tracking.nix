# tests/vm/apm/tracking.nix — Registry tracking mode VM tests (7 tests)
#
# Tests for different registry tracking modes: branch, tag, version (~, ^),
# commit, default, and git-native clean-break behavior.  Each test creates a
# local git registry with appropriate refs/tags and verifies that
# `apm registry add` with the
# matching tracking flag produces the correct config, and that the tracking
# mode semantics are correct.
{
  testing,
  pkgs,
  aosPkg,
}: let
  fixtures = import ./fixtures.nix {inherit pkgs aosPkg;};
in {
  # -------------------------------------------------------------------------
  # 1. tracking-branch — Track a named branch HEAD
  # -------------------------------------------------------------------------
  tracking-branch = testing.mkVMTest {
    name = "apm-tracking-branch";
    rootfsDeps = fixtures.commonDeps;
    memory = 512;
    testScript = ''
            ${fixtures.setupPreamble}
            ${fixtures.mkFakePackageToml}
            ${fixtures.mkRemoteRegistry}

            echo "==> Test: branch tracking mode"

            # Create a remote with a 'stable' branch
            create_remote_registry /tmp/remote-branch.git

            # Clone, create stable branch with a package, push
            git clone /tmp/remote-branch.git /tmp/branch-setup
            cd /tmp/branch-setup
            git checkout -b stable
            mkdir -p packages/h
            cat > packages/h/hello.toml << 'EOF'
      [package]
      name = "hello"
      description = "Hello package on stable"
      license = "MIT"
      maintainer = "test"

      [[versions]]
      version = "1.0.0"

      [versions.platforms.x86_64-linux]
      store_path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-hello-1.0.0"
      nar_hash = "sha256:0000000000000000000000000000000000000000000000000000"
      nar_size = 1024
      closure_size = 2048
      source_drv = ""
      source_nar_hash = ""
      references = []
      EOF
            git add -A
            git commit -m "add hello 1.0.0 on stable"
            git push origin stable
            cd /tmp
            rm -rf /tmp/branch-setup

            # Add registry with branch tracking
            $APM registry add file:///tmp/remote-branch.git --name branch-reg --branch stable

            # Verify config has branch field
            assert_file_contains "$APM_CONFIG/registries.d/branch-reg.toml" \
              'branch = "stable"' "config has branch = stable"

            # Verify apr list shows branch tracking
            assert_cmd_output_contains "$APR list" "branch:stable" \
              "apr list shows branch tracking mode"

            check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # 2. tracking-tag — Pin to an exact tag name
  # -------------------------------------------------------------------------
  tracking-tag = testing.mkVMTest {
    name = "apm-tracking-tag";
    rootfsDeps = fixtures.commonDeps;
    memory = 512;
    testScript = ''
      ${fixtures.setupPreamble}
      ${fixtures.mkRemoteRegistry}

      echo "==> Test: tag tracking mode"

      # Create remote, add a tag
      create_remote_registry /tmp/remote-tag.git

      git clone /tmp/remote-tag.git /tmp/tag-setup
      cd /tmp/tag-setup
      git tag v1.0
      git push origin v1.0

      # Advance past v1.0
      echo "# advanced" >> registry.toml
      git add -A
      git commit -m "advance past v1.0"
      git push origin
      cd /tmp
      rm -rf /tmp/tag-setup

      # Add registry pinned to tag
      $APM registry add file:///tmp/remote-tag.git --name tag-reg --tag v1.0

      # Verify config has tag field
      assert_file_contains "$APM_CONFIG/registries.d/tag-reg.toml" \
        'tag = "v1.0"' "config has tag = v1.0"

      # Verify tracking mode display
      assert_cmd_output_contains "$APR list" "tag:v1.0" \
        "apr list shows tag tracking mode"

      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # 3. tracking-version-tilde — Semver tilde constraint (~1.0)
  # -------------------------------------------------------------------------
  tracking-version-tilde = testing.mkVMTest {
    name = "apm-tracking-version-tilde";
    rootfsDeps = fixtures.commonDeps;
    memory = 512;
    testScript = ''
      ${fixtures.setupPreamble}
      ${fixtures.mkRemoteRegistry}

      echo "==> Test: version tilde tracking mode (~1.0)"

      # Create remote with multiple version tags
      create_remote_registry /tmp/remote-vtilde.git

      git clone /tmp/remote-vtilde.git /tmp/vtilde-setup
      cd /tmp/vtilde-setup

      # Create versioned tags
      git tag v1.0.0
      echo "# v1.0.1" >> registry.toml
      git add -A
      git commit -m "v1.0.1"
      git tag v1.0.1

      echo "# v1.0.2" >> registry.toml
      git add -A
      git commit -m "v1.0.2"
      git tag v1.0.2

      echo "# v1.1.0" >> registry.toml
      git add -A
      git commit -m "v1.1.0"
      git tag v1.1.0

      git push origin --tags
      cd /tmp
      rm -rf /tmp/vtilde-setup

      # Add registry with tilde version constraint
      $APM registry add file:///tmp/remote-vtilde.git --name vtilde-reg --version "~1.0"

      # Verify config has version field
      assert_file_contains "$APM_CONFIG/registries.d/vtilde-reg.toml" \
        'version = "~1.0"' "config has version = ~1.0"

      # Verify tracking mode display
      assert_cmd_output_contains "$APR list" "version" \
        "apr list shows version tracking mode"

      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # 4. tracking-version-caret — Semver caret constraint (^1)
  # -------------------------------------------------------------------------
  tracking-version-caret = testing.mkVMTest {
    name = "apm-tracking-version-caret";
    rootfsDeps = fixtures.commonDeps;
    memory = 512;
    testScript = ''
      ${fixtures.setupPreamble}
      ${fixtures.mkRemoteRegistry}

      echo "==> Test: version caret tracking mode (^1)"

      # Create remote with version tags
      create_remote_registry /tmp/remote-vcaret.git

      git clone /tmp/remote-vcaret.git /tmp/vcaret-setup
      cd /tmp/vcaret-setup

      git tag v1.0.0
      echo "# v1.1.0" >> registry.toml
      git add -A
      git commit -m "v1.1.0"
      git tag v1.1.0

      echo "# v2.0.0" >> registry.toml
      git add -A
      git commit -m "v2.0.0"
      git tag v2.0.0

      git push origin --tags
      cd /tmp
      rm -rf /tmp/vcaret-setup

      # Add registry with caret version constraint
      $APM registry add file:///tmp/remote-vcaret.git --name vcaret-reg --version "^1"

      # Verify config
      assert_file_contains "$APM_CONFIG/registries.d/vcaret-reg.toml" \
        'version = "^1"' "config has version = ^1"

      # Verify tracking mode display
      assert_cmd_output_contains "$APR list" "version" \
        "apr list shows version tracking mode"

      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # 5. tracking-commit — Pin to exact commit hash
  # -------------------------------------------------------------------------
  tracking-commit = testing.mkVMTest {
    name = "apm-tracking-commit";
    rootfsDeps = fixtures.commonDeps;
    memory = 512;
    testScript = ''
      ${fixtures.setupPreamble}
      ${fixtures.mkRemoteRegistry}

      echo "==> Test: commit tracking mode"

      # Create remote and get a commit hash
      create_remote_registry /tmp/remote-commit.git

      git clone /tmp/remote-commit.git /tmp/commit-setup
      cd /tmp/commit-setup
      PINNED_COMMIT=$(git rev-parse HEAD)
      echo "Pinned commit: $PINNED_COMMIT"

      # Advance past the pinned commit
      echo "# advanced" >> registry.toml
      git add -A
      git commit -m "advance past pinned"
      git push origin
      cd /tmp
      rm -rf /tmp/commit-setup

      # Add registry with commit pin
      $APM registry add file:///tmp/remote-commit.git --name commit-reg --commit "$PINNED_COMMIT"

      # Verify config has commit field
      SHORT_COMMIT=$(echo "$PINNED_COMMIT" | cut -c1-12)
      assert_file_contains "$APM_CONFIG/registries.d/commit-reg.toml" \
        "commit = " "config has commit field"

      # Verify tracking mode display
      assert_cmd_output_contains "$APR list" "commit:" \
        "apr list shows commit tracking mode"

      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # 6. tracking-default — No tracking mode (uses default branch HEAD)
  # -------------------------------------------------------------------------
  tracking-default = testing.mkVMTest {
    name = "apm-tracking-default";
    rootfsDeps = fixtures.commonDeps;
    memory = 512;
    testScript = ''
      ${fixtures.setupPreamble}
      ${fixtures.mkRemoteRegistry}

      echo "==> Test: default tracking mode"

      create_remote_registry /tmp/remote-default.git

      # Add registry with NO tracking flags
      $APM registry add file:///tmp/remote-default.git --name default-reg

      # Verify config has NO commit/branch/tag/version fields
      CONFIG_FILE="$APM_CONFIG/registries.d/default-reg.toml"
      assert_file_exists "$CONFIG_FILE" "config file exists"

      # Check that none of the tracking fields are present
      if grep -q "^commit = " "$CONFIG_FILE" 2>/dev/null; then
        fail "config should not have commit field"
      else
        pass "config has no commit field"
      fi

      if grep -q "^branch = " "$CONFIG_FILE" 2>/dev/null; then
        fail "config should not have branch field"
      else
        pass "config has no branch field"
      fi

      if grep -q "^tag = " "$CONFIG_FILE" 2>/dev/null; then
        fail "config should not have tag field"
      else
        pass "config has no tag field"
      fi

      if grep -q "^version = " "$CONFIG_FILE" 2>/dev/null; then
        fail "config should not have version field"
      else
        pass "config has no version field"
      fi

      # Verify tracking shows as default
      assert_cmd_output_contains "$APR list" "default" \
        "apr list shows default tracking mode"

      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # 7. tracking-bundle-sync — Legacy selector for git-native clean-break tracking
  # -------------------------------------------------------------------------
  tracking-bundle-sync = testing.mkVMTest {
    name = "apm-tracking-git-native-clean-break";
    rootfsDeps = fixtures.commonDeps;
    memory = 512;
    testScript = ''
      ${fixtures.setupPreamble}
      ${fixtures.mkFakePackageToml}
      ${fixtures.mkRemoteRegistry}

      echo "==> Test: git-native version tracking after bundle cutover"

      create_remote_registry /tmp/remote-git-native.git

      git clone /tmp/remote-git-native.git /tmp/git-native-setup
      cd /tmp/git-native-setup
      git tag v1.0.0
      echo "# v1.1.0" >> registry.toml
      git add -A
      git commit -m "v1.1.0"
      git tag v1.1.0
      git update-server-info
      git push origin --tags
      git push origin "$(git branch --show-current)"
      cd /tmp
      rm -rf /tmp/git-native-setup

      $APM registry add file:///tmp/remote-git-native.git \
        --name git-native-reg --version "~1"

      assert_file_contains "$APM_CONFIG/registries.d/git-native-reg.toml" \
        'version = "~1"' "config keeps git-native version tracking"
      assert_cmd_output_contains "$APR list" "version" \
        "apr list shows version tracking mode"

      if $APR bundle --tag v1.1.0 --output /tmp/bundles --registry git-native-reg \
        > /tmp/bundle-out 2>&1; then
        fail "apr bundle should not exist after git-native cutover"
      elif grep -q "unrecognized subcommand" /tmp/bundle-out; then
        pass "bundle transport command is removed"
      else
        fail "apr bundle failed with unexpected output"
        cat /tmp/bundle-out
      fi

      check_fail
    '';
  };
}
