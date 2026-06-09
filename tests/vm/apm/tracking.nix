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
  nixRuntimeDeps = [
    pkgs.nix
    pkgs.brotli
    pkgs.curl
    pkgs.openssl
    pkgs.sqlite
    pkgs.boost
    pkgs.editline
    pkgs.libsodium
    pkgs.libarchive
    pkgs.gc
    pkgs.lowdown
    pkgs.bzip2
    pkgs.zlib
  ];
  nixLibPath = builtins.concatStringsSep ":" (map (pkg: "${pkg}/lib") nixRuntimeDeps);
  setupNixEnv = ''
    export NIX_REMOTE=""
    export NIX_CONF_DIR=/tmp/nix-conf
    export LD_LIBRARY_PATH="${nixLibPath}''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    mkdir -p "$NIX_CONF_DIR" /nix/var/nix/db /nix/var/nix/gcroots
    cat > "$NIX_CONF_DIR/nix.conf" << 'NIXCONF'
    experimental-features = nix-command
    sandbox = false
    NIXCONF
    nix-store --init || true
    nix-store --load-db < /aos-registration
  '';
  trackingWorkflowDeps =
    fixtures.commonDeps
    ++ nixRuntimeDeps
    ++ [
      pkgs.findutils
      pkgs.iproute2
      pkgs.python3
      pkgs.zstd
    ];
in {
  # -------------------------------------------------------------------------
  # 1. tracking-branch — Track a named branch HEAD
  # -------------------------------------------------------------------------
  tracking-branch = testing.mkVMTest {
    name = "apm-tracking-branch";
    rootfsDeps = trackingWorkflowDeps;
    memory = 2048;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixEnv}

      echo "==> Test: branch tracking follows selected branch"

      make_branch_tool() {
        version="$1"
        src="/tmp/branch-tool-$version-src"
        rm -rf "$src"
        mkdir -p "$src/bin" "$src/share/branch-tool"
        cat > "$src/bin/branch-tool" << EOF
      #!/bin/sh
      echo "branch-tool $version executed"
      EOF
        chmod +x "$src/bin/branch-tool"
        printf "branch-tool payload %s\n" "$version" \
          > "$src/share/branch-tool/payload.txt"
        nix-store --add "$src"
      }

      assert_file_not_contains() {
        if grep -q "$2" "$1" 2>/dev/null; then
          fail "$3 (pattern '$2' unexpectedly found in $1)"
          cat "$1" 2>/dev/null || true
        else
          pass "$3"
        fi
      }

      delete_store_path() {
        path="$1"
        label="$2"
        nix-store --delete --ignore-liveness "$path" > "/tmp/branch-delete-$label.out" 2>&1 || {
          cat "/tmp/branch-delete-$label.out"
          fail "delete $label before apm download"
          return
        }
        if nix-store --check-validity "$path" > "/tmp/branch-valid-$label.out" 2>&1; then
          cat "/tmp/branch-valid-$label.out"
          fail "$label should be missing before apm download"
        else
          pass "$label missing before apm download"
        fi
      }

      assert_store_valid() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/branch-valid-after-$label.out" 2>&1; then
          pass "$label valid after apm import"
        else
          cat "/tmp/branch-valid-after-$label.out"
          fail "$label should be valid after apm import"
        fi
      }

      publish_branch_version() {
        version="$1"
        store_path="$2"
        $APR publish "$store_path" \
          --name branch-tool \
          --version "$version" \
          --description "Branch tracking workflow tool" \
          --license MIT \
          --maintainer tracking@example.invalid \
          --registry branch-reg \
          --no-commit
        $APR cache generate \
          --registry branch-reg \
          --output /tmp/branch-cache \
          --cache-url http://127.0.0.1:18104 \
          --priority 44 \
          --no-commit
        git -C "$REG_DIR" add -A
        git -C "$REG_DIR" commit -m "release: branch-tool $version"
      }

      TOOL_V1_STORE=$(make_branch_tool 1.0.0)
      TOOL_V2_STORE=$(make_branch_tool 2.0.0)
      TOOL_V9_STORE=$(make_branch_tool 9.0.0)
      TOOL_V1_HASH=$(basename "$TOOL_V1_STORE" | cut -d- -f1)
      TOOL_V2_HASH=$(basename "$TOOL_V2_STORE" | cut -d- -f1)
      TOOL_V9_HASH=$(basename "$TOOL_V9_STORE" | cut -d- -f1)

      $APR create branch-reg
      REG_DIR="$REG_STORAGE/branch-reg"
      DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)
      git init --bare --object-format=sha256 /tmp/branch-origin.git
      git -C /tmp/branch-origin.git symbolic-ref HEAD "refs/heads/$DEFAULT_BRANCH"
      git -C "$REG_DIR" remote add origin /tmp/branch-origin.git
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      $APR branch create release --registry branch-reg
      $APR branch switch release --registry branch-reg
      publish_branch_version 1.0.0 "$TOOL_V1_STORE"
      assert_file_exists "/tmp/branch-cache/$TOOL_V1_HASH.narinfo" \
        "static cache has branch-tool release v1 narinfo"
      git -C "$REG_DIR" push origin release

      $APR branch switch "$DEFAULT_BRANCH" --registry branch-reg
      publish_branch_version 9.0.0 "$TOOL_V9_STORE"
      assert_file_exists "/tmp/branch-cache/$TOOL_V9_HASH.narinfo" \
        "static cache has default branch distraction narinfo"
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true

      python3 -m http.server 18104 --bind 127.0.0.1 \
        --directory /tmp/branch-cache > /tmp/branch-cache-http.log 2>&1 &
      CACHE_PID=$!
      for _i in 1 2 3 4 5 6 7 8 9 10; do
        if curl -sf http://127.0.0.1:18104/nix-cache-info >/dev/null; then
          break
        fi
        sleep 1
      done
      if curl -sf http://127.0.0.1:18104/nix-cache-info >/dev/null; then
        pass "branch static cache HTTP server started"
      else
        cat /tmp/branch-cache-http.log || true
        fail "branch static cache HTTP server started"
      fi

      export HOME=/tmp/branch-consumer
      export USER=branchuser
      mkdir -p "$HOME"
      APM_CONFIG="$HOME/.config/apm"

      $APM registry add file:///tmp/branch-origin.git \
        --name branch-reg \
        --branch release > /tmp/branch-add.out 2>&1 || {
        cat /tmp/branch-add.out
        fail "apm registry add syncs selected branch"
      }
      cat /tmp/branch-add.out
      CONFIG_FILE="$APM_CONFIG/registries.d/branch-reg.toml"
      assert_file_contains "$CONFIG_FILE" 'branch = "release"' \
        "config has branch = release"
      assert_cmd_output_contains "$APR list" "branch:release" \
        "apr list shows branch tracking mode"

      $APM search branch-tool --registry branch-reg > /tmp/branch-search-v1.out 2>&1 || {
        cat /tmp/branch-search-v1.out
        fail "apm search sees selected branch package"
      }
      assert_file_contains /tmp/branch-search-v1.out "1.0.0" \
        "branch tracking initial sync exposes release v1"
      assert_file_not_contains /tmp/branch-search-v1.out "9.0.0" \
        "branch tracking does not expose default branch package"

      mount -o remount,rw / || true
      delete_store_path "$TOOL_V1_STORE" "branch-tool-v1"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"

      $APM install branch-tool --registry branch-reg --yes \
        > /tmp/branch-install-v1.out 2>&1 || {
        cat /tmp/branch-install-v1.out
        fail "apm install downloads selected branch v1"
      }
      cat /tmp/branch-install-v1.out
      assert_file_contains /tmp/branch-install-v1.out "Downloading" \
        "apm install downloads branch v1 NAR"
      assert_store_valid "$TOOL_V1_STORE" "branch-tool v1"
      PROFILE_TOOL="/var/lib/profiles/per-user/$USER/current/bin/branch-tool"
      "$PROFILE_TOOL" > /tmp/branch-run-v1.out
      assert_file_contains /tmp/branch-run-v1.out \
        "branch-tool 1.0.0 executed" "installed branch v1 tool executes"

      export HOME=/tmp
      APM_CONFIG="$HOME/.config/apm"
      $APR branch switch release --registry branch-reg
      publish_branch_version 2.0.0 "$TOOL_V2_STORE"
      assert_file_exists "/tmp/branch-cache/$TOOL_V2_HASH.narinfo" \
        "static cache has branch-tool release v2 narinfo"
      git -C "$REG_DIR" push origin release

      export HOME=/tmp/branch-consumer
      export USER=branchuser
      APM_CONFIG="$HOME/.config/apm"
      delete_store_path "$TOOL_V2_STORE" "branch-tool-v2"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"

      $APM update --registry branch-reg > /tmp/branch-update-v2.out 2>&1 || {
        cat /tmp/branch-update-v2.out
        fail "apm update follows selected branch v2"
      }
      cat /tmp/branch-update-v2.out
      $APM list --upgradable > /tmp/branch-upgradable.out 2>&1 || {
        cat /tmp/branch-upgradable.out
        fail "apm list --upgradable sees selected branch update"
      }
      assert_file_contains /tmp/branch-upgradable.out "branch-tool" \
        "branch update names package"
      assert_file_contains /tmp/branch-upgradable.out "2.0.0" \
        "branch update shows release v2"
      assert_file_not_contains /tmp/branch-upgradable.out "9.0.0" \
        "branch update ignores default branch v9"

      $APM upgrade branch-tool --yes > /tmp/branch-upgrade.out 2>&1 || {
        cat /tmp/branch-upgrade.out
        fail "apm upgrade downloads selected branch v2"
      }
      cat /tmp/branch-upgrade.out
      assert_file_contains /tmp/branch-upgrade.out "Downloading" \
        "apm upgrade downloads branch v2 NAR"
      assert_file_contains /tmp/branch-upgrade.out "Upgraded 1 package" \
        "apm upgrade activates branch v2"
      assert_store_valid "$TOOL_V2_STORE" "branch-tool v2"
      "$PROFILE_TOOL" > /tmp/branch-run-v2.out
      assert_file_contains /tmp/branch-run-v2.out \
        "branch-tool 2.0.0 executed" "upgraded branch v2 tool executes"

      kill "$CACHE_PID" 2>/dev/null || true
      wait "$CACHE_PID" 2>/dev/null || true
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
    rootfsDeps = trackingWorkflowDeps;
    memory = 2048;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixEnv}

      echo "==> Test: default tracking follows default branch HEAD"

      make_default_tool() {
        version="$1"
        src="/tmp/default-tool-$version-src"
        rm -rf "$src"
        mkdir -p "$src/bin" "$src/share/default-tool"
        cat > "$src/bin/default-tool" << EOF
      #!/bin/sh
      echo "default-tool $version executed"
      EOF
        chmod +x "$src/bin/default-tool"
        printf "default-tool payload %s\n" "$version" \
          > "$src/share/default-tool/payload.txt"
        nix-store --add "$src"
      }

      delete_store_path() {
        path="$1"
        label="$2"
        nix-store --delete --ignore-liveness "$path" > "/tmp/delete-$label.out" 2>&1 || {
          cat "/tmp/delete-$label.out"
          fail "delete $label before apm download"
          return
        }
        if nix-store --check-validity "$path" > "/tmp/valid-$label.out" 2>&1; then
          cat "/tmp/valid-$label.out"
          fail "$label should be missing before apm download"
        else
          pass "$label missing before apm download"
        fi
      }

      assert_store_valid() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/valid-after-$label.out" 2>&1; then
          pass "$label valid after apm import"
        else
          cat "/tmp/valid-after-$label.out"
          fail "$label should be valid after apm import"
        fi
      }

      publish_default_version() {
        version="$1"
        store_path="$2"
        $APR publish "$store_path" \
          --name default-tool \
          --version "$version" \
          --description "Default tracking workflow tool" \
          --license MIT \
          --maintainer tracking@example.invalid \
          --registry default-reg \
          --no-commit
        $APR cache generate \
          --registry default-reg \
          --output /tmp/default-cache \
          --cache-url http://127.0.0.1:18103 \
          --priority 45 \
          --no-commit
        git -C "$REG_DIR" add -A
        git -C "$REG_DIR" commit -m "release: default-tool $version"
      }

      TOOL_V1_STORE=$(make_default_tool 1.0.0)
      TOOL_V2_STORE=$(make_default_tool 2.0.0)
      TOOL_V1_HASH=$(basename "$TOOL_V1_STORE" | cut -d- -f1)
      TOOL_V2_HASH=$(basename "$TOOL_V2_STORE" | cut -d- -f1)

      $APR create default-reg
      REG_DIR="$REG_STORAGE/default-reg"
      DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)
      publish_default_version 1.0.0 "$TOOL_V1_STORE"
      if git -C "$REG_DIR" tag -l | grep -q .; then
        git -C "$REG_DIR" tag -l
        fail "default tracking workflow should not create release tags"
      else
        pass "default tracking registry has no release tags"
      fi
      assert_file_exists "/tmp/default-cache/$TOOL_V1_HASH.narinfo" \
        "static cache has default-tool v1 narinfo"

      git init --bare --object-format=sha256 /tmp/default-origin.git
      git -C /tmp/default-origin.git symbolic-ref HEAD "refs/heads/$DEFAULT_BRANCH"
      git -C "$REG_DIR" remote add origin /tmp/default-origin.git
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true

      python3 -m http.server 18103 --bind 127.0.0.1 \
        --directory /tmp/default-cache > /tmp/default-cache-http.log 2>&1 &
      CACHE_PID=$!
      for _i in 1 2 3 4 5 6 7 8 9 10; do
        if curl -sf http://127.0.0.1:18103/nix-cache-info >/dev/null; then
          break
        fi
        sleep 1
      done
      if curl -sf http://127.0.0.1:18103/nix-cache-info >/dev/null; then
        pass "default static cache HTTP server started"
      else
        cat /tmp/default-cache-http.log || true
        fail "default static cache HTTP server started"
      fi

      export HOME=/tmp/default-consumer
      export USER=defaultuser
      mkdir -p "$HOME"
      APM_CONFIG="$HOME/.config/apm"

      # Add registry with NO tracking flags
      $APM registry add file:///tmp/default-origin.git --name default-reg \
        > /tmp/default-add.out 2>&1 || {
        cat /tmp/default-add.out
        fail "apm registry add syncs default branch"
      }
      cat /tmp/default-add.out

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

      $APM search default-tool --registry default-reg > /tmp/default-search-v1.out 2>&1 || {
        cat /tmp/default-search-v1.out
        fail "apm search sees package from default branch"
      }
      assert_file_contains /tmp/default-search-v1.out "1.0.0" \
        "default tracking initial sync exposes v1 package"

      mount -o remount,rw / || true
      delete_store_path "$TOOL_V1_STORE" "default-tool-v1"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"

      $APM install default-tool --registry default-reg --yes \
        > /tmp/default-install-v1.out 2>&1 || {
        cat /tmp/default-install-v1.out
        fail "apm install downloads default branch v1"
      }
      cat /tmp/default-install-v1.out
      assert_file_contains /tmp/default-install-v1.out "Downloading" \
        "apm install downloads default v1 NAR"
      assert_store_valid "$TOOL_V1_STORE" "default-tool v1"
      PROFILE_TOOL="/var/lib/profiles/per-user/$USER/current/bin/default-tool"
      "$PROFILE_TOOL" > /tmp/default-run-v1.out
      assert_file_contains /tmp/default-run-v1.out \
        "default-tool 1.0.0 executed" "installed default v1 tool executes"

      export HOME=/tmp
      APM_CONFIG="$HOME/.config/apm"
      publish_default_version 2.0.0 "$TOOL_V2_STORE"
      assert_file_exists "/tmp/default-cache/$TOOL_V2_HASH.narinfo" \
        "static cache has default-tool v2 narinfo"
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      export HOME=/tmp/default-consumer
      export USER=defaultuser
      APM_CONFIG="$HOME/.config/apm"
      delete_store_path "$TOOL_V2_STORE" "default-tool-v2"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"

      $APM update --registry default-reg > /tmp/default-update-v2.out 2>&1 || {
        cat /tmp/default-update-v2.out
        fail "apm update follows default branch v2"
      }
      cat /tmp/default-update-v2.out
      $APM list --upgradable > /tmp/default-upgradable.out 2>&1 || {
        cat /tmp/default-upgradable.out
        fail "apm list --upgradable sees default branch update"
      }
      assert_file_contains /tmp/default-upgradable.out "default-tool" \
        "default branch update names package"
      assert_file_contains /tmp/default-upgradable.out "2.0.0" \
        "default branch update shows v2"

      $APM upgrade default-tool --yes > /tmp/default-upgrade.out 2>&1 || {
        cat /tmp/default-upgrade.out
        fail "apm upgrade downloads default branch v2"
      }
      cat /tmp/default-upgrade.out
      assert_file_contains /tmp/default-upgrade.out "Downloading" \
        "apm upgrade downloads default v2 NAR"
      assert_file_contains /tmp/default-upgrade.out "Upgraded 1 package" \
        "apm upgrade activates default v2"
      assert_store_valid "$TOOL_V2_STORE" "default-tool v2"
      "$PROFILE_TOOL" > /tmp/default-run-v2.out
      assert_file_contains /tmp/default-run-v2.out \
        "default-tool 2.0.0 executed" "upgraded default v2 tool executes"

      kill "$CACHE_PID" 2>/dev/null || true
      wait "$CACHE_PID" 2>/dev/null || true
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
