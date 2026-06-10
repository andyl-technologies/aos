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

      $APM registry add --no-verify file:///tmp/branch-origin.git \
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
    rootfsDeps = trackingWorkflowDeps;
    memory = 2048;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixEnv}

      echo "==> Test: tag tracking stays pinned to selected tag"

      make_tag_tool() {
        version="$1"
        src="/tmp/tag-tool-$version-src"
        rm -rf "$src"
        mkdir -p "$src/bin" "$src/share/tag-tool"
        cat > "$src/bin/tag-tool" << EOF
      #!/bin/sh
      echo "tag-tool $version executed"
      EOF
        chmod +x "$src/bin/tag-tool"
        printf "tag-tool payload %s\n" "$version" \
          > "$src/share/tag-tool/payload.txt"
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
        nix-store --delete --ignore-liveness "$path" > "/tmp/tag-delete-$label.out" 2>&1 || {
          cat "/tmp/tag-delete-$label.out"
          fail "delete $label before apm download"
          return
        }
        if nix-store --check-validity "$path" > "/tmp/tag-valid-$label.out" 2>&1; then
          cat "/tmp/tag-valid-$label.out"
          fail "$label should be missing before apm download"
        else
          pass "$label missing before apm download"
        fi
      }

      assert_store_valid() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/tag-valid-after-$label.out" 2>&1; then
          pass "$label valid after apm import"
        else
          cat "/tmp/tag-valid-after-$label.out"
          fail "$label should be valid after apm import"
        fi
      }

      assert_store_missing() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/tag-missing-$label.out" 2>&1; then
          cat "/tmp/tag-missing-$label.out"
          fail "$label should remain missing"
        else
          pass "$label remains missing"
        fi
      }

      publish_tag_version() {
        version="$1"
        store_path="$2"
        $APR publish "$store_path" \
          --name tag-tool \
          --version "$version" \
          --description "Tag tracking workflow tool" \
          --license MIT \
          --maintainer tracking@example.invalid \
          --registry tag-reg \
          --no-commit > "/tmp/tag-publish-$version.out" 2>&1 || {
          cat "/tmp/tag-publish-$version.out"
          fail "apr publish tag-tool $version"
          return
        }
        cat "/tmp/tag-publish-$version.out"
        $APR cache generate \
          --registry tag-reg \
          --output /tmp/tag-cache \
          --cache-url http://127.0.0.1:18105 \
          --priority 46 \
          --no-commit > "/tmp/tag-cache-generate-$version.out" 2>&1 || {
          cat "/tmp/tag-cache-generate-$version.out"
          fail "apr cache generate after tag-tool $version"
          return
        }
        cat "/tmp/tag-cache-generate-$version.out"
        git -C "$REG_DIR" add -A
        git -C "$REG_DIR" commit -m "release: tag-tool $version" \
          > "/tmp/tag-commit-$version.out" 2>&1 || {
          cat "/tmp/tag-commit-$version.out"
          fail "git commit tag-tool $version"
          return
        }
        cat "/tmp/tag-commit-$version.out"
      }

      TOOL_V1_STORE=$(make_tag_tool 1.0.0)
      TOOL_V2_STORE=$(make_tag_tool 2.0.0)
      TOOL_V1_HASH=$(basename "$TOOL_V1_STORE" | cut -d- -f1)
      TOOL_V2_HASH=$(basename "$TOOL_V2_STORE" | cut -d- -f1)

      $APR create tag-reg
      REG_DIR="$REG_STORAGE/tag-reg"
      DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)
      publish_tag_version 1.0.0 "$TOOL_V1_STORE"
      git -C "$REG_DIR" tag v1.0.0
      assert_file_exists "/tmp/tag-cache/$TOOL_V1_HASH.narinfo" \
        "static cache has tag-tool v1 narinfo"

      git init --bare --object-format=sha256 /tmp/tag-origin.git
      git -C /tmp/tag-origin.git symbolic-ref HEAD "refs/heads/$DEFAULT_BRANCH"
      git -C "$REG_DIR" remote add origin /tmp/tag-origin.git
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"
      git -C "$REG_DIR" push origin v1.0.0

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true

      python3 -m http.server 18105 --bind 127.0.0.1 \
        --directory /tmp/tag-cache > /tmp/tag-cache-http.log 2>&1 &
      CACHE_PID=$!
      for _i in 1 2 3 4 5 6 7 8 9 10; do
        if curl -sf http://127.0.0.1:18105/nix-cache-info >/dev/null; then
          break
        fi
        sleep 1
      done
      if curl -sf http://127.0.0.1:18105/nix-cache-info >/dev/null; then
        pass "tag static cache HTTP server started"
      else
        cat /tmp/tag-cache-http.log || true
        fail "tag static cache HTTP server started"
      fi

      export HOME=/tmp/tag-consumer
      export USER=taguser
      mkdir -p "$HOME"
      APM_CONFIG="$HOME/.config/apm"

      $APM registry add --no-verify file:///tmp/tag-origin.git \
        --name tag-reg \
        --tag v1.0.0 > /tmp/tag-add.out 2>&1 || {
        cat /tmp/tag-add.out
        fail "apm registry add syncs selected tag"
      }
      cat /tmp/tag-add.out
      CONFIG_FILE="$APM_CONFIG/registries.d/tag-reg.toml"
      assert_file_contains "$CONFIG_FILE" 'tag = "v1.0.0"' \
        "config has tag = v1.0.0"
      assert_cmd_output_contains "$APR list" "tag:v1.0.0" \
        "apr list shows tag tracking mode"

      $APM search tag-tool --registry tag-reg > /tmp/tag-search-v1.out 2>&1 || {
        cat /tmp/tag-search-v1.out
        fail "apm search sees tagged package"
      }
      assert_file_contains /tmp/tag-search-v1.out "1.0.0" \
        "tag tracking initial sync exposes tagged v1"
      assert_file_not_contains /tmp/tag-search-v1.out "2.0.0" \
        "tag tracking initial sync hides future v2"

      mount -o remount,rw / || true
      delete_store_path "$TOOL_V1_STORE" "tag-tool-v1"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"

      $APM install tag-tool --registry tag-reg --yes \
        > /tmp/tag-install-v1.out 2>&1 || {
        cat /tmp/tag-install-v1.out
        fail "apm install downloads selected tag v1"
      }
      cat /tmp/tag-install-v1.out
      assert_file_contains /tmp/tag-install-v1.out "Downloading" \
        "apm install downloads tag v1 NAR"
      assert_store_valid "$TOOL_V1_STORE" "tag-tool v1"
      PROFILE_TOOL="/var/lib/profiles/per-user/$USER/current/bin/tag-tool"
      "$PROFILE_TOOL" > /tmp/tag-run-v1.out
      assert_file_contains /tmp/tag-run-v1.out \
        "tag-tool 1.0.0 executed" "installed tag v1 tool executes"

      export HOME=/tmp
      APM_CONFIG="$HOME/.config/apm"
      publish_tag_version 2.0.0 "$TOOL_V2_STORE"
      assert_file_exists "/tmp/tag-cache/$TOOL_V2_HASH.narinfo" \
        "static cache has tag-tool v2 narinfo on default branch"
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      export HOME=/tmp/tag-consumer
      export USER=taguser
      APM_CONFIG="$HOME/.config/apm"
      delete_store_path "$TOOL_V2_STORE" "tag-tool-v2"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"

      $APM update --registry tag-reg > /tmp/tag-update-after-v2.out 2>&1 || {
        cat /tmp/tag-update-after-v2.out
        fail "apm update keeps selected tag after branch advances"
      }
      cat /tmp/tag-update-after-v2.out
      $APM search tag-tool --registry tag-reg > /tmp/tag-search-after-v2.out 2>&1 || {
        cat /tmp/tag-search-after-v2.out
        fail "apm search still sees selected tag package"
      }
      assert_file_contains /tmp/tag-search-after-v2.out "1.0.0" \
        "tag tracking still exposes v1 after default branch advances"
      assert_file_not_contains /tmp/tag-search-after-v2.out "2.0.0" \
        "tag tracking ignores untagged default branch v2"

      $APM list --upgradable > /tmp/tag-upgradable.out 2>&1 || {
        cat /tmp/tag-upgradable.out
        fail "apm list --upgradable succeeds for tag-pinned registry"
      }
      assert_file_not_contains /tmp/tag-upgradable.out "tag-tool" \
        "tag-pinned registry does not advertise default branch v2"

      $APM upgrade tag-tool --yes > /tmp/tag-upgrade.out 2>&1 || {
        cat /tmp/tag-upgrade.out
        fail "tag-pinned apm upgrade is a no-op"
      }
      cat /tmp/tag-upgrade.out
      assert_file_contains /tmp/tag-upgrade.out "All packages are up to date" \
        "tag-pinned upgrade reports no candidate"
      assert_file_not_contains /tmp/tag-upgrade.out "Downloading" \
        "tag-pinned upgrade does not download default branch v2"
      assert_store_missing "$TOOL_V2_STORE" "tag-tool v2"
      "$PROFILE_TOOL" > /tmp/tag-run-still-v1.out
      assert_file_contains /tmp/tag-run-still-v1.out \
        "tag-tool 1.0.0 executed" "tag-pinned profile remains on v1"

      kill "$CACHE_PID" 2>/dev/null || true
      wait "$CACHE_PID" 2>/dev/null || true
      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # 3. tracking-version-tilde — Semver tilde constraint (~1.0)
  # -------------------------------------------------------------------------
  tracking-version-tilde = testing.mkVMTest {
    name = "apm-tracking-version-tilde";
    rootfsDeps = trackingWorkflowDeps;
    memory = 2048;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixEnv}

      echo "==> Test: version tilde tracking follows best matching tag"

      make_vtilde_tool() {
        version="$1"
        src="/tmp/vtilde-tool-$version-src"
        rm -rf "$src"
        mkdir -p "$src/bin" "$src/share/vtilde-tool"
        cat > "$src/bin/vtilde-tool" << EOF
      #!/bin/sh
      echo "vtilde-tool $version executed"
      EOF
        chmod +x "$src/bin/vtilde-tool"
        printf "vtilde-tool payload %s\n" "$version" \
          > "$src/share/vtilde-tool/payload.txt"
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
        nix-store --delete --ignore-liveness "$path" > "/tmp/vtilde-delete-$label.out" 2>&1 || {
          cat "/tmp/vtilde-delete-$label.out"
          fail "delete $label before apm download"
          return
        }
        if nix-store --check-validity "$path" > "/tmp/vtilde-valid-$label.out" 2>&1; then
          cat "/tmp/vtilde-valid-$label.out"
          fail "$label should be missing before apm download"
        else
          pass "$label missing before apm download"
        fi
      }

      assert_store_valid() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/vtilde-valid-after-$label.out" 2>&1; then
          pass "$label valid after apm import"
        else
          cat "/tmp/vtilde-valid-after-$label.out"
          fail "$label should be valid after apm import"
        fi
      }

      assert_store_missing() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/vtilde-missing-$label.out" 2>&1; then
          cat "/tmp/vtilde-missing-$label.out"
          fail "$label should remain missing"
        else
          pass "$label remains missing"
        fi
      }

      publish_vtilde_version() {
        version="$1"
        store_path="$2"
        $APR publish "$store_path" \
          --name vtilde-tool \
          --version "$version" \
          --description "Tilde tracking workflow tool" \
          --license MIT \
          --maintainer tracking@example.invalid \
          --registry vtilde-reg \
          --no-commit > "/tmp/vtilde-publish-$version.out" 2>&1 || {
          cat "/tmp/vtilde-publish-$version.out"
          fail "apr publish vtilde-tool $version"
          return
        }
        cat "/tmp/vtilde-publish-$version.out"
        $APR cache generate \
          --registry vtilde-reg \
          --output /tmp/vtilde-cache \
          --cache-url http://127.0.0.1:18106 \
          --priority 47 \
          --no-commit > "/tmp/vtilde-cache-generate-$version.out" 2>&1 || {
          cat "/tmp/vtilde-cache-generate-$version.out"
          fail "apr cache generate after vtilde-tool $version"
          return
        }
        cat "/tmp/vtilde-cache-generate-$version.out"
        git -C "$REG_DIR" add -A
        git -C "$REG_DIR" commit -m "release: vtilde-tool $version" \
          > "/tmp/vtilde-commit-$version.out" 2>&1 || {
          cat "/tmp/vtilde-commit-$version.out"
          fail "git commit vtilde-tool $version"
          return
        }
        cat "/tmp/vtilde-commit-$version.out"
        git -C "$REG_DIR" tag "v$version" \
          > "/tmp/vtilde-tag-$version.out" 2>&1 || {
          cat "/tmp/vtilde-tag-$version.out"
          fail "git tag v$version"
          return
        }
      }

      TOOL_100_STORE=$(make_vtilde_tool 1.0.0)
      TOOL_101_STORE=$(make_vtilde_tool 1.0.1)
      TOOL_102_STORE=$(make_vtilde_tool 1.0.2)
      TOOL_110_STORE=$(make_vtilde_tool 1.1.0)
      TOOL_103_STORE=$(make_vtilde_tool 1.0.3)
      TOOL_111_STORE=$(make_vtilde_tool 1.1.1)
      TOOL_102_HASH=$(basename "$TOOL_102_STORE" | cut -d- -f1)
      TOOL_103_HASH=$(basename "$TOOL_103_STORE" | cut -d- -f1)
      TOOL_110_HASH=$(basename "$TOOL_110_STORE" | cut -d- -f1)
      TOOL_111_HASH=$(basename "$TOOL_111_STORE" | cut -d- -f1)

      $APR create vtilde-reg
      REG_DIR="$REG_STORAGE/vtilde-reg"
      DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)
      publish_vtilde_version 1.0.0 "$TOOL_100_STORE"
      publish_vtilde_version 1.0.1 "$TOOL_101_STORE"
      publish_vtilde_version 1.0.2 "$TOOL_102_STORE"
      publish_vtilde_version 1.1.0 "$TOOL_110_STORE"
      assert_file_exists "/tmp/vtilde-cache/$TOOL_102_HASH.narinfo" \
        "static cache has vtilde-tool 1.0.2 narinfo"
      assert_file_exists "/tmp/vtilde-cache/$TOOL_110_HASH.narinfo" \
        "static cache has out-of-range 1.1.0 narinfo"

      git init --bare --object-format=sha256 /tmp/vtilde-origin.git
      git -C /tmp/vtilde-origin.git symbolic-ref HEAD "refs/heads/$DEFAULT_BRANCH"
      git -C "$REG_DIR" remote add origin /tmp/vtilde-origin.git
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"
      git -C "$REG_DIR" push origin --tags

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true

      python3 -m http.server 18106 --bind 127.0.0.1 \
        --directory /tmp/vtilde-cache > /tmp/vtilde-cache-http.log 2>&1 &
      CACHE_PID=$!
      for _i in 1 2 3 4 5 6 7 8 9 10; do
        if curl -sf http://127.0.0.1:18106/nix-cache-info >/dev/null; then
          break
        fi
        sleep 1
      done
      if curl -sf http://127.0.0.1:18106/nix-cache-info >/dev/null; then
        pass "vtilde static cache HTTP server started"
      else
        cat /tmp/vtilde-cache-http.log || true
        fail "vtilde static cache HTTP server started"
      fi

      export HOME=/tmp/vtilde-consumer
      export USER=vtildeuser
      mkdir -p "$HOME"
      APM_CONFIG="$HOME/.config/apm"

      $APM registry add --no-verify file:///tmp/vtilde-origin.git \
        --name vtilde-reg \
        --version "~1.0" > /tmp/vtilde-add.out 2>&1 || {
        cat /tmp/vtilde-add.out
        fail "apm registry add resolves best initial tilde tag"
      }
      cat /tmp/vtilde-add.out
      CONFIG_FILE="$APM_CONFIG/registries.d/vtilde-reg.toml"
      assert_file_contains "$CONFIG_FILE" 'version = "~1.0"' \
        "config has version = ~1.0"
      assert_cmd_output_contains "$APR list" "version:~1.0" \
        "apr list shows version tracking mode"

      $APM search vtilde-tool --registry vtilde-reg > /tmp/vtilde-search-initial.out 2>&1 || {
        cat /tmp/vtilde-search-initial.out
        fail "apm search sees initial best tilde package"
      }
      assert_file_contains /tmp/vtilde-search-initial.out "1.0.2" \
        "tilde tracking selects initial best 1.0.x tag"
      assert_file_not_contains /tmp/vtilde-search-initial.out "1.1.0" \
        "tilde tracking ignores initial out-of-range 1.1.0 tag"

      mount -o remount,rw / || true
      delete_store_path "$TOOL_102_STORE" "vtilde-tool-1.0.2"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"

      $APM install vtilde-tool --registry vtilde-reg --yes \
        > /tmp/vtilde-install.out 2>&1 || {
        cat /tmp/vtilde-install.out
        fail "apm install downloads initial best tilde package"
      }
      cat /tmp/vtilde-install.out
      assert_file_contains /tmp/vtilde-install.out "Downloading" \
        "apm install downloads initial tilde NAR"
      assert_store_valid "$TOOL_102_STORE" "vtilde-tool 1.0.2"
      PROFILE="/var/lib/profiles/per-user/$USER"
      assert_file_not_exists "$PROFILE/meta/$TOOL_110_HASH.json" \
        "initial tilde install does not record out-of-range 1.1.0 metadata"
      if [ -L "$PROFILE/current/usr/$TOOL_110_HASH" ]; then
        fail "initial tilde install should not root out-of-range 1.1.0"
      else
        pass "initial tilde install does not root out-of-range 1.1.0"
      fi
      PROFILE_TOOL="/var/lib/profiles/per-user/$USER/current/bin/vtilde-tool"
      "$PROFILE_TOOL" > /tmp/vtilde-run-initial.out
      assert_file_contains /tmp/vtilde-run-initial.out \
        "vtilde-tool 1.0.2 executed" "installed initial tilde tool executes"

      export HOME=/tmp
      APM_CONFIG="$HOME/.config/apm"
      git -C "$REG_DIR" checkout -b maintenance-1.0 v1.0.2
      publish_vtilde_version 1.0.3 "$TOOL_103_STORE"
      git -C "$REG_DIR" checkout "$DEFAULT_BRANCH"
      publish_vtilde_version 1.1.1 "$TOOL_111_STORE"
      assert_file_exists "/tmp/vtilde-cache/$TOOL_103_HASH.narinfo" \
        "static cache has in-range vtilde-tool 1.0.3 narinfo"
      assert_file_exists "/tmp/vtilde-cache/$TOOL_111_HASH.narinfo" \
        "static cache has out-of-range vtilde-tool 1.1.1 narinfo"
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"
      git -C "$REG_DIR" push origin maintenance-1.0
      git -C "$REG_DIR" push origin --tags

      export HOME=/tmp/vtilde-consumer
      export USER=vtildeuser
      APM_CONFIG="$HOME/.config/apm"
      delete_store_path "$TOOL_103_STORE" "vtilde-tool-1.0.3"
      delete_store_path "$TOOL_111_STORE" "vtilde-tool-1.1.1"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"

      $APM update --registry vtilde-reg > /tmp/vtilde-update.out 2>&1 || {
        cat /tmp/vtilde-update.out
        fail "apm update advances to best in-range tilde tag"
      }
      cat /tmp/vtilde-update.out
      $APM list --upgradable > /tmp/vtilde-upgradable.out 2>&1 || {
        cat /tmp/vtilde-upgradable.out
        fail "apm list --upgradable sees in-range tilde update"
      }
      assert_file_contains /tmp/vtilde-upgradable.out "vtilde-tool" \
        "tilde update names package"
      assert_file_contains /tmp/vtilde-upgradable.out "1.0.3" \
        "tilde update shows best in-range 1.0.3"
      assert_file_not_contains /tmp/vtilde-upgradable.out "1.1.1" \
        "tilde update ignores out-of-range 1.1.1"

      $APM upgrade vtilde-tool --yes > /tmp/vtilde-upgrade.out 2>&1 || {
        cat /tmp/vtilde-upgrade.out
        fail "apm upgrade downloads in-range tilde update"
      }
      cat /tmp/vtilde-upgrade.out
      assert_file_contains /tmp/vtilde-upgrade.out "vtilde-tool (1.0.2 -> 1.0.3)" \
        "tilde upgrade plans in-range update"
      assert_file_not_contains /tmp/vtilde-upgrade.out "1.1.1" \
        "tilde upgrade does not plan out-of-range update"
      assert_file_contains /tmp/vtilde-upgrade.out "Downloading" \
        "tilde upgrade downloads in-range NAR"
      assert_store_valid "$TOOL_103_STORE" "vtilde-tool 1.0.3"
      assert_store_missing "$TOOL_111_STORE" "vtilde-tool 1.1.1"
      "$PROFILE_TOOL" > /tmp/vtilde-run-upgraded.out
      assert_file_contains /tmp/vtilde-run-upgraded.out \
        "vtilde-tool 1.0.3 executed" "upgraded tilde tool executes"

      kill "$CACHE_PID" 2>/dev/null || true
      wait "$CACHE_PID" 2>/dev/null || true
      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # 4. tracking-version-caret — Semver caret constraint (^1)
  # -------------------------------------------------------------------------
  tracking-version-caret = testing.mkVMTest {
    name = "apm-tracking-version-caret";
    rootfsDeps = trackingWorkflowDeps;
    memory = 2048;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixEnv}

      echo "==> Test: version caret tracking follows best matching tag"

      make_vcaret_tool() {
        version="$1"
        src="/tmp/vcaret-tool-$version-src"
        rm -rf "$src"
        mkdir -p "$src/bin" "$src/share/vcaret-tool"
        cat > "$src/bin/vcaret-tool" << EOF
      #!/bin/sh
      echo "vcaret-tool $version executed"
      EOF
        chmod +x "$src/bin/vcaret-tool"
        printf "vcaret-tool payload %s\n" "$version" \
          > "$src/share/vcaret-tool/payload.txt"
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
        nix-store --delete --ignore-liveness "$path" > "/tmp/vcaret-delete-$label.out" 2>&1 || {
          cat "/tmp/vcaret-delete-$label.out"
          fail "delete $label before apm download"
          return
        }
        if nix-store --check-validity "$path" > "/tmp/vcaret-valid-$label.out" 2>&1; then
          cat "/tmp/vcaret-valid-$label.out"
          fail "$label should be missing before apm download"
        else
          pass "$label missing before apm download"
        fi
      }

      assert_store_valid() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/vcaret-valid-after-$label.out" 2>&1; then
          pass "$label valid after apm import"
        else
          cat "/tmp/vcaret-valid-after-$label.out"
          fail "$label should be valid after apm import"
        fi
      }

      assert_store_missing() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/vcaret-missing-$label.out" 2>&1; then
          cat "/tmp/vcaret-missing-$label.out"
          fail "$label should remain missing"
        else
          pass "$label remains missing"
        fi
      }

      publish_vcaret_version() {
        version="$1"
        store_path="$2"
        $APR publish "$store_path" \
          --name vcaret-tool \
          --version "$version" \
          --description "Caret tracking workflow tool" \
          --license MIT \
          --maintainer tracking@example.invalid \
          --registry vcaret-reg \
          --no-commit > "/tmp/vcaret-publish-$version.out" 2>&1 || {
          cat "/tmp/vcaret-publish-$version.out"
          fail "apr publish vcaret-tool $version"
          return
        }
        cat "/tmp/vcaret-publish-$version.out"
        $APR cache generate \
          --registry vcaret-reg \
          --output /tmp/vcaret-cache \
          --cache-url http://127.0.0.1:18107 \
          --priority 48 \
          --no-commit > "/tmp/vcaret-cache-generate-$version.out" 2>&1 || {
          cat "/tmp/vcaret-cache-generate-$version.out"
          fail "apr cache generate after vcaret-tool $version"
          return
        }
        cat "/tmp/vcaret-cache-generate-$version.out"
        git -C "$REG_DIR" add -A
        git -C "$REG_DIR" commit -m "release: vcaret-tool $version" \
          > "/tmp/vcaret-commit-$version.out" 2>&1 || {
          cat "/tmp/vcaret-commit-$version.out"
          fail "git commit vcaret-tool $version"
          return
        }
        cat "/tmp/vcaret-commit-$version.out"
        git -C "$REG_DIR" tag "v$version" \
          > "/tmp/vcaret-tag-$version.out" 2>&1 || {
          cat "/tmp/vcaret-tag-$version.out"
          fail "git tag v$version"
          return
        }
      }

      TOOL_100_STORE=$(make_vcaret_tool 1.0.0)
      TOOL_120_STORE=$(make_vcaret_tool 1.2.0)
      TOOL_200_STORE=$(make_vcaret_tool 2.0.0)
      TOOL_130_STORE=$(make_vcaret_tool 1.3.0)
      TOOL_210_STORE=$(make_vcaret_tool 2.1.0)
      TOOL_120_HASH=$(basename "$TOOL_120_STORE" | cut -d- -f1)
      TOOL_130_HASH=$(basename "$TOOL_130_STORE" | cut -d- -f1)
      TOOL_200_HASH=$(basename "$TOOL_200_STORE" | cut -d- -f1)
      TOOL_210_HASH=$(basename "$TOOL_210_STORE" | cut -d- -f1)

      $APR create vcaret-reg
      REG_DIR="$REG_STORAGE/vcaret-reg"
      DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)
      publish_vcaret_version 1.0.0 "$TOOL_100_STORE"
      publish_vcaret_version 1.2.0 "$TOOL_120_STORE"
      publish_vcaret_version 2.0.0 "$TOOL_200_STORE"
      assert_file_exists "/tmp/vcaret-cache/$TOOL_120_HASH.narinfo" \
        "static cache has vcaret-tool 1.2.0 narinfo"
      assert_file_exists "/tmp/vcaret-cache/$TOOL_200_HASH.narinfo" \
        "static cache has out-of-range 2.0.0 narinfo"

      git init --bare --object-format=sha256 /tmp/vcaret-origin.git
      git -C /tmp/vcaret-origin.git symbolic-ref HEAD "refs/heads/$DEFAULT_BRANCH"
      git -C "$REG_DIR" remote add origin /tmp/vcaret-origin.git
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"
      git -C "$REG_DIR" push origin --tags

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true

      python3 -m http.server 18107 --bind 127.0.0.1 \
        --directory /tmp/vcaret-cache > /tmp/vcaret-cache-http.log 2>&1 &
      CACHE_PID=$!
      for _i in 1 2 3 4 5 6 7 8 9 10; do
        if curl -sf http://127.0.0.1:18107/nix-cache-info >/dev/null; then
          break
        fi
        sleep 1
      done
      if curl -sf http://127.0.0.1:18107/nix-cache-info >/dev/null; then
        pass "vcaret static cache HTTP server started"
      else
        cat /tmp/vcaret-cache-http.log || true
        fail "vcaret static cache HTTP server started"
      fi

      export HOME=/tmp/vcaret-consumer
      export USER=vcaretuser
      mkdir -p "$HOME"
      APM_CONFIG="$HOME/.config/apm"

      $APM registry add --no-verify file:///tmp/vcaret-origin.git \
        --name vcaret-reg \
        --version "^1" > /tmp/vcaret-add.out 2>&1 || {
        cat /tmp/vcaret-add.out
        fail "apm registry add resolves best initial caret tag"
      }
      cat /tmp/vcaret-add.out
      CONFIG_FILE="$APM_CONFIG/registries.d/vcaret-reg.toml"
      assert_file_contains "$CONFIG_FILE" 'version = "^1"' \
        "config has version = ^1"
      assert_cmd_output_contains "$APR list" "version:^1" \
        "apr list shows version tracking mode"

      $APM search vcaret-tool --registry vcaret-reg > /tmp/vcaret-search-initial.out 2>&1 || {
        cat /tmp/vcaret-search-initial.out
        fail "apm search sees initial best caret package"
      }
      assert_file_contains /tmp/vcaret-search-initial.out "1.2.0" \
        "caret tracking selects initial best 1.x tag"
      assert_file_not_contains /tmp/vcaret-search-initial.out "2.0.0" \
        "caret tracking ignores initial out-of-range 2.0.0 tag"

      mount -o remount,rw / || true
      delete_store_path "$TOOL_120_STORE" "vcaret-tool-1.2.0"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"

      $APM install vcaret-tool --registry vcaret-reg --yes \
        > /tmp/vcaret-install.out 2>&1 || {
        cat /tmp/vcaret-install.out
        fail "apm install downloads initial best caret package"
      }
      cat /tmp/vcaret-install.out
      assert_file_contains /tmp/vcaret-install.out "Downloading" \
        "apm install downloads initial caret NAR"
      assert_store_valid "$TOOL_120_STORE" "vcaret-tool 1.2.0"
      PROFILE="/var/lib/profiles/per-user/$USER"
      assert_file_not_exists "$PROFILE/meta/$TOOL_200_HASH.json" \
        "initial caret install does not record out-of-range 2.0.0 metadata"
      if [ -L "$PROFILE/current/usr/$TOOL_200_HASH" ]; then
        fail "initial caret install should not root out-of-range 2.0.0"
      else
        pass "initial caret install does not root out-of-range 2.0.0"
      fi
      PROFILE_TOOL="/var/lib/profiles/per-user/$USER/current/bin/vcaret-tool"
      "$PROFILE_TOOL" > /tmp/vcaret-run-initial.out
      assert_file_contains /tmp/vcaret-run-initial.out \
        "vcaret-tool 1.2.0 executed" "installed initial caret tool executes"

      export HOME=/tmp
      APM_CONFIG="$HOME/.config/apm"
      git -C "$REG_DIR" checkout -b maintenance-1 v1.2.0
      publish_vcaret_version 1.3.0 "$TOOL_130_STORE"
      git -C "$REG_DIR" checkout "$DEFAULT_BRANCH"
      publish_vcaret_version 2.1.0 "$TOOL_210_STORE"
      assert_file_exists "/tmp/vcaret-cache/$TOOL_130_HASH.narinfo" \
        "static cache has in-range vcaret-tool 1.3.0 narinfo"
      assert_file_exists "/tmp/vcaret-cache/$TOOL_210_HASH.narinfo" \
        "static cache has out-of-range vcaret-tool 2.1.0 narinfo"
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"
      git -C "$REG_DIR" push origin maintenance-1
      git -C "$REG_DIR" push origin --tags

      export HOME=/tmp/vcaret-consumer
      export USER=vcaretuser
      APM_CONFIG="$HOME/.config/apm"
      delete_store_path "$TOOL_130_STORE" "vcaret-tool-1.3.0"
      delete_store_path "$TOOL_210_STORE" "vcaret-tool-2.1.0"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"

      $APM update --registry vcaret-reg > /tmp/vcaret-update.out 2>&1 || {
        cat /tmp/vcaret-update.out
        fail "apm update advances to best in-range caret tag"
      }
      cat /tmp/vcaret-update.out
      $APM list --upgradable > /tmp/vcaret-upgradable.out 2>&1 || {
        cat /tmp/vcaret-upgradable.out
        fail "apm list --upgradable sees in-range caret update"
      }
      assert_file_contains /tmp/vcaret-upgradable.out "vcaret-tool" \
        "caret update names package"
      assert_file_contains /tmp/vcaret-upgradable.out "1.3.0" \
        "caret update shows best in-range 1.3.0"
      assert_file_not_contains /tmp/vcaret-upgradable.out "2.1.0" \
        "caret update ignores out-of-range 2.1.0"

      $APM upgrade vcaret-tool --yes > /tmp/vcaret-upgrade.out 2>&1 || {
        cat /tmp/vcaret-upgrade.out
        fail "apm upgrade downloads in-range caret update"
      }
      cat /tmp/vcaret-upgrade.out
      assert_file_contains /tmp/vcaret-upgrade.out "vcaret-tool (1.2.0 -> 1.3.0)" \
        "caret upgrade plans in-range update"
      assert_file_not_contains /tmp/vcaret-upgrade.out "2.1.0" \
        "caret upgrade does not plan out-of-range update"
      assert_file_contains /tmp/vcaret-upgrade.out "Downloading" \
        "caret upgrade downloads in-range NAR"
      assert_store_valid "$TOOL_130_STORE" "vcaret-tool 1.3.0"
      assert_store_missing "$TOOL_210_STORE" "vcaret-tool 2.1.0"
      "$PROFILE_TOOL" > /tmp/vcaret-run-upgraded.out
      assert_file_contains /tmp/vcaret-run-upgraded.out \
        "vcaret-tool 1.3.0 executed" "upgraded caret tool executes"

      kill "$CACHE_PID" 2>/dev/null || true
      wait "$CACHE_PID" 2>/dev/null || true
      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # 5. tracking-commit — Pin to exact commit hash
  # -------------------------------------------------------------------------
  tracking-commit = testing.mkVMTest {
    name = "apm-tracking-commit";
    rootfsDeps = trackingWorkflowDeps;
    memory = 2048;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixEnv}

      echo "==> Test: commit tracking stays pinned to selected commit"

      make_commit_tool() {
        version="$1"
        src="/tmp/commit-tool-$version-src"
        rm -rf "$src"
        mkdir -p "$src/bin" "$src/share/commit-tool"
        cat > "$src/bin/commit-tool" << EOF
      #!/bin/sh
      echo "commit-tool $version executed"
      EOF
        chmod +x "$src/bin/commit-tool"
        printf "commit-tool payload %s\n" "$version" \
          > "$src/share/commit-tool/payload.txt"
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
        nix-store --delete --ignore-liveness "$path" > "/tmp/commit-delete-$label.out" 2>&1 || {
          cat "/tmp/commit-delete-$label.out"
          fail "delete $label before apm download"
          return
        }
        if nix-store --check-validity "$path" > "/tmp/commit-valid-$label.out" 2>&1; then
          cat "/tmp/commit-valid-$label.out"
          fail "$label should be missing before apm download"
        else
          pass "$label missing before apm download"
        fi
      }

      assert_store_valid() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/commit-valid-after-$label.out" 2>&1; then
          pass "$label valid after apm import"
        else
          cat "/tmp/commit-valid-after-$label.out"
          fail "$label should be valid after apm import"
        fi
      }

      assert_store_missing() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/commit-missing-$label.out" 2>&1; then
          cat "/tmp/commit-missing-$label.out"
          fail "$label should remain missing"
        else
          pass "$label remains missing"
        fi
      }

      publish_commit_version() {
        version="$1"
        store_path="$2"
        $APR publish "$store_path" \
          --name commit-tool \
          --version "$version" \
          --description "Commit tracking workflow tool" \
          --license MIT \
          --maintainer tracking@example.invalid \
          --registry commit-reg \
          --no-commit > "/tmp/commit-publish-$version.out" 2>&1 || {
          cat "/tmp/commit-publish-$version.out"
          fail "apr publish commit-tool $version"
          return
        }
        cat "/tmp/commit-publish-$version.out"
        $APR cache generate \
          --registry commit-reg \
          --output /tmp/commit-cache \
          --cache-url http://127.0.0.1:18108 \
          --priority 49 \
          --no-commit > "/tmp/commit-cache-generate-$version.out" 2>&1 || {
          cat "/tmp/commit-cache-generate-$version.out"
          fail "apr cache generate after commit-tool $version"
          return
        }
        cat "/tmp/commit-cache-generate-$version.out"
        git -C "$REG_DIR" add -A
        git -C "$REG_DIR" commit -m "release: commit-tool $version" \
          > "/tmp/commit-commit-$version.out" 2>&1 || {
          cat "/tmp/commit-commit-$version.out"
          fail "git commit commit-tool $version"
          return
        }
        cat "/tmp/commit-commit-$version.out"
      }

      TOOL_V1_STORE=$(make_commit_tool 1.0.0)
      TOOL_V2_STORE=$(make_commit_tool 2.0.0)
      TOOL_V1_HASH=$(basename "$TOOL_V1_STORE" | cut -d- -f1)
      TOOL_V2_HASH=$(basename "$TOOL_V2_STORE" | cut -d- -f1)

      $APR create commit-reg
      REG_DIR="$REG_STORAGE/commit-reg"
      DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)
      publish_commit_version 1.0.0 "$TOOL_V1_STORE"
      PINNED_COMMIT=$(git -C "$REG_DIR" rev-parse HEAD)
      SHORT_COMMIT=$(printf "%s" "$PINNED_COMMIT" | cut -c1-12)
      echo "Pinned commit: $PINNED_COMMIT"
      assert_file_exists "/tmp/commit-cache/$TOOL_V1_HASH.narinfo" \
        "static cache has commit-tool v1 narinfo"

      publish_commit_version 2.0.0 "$TOOL_V2_STORE"
      ADVANCED_COMMIT=$(git -C "$REG_DIR" rev-parse HEAD)
      assert_file_exists "/tmp/commit-cache/$TOOL_V2_HASH.narinfo" \
        "static cache has commit-tool v2 narinfo"
      if [ "$PINNED_COMMIT" = "$ADVANCED_COMMIT" ]; then
        fail "advanced commit should differ from pinned commit"
      else
        pass "registry advanced past pinned commit"
      fi

      git init --bare --object-format=sha256 /tmp/commit-origin.git
      git -C /tmp/commit-origin.git symbolic-ref HEAD "refs/heads/$DEFAULT_BRANCH"
      git -C "$REG_DIR" remote add origin /tmp/commit-origin.git
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true

      python3 -m http.server 18108 --bind 127.0.0.1 \
        --directory /tmp/commit-cache > /tmp/commit-cache-http.log 2>&1 &
      CACHE_PID=$!
      for _i in 1 2 3 4 5 6 7 8 9 10; do
        if curl -sf http://127.0.0.1:18108/nix-cache-info >/dev/null; then
          break
        fi
        sleep 1
      done
      if curl -sf http://127.0.0.1:18108/nix-cache-info >/dev/null; then
        pass "commit static cache HTTP server started"
      else
        cat /tmp/commit-cache-http.log || true
        fail "commit static cache HTTP server started"
      fi

      export HOME=/tmp/commit-consumer
      export USER=commituser
      mkdir -p "$HOME"
      APM_CONFIG="$HOME/.config/apm"

      $APM registry add --no-verify file:///tmp/commit-origin.git \
        --name commit-reg \
        --commit "$PINNED_COMMIT" > /tmp/commit-add.out 2>&1 || {
        cat /tmp/commit-add.out
        fail "apm registry add syncs selected commit"
      }
      cat /tmp/commit-add.out
      CONFIG_FILE="$APM_CONFIG/registries.d/commit-reg.toml"
      assert_file_contains "$CONFIG_FILE" "commit = \"$PINNED_COMMIT\"" \
        "config has exact commit pin"
      assert_cmd_output_contains "$APR list" "commit:$SHORT_COMMIT" \
        "apr list shows commit tracking mode"

      $APM search commit-tool --registry commit-reg > /tmp/commit-search-initial.out 2>&1 || {
        cat /tmp/commit-search-initial.out
        fail "apm search sees pinned commit package"
      }
      assert_file_contains /tmp/commit-search-initial.out "1.0.0" \
        "commit tracking exposes pinned v1"
      assert_file_not_contains /tmp/commit-search-initial.out "2.0.0" \
        "commit tracking hides later v2"

      mount -o remount,rw / || true
      delete_store_path "$TOOL_V1_STORE" "commit-tool-v1"
      delete_store_path "$TOOL_V2_STORE" "commit-tool-v2"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"

      $APM install commit-tool --registry commit-reg --yes \
        > /tmp/commit-install.out 2>&1 || {
        cat /tmp/commit-install.out
        fail "apm install downloads pinned commit v1"
      }
      cat /tmp/commit-install.out
      assert_file_contains /tmp/commit-install.out "Downloading" \
        "apm install downloads pinned commit NAR"
      assert_store_valid "$TOOL_V1_STORE" "commit-tool v1"
      assert_store_missing "$TOOL_V2_STORE" "commit-tool v2"
      PROFILE="/var/lib/profiles/per-user/$USER"
      assert_file_not_exists "$PROFILE/meta/$TOOL_V2_HASH.json" \
        "commit-pinned install does not record later v2 metadata"
      PROFILE_TOOL="$PROFILE/current/bin/commit-tool"
      "$PROFILE_TOOL" > /tmp/commit-run-v1.out
      assert_file_contains /tmp/commit-run-v1.out \
        "commit-tool 1.0.0 executed" "installed commit-pinned v1 tool executes"

      $APM update --registry commit-reg > /tmp/commit-update.out 2>&1 || {
        cat /tmp/commit-update.out
        fail "apm update keeps selected commit"
      }
      cat /tmp/commit-update.out
      $APM search commit-tool --registry commit-reg > /tmp/commit-search-after-update.out 2>&1 || {
        cat /tmp/commit-search-after-update.out
        fail "apm search still sees pinned commit package"
      }
      assert_file_contains /tmp/commit-search-after-update.out "1.0.0" \
        "commit tracking still exposes pinned v1 after update"
      assert_file_not_contains /tmp/commit-search-after-update.out "2.0.0" \
        "commit tracking still hides later v2 after update"

      $APM list --upgradable > /tmp/commit-upgradable.out 2>&1 || {
        cat /tmp/commit-upgradable.out
        fail "apm list --upgradable succeeds for commit-pinned registry"
      }
      assert_file_not_contains /tmp/commit-upgradable.out "commit-tool" \
        "commit-pinned registry does not advertise later v2"

      $APM upgrade commit-tool --yes > /tmp/commit-upgrade.out 2>&1 || {
        cat /tmp/commit-upgrade.out
        fail "commit-pinned apm upgrade is a no-op"
      }
      cat /tmp/commit-upgrade.out
      assert_file_contains /tmp/commit-upgrade.out "All packages are up to date" \
        "commit-pinned upgrade reports no candidate"
      assert_file_not_contains /tmp/commit-upgrade.out "Downloading" \
        "commit-pinned upgrade does not download later v2"
      assert_store_missing "$TOOL_V2_STORE" "commit-tool v2"
      "$PROFILE_TOOL" > /tmp/commit-run-still-v1.out
      assert_file_contains /tmp/commit-run-still-v1.out \
        "commit-tool 1.0.0 executed" "commit-pinned profile remains on v1"

      kill "$CACHE_PID" 2>/dev/null || true
      wait "$CACHE_PID" 2>/dev/null || true
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
      $APM registry add --no-verify file:///tmp/default-origin.git --name default-reg \
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
    rootfsDeps = trackingWorkflowDeps;
    memory = 2048;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixEnv}

      echo "==> Test: real git-native version tracking after bundle cutover"

      make_git_native_tool() {
        version="$1"
        src="/tmp/git-native-tool-$version-src"
        rm -rf "$src"
        mkdir -p "$src/bin" "$src/share/git-native-tool"
        cat > "$src/bin/git-native-tool" << EOF
      #!/bin/sh
      echo "git-native-tool $version executed"
      EOF
        chmod +x "$src/bin/git-native-tool"
        printf "git-native-tool payload %s\n" "$version" \
          > "$src/share/git-native-tool/payload.txt"
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
        nix-store --delete --ignore-liveness "$path" > "/tmp/git-native-delete-$label.out" 2>&1 || {
          cat "/tmp/git-native-delete-$label.out"
          fail "delete $label before apm download"
          return
        }
        if nix-store --check-validity "$path" > "/tmp/git-native-valid-$label.out" 2>&1; then
          cat "/tmp/git-native-valid-$label.out"
          fail "$label should be missing before apm download"
        else
          pass "$label missing before apm download"
        fi
      }

      assert_store_valid() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/git-native-valid-after-$label.out" 2>&1; then
          pass "$label valid after apm import"
        else
          cat "/tmp/git-native-valid-after-$label.out"
          fail "$label should be valid after apm import"
        fi
      }

      assert_store_missing() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/git-native-missing-$label.out" 2>&1; then
          cat "/tmp/git-native-missing-$label.out"
          fail "$label should remain missing"
        else
          pass "$label remains missing"
        fi
      }

      publish_git_native_version() {
        version="$1"
        store_path="$2"
        $APR publish "$store_path" \
          --name git-native-tool \
          --version "$version" \
          --description "Git-native tracking workflow tool" \
          --license MIT \
          --maintainer tracking@example.invalid \
          --registry git-native-reg \
          --no-commit > "/tmp/git-native-publish-$version.out" 2>&1 || {
          cat "/tmp/git-native-publish-$version.out"
          fail "apr publish git-native-tool $version"
          return
        }
        cat "/tmp/git-native-publish-$version.out"
        $APR cache generate \
          --registry git-native-reg \
          --output /tmp/git-native-cache \
          --cache-url http://127.0.0.1:18109 \
          --priority 49 \
          --no-commit > "/tmp/git-native-cache-generate-$version.out" 2>&1 || {
          cat "/tmp/git-native-cache-generate-$version.out"
          fail "apr cache generate after git-native-tool $version"
          return
        }
        cat "/tmp/git-native-cache-generate-$version.out"
        git -C "$REG_DIR" add -A
        git -C "$REG_DIR" commit -m "release: git-native-tool $version" \
          > "/tmp/git-native-commit-$version.out" 2>&1 || {
          cat "/tmp/git-native-commit-$version.out"
          fail "git commit git-native-tool $version"
          return
        }
        cat "/tmp/git-native-commit-$version.out"
        git -C "$REG_DIR" tag "v$version" \
          > "/tmp/git-native-tag-$version.out" 2>&1 || {
          cat "/tmp/git-native-tag-$version.out"
          fail "git tag v$version"
          return
        }
      }

      TOOL_100_STORE=$(make_git_native_tool 1.0.0)
      TOOL_110_STORE=$(make_git_native_tool 1.1.0)
      TOOL_200_STORE=$(make_git_native_tool 2.0.0)
      TOOL_110_HASH=$(basename "$TOOL_110_STORE" | cut -d- -f1)
      TOOL_200_HASH=$(basename "$TOOL_200_STORE" | cut -d- -f1)

      $APR create git-native-reg
      REG_DIR="$REG_STORAGE/git-native-reg"
      DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)
      publish_git_native_version 1.0.0 "$TOOL_100_STORE"
      publish_git_native_version 1.1.0 "$TOOL_110_STORE"
      publish_git_native_version 2.0.0 "$TOOL_200_STORE"
      assert_file_exists "/tmp/git-native-cache/$TOOL_110_HASH.narinfo" \
        "static cache has git-native-tool 1.1.0 narinfo"
      assert_file_exists "/tmp/git-native-cache/$TOOL_200_HASH.narinfo" \
        "static cache has out-of-range git-native-tool 2.0.0 narinfo"

      git init --bare --object-format=sha256 /tmp/git-native-origin.git
      git -C /tmp/git-native-origin.git symbolic-ref HEAD "refs/heads/$DEFAULT_BRANCH"
      git -C "$REG_DIR" remote add origin /tmp/git-native-origin.git
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"
      git -C "$REG_DIR" push origin --tags

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true

      python3 -m http.server 18109 --bind 127.0.0.1 \
        --directory /tmp/git-native-cache > /tmp/git-native-cache-http.log 2>&1 &
      CACHE_PID=$!
      for _i in 1 2 3 4 5 6 7 8 9 10; do
        if curl -sf http://127.0.0.1:18109/nix-cache-info >/dev/null; then
          break
        fi
        sleep 1
      done
      if curl -sf http://127.0.0.1:18109/nix-cache-info >/dev/null; then
        pass "git-native static cache HTTP server started"
      else
        cat /tmp/git-native-cache-http.log || true
        fail "git-native static cache HTTP server started"
      fi

      export HOME=/tmp/git-native-consumer
      export USER=gitnativeuser
      mkdir -p "$HOME"
      APM_CONFIG="$HOME/.config/apm"

      $APM registry add --no-verify file:///tmp/git-native-origin.git \
        --name git-native-reg --version "~1" > /tmp/git-native-add.out 2>&1 || {
        cat /tmp/git-native-add.out
        fail "apm registry add resolves best git-native version tag"
      }
      cat /tmp/git-native-add.out

      assert_file_contains "$APM_CONFIG/registries.d/git-native-reg.toml" \
        'version = "~1"' "config keeps git-native version tracking"
      assert_cmd_output_contains "$APR list" "version:~1" \
        "apr list shows version tracking mode"

      $APM search git-native-tool --registry git-native-reg > /tmp/git-native-search.out 2>&1 || {
        cat /tmp/git-native-search.out
        fail "apm search sees best git-native package"
      }
      assert_file_contains /tmp/git-native-search.out "1.1.0" \
        "git-native version tracking exposes best in-range package"
      assert_file_not_contains /tmp/git-native-search.out "2.0.0" \
        "git-native version tracking ignores out-of-range package"

      $APM show git-native-tool --registry git-native-reg > /tmp/git-native-show.out 2>&1 || {
        cat /tmp/git-native-show.out
        fail "apm show resolves best git-native package"
      }
      assert_file_contains /tmp/git-native-show.out "Git-native tracking workflow tool" \
        "apm show displays real package metadata"

      mount -o remount,rw / || true
      delete_store_path "$TOOL_110_STORE" "git-native-tool-1.1.0"
      delete_store_path "$TOOL_200_STORE" "git-native-tool-2.0.0"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"

      $APM install git-native-tool --registry git-native-reg --yes \
        > /tmp/git-native-install.out 2>&1 || {
        cat /tmp/git-native-install.out
        fail "apm install downloads best git-native package"
      }
      cat /tmp/git-native-install.out
      assert_file_contains /tmp/git-native-install.out "Downloading" \
        "apm install downloads git-native NAR"
      assert_store_valid "$TOOL_110_STORE" "git-native-tool 1.1.0"
      assert_store_missing "$TOOL_200_STORE" "git-native-tool 2.0.0"
      PROFILE_TOOL="/var/lib/profiles/per-user/$USER/current/bin/git-native-tool"
      "$PROFILE_TOOL" > /tmp/git-native-run.out
      assert_file_contains /tmp/git-native-run.out \
        "git-native-tool 1.1.0 executed" "installed git-native tool executes"

      if $APR bundle --tag v1.1.0 --output /tmp/bundles --registry git-native-reg \
        > /tmp/bundle-out 2>&1; then
        fail "apr bundle should not exist after git-native cutover"
      elif grep -q "unrecognized subcommand" /tmp/bundle-out; then
        pass "bundle transport command is removed"
      else
        fail "apr bundle failed with unexpected output"
        cat /tmp/bundle-out
      fi

      kill "$CACHE_PID" 2>/dev/null || true
      wait "$CACHE_PID" 2>/dev/null || true
      check_fail
    '';
  };
}
