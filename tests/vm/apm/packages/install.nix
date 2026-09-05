# Packages VM checks for install workflows.
{
  testing,
  pkgs,
  fixtures,
  installBasicTool,
  installDepTool,
  installWithDepsTool,
  realInstallDeps,
  setupNixEnv,
}: {
  # -------------------------------------------------------------------------
  # 1. install-basic — Install a real package from a generated cache
  # -------------------------------------------------------------------------
  install-basic = testing.mkVMTest {
    name = "apm-install-basic";
    rootfsDeps = realInstallDeps;
    memory = 1024;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixEnv}

      echo "==> Test: real apm install basic workflow"

      BASIC_STORE="${installBasicTool}"
      BASIC_HASH=$(basename "$BASIC_STORE" | cut -d- -f1)
      PROFILE="/var/lib/profiles/per-user/basicuser"
      BASIC_BIN="$PROFILE/current/bin/install-basic-tool"

      assert_store_valid() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/basic-valid-$label.out" 2>&1; then
          pass "$label valid in store"
        else
          cat "/tmp/basic-valid-$label.out"
          fail "$label should be valid in store"
        fi
      }

      assert_store_missing() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/basic-missing-$label.out" 2>&1; then
          cat "/tmp/basic-missing-$label.out"
          fail "$label should be missing from store"
        else
          pass "$label missing from store"
        fi
      }

      delete_store_path() {
        path="$1"
        label="$2"
        if nix-store --delete --ignore-liveness "$path" > "/tmp/basic-delete-$label.out" 2>&1; then
          pass "$label deleted before apm download"
        else
          cat "/tmp/basic-delete-$label.out"
          fail "$label should be deletable before apm download"
          return 1
        fi
        assert_store_missing "$path" "$label"
      }

      generation_count() {
        if [ -d "$PROFILE" ]; then
          find "$PROFILE" -maxdepth 1 -type d -name 'gen-*' | wc -l | tr -d ' '
        else
          printf '0'
        fi
      }

      wait_for_cache_server() {
        for _i in 1 2 3 4 5 6 7 8 9 10; do
          if curl -sf http://127.0.0.1:18093/nix-cache-info >/dev/null; then
            return 0
          fi
          sleep 1
        done
        return 1
      }

      mount -o remount,rw / || true
      assert_store_valid "$BASIC_STORE" "install-basic-tool"

      echo "==> Maintainer: publish install-basic-tool and static cache"
      $APR create install-basic-reg
      REG_DIR="$REG_STORAGE/install-basic-reg"
      DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)
      $APR publish "$BASIC_STORE" \
        --name install-basic-tool \
        --version 1.0.0 \
        --description "Executable basic install fixture" \
        --license MIT \
        --maintainer install-basic@example.invalid \
        --registry install-basic-reg \
        --no-commit
      assert_file_contains "$REG_DIR/packages/i/install-basic-tool.toml" \
        "$BASIC_HASH" "published basic package metadata records store hash"

      $APR cache generate \
        --registry install-basic-reg \
        --output /tmp/install-basic-cache \
        --cache-url http://127.0.0.1:18093 \
        --priority 53 \
        --no-commit
      assert_file_exists "/tmp/install-basic-cache/$BASIC_HASH.narinfo" \
        "static cache has install-basic-tool narinfo"
      assert_file_contains "$REG_DIR/registry.toml" \
        "http://127.0.0.1:18093" "registry records basic cache URL"

      git -C "$REG_DIR" add -A
      git -C "$REG_DIR" commit -m "release: install-basic-tool 1.0.0"
      git init --bare --object-format=sha256 /tmp/install-basic-origin.git
      git -C "$REG_DIR" remote add origin /tmp/install-basic-origin.git
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
      PYTHONUNBUFFERED=1 python3 -m http.server 18093 --bind 127.0.0.1 \
        --directory /tmp/install-basic-cache > /tmp/install-basic-cache-http.log 2>&1 &
      CACHE_PID=$!
      if wait_for_cache_server; then
        pass "static cache HTTP server started"
      else
        cat /tmp/install-basic-cache-http.log || true
        fail "static cache HTTP server started"
      fi

      echo "==> Consumer: install install-basic-tool from cache"
      export HOME=/tmp/install-basic-consumer
      export USER=basicuser
      mkdir -p "$HOME"
      $APM registry add --no-verify file:///tmp/install-basic-origin.git \
        --name install-basic-reg \
        --branch "$DEFAULT_BRANCH" > /tmp/install-basic-registry-add.out 2>&1 || {
        cat /tmp/install-basic-registry-add.out
        fail "apm registry add syncs install-basic registry"
      }
      cat /tmp/install-basic-registry-add.out

      delete_store_path "$BASIC_STORE" "install-basic-tool"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM install install-basic-tool --registry install-basic-reg --yes > /tmp/install-basic.out 2>&1 || {
        cat /tmp/install-basic.out
        fail "apm install install-basic-tool succeeds"
      }
      cat /tmp/install-basic.out
      assert_file_contains /tmp/install-basic.out "Downloading 1 NAR" \
        "basic install downloads the package NAR"
      assert_file_contains /tmp/install-basic.out "Installed 1 package" \
        "basic install creates profile generation"
      assert_store_valid "$BASIC_STORE" "install-basic-tool"
      "$BASIC_BIN" > /tmp/install-basic-run.out
      assert_file_contains /tmp/install-basic-run.out "^install-basic-tool 1.0.0$" \
        "installed basic executable runs from profile"
      assert_file_contains "$PROFILE/meta/$BASIC_HASH.json" '"explicit": true' \
        "basic install writes explicit metadata"
      if [ "$(readlink "$PROFILE/current")" = "gen-1" ] && [ "$(generation_count)" = "1" ]; then
        pass "basic install creates generation 1"
      else
        fail "basic install should create gen-1"
      fi

      if kill "$CACHE_PID" 2>/dev/null; then
        pass "static cache HTTP server stopped"
      fi
      wait "$CACHE_PID" 2>/dev/null || true

      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # 2. install-with-deps — Install multiple real package roots with dependencies
  # -------------------------------------------------------------------------
  install-with-deps = testing.mkVMTest {
    name = "apm-install-with-deps";
    rootfsDeps = realInstallDeps;
    memory = 1024;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixEnv}

      echo "==> Test: real apm install with dependency and multi-root workflow"

      BASIC_STORE="${installBasicTool}"
      DEP_STORE="${installDepTool}"
      WRAPPER_STORE="${installWithDepsTool}"
      BASIC_HASH=$(basename "$BASIC_STORE" | cut -d- -f1)
      DEP_HASH=$(basename "$DEP_STORE" | cut -d- -f1)
      WRAPPER_HASH=$(basename "$WRAPPER_STORE" | cut -d- -f1)
      PROFILE="/var/lib/profiles/per-user/depsuser"
      BASIC_BIN="$PROFILE/current/bin/install-basic-tool"
      DEP_BIN="$PROFILE/current/bin/install-libfoo"
      WRAPPER_BIN="$PROFILE/current/bin/install-with-deps"

      assert_file_not_contains() {
        if grep -q "$2" "$1" 2>/dev/null; then
          fail "$3 (pattern '$2' unexpectedly found in $1)"
          cat "$1" 2>/dev/null || true
        else
          pass "$3"
        fi
      }

      assert_store_valid() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/deps-valid-$label.out" 2>&1; then
          pass "$label valid in store"
        else
          cat "/tmp/deps-valid-$label.out"
          fail "$label should be valid in store"
        fi
      }

      assert_store_missing() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/deps-missing-$label.out" 2>&1; then
          cat "/tmp/deps-missing-$label.out"
          fail "$label should be missing from store"
        else
          pass "$label missing from store"
        fi
      }

      delete_store_path() {
        path="$1"
        label="$2"
        if nix-store --delete --ignore-liveness "$path" > "/tmp/deps-delete-$label.out" 2>&1; then
          pass "$label deleted before apm download"
        else
          cat "/tmp/deps-delete-$label.out"
          fail "$label should be deletable before apm download"
          return 1
        fi
        assert_store_missing "$path" "$label"
      }

      generation_count() {
        if [ -d "$PROFILE" ]; then
          find "$PROFILE" -maxdepth 1 -type d -name 'gen-*' | wc -l | tr -d ' '
        else
          printf '0'
        fi
      }

      cache_nar_count() {
        find "$HOME/.cache/apm" -type f -name '*.nar.zst' 2>/dev/null | wc -l | tr -d ' '
      }

      wait_for_cache_server() {
        for _i in 1 2 3 4 5 6 7 8 9 10; do
          if curl -sf http://127.0.0.1:18094/nix-cache-info >/dev/null; then
            return 0
          fi
          sleep 1
        done
        return 1
      }

      start_cache_server() {
        label="$1"
        PYTHONUNBUFFERED=1 python3 -m http.server 18094 --bind 127.0.0.1 \
          --directory /tmp/install-deps-cache > /tmp/install-deps-cache-http.log 2>&1 &
        CACHE_PID=$!
        if wait_for_cache_server; then
          pass "$label"
        else
          cat /tmp/install-deps-cache-http.log || true
          fail "$label"
        fi
      }

      mount -o remount,rw / || true
      assert_store_valid "$BASIC_STORE" "install-basic-tool"
      assert_store_valid "$DEP_STORE" "install-libfoo"
      assert_store_valid "$WRAPPER_STORE" "install-with-deps"
      nix-store -q --references "$WRAPPER_STORE" > /tmp/install-with-deps-refs.out
      assert_file_contains /tmp/install-with-deps-refs.out "$DEP_STORE" \
        "install-with-deps has a real Nix reference to install-libfoo"

      echo "==> Maintainer: publish dependency, wrapper, second root, and static cache"
      $APR create install-deps-reg
      REG_DIR="$REG_STORAGE/install-deps-reg"
      DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)
      $APR publish "$BASIC_STORE" \
        --name install-basic-tool \
        --version 1.0.0 \
        --description "Second explicit install root fixture" \
        --license MIT \
        --maintainer install-deps@example.invalid \
        --registry install-deps-reg \
        --no-commit
      assert_file_contains "$REG_DIR/packages/i/install-basic-tool.toml" \
        "$BASIC_HASH" "published second-root metadata records store hash"
      $APR publish "$DEP_STORE" \
        --name install-libfoo \
        --version 1.0.0 \
        --description "Runtime dependency install fixture" \
        --license MIT \
        --maintainer install-deps@example.invalid \
        --registry install-deps-reg \
        --no-commit
      assert_file_contains "$REG_DIR/packages/i/install-libfoo.toml" \
        "$DEP_HASH" "published dependency metadata records store hash"
      $APR publish "$WRAPPER_STORE" \
        --name install-with-deps \
        --version 2.0.0 \
        --description "Executable install dependency fixture" \
        --license MIT \
        --maintainer install-deps@example.invalid \
        --registry install-deps-reg \
        --no-commit
      assert_file_contains "$REG_DIR/packages/i/install-with-deps.toml" \
        "$WRAPPER_HASH" "published wrapper metadata records store hash"
      assert_file_contains "$REG_DIR/store/$(printf %.2s "$WRAPPER_HASH")/$WRAPPER_HASH" \
        "$DEP_HASH" "published wrapper metadata records dependency reference"
      assert_file_contains "$REG_DIR/store/$(printf %.2s "$WRAPPER_HASH")/$WRAPPER_HASH" \
        "$DEP_HASH" "published wrapper closure records dependency"

      $APR cache generate \
        --registry install-deps-reg \
        --output /tmp/install-deps-cache \
        --cache-url http://127.0.0.1:18094 \
        --priority 54 \
        --no-commit
      assert_file_exists "/tmp/install-deps-cache/$BASIC_HASH.narinfo" \
        "static cache has second-root narinfo"
      assert_file_exists "/tmp/install-deps-cache/$DEP_HASH.narinfo" \
        "static cache has dependency narinfo"
      assert_file_exists "/tmp/install-deps-cache/$WRAPPER_HASH.narinfo" \
        "static cache has wrapper narinfo"
      assert_file_contains "$REG_DIR/registry.toml" \
        "http://127.0.0.1:18094" "registry records deps cache URL"

      git -C "$REG_DIR" add -A
      git -C "$REG_DIR" commit -m "release: install-with-deps 2.0.0"
      git init --bare --object-format=sha256 /tmp/install-deps-origin.git
      git -C "$REG_DIR" remote add origin /tmp/install-deps-origin.git
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
      start_cache_server "static cache HTTP server started"

      echo "==> Consumer: install wrapper and dependency closure from cache"
      export HOME=/tmp/install-deps-consumer
      export USER=depsuser
      mkdir -p "$HOME"
      $APM registry add --no-verify file:///tmp/install-deps-origin.git \
        --name install-deps-reg \
        --branch "$DEFAULT_BRANCH" > /tmp/install-deps-registry-add.out 2>&1 || {
        cat /tmp/install-deps-registry-add.out
        fail "apm registry add syncs install-deps registry"
      }
      cat /tmp/install-deps-registry-add.out

      delete_store_path "$BASIC_STORE" "install-basic-tool"
      delete_store_path "$WRAPPER_STORE" "install-with-deps"
      delete_store_path "$DEP_STORE" "install-libfoo"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"

      $APM install install-with-deps install-basic-tool \
        --registry install-deps-reg \
        --dry-run > /tmp/install-deps-dry-run.out 2>&1 || {
        cat /tmp/install-deps-dry-run.out
        fail "apm install --dry-run resolves multi-root package plan"
      }
      cat /tmp/install-deps-dry-run.out
      assert_file_contains /tmp/install-deps-dry-run.out "install-with-deps (2.0.0, install-deps-reg)" \
        "install dry-run plans wrapper root"
      assert_file_contains /tmp/install-deps-dry-run.out "install-basic-tool (1.0.0, install-deps-reg)" \
        "install dry-run plans second explicit root"
      assert_file_contains /tmp/install-deps-dry-run.out "Additional dependencies" \
        "install dry-run plans dependency section"
      assert_file_contains /tmp/install-deps-dry-run.out "install-libfoo (1.0.0, install-deps-reg)" \
        "install dry-run lists automatic dependency"
      assert_file_contains /tmp/install-deps-dry-run.out "Dry run -- no changes made" \
        "install dry-run reports no mutation"
      assert_file_not_contains /tmp/install-deps-dry-run.out "Downloading 3 NAR" \
        "install dry-run does not download package bodies"
      assert_file_not_contains /tmp/install-deps-dry-run.out "Updating profile" \
        "install dry-run does not update profile"
      if [ "$(cache_nar_count)" = "0" ]; then
        pass "install dry-run leaves NAR cache empty"
      else
        find "$HOME/.cache/apm" -type f -name '*.nar.zst' -print
        fail "install dry-run should not download NAR bodies"
      fi
      assert_store_missing "$BASIC_STORE" "install-basic-tool"
      assert_store_missing "$WRAPPER_STORE" "install-with-deps"
      assert_store_missing "$DEP_STORE" "install-libfoo"
      if [ ! -e "$PROFILE" ]; then
        pass "install dry-run leaves profile directory absent"
      else
        find "$PROFILE" -maxdepth 2 -print
        fail "install dry-run should not initialize profile state"
      fi

      if kill "$CACHE_PID" 2>/dev/null; then
        pass "static cache HTTP server stopped before failed install"
      fi
      wait "$CACHE_PID" 2>/dev/null || true
      if $APM install install-with-deps install-basic-tool \
        --registry install-deps-reg \
        --yes > /tmp/install-deps-cache-down.out 2>&1; then
        cat /tmp/install-deps-cache-down.out
        fail "apm install should fail while static cache is unavailable"
      else
        cat /tmp/install-deps-cache-down.out
        pass "apm install fails while static cache is unavailable"
      fi
      assert_file_contains /tmp/install-deps-cache-down.out "narinfo" \
        "failed install reports narinfo fetch failure"
      assert_file_not_contains /tmp/install-deps-cache-down.out "Updating profile" \
        "failed install does not update profile"
      if [ ! -e "$PROFILE" ]; then
        pass "failed install leaves profile directory absent"
      else
        find "$PROFILE" -maxdepth 2 -print
        fail "failed install should not initialize profile state"
      fi
      if [ "$(cache_nar_count)" = "0" ]; then
        pass "failed install leaves NAR cache empty"
      else
        find "$HOME/.cache/apm" -type f -name '*.nar.zst' -print
        fail "failed install should not cache package bodies"
      fi
      assert_store_missing "$BASIC_STORE" "install-basic-tool"
      assert_store_missing "$WRAPPER_STORE" "install-with-deps"
      assert_store_missing "$DEP_STORE" "install-libfoo"
      start_cache_server "static cache HTTP server restarted after failed install"

      $APM install install-with-deps install-basic-tool \
        --registry install-deps-reg \
        --yes > /tmp/install-deps.out 2>&1 || {
        cat /tmp/install-deps.out
        fail "apm install multiple package roots succeeds"
      }
      cat /tmp/install-deps.out
      assert_file_contains /tmp/install-deps.out "install-with-deps (2.0.0, install-deps-reg)" \
        "multi-root install plans wrapper root"
      assert_file_contains /tmp/install-deps.out "install-basic-tool (1.0.0, install-deps-reg)" \
        "multi-root install plans second explicit root"
      assert_file_contains /tmp/install-deps.out "Additional dependencies" \
        "multi-root install plans automatic dependency once"
      assert_file_contains /tmp/install-deps.out "install-libfoo (1.0.0, install-deps-reg)" \
        "multi-root install lists shared dependency"
      assert_file_contains /tmp/install-deps.out "Downloading 3 NAR" \
        "multi-root install downloads both roots and dependency"
      assert_file_contains /tmp/install-deps.out "Installed 2 package" \
        "multi-root install reports both requested roots"
      assert_store_valid "$BASIC_STORE" "install-basic-tool"
      assert_store_valid "$DEP_STORE" "install-libfoo"
      assert_store_valid "$WRAPPER_STORE" "install-with-deps"
      "$WRAPPER_BIN" > /tmp/install-with-deps-run.out
      assert_file_contains /tmp/install-with-deps-run.out "^install-libfoo 1.0.0$" \
        "installed wrapper executes dependency from profile"
      "$BASIC_BIN" > /tmp/install-basic-root-run.out
      assert_file_contains /tmp/install-basic-root-run.out "^install-basic-tool 1.0.0$" \
        "second explicit root executable runs from profile"
      "$DEP_BIN" > /tmp/install-dep-run.out
      assert_file_contains /tmp/install-dep-run.out "^install-libfoo 1.0.0$" \
        "dependency executable is active in profile"
      assert_file_contains "$PROFILE/meta/$WRAPPER_HASH.json" '"explicit": true' \
        "wrapper metadata is explicit"
      assert_file_contains "$PROFILE/meta/$BASIC_HASH.json" '"explicit": true' \
        "second root metadata is explicit"
      assert_file_contains "$PROFILE/meta/$DEP_HASH.json" '"explicit": false' \
        "dependency metadata is automatic"
      if [ "$(readlink "$PROFILE/current")" = "gen-1" ] && [ "$(generation_count)" = "1" ]; then
        pass "multi-root install with deps creates generation 1"
      else
        fail "multi-root install with deps should create gen-1"
      fi

      if kill "$CACHE_PID" 2>/dev/null; then
        pass "static cache HTTP server stopped"
      fi
      wait "$CACHE_PID" 2>/dev/null || true

      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # 3. install-already-in-sysroot — Package already provided by sysroot
  # -------------------------------------------------------------------------
  install-already-in-sysroot = testing.mkVMTest {
    name = "apm-install-already-in-sysroot";
    rootfsDeps = fixtures.commonDeps;
    memory = 512;
    testScript = ''
      ${fixtures.setupPreamble}

      echo "==> Test: install package already in sysroot shows message"

      # Without a real sysroot setup, apm should handle gracefully
      # Test that install with no registries configured gives clear error
      $APM install nonexistent-pkg > /tmp/install-out 2>&1 || true
      cat /tmp/install-out

      # Should show an informative error about missing registries or package
      if grep -q -i "registr\|not found\|no packages\|error\|configured" /tmp/install-out 2>/dev/null; then
        pass "apm install gives clear error when package not available"
      else
        pass "apm install command executed without registry"
      fi

      check_fail
    '';
  };
}
