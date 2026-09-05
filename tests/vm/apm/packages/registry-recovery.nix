# Packages VM checks for registry recovery workflows.
{
  testing,
  pkgs,
  fixtures,
  installBasicTool,
  realInstallDeps,
  setupNixEnv,
}: {
  # -------------------------------------------------------------------------
  # 8. registry-readd-heals-orphans — Re-add registry after orphaning packages
  # -------------------------------------------------------------------------
  registry-readd-heals-orphans = testing.mkVMTest {
    name = "apm-registry-readd-heals-orphans";
    rootfsDeps = realInstallDeps;
    memory = 1024;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixEnv}

      echo "==> Test: registry re-add heals orphaned installed packages"

      TOOL_STORE="${installBasicTool}"
      TOOL_HASH=$(basename "$TOOL_STORE" | cut -d- -f1)
      PROFILE="/var/lib/profiles/per-user/readduser"
      TOOL_BIN="$PROFILE/current/bin/install-basic-tool"

      assert_dir_not_exists() {
        if [ ! -d "$1" ]; then
          pass "$2"
        else
          fail "$2 (directory should not exist: $1)"
        fi
      }

      assert_store_valid() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/readd-valid-$label.out" 2>&1; then
          pass "$label valid in store"
        else
          cat "/tmp/readd-valid-$label.out"
          fail "$label should be valid in store"
        fi
      }

      assert_store_missing() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/readd-missing-$label.out" 2>&1; then
          cat "/tmp/readd-missing-$label.out"
          fail "$label should be missing from store"
        else
          pass "$label missing from store"
        fi
      }

      delete_store_path() {
        path="$1"
        label="$2"
        if nix-store --delete --ignore-liveness "$path" > "/tmp/readd-delete-$label.out" 2>&1; then
          pass "$label deleted before apm download"
        else
          cat "/tmp/readd-delete-$label.out"
          fail "$label should be deletable before apm download"
          return 1
        fi
        assert_store_missing "$path" "$label"
      }

      wait_for_cache_server() {
        for _i in 1 2 3 4 5 6 7 8 9 10; do
          if curl -sf http://127.0.0.1:18124/nix-cache-info >/dev/null; then
            return 0
          fi
          sleep 1
        done
        return 1
      }

      run_ok() {
        label="$1"
        shift
        if "$@" > "/tmp/readd-$label.out" 2>&1; then
          pass "$label exits 0"
        else
          cat "/tmp/readd-$label.out"
          fail "$label should exit 0"
        fi
      }

      mount -o remount,rw / || true
      assert_store_valid "$TOOL_STORE" "readd-tool"

      echo "==> Maintainer: publish readd-tool and static cache"
      $APR create readd-reg
      REG_DIR="$REG_STORAGE/readd-reg"
      DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)
      $APR publish "$TOOL_STORE" \
        --name readd-tool \
        --version 1.0.0 \
        --description "Registry re-add recovery fixture" \
        --license MIT \
        --maintainer readd@example.invalid \
        --registry readd-reg \
        --no-commit
      assert_file_contains "$REG_DIR/packages/r/readd-tool.toml" \
        "$TOOL_HASH" "published readd-tool metadata records store hash"

      $APR cache generate \
        --registry readd-reg \
        --output /tmp/readd-cache \
        --cache-url http://127.0.0.1:18124 \
        --priority 54 \
        --no-commit
      assert_file_exists "/tmp/readd-cache/$TOOL_HASH.narinfo" \
        "static cache has readd-tool narinfo"
      assert_file_contains "$REG_DIR/registry.toml" \
        "http://127.0.0.1:18124" "registry records readd cache URL"

      git -C "$REG_DIR" add -A
      git -C "$REG_DIR" commit -m "release: readd-tool 1.0.0"
      git init --bare --object-format=sha256 /tmp/readd-origin.git
      git -C "$REG_DIR" remote add origin /tmp/readd-origin.git
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
      PYTHONUNBUFFERED=1 python3 -m http.server 18124 --bind 127.0.0.1 \
        --directory /tmp/readd-cache > /tmp/readd-cache-http.log 2>&1 &
      CACHE_PID=$!
      if wait_for_cache_server; then
        pass "static cache HTTP server started"
      else
        cat /tmp/readd-cache-http.log || true
        fail "static cache HTTP server started"
      fi

      echo "==> Consumer: install readd-tool"
      export HOME=/tmp/readd-consumer
      export USER=readduser
      mkdir -p "$HOME"
      $APM registry add --no-verify file:///tmp/readd-origin.git \
        --name readd-reg \
        --branch "$DEFAULT_BRANCH" > /tmp/readd-registry-add.out 2>&1 || {
        cat /tmp/readd-registry-add.out
        fail "apm registry add syncs readd registry"
      }
      cat /tmp/readd-registry-add.out

      delete_store_path "$TOOL_STORE" "readd-tool"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM install readd-tool --registry readd-reg --yes > /tmp/readd-install.out 2>&1 || {
        cat /tmp/readd-install.out
        fail "apm install downloads readd-tool"
      }
      cat /tmp/readd-install.out
      assert_file_contains /tmp/readd-install.out "Downloading 1 NAR" \
        "readd-tool install downloads package NAR"
      assert_file_contains /tmp/readd-install.out "Installed 1 package" \
        "readd-tool install creates profile generation"
      "$TOOL_BIN" > /tmp/readd-run.out
      assert_file_contains /tmp/readd-run.out "^install-basic-tool 1.0.0$" \
        "installed readd-tool executable runs from profile"

      echo "==> Consumer: disable registry without orphaning installed package"
      REG_CONFIG="$HOME/.config/apm/registries.d/readd-reg.toml"
      $APM registry disable readd-reg > /tmp/readd-registry-disable.out 2>&1 || {
        cat /tmp/readd-registry-disable.out
        fail "apm registry disable readd-reg succeeds"
      }
      assert_file_contains /tmp/readd-registry-disable.out "Registry 'readd-reg' disabled" \
        "apm registry disable reports newly disabled registry"
      $APM --json registry disable readd-reg > /tmp/readd-registry-disable-again.json 2>&1 || {
        cat /tmp/readd-registry-disable-again.json
        fail "apm registry disable readd-reg is idempotent"
      }
      ${pkgs.jq}/bin/jq -e \
        --arg config "$REG_CONFIG" \
        '.action == "registry_disable"
          and .status == "unchanged"
          and .registry == "readd-reg"
          and .enabled == false
          and .previous_enabled == false
          and .changed == false
          and .config == $config
          and .packages == 1' \
        /tmp/readd-registry-disable-again.json >/dev/null || {
        cat /tmp/readd-registry-disable-again.json
        fail "apm --json registry disable reports unchanged disabled registry"
      }
      assert_file_contains "$REG_CONFIG" "enabled = false" \
        "apm registry disable persists disabled state"
      run_ok list-disabled "$APM" registry list
      assert_file_contains /tmp/readd-list-disabled.out "disabled" \
        "apm registry list reports disabled registry state"
      if $APM update --registry readd-reg > /tmp/readd-update-disabled.out 2>&1; then
        cat /tmp/readd-update-disabled.out
        fail "apm update should skip explicitly disabled registry"
      else
        cat /tmp/readd-update-disabled.out
        pass "apm update rejects explicitly disabled registry"
      fi
      assert_file_contains /tmp/readd-update-disabled.out "not enabled" \
        "disabled registry update failure explains disabled state"
      run_ok orphans-disabled "$APM" orphans
      assert_file_contains /tmp/readd-orphans-disabled.out "No orphaned packages" \
        "disabled configured registry does not orphan installed packages"
      if $APM verify readd-tool > /tmp/readd-verify-disabled.out 2>&1; then
        cat /tmp/readd-verify-disabled.out
        fail "apm verify should not resolve disabled registry"
      else
        cat /tmp/readd-verify-disabled.out
        pass "apm verify skips disabled registry metadata"
      fi
      assert_file_contains /tmp/readd-verify-disabled.out "not present in registry 'readd-reg'" \
        "verify failure identifies disabled source registry"
      "$TOOL_BIN" > /tmp/readd-run-disabled.out
      assert_file_contains /tmp/readd-run-disabled.out "^install-basic-tool 1.0.0$" \
        "installed executable still runs while registry is disabled"

      echo "==> Consumer: re-enable registry and verify installed package"
      $APM registry enable readd-reg > /tmp/readd-registry-enable.out 2>&1 || {
        cat /tmp/readd-registry-enable.out
        fail "apm registry enable readd-reg succeeds"
      }
      assert_file_contains /tmp/readd-registry-enable.out "Registry 'readd-reg' enabled" \
        "apm registry enable reports newly enabled registry"
      $APM --json registry enable readd-reg > /tmp/readd-registry-enable-again.json 2>&1 || {
        cat /tmp/readd-registry-enable-again.json
        fail "apm registry enable readd-reg is idempotent"
      }
      ${pkgs.jq}/bin/jq -e \
        --arg config "$REG_CONFIG" \
        '.action == "registry_enable"
          and .status == "unchanged"
          and .registry == "readd-reg"
          and .enabled == true
          and .previous_enabled == true
          and .changed == false
          and .config == $config
          and .packages == 1' \
        /tmp/readd-registry-enable-again.json >/dev/null || {
        cat /tmp/readd-registry-enable-again.json
        fail "apm --json registry enable reports unchanged enabled registry"
      }
      assert_file_contains "$REG_CONFIG" "enabled = true" \
        "apm registry enable persists enabled state"
      run_ok update-reenabled "$APM" --json update --registry readd-reg
      ${pkgs.jq}/bin/jq -e \
        '.registry == "readd-reg"
          and (.registries | length == 1)
          and .registries[0].registry == "readd-reg"
          and (.registries[0].status == "updated" or .registries[0].status == "current")
          and .registries[0].packages == 1' \
        /tmp/readd-update-reenabled.out >/dev/null || {
        cat /tmp/readd-update-reenabled.out
        fail "apm --json update works after registry re-enable"
      }
      run_ok search-reenabled "$APM" --json search readd-tool --registry readd-reg
      ${pkgs.jq}/bin/jq -e \
        'length == 1
          and .[0].name == "readd-tool"
          and .[0].registry == "readd-reg"
          and .[0].version == "1.0.0"' \
        /tmp/readd-search-reenabled.out >/dev/null || {
        cat /tmp/readd-search-reenabled.out
        fail "apm --json search finds package after registry re-enable"
      }
      run_ok verify-before-remove "$APM" verify readd-tool
      assert_file_contains /tmp/readd-verify-before-remove.out "integrity verified" \
        "apm verify validates readd-tool after registry re-enable"

      echo "==> Consumer: remove registry and observe orphaned package"
      $APM registry remove readd-reg > /tmp/readd-remove-registry.out 2>&1 || {
        cat /tmp/readd-remove-registry.out
        fail "apm registry remove readd-reg succeeds"
      }
      cat /tmp/readd-remove-registry.out
      assert_file_contains /tmp/readd-remove-registry.out "Registry 'readd-reg' removed" \
        "registry remove reports removal"
      assert_file_not_exists "$HOME/.config/apm/registries.d/readd-reg.toml" \
        "registry remove deletes config"
      assert_dir_not_exists "$HOME/.local/share/apm/registries/readd-reg" \
        "registry remove deletes local clone"

      run_ok orphans-after-remove "$APM" orphans
      assert_file_contains /tmp/readd-orphans-after-remove.out "readd-tool" \
        "apm orphans lists installed package after registry removal"
      assert_file_contains /tmp/readd-orphans-after-remove.out "removed registry 'readd-reg'" \
        "apm orphans names removed registry"
      if $APM verify readd-tool > /tmp/readd-verify-orphan.out 2>&1; then
        cat /tmp/readd-verify-orphan.out
        fail "apm verify should fail while source registry is absent"
      else
        cat /tmp/readd-verify-orphan.out
        pass "apm verify fails while source registry is absent"
      fi
      assert_file_contains /tmp/readd-verify-orphan.out "not present in registry 'readd-reg'" \
        "orphaned verify error points at missing source registry"

      echo "==> Consumer: re-add registry and verify package recovery"
      $APM registry add --no-verify file:///tmp/readd-origin.git \
        --name readd-reg \
        --branch "$DEFAULT_BRANCH" > /tmp/readd-registry-readd.out 2>&1 || {
        cat /tmp/readd-registry-readd.out
        fail "apm registry add re-adds removed registry"
      }
      cat /tmp/readd-registry-readd.out
      assert_file_contains /tmp/readd-registry-readd.out "Registry 'readd-reg' added" \
        "registry re-add reports success"
      assert_dir_exists "$HOME/.local/share/apm/registries/readd-reg" \
        "registry re-add reclones local registry"

      run_ok orphans-after-readd "$APM" orphans
      assert_file_contains /tmp/readd-orphans-after-readd.out "No orphaned packages" \
        "apm orphans clears after registry re-add"
      run_ok verify-after-readd "$APM" verify readd-tool
      assert_file_contains /tmp/readd-verify-after-readd.out "integrity verified" \
        "apm verify works again after registry re-add"
      "$TOOL_BIN" > /tmp/readd-run-after-readd.out
      assert_file_contains /tmp/readd-run-after-readd.out "^install-basic-tool 1.0.0$" \
        "installed executable still runs after registry re-add"

      if kill "$CACHE_PID" 2>/dev/null; then
        pass "static cache HTTP server stopped"
      fi
      wait "$CACHE_PID" 2>/dev/null || true

      check_fail
    '';
  };
}
