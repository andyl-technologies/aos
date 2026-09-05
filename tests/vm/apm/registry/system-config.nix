# Registry VM checks for system config workflows.
{
  testing,
  pkgs,
  fixtures,
  maintainerWorkflowDeps,
  setupNixPublishEnv,
  closureLeafTool,
  closureRootTool,
}: {
  # -------------------------------------------------------------------------
  # registry-system-config-dir-workflow — Redirected system config on non-AOS hosts
  # -------------------------------------------------------------------------
  registry-system-config-dir-workflow = testing.mkVMTest {
    name = "apm-registry-system-config-dir-workflow";
    rootfsDeps =
      maintainerWorkflowDeps
      ++ [
        pkgs.jq
        closureLeafTool
        closureRootTool
      ];
    memory = 2048;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixPublishEnv}

      echo "==> Test: redirected system config supports real registry workflows"

      ROOT_STORE="${closureRootTool}"
      LEAF_STORE="${closureLeafTool}"
      ROOT_HASH=$(basename "$ROOT_STORE" | cut -d- -f1)
      LEAF_HASH=$(basename "$LEAF_STORE" | cut -d- -f1)

      $APR create override-reg
      REG_DIR="$REG_STORAGE/override-reg"
      DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)

      $APR publish "$ROOT_STORE" \
        --name override-root \
        --version 1.0.0 \
        --description "System config override workflow root" \
        --license MIT \
        --maintainer override-workflow@example.invalid \
        --registry override-reg \
        --sysroot \
        --no-commit
      $APR cache generate \
        --registry override-reg \
        --output /tmp/override-cache \
        --cache-url http://127.0.0.1:18131 \
        --priority 53 \
        --no-commit
      $APR verify --registry override-reg > /tmp/override-verify.out 2>&1 || {
        cat /tmp/override-verify.out
        fail "apr verify accepts override registry"
      }
      assert_file_exists "/tmp/override-cache/$ROOT_HASH.narinfo" \
        "static cache includes override root package"
      assert_file_exists "/tmp/override-cache/$LEAF_HASH.narinfo" \
        "static cache includes override dependency package"

      git -C "$REG_DIR" add -A
      git -C "$REG_DIR" commit -m "release: override root 1.0.0"
      git init --bare --object-format=sha256 /tmp/override-origin.git
      git -C "$REG_DIR" remote add origin /tmp/override-origin.git
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
      PYTHONUNBUFFERED=1 python3 -m http.server 18131 --bind 127.0.0.1 \
        --directory /tmp/override-cache > /tmp/override-cache-http.log 2>&1 &
      CACHE_PID=$!
      for _i in 1 2 3 4 5 6 7 8 9 10; do
        if curl -sf http://127.0.0.1:18131/nix-cache-info >/dev/null; then
          break
        fi
        sleep 1
      done
      if ! curl -sf http://127.0.0.1:18131/nix-cache-info >/dev/null; then
        cat /tmp/override-cache-http.log || true
        fail "override static cache HTTP server started"
      else
        pass "override static cache HTTP server started"
      fi

      export HOME=/tmp/override-consumer
      export USER=overrideuser
      export AOS_ROOT=/tmp/override-root
      # AOS_ROOT also derives the Nix store/state paths; keep the install
      # operating on the real store so NAR import works (the redirect is only
      # meant to relocate the apm system config tree here).
      export AOS_NIX_STORE_DIR=/nix/store
      export AOS_NIX_STATE_DIR=/nix/var/nix
      SYSTEM_REG_CONFIG="$AOS_ROOT/var/lib/apm/config/registries.d/override-reg.toml"
      USER_REG_CONFIG="$HOME/.config/apm/registries.d/override-reg.toml"
      # This fixture deliberately has no authenticated image-generation state:
      # it emulates registry administration from a non-AOS host. A sysroot
      # download may populate the Nix store, but it must not recreate the
      # retired single-axis system-generation authority.
      SYSTEM_PROFILE="/var/lib/profiles/system"
      mkdir -p "$HOME"

      if [ -e "$USER_REG_CONFIG" ]; then
        fail "consumer should start without a user registry config"
      else
        pass "consumer starts without a user registry config"
      fi

      $APM --json registry --system add --no-verify file:///tmp/override-origin.git \
        --name override-reg \
        --branch "$DEFAULT_BRANCH" \
        --priority 701 > /tmp/override-system-add.json 2>&1 || {
        cat /tmp/override-system-add.json
        fail "apm registry --system add creates redirected system registry"
      }
      ${pkgs.jq}/bin/jq -e \
        --arg config "$SYSTEM_REG_CONFIG" \
        --arg tracking "branch:$DEFAULT_BRANCH" \
        '.action == "registry_add"
          and .status == "added"
          and .registry == "override-reg"
          and .url == "file:///tmp/override-origin.git"
          and .priority == 701
          and .tracking == $tracking
          and .clone == true
          and .synced == true
          and .verification_disabled == true
          and .config == $config
          and .packages == 1
          and (.last_commit | length == 64)' \
        /tmp/override-system-add.json >/dev/null || {
        cat /tmp/override-system-add.json
        fail "apm --json registry --system add reports redirected system registry"
      }
      pass "apm --json registry --system add reports redirected system registry"
      assert_file_contains "$SYSTEM_REG_CONFIG" "last_commit = " \
        "apm registry --system add writes sync state to redirected system config"
      assert_file_not_exists "$USER_REG_CONFIG" \
        "apm registry --system add does not create a shadow user registry config"

      $APM --json registry --system list > /tmp/override-system-list.json 2>&1 || {
        cat /tmp/override-system-list.json
        fail "apm registry --system list reads redirected system registry"
      }
      ${pkgs.jq}/bin/jq -e \
        'length == 1
          and .[0].name == "override-reg"
          and .[0].priority == 701
          and .[0].enabled == true
          and .[0].packages == 1' \
        /tmp/override-system-list.json >/dev/null || {
        cat /tmp/override-system-list.json
        fail "apm --json registry --system list reports redirected system registry"
      }
      pass "apm --json registry --system list reports redirected system registry"

      $APM --json update --system --registry override-reg > /tmp/override-update.json 2>&1 || {
        cat /tmp/override-update.json
        fail "apm update syncs registry from redirected system config"
      }
      ${pkgs.jq}/bin/jq -e \
        '.registry == "override-reg"
          and (.registries | length == 1)
          and .registries[0].registry == "override-reg"
          and (.registries[0].status == "updated" or .registries[0].status == "current")
          and .registries[0].packages == 1' \
        /tmp/override-update.json >/dev/null || {
        cat /tmp/override-update.json
        fail "apm --json update reports redirected system registry sync"
      }
      pass "apm --json update reports redirected system registry sync"
      assert_file_contains "$SYSTEM_REG_CONFIG" "last_commit = " \
        "apm update writes sync state back to redirected system config"
      assert_file_not_exists "$USER_REG_CONFIG" \
        "apm update does not create a shadow user registry config"

      $APM --json search override-root --system --registry override-reg \
        > /tmp/override-search.json 2>&1 || {
        cat /tmp/override-search.json
        fail "apm search resolves package from redirected system registry"
      }
      ${pkgs.jq}/bin/jq -e \
        'length == 1
          and .[0].name == "override-root"
          and .[0].registry == "override-reg"
          and .[0].version == "1.0.0"' \
        /tmp/override-search.json >/dev/null || {
        cat /tmp/override-search.json
        fail "apm --json search reports redirected system registry package"
      }
      pass "apm --json search reports redirected system registry package"

      mount -o remount,rw / || true
      nix-store --delete --ignore-liveness "$ROOT_STORE" > /tmp/override-delete-root.out 2>&1 || {
        cat /tmp/override-delete-root.out
        fail "deleted override root before install"
      }
      nix-store --delete --ignore-liveness "$LEAF_STORE" > /tmp/override-delete-leaf.out 2>&1 || {
        cat /tmp/override-delete-leaf.out
        fail "deleted override dependency before install"
      }
      if nix-store --check-validity "$ROOT_STORE" >/tmp/override-root-valid.out 2>&1; then
        cat /tmp/override-root-valid.out
        fail "override root should be missing before install"
      else
        pass "override root missing before install"
      fi
      if nix-store --check-validity "$LEAF_STORE" >/tmp/override-leaf-valid.out 2>&1; then
        cat /tmp/override-leaf-valid.out
        fail "override dependency should be missing before install"
      else
        pass "override dependency missing before install"
      fi

      if $APM install override-root --system --registry override-reg --yes \
        > /tmp/override-install.out 2>&1; then
        cat /tmp/override-install.out
        fail "apm install must reject sysroot activation without image-generation authority"
      else
        pass "apm install rejects sysroot activation without image-generation authority"
      fi
      cat /tmp/override-install.out
      assert_file_contains /tmp/override-install.out "Downloading" \
        "apm install downloads from redirected system registry cache"
      assert_file_contains /tmp/override-install.out \
        "image generation state is absent" \
        "apm install explains missing image-generation authority"
      if nix-store --check-validity "$ROOT_STORE" >/tmp/override-root-imported.out 2>&1; then
        pass "redirected system install imports the downloaded sysroot"
      else
        cat /tmp/override-root-imported.out
        fail "redirected system install should import the downloaded sysroot"
      fi
      if nix-store --check-validity "$LEAF_STORE" >/tmp/override-leaf-imported.out 2>&1; then
        pass "redirected system install imports the downloaded dependency"
      else
        cat /tmp/override-leaf-imported.out
        fail "redirected system install should import the downloaded dependency"
      fi
      if [ -e "$SYSTEM_PROFILE/current" ] || [ -e "$SYSTEM_PROFILE/state.json" ]; then
        fail "rejected non-AOS sysroot activation must not create system generations"
      else
        pass "rejected non-AOS sysroot activation creates no system generation"
      fi
      "$ROOT_STORE/bin/closure-root" > /tmp/override-run.out
      assert_file_contains /tmp/override-run.out \
        "^closure-root 1.0.0 via closure-leaf 1.0.0$" \
        "downloaded redirected system registry closure runs"

      $APM --json registry --system disable override-reg \
        > /tmp/override-disable.json 2>&1 || {
        cat /tmp/override-disable.json
        fail "apm registry --system disable writes redirected system config"
      }
      ${pkgs.jq}/bin/jq -e \
        --arg config "$SYSTEM_REG_CONFIG" \
        '.action == "registry_disable"
          and .status == "disabled"
          and .registry == "override-reg"
          and .enabled == false
          and .previous_enabled == true
          and .changed == true
          and .config == $config
          and .packages == 1' \
        /tmp/override-disable.json >/dev/null || {
        cat /tmp/override-disable.json
        fail "apm --json registry disable reports redirected system config"
      }
      pass "apm --json registry disable reports redirected system config"
      assert_file_contains "$SYSTEM_REG_CONFIG" "enabled = false" \
        "apm registry --system disable persists to redirected system config"
      assert_file_not_exists "$USER_REG_CONFIG" \
        "apm registry --system disable does not create a shadow user registry config"
      if $APM update --system --registry override-reg > /tmp/override-update-disabled.out 2>&1; then
        cat /tmp/override-update-disabled.out
        fail "apm update should reject disabled redirected system registry"
      else
        assert_file_contains /tmp/override-update-disabled.out \
          "registry 'override-reg' is not enabled" \
          "disabled redirected system registry blocks update"
      fi

      $APM --json registry --system enable override-reg \
        > /tmp/override-enable.json 2>&1 || {
        cat /tmp/override-enable.json
        fail "apm registry --system enable writes redirected system config"
      }
      ${pkgs.jq}/bin/jq -e \
        --arg config "$SYSTEM_REG_CONFIG" \
        '.action == "registry_enable"
          and .status == "enabled"
          and .registry == "override-reg"
          and .enabled == true
          and .previous_enabled == false
          and .changed == true
          and .config == $config
          and .packages == 1' \
        /tmp/override-enable.json >/dev/null || {
        cat /tmp/override-enable.json
        fail "apm --json registry enable reports redirected system config"
      }
      pass "apm --json registry enable reports redirected system config"
      assert_file_contains "$SYSTEM_REG_CONFIG" "enabled = true" \
        "apm registry --system enable persists to redirected system config"

      $APM --json registry --system remove override-reg --keep-local \
        > /tmp/override-remove.json 2>&1 || {
        cat /tmp/override-remove.json
        fail "apm registry --system remove deletes redirected system config"
      }
      ${pkgs.jq}/bin/jq -e \
        --arg config "$SYSTEM_REG_CONFIG" \
        '.action == "registry_remove"
          and .status == "removed"
          and .registry == "override-reg"
          and .keep_local == true
          and .config == $config
          and .config_removed == true
          and .local_removed == false' \
        /tmp/override-remove.json >/dev/null || {
        cat /tmp/override-remove.json
        fail "apm --json registry remove reports redirected system config deletion"
      }
      pass "apm --json registry remove reports redirected system config deletion"
      assert_file_not_exists "$SYSTEM_REG_CONFIG" \
        "apm registry remove deletes redirected system registry config"
      assert_file_not_exists "$USER_REG_CONFIG" \
        "apm registry remove leaves user registry config absent"
      "$ROOT_STORE/bin/closure-root" > /tmp/override-run-after-remove.out
      assert_file_contains /tmp/override-run-after-remove.out \
        "^closure-root 1.0.0 via closure-leaf 1.0.0$" \
        "downloaded redirected system registry closure still runs after registry removal"

      kill "$CACHE_PID" 2>/dev/null || true
      wait "$CACHE_PID" 2>/dev/null || true
      check_fail
    '';
  };
}
