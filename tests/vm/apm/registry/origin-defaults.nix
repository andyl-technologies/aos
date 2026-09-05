# Registry VM checks for origin defaults workflows.
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
  # registry-origin-defaults-workflow — APR upload defaults from isolated config
  # -------------------------------------------------------------------------
  registry-origin-defaults-workflow = testing.mkVMTest {
    name = "apm-registry-origin-defaults-workflow";
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

      echo "==> Test: APR origin upload defaults support isolated maintainer workflows"

      ROOT_STORE="${closureRootTool}"
      LEAF_STORE="${closureLeafTool}"
      ROOT_HASH=$(basename "$ROOT_STORE" | cut -d- -f1)
      LEAF_HASH=$(basename "$LEAF_STORE" | cut -d- -f1)
      ORIGIN_UPLOAD_URL="file:///tmp/origin-default-upload"
      HTTP_ORIGIN_URL="http://127.0.0.1:18132"

      set_isolated_home() {
        export HOME="$1"
        export USER="$2"
        export XDG_CONFIG_HOME="$HOME/.config"
        export XDG_DATA_HOME="$HOME/.local/share"
        export XDG_CACHE_HOME="$HOME/.cache"
        mkdir -p "$HOME"
      }

      assert_store_valid() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/origin-default-valid-$label.out" 2>&1; then
          pass "$label valid in store"
        else
          cat "/tmp/origin-default-valid-$label.out"
          fail "$label should be valid in store"
        fi
      }

      assert_store_missing() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/origin-default-missing-$label.out" 2>&1; then
          cat "/tmp/origin-default-missing-$label.out"
          fail "$label should be missing from store"
        else
          pass "$label missing from store"
        fi
      }

      delete_store_path() {
        path="$1"
        label="$2"
        if nix-store --delete --ignore-liveness "$path" > "/tmp/origin-default-delete-$label.out" 2>&1; then
          pass "$label deleted from store"
        else
          cat "/tmp/origin-default-delete-$label.out"
          fail "$label should be deletable from store"
          return 1
        fi
        assert_store_missing "$path" "$label"
      }

      cache_nar_count() {
        find "$HOME/.cache/apm" -type f -name '*.nar.zst' 2>/dev/null | wc -l | tr -d ' '
      }

      cache_nar_http_get_count() {
        grep -E 'GET /nar/.*\.nar\.zst HTTP/' /tmp/origin-default-http.log 2>/dev/null | wc -l | tr -d ' '
      }

      wait_for_origin_default_http() {
        for _i in 1 2 3 4 5 6 7 8 9 10; do
          if curl -sf "$HTTP_ORIGIN_URL/HEAD" >/dev/null \
            && curl -sf "$HTTP_ORIGIN_URL/nix-cache-info" >/dev/null; then
            return 0
          fi
          sleep 1
        done
        return 1
      }

      export APM_SYSTEM_CONFIG_DIR=/tmp/origin-default-system-config
      mkdir -p "$APM_SYSTEM_CONFIG_DIR"

      echo "==> Maintainer seed: create and publish an empty remote registry"
      set_isolated_home /tmp/origin-default-seed originseed
      $APR create origin-default-reg
      SEED_REG_DIR="$XDG_DATA_HOME/apm/registries/origin-default-reg"
      DEFAULT_BRANCH=$(git -C "$SEED_REG_DIR" symbolic-ref --short HEAD)
      git init --bare --object-format=sha256 /tmp/origin-default.git
      git -C "$SEED_REG_DIR" remote add origin /tmp/origin-default.git
      git -C "$SEED_REG_DIR" push origin "$DEFAULT_BRANCH"

      echo "==> Maintainer: add registry through APR in isolated user config"
      set_isolated_home /tmp/origin-default-maintainer originmaint
      APR_REG_CONFIG="$XDG_CONFIG_HOME/apm/registries.d/origin-default-reg.toml"
      APR_REG_DIR="$XDG_DATA_HOME/apm/registries/origin-default-reg"
      SYSTEM_REG_CONFIG="$APM_SYSTEM_CONFIG_DIR/registries.d/origin-default-reg.toml"
      $APR --json add --no-verify file:///tmp/origin-default.git \
        --name origin-default-reg \
        --branch "$DEFAULT_BRANCH" \
        --priority 612 > /tmp/origin-default-add.json 2>&1 || {
        cat /tmp/origin-default-add.json
        fail "apr add creates isolated maintainer registry config"
      }
      ${pkgs.jq}/bin/jq -e \
        --arg config "$APR_REG_CONFIG" \
        --arg tracking "branch:$DEFAULT_BRANCH" \
        '.action == "registry_add"
          and .status == "added"
          and .registry == "origin-default-reg"
          and .url == "file:///tmp/origin-default.git"
          and .priority == 612
          and .tracking == $tracking
          and .clone == true
          and .synced == true
          and .verification_disabled == true
          and .config == $config
          and .packages == 0' \
        /tmp/origin-default-add.json >/dev/null || {
        cat /tmp/origin-default-add.json
        fail "apr --json add reports isolated maintainer registry config"
      }
      pass "apr --json add reports isolated maintainer registry config"
      assert_dir_exists "$APR_REG_DIR/.git" \
        "apr add creates a writable maintainer git clone"
      if git -C "$APR_REG_DIR" rev-parse --is-inside-work-tree \
        > /tmp/origin-default-authoring-worktree.out 2>&1; then
        assert_file_contains /tmp/origin-default-authoring-worktree.out "^true$" \
          "apr add leaves maintainer registry as a git worktree"
      else
        cat /tmp/origin-default-authoring-worktree.out
        fail "apr add should leave maintainer registry as a git worktree"
      fi
      git -C "$APR_REG_DIR" branch --show-current \
        > /tmp/origin-default-authoring-branch.out 2>&1 || {
        cat /tmp/origin-default-authoring-branch.out
        fail "apr add should check out maintainer branch"
      }
      assert_file_contains /tmp/origin-default-authoring-branch.out "^$DEFAULT_BRANCH$" \
        "apr add checks out maintainer branch"
      assert_file_exists "$APR_REG_CONFIG" \
        "apr add writes user registry config"
      assert_file_not_exists "$SYSTEM_REG_CONFIG" \
        "apr add does not write redirected system registry config"

      $APR --json origin config --registry origin-default-reg \
        > /tmp/origin-default-config-empty.json 2>&1 || {
        cat /tmp/origin-default-config-empty.json
        fail "apr origin config reads empty upload defaults"
      }
      ${pkgs.jq}/bin/jq -e \
        '.action == "origin_config"
          and .registry == "origin-default-reg"
          and (.upload_auth.upload_urls | length == 0)' \
        /tmp/origin-default-config-empty.json >/dev/null || {
        cat /tmp/origin-default-config-empty.json
        fail "apr --json origin config reports empty upload defaults"
      }
      pass "apr --json origin config reports empty upload defaults"

      $APR --json origin config --registry origin-default-reg \
        --upload-url "$ORIGIN_UPLOAD_URL" \
        > /tmp/origin-default-config-set.json 2>&1 || {
        cat /tmp/origin-default-config-set.json
        fail "apr origin config stores upload defaults"
      }
      ${pkgs.jq}/bin/jq -e \
        --arg config "$APR_REG_CONFIG" \
        --arg upload "$ORIGIN_UPLOAD_URL" \
        '.action == "origin_config"
          and .registry == "origin-default-reg"
          and .config == $config
          and .upload_auth.upload_urls == [$upload]' \
        /tmp/origin-default-config-set.json >/dev/null || {
        cat /tmp/origin-default-config-set.json
        fail "apr --json origin config reports stored upload defaults"
      }
      pass "apr --json origin config reports stored upload defaults"
      assert_file_contains "$APR_REG_CONFIG" "upload_urls" \
        "apr origin config persists upload defaults in user config"
      assert_file_not_exists "$SYSTEM_REG_CONFIG" \
        "apr origin config does not write redirected system registry config"

      ssh-keygen -q -t ed25519 -N "" -f /tmp/origin-default-release-key
      $APR --json release 1.0.0 \
        --registry origin-default-reg \
        --store-path "$ROOT_STORE" \
        --name origin-default-root \
        --description "Origin default upload workflow root" \
        --license MIT \
        --maintainer origin-default@example.invalid \
        --key /tmp/origin-default-release-key \
        --cache-url "$HTTP_ORIGIN_URL" \
        > /tmp/origin-default-release.json 2>&1 || {
        cat /tmp/origin-default-release.json
        fail "apr release uses persisted origin upload defaults"
      }
      ${pkgs.jq}/bin/jq -e \
        --arg upload "$ORIGIN_UPLOAD_URL" \
        '.action == "release"
          and .status == "released"
          and .registry == "origin-default-reg"
          and .version == "1.0.0"
          and .upload_urls == [$upload]
          and (.uploaded_files | type == "number" and . > 0)
          and (.cache.narinfos >= 2)
          and (.cache.nars >= 2)' \
        /tmp/origin-default-release.json >/dev/null || {
        cat /tmp/origin-default-release.json
        fail "apr --json release reports persisted upload destination"
      }
      pass "apr --json release reports persisted upload destination"
      assert_file_exists "/tmp/origin-default-upload/HEAD" \
        "persisted upload destination has HEAD"
      assert_file_exists "/tmp/origin-default-upload/info/refs" \
        "persisted upload destination has dumb HTTP refs"
      assert_file_exists "/tmp/origin-default-upload/$ROOT_HASH.narinfo" \
        "persisted upload destination has root narinfo"
      assert_file_exists "/tmp/origin-default-upload/$LEAF_HASH.narinfo" \
        "persisted upload destination has dependency narinfo"

      rm -f /tmp/origin-default-upload/info/refs
      ORIGIN_DEFAULT_CACHE_DIR="$HOME/.cache/apm/registry-static/origin-default-reg"
      $APR --json origin upload --registry origin-default-reg \
        --cache-dir "$ORIGIN_DEFAULT_CACHE_DIR" \
        > /tmp/origin-default-upload.json 2>&1 || {
        cat /tmp/origin-default-upload.json
        fail "apr origin upload reuses persisted upload defaults"
      }
      ${pkgs.jq}/bin/jq -e \
        --arg upload "$ORIGIN_UPLOAD_URL" \
        --arg cache_dir "$ORIGIN_DEFAULT_CACHE_DIR" \
        '.action == "origin_upload"
          and .registry == "origin-default-reg"
          and .upload_urls == [$upload]
          and .cache_dir == $cache_dir
          and (.files | type == "number" and . > 0)
          and (.bytes | type == "number" and . > 0)' \
        /tmp/origin-default-upload.json >/dev/null || {
        cat /tmp/origin-default-upload.json
        fail "apr --json origin upload reports persisted upload destination"
      }
      pass "apr --json origin upload reports persisted upload destination"
      assert_file_exists "/tmp/origin-default-upload/info/refs" \
        "apr origin upload refreshes missing dumb HTTP refs"

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
      PYTHONUNBUFFERED=1 python3 -m http.server 18132 --bind 127.0.0.1 \
        --directory /tmp/origin-default-upload > /tmp/origin-default-http.log 2>&1 &
      ORIGIN_PID=$!
      if wait_for_origin_default_http; then
        pass "uploaded origin default HTTP server started"
      else
        cat /tmp/origin-default-http.log || true
        fail "uploaded origin default HTTP server started"
      fi

      echo "==> Consumer: install from uploaded origin default workflow"
      set_isolated_home /tmp/origin-default-consumer originconsumer
      PROFILE_BIN="/var/lib/profiles/per-user/$USER/current/bin/closure-root"
      $APM registry add --no-verify "$HTTP_ORIGIN_URL" \
        --name origin-default-reg \
        --branch "$DEFAULT_BRANCH" > /tmp/origin-default-consumer-add.out 2>&1 || {
        cat /tmp/origin-default-consumer-add.out
        fail "apm registry add syncs origin-default upload"
      }
      assert_file_contains /tmp/origin-default-consumer-add.out "Registry 'origin-default-reg' added" \
        "consumer adds uploaded origin-default registry"

      mount -o remount,rw / || true
      delete_store_path "$ROOT_STORE" "origin-default-root"
      delete_store_path "$LEAF_STORE" "origin-default-leaf"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      NAR_GETS_BEFORE_INSTALL=$(cache_nar_http_get_count)
      $APM install origin-default-root --registry origin-default-reg --yes \
        > /tmp/origin-default-install.out 2>&1 || {
        cat /tmp/origin-default-install.out
        fail "apm install downloads package from origin-default upload"
      }
      cat /tmp/origin-default-install.out
      assert_file_contains /tmp/origin-default-install.out "Downloading 2 NAR" \
        "apm install downloads root and dependency from origin-default upload"
      assert_file_contains /tmp/origin-default-install.out "Installed 1 package" \
        "apm install activates origin-default package"
      EXPECTED_NAR_GETS_AFTER_INSTALL=$((NAR_GETS_BEFORE_INSTALL + 2))
      if [ "$(cache_nar_http_get_count)" = "$EXPECTED_NAR_GETS_AFTER_INSTALL" ]; then
        pass "origin-default install fetches exactly two NAR bodies"
      else
        cat /tmp/origin-default-http.log || true
        fail "origin-default install should fetch exactly two NAR bodies"
      fi
      if [ "$(cache_nar_count)" = "2" ]; then
        pass "origin-default install leaves root and dependency NARs in user cache"
      else
        fail "origin-default install should cache exactly two release NARs"
      fi
      assert_store_valid "$ROOT_STORE" "origin-default-root"
      assert_store_valid "$LEAF_STORE" "origin-default-leaf"
      "$PROFILE_BIN" > /tmp/origin-default-run.out
      assert_file_contains /tmp/origin-default-run.out \
        "^closure-root 1.0.0 via closure-leaf 1.0.0$" \
        "installed origin-default closure executes with its dependency"

      kill "$ORIGIN_PID" 2>/dev/null || true
      wait "$ORIGIN_PID" 2>/dev/null || true
      check_fail
    '';
  };
}
