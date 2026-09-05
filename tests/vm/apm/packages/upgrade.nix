# Packages VM checks for upgrade workflows.
{
  testing,
  pkgs,
  fixtures,
  upgradeAlphaV1,
  upgradeAlphaV2,
  upgradeBetaV1,
  upgradeBetaV2,
  realUpgradeDeps,
  setupNixEnv,
}: {
  # -------------------------------------------------------------------------
  # 10. upgrade-package — Upgrade package to newer version
  # -------------------------------------------------------------------------
  upgrade-package = testing.mkVMTest {
    name = "apm-upgrade-package";
    rootfsDeps = realUpgradeDeps;
    memory = 1024;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixEnv}

      echo "==> Test: real apm targeted and full upgrade workflow"

      ALPHA_V1_STORE="${upgradeAlphaV1}"
      ALPHA_V2_STORE="${upgradeAlphaV2}"
      BETA_V1_STORE="${upgradeBetaV1}"
      BETA_V2_STORE="${upgradeBetaV2}"
      ALPHA_V1_HASH=$(basename "$ALPHA_V1_STORE" | cut -d- -f1)
      ALPHA_V2_HASH=$(basename "$ALPHA_V2_STORE" | cut -d- -f1)
      BETA_V1_HASH=$(basename "$BETA_V1_STORE" | cut -d- -f1)
      BETA_V2_HASH=$(basename "$BETA_V2_STORE" | cut -d- -f1)
      MAINTAINER_HOME=/tmp
      CONSUMER_HOME=/tmp/upgrade-consumer
      PROFILE="/var/lib/profiles/per-user/upgradeuser"
      ALPHA_BIN="$PROFILE/current/bin/upgrade-alpha"
      BETA_BIN="$PROFILE/current/bin/upgrade-beta"

      as_maintainer() {
        export HOME="$MAINTAINER_HOME"
        export USER=root
      }

      as_consumer() {
        export HOME="$CONSUMER_HOME"
        export USER=upgradeuser
        mkdir -p "$HOME"
      }

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
        if nix-store --check-validity "$path" > "/tmp/upgrade-valid-$label.out" 2>&1; then
          pass "$label valid in store"
        else
          cat "/tmp/upgrade-valid-$label.out"
          fail "$label should be valid in store"
        fi
      }

      assert_store_missing() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/upgrade-missing-$label.out" 2>&1; then
          cat "/tmp/upgrade-missing-$label.out"
          fail "$label should be missing from store"
        else
          pass "$label missing from store"
        fi
      }

      delete_store_path() {
        path="$1"
        label="$2"
        if nix-store --delete --ignore-liveness "$path" > "/tmp/upgrade-delete-$label.out" 2>&1; then
          pass "$label deleted before apm download"
        else
          cat "/tmp/upgrade-delete-$label.out"
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
          if curl -sf http://127.0.0.1:18092/nix-cache-info >/dev/null; then
            return 0
          fi
          sleep 1
        done
        return 1
      }

      publish_upgrade_tool() {
        store="$1"
        name="$2"
        version="$3"
        hash=$(basename "$store" | cut -d- -f1)
        as_maintainer
        $APR publish "$store" \
          --name "$name" \
          --version "$version" \
          --description "Executable upgrade workflow fixture" \
          --license MIT \
          --maintainer upgrade-workflow@example.invalid \
          --registry upgrade-reg \
          --no-commit > "/tmp/upgrade-publish-$name-$version.out" 2>&1 || {
          cat "/tmp/upgrade-publish-$name-$version.out"
          fail "apr publish succeeds for $name $version"
          return 1
        }
        cat "/tmp/upgrade-publish-$name-$version.out"
        assert_file_contains "$REG_DIR/packages/u/$name.toml" \
          "$hash" "published $name $version metadata records store hash"
      }

      generate_upgrade_cache() {
        as_maintainer
        $APR cache generate \
          --registry upgrade-reg \
          --output /tmp/upgrade-cache \
          --cache-url http://127.0.0.1:18092 \
          --priority 43 \
          --no-commit
      }

      mount -o remount,rw / || true
      assert_store_valid "$ALPHA_V1_STORE" "upgrade-alpha-v1"
      assert_store_valid "$ALPHA_V2_STORE" "upgrade-alpha-v2"
      assert_store_valid "$BETA_V1_STORE" "upgrade-beta-v1"
      assert_store_valid "$BETA_V2_STORE" "upgrade-beta-v2"

      echo "==> Maintainer: publish upgrade-alpha and upgrade-beta 1.0.0"
      as_maintainer
      $APR create upgrade-reg
      REG_DIR="$MAINTAINER_HOME/.local/share/apm/registries/upgrade-reg"
      DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)
      publish_upgrade_tool "$ALPHA_V1_STORE" upgrade-alpha 1.0.0
      publish_upgrade_tool "$BETA_V1_STORE" upgrade-beta 1.0.0
      generate_upgrade_cache
      assert_file_exists "/tmp/upgrade-cache/$ALPHA_V1_HASH.narinfo" \
        "static cache has upgrade-alpha v1 narinfo"
      assert_file_exists "/tmp/upgrade-cache/$BETA_V1_HASH.narinfo" \
        "static cache has upgrade-beta v1 narinfo"
      assert_file_contains "$REG_DIR/registry.toml" \
        "http://127.0.0.1:18092" "registry records upgrade cache URL"

      git -C "$REG_DIR" add -A
      git -C "$REG_DIR" commit -m "release: upgrade tools 1.0.0"
      git init --bare --object-format=sha256 /tmp/upgrade-origin.git
      git -C "$REG_DIR" remote add origin /tmp/upgrade-origin.git
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
      PYTHONUNBUFFERED=1 python3 -m http.server 18092 --bind 127.0.0.1 \
        --directory /tmp/upgrade-cache > /tmp/upgrade-cache-http.log 2>&1 &
      CACHE_PID=$!
      if wait_for_cache_server; then
        pass "static cache HTTP server started"
      else
        cat /tmp/upgrade-cache-http.log || true
        fail "static cache HTTP server started"
      fi

      echo "==> Consumer: install both upgrade tools at 1.0.0"
      as_consumer
      $APM registry add --no-verify file:///tmp/upgrade-origin.git \
        --name upgrade-reg \
        --branch "$DEFAULT_BRANCH" > /tmp/upgrade-registry-add.out 2>&1 || {
        cat /tmp/upgrade-registry-add.out
        fail "apm registry add syncs upgrade registry"
      }
      cat /tmp/upgrade-registry-add.out

      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM upgrade --dry-run > /tmp/upgrade-empty-dry-run.out 2>&1 || {
        cat /tmp/upgrade-empty-dry-run.out
        fail "apm upgrade --dry-run succeeds before any package is installed"
      }
      cat /tmp/upgrade-empty-dry-run.out
      assert_file_contains /tmp/upgrade-empty-dry-run.out "All packages are up to date" \
        "empty upgrade dry-run reports no candidates"
      assert_file_not_contains /tmp/upgrade-empty-dry-run.out "Updating profile" \
        "empty upgrade dry-run does not update profile"
      if [ ! -e "$PROFILE" ]; then
        pass "empty upgrade dry-run leaves profile directory absent"
      else
        find "$PROFILE" -maxdepth 2 -print
        fail "empty upgrade dry-run should not initialize profile state"
      fi
      if [ "$(cache_nar_count)" = "0" ]; then
        pass "empty upgrade dry-run leaves NAR cache empty"
      else
        find "$HOME/.cache/apm" -type f -name '*.nar.zst' -print
        fail "empty upgrade dry-run should not download NAR bodies"
      fi

      $APM upgrade --yes > /tmp/upgrade-empty.out 2>&1 || {
        cat /tmp/upgrade-empty.out
        fail "apm upgrade succeeds before any package is installed"
      }
      cat /tmp/upgrade-empty.out
      assert_file_contains /tmp/upgrade-empty.out "All packages are up to date" \
        "empty upgrade reports no candidates"
      assert_file_not_contains /tmp/upgrade-empty.out "Updating profile" \
        "empty upgrade does not update profile"
      if [ ! -e "$PROFILE" ]; then
        pass "empty upgrade leaves profile directory absent"
      else
        find "$PROFILE" -maxdepth 2 -print
        fail "empty upgrade should not initialize profile state"
      fi
      if [ "$(cache_nar_count)" = "0" ]; then
        pass "empty upgrade leaves NAR cache empty"
      else
        find "$HOME/.cache/apm" -type f -name '*.nar.zst' -print
        fail "empty upgrade should not download NAR bodies"
      fi

      delete_store_path "$ALPHA_V1_STORE" "upgrade-alpha-v1"
      delete_store_path "$BETA_V1_STORE" "upgrade-beta-v1"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM install upgrade-alpha upgrade-beta --registry upgrade-reg --yes > /tmp/upgrade-install.out 2>&1 || {
        cat /tmp/upgrade-install.out
        fail "apm install downloads both upgrade tools"
      }
      cat /tmp/upgrade-install.out
      assert_file_contains /tmp/upgrade-install.out "Downloading 2 NAR" \
        "initial install downloads both upgrade tools"
      "$ALPHA_BIN" > /tmp/upgrade-alpha-v1-run.out
      assert_file_contains /tmp/upgrade-alpha-v1-run.out "^upgrade-alpha 1.0.0$" \
        "upgrade-alpha v1 executable runs"
      "$BETA_BIN" > /tmp/upgrade-beta-v1-run.out
      assert_file_contains /tmp/upgrade-beta-v1-run.out "^upgrade-beta 1.0.0$" \
        "upgrade-beta v1 executable runs"
      if [ "$(readlink "$PROFILE/current")" = "gen-1" ] && [ "$(generation_count)" = "1" ]; then
        pass "initial install creates generation 1"
      else
        fail "initial install should create gen-1"
      fi

      echo "==> Maintainer: publish upgrade-alpha and upgrade-beta 2.0.0"
      publish_upgrade_tool "$ALPHA_V2_STORE" upgrade-alpha 2.0.0
      publish_upgrade_tool "$BETA_V2_STORE" upgrade-beta 2.0.0
      generate_upgrade_cache
      assert_file_exists "/tmp/upgrade-cache/$ALPHA_V2_HASH.narinfo" \
        "static cache has upgrade-alpha v2 narinfo"
      assert_file_exists "/tmp/upgrade-cache/$BETA_V2_HASH.narinfo" \
        "static cache has upgrade-beta v2 narinfo"
      git -C "$REG_DIR" add -A
      git -C "$REG_DIR" commit -m "release: upgrade tools 2.0.0"
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      delete_store_path "$ALPHA_V2_STORE" "upgrade-alpha-v2"
      delete_store_path "$BETA_V2_STORE" "upgrade-beta-v2"
      as_consumer
      $APM update --registry upgrade-reg > /tmp/upgrade-update.out 2>&1 || {
        cat /tmp/upgrade-update.out
        fail "apm update syncs upgrade registry v2"
      }
      cat /tmp/upgrade-update.out

      $APM list --upgradable > /tmp/upgrade-list.out 2>&1 || {
        cat /tmp/upgrade-list.out
        fail "apm list --upgradable succeeds for upgrade tools"
      }
      assert_file_contains /tmp/upgrade-list.out "upgrade-alpha" \
        "upgradable list includes upgrade-alpha"
      assert_file_contains /tmp/upgrade-list.out "upgrade-beta" \
        "upgradable list includes upgrade-beta"

      echo "==> Consumer: targeted upgrade dry-run leaves profile and store untouched"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM upgrade upgrade-alpha --dry-run > /tmp/upgrade-alpha-dry-run.out 2>&1 || {
        cat /tmp/upgrade-alpha-dry-run.out
        fail "targeted apm upgrade --dry-run upgrade-alpha succeeds"
      }
      cat /tmp/upgrade-alpha-dry-run.out
      assert_file_contains /tmp/upgrade-alpha-dry-run.out "upgrade-alpha (1.0.0 -> 2.0.0)" \
        "targeted upgrade dry-run plans upgrade-alpha"
      assert_file_not_contains /tmp/upgrade-alpha-dry-run.out "upgrade-beta (1.0.0 -> 2.0.0)" \
        "targeted upgrade dry-run does not plan upgrade-beta"
      assert_file_contains /tmp/upgrade-alpha-dry-run.out "Dry run -- no changes made" \
        "targeted upgrade dry-run reports no mutation"
      assert_file_not_contains /tmp/upgrade-alpha-dry-run.out "Downloading" \
        "targeted upgrade dry-run does not download package bodies"
      assert_file_not_contains /tmp/upgrade-alpha-dry-run.out "Updating profile" \
        "targeted upgrade dry-run does not update profile"
      assert_store_missing "$ALPHA_V2_STORE" "upgrade-alpha-v2"
      assert_store_missing "$BETA_V2_STORE" "upgrade-beta-v2"
      if [ "$(cache_nar_count)" = "0" ]; then
        pass "targeted upgrade dry-run leaves NAR cache empty"
      else
        find "$HOME/.cache/apm" -type f -name '*.nar.zst' -print
        fail "targeted upgrade dry-run should not download NAR bodies"
      fi
      "$ALPHA_BIN" > /tmp/upgrade-alpha-v1-run-after-dry-run.out
      assert_file_contains /tmp/upgrade-alpha-v1-run-after-dry-run.out "^upgrade-alpha 1.0.0$" \
        "targeted upgrade dry-run leaves upgrade-alpha at v1"
      "$BETA_BIN" > /tmp/upgrade-beta-v1-run-after-dry-run.out
      assert_file_contains /tmp/upgrade-beta-v1-run-after-dry-run.out "^upgrade-beta 1.0.0$" \
        "targeted upgrade dry-run leaves upgrade-beta at v1"
      assert_file_contains "$PROFILE/meta/$ALPHA_V1_HASH.json" '"explicit": true' \
        "targeted upgrade dry-run preserves alpha v1 metadata"
      assert_file_not_exists "$PROFILE/meta/$ALPHA_V2_HASH.json" \
        "targeted upgrade dry-run does not write alpha v2 metadata"
      if [ "$(readlink "$PROFILE/current")" = "gen-1" ] && [ "$(generation_count)" = "1" ]; then
        pass "targeted upgrade dry-run keeps generation 1 active"
      else
        fail "targeted upgrade dry-run should keep gen-1"
      fi

      echo "==> Consumer: targeted upgrade changes only upgrade-alpha"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM upgrade upgrade-alpha --yes > /tmp/upgrade-alpha.out 2>&1 || {
        cat /tmp/upgrade-alpha.out
        fail "targeted apm upgrade upgrade-alpha succeeds"
      }
      cat /tmp/upgrade-alpha.out
      assert_file_contains /tmp/upgrade-alpha.out "upgrade-alpha (1.0.0 -> 2.0.0)" \
        "targeted upgrade plans upgrade-alpha"
      assert_file_not_contains /tmp/upgrade-alpha.out "upgrade-beta (1.0.0 -> 2.0.0)" \
        "targeted upgrade does not plan upgrade-beta"
      assert_file_contains /tmp/upgrade-alpha.out "Downloading 1 NAR" \
        "targeted upgrade downloads only upgrade-alpha"
      "$ALPHA_BIN" > /tmp/upgrade-alpha-v2-run.out
      assert_file_contains /tmp/upgrade-alpha-v2-run.out "^upgrade-alpha 2.0.0$" \
        "targeted upgrade activates upgrade-alpha v2"
      "$BETA_BIN" > /tmp/upgrade-beta-still-v1-run.out
      assert_file_contains /tmp/upgrade-beta-still-v1-run.out "^upgrade-beta 1.0.0$" \
        "targeted upgrade leaves upgrade-beta at v1"
      assert_file_contains "$PROFILE/meta/$ALPHA_V2_HASH.json" '"explicit": true' \
        "targeted upgrade writes alpha v2 metadata"
      assert_file_contains "$PROFILE/meta/$BETA_V1_HASH.json" '"explicit": true' \
        "targeted upgrade preserves beta v1 metadata"
      assert_file_not_exists "$PROFILE/meta/$BETA_V2_HASH.json" \
        "targeted upgrade does not write beta v2 metadata"
      if [ "$(readlink "$PROFILE/current")" = "gen-2" ] && [ "$(generation_count)" = "2" ]; then
        pass "targeted upgrade creates generation 2"
      else
        fail "targeted upgrade should create gen-2"
      fi

      echo "==> Consumer: excluded full upgrade leaves upgrade-beta untouched"
      $APM upgrade --exclude upgrade-beta --yes > /tmp/upgrade-exclude.out 2>&1 || {
        cat /tmp/upgrade-exclude.out
        fail "excluded apm upgrade succeeds"
      }
      cat /tmp/upgrade-exclude.out
      assert_file_contains /tmp/upgrade-exclude.out "held back" \
        "excluded upgrade reports held-back package"
      assert_file_contains /tmp/upgrade-exclude.out "upgrade-beta" \
        "excluded upgrade names upgrade-beta"
      assert_file_not_contains /tmp/upgrade-exclude.out "Downloading" \
        "excluded upgrade does not download beta"
      "$BETA_BIN" > /tmp/upgrade-beta-excluded-run.out
      assert_file_contains /tmp/upgrade-beta-excluded-run.out "^upgrade-beta 1.0.0$" \
        "excluded upgrade leaves upgrade-beta at v1"
      if [ "$(readlink "$PROFILE/current")" = "gen-2" ] && [ "$(generation_count)" = "2" ]; then
        pass "excluded upgrade does not create a generation"
      else
        fail "excluded upgrade should keep generation 2"
      fi

      echo "==> Consumer: full upgrade changes remaining upgrade-beta"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM upgrade --yes > /tmp/upgrade-all.out 2>&1 || {
        cat /tmp/upgrade-all.out
        fail "full apm upgrade succeeds"
      }
      cat /tmp/upgrade-all.out
      assert_file_contains /tmp/upgrade-all.out "upgrade-beta (1.0.0 -> 2.0.0)" \
        "full upgrade plans remaining beta upgrade"
      assert_file_not_contains /tmp/upgrade-all.out "upgrade-alpha (1.0.0 -> 2.0.0)" \
        "full upgrade does not replan already upgraded alpha"
      assert_file_contains /tmp/upgrade-all.out "Downloading 1 NAR" \
        "full upgrade downloads only upgrade-beta"
      "$ALPHA_BIN" > /tmp/upgrade-alpha-final-run.out
      assert_file_contains /tmp/upgrade-alpha-final-run.out "^upgrade-alpha 2.0.0$" \
        "full upgrade keeps upgrade-alpha at v2"
      "$BETA_BIN" > /tmp/upgrade-beta-v2-run.out
      assert_file_contains /tmp/upgrade-beta-v2-run.out "^upgrade-beta 2.0.0$" \
        "full upgrade activates upgrade-beta v2"
      assert_file_contains "$PROFILE/meta/$ALPHA_V2_HASH.json" '"explicit": true' \
        "full upgrade keeps alpha v2 metadata"
      assert_file_contains "$PROFILE/meta/$BETA_V2_HASH.json" '"explicit": true' \
        "full upgrade writes beta v2 metadata"
      assert_file_not_exists "$PROFILE/meta/$ALPHA_V1_HASH.json" \
        "full upgrade has no stale alpha v1 metadata"
      assert_file_not_exists "$PROFILE/meta/$BETA_V1_HASH.json" \
        "full upgrade drops beta v1 metadata"
      if [ "$(readlink "$PROFILE/current")" = "gen-3" ] && [ "$(generation_count)" = "3" ]; then
        pass "full upgrade creates generation 3"
      else
        fail "full upgrade should create gen-3"
      fi

      if kill "$CACHE_PID" 2>/dev/null; then
        pass "static cache HTTP server stopped"
      fi
      wait "$CACHE_PID" 2>/dev/null || true

      check_fail
    '';
  };
}
