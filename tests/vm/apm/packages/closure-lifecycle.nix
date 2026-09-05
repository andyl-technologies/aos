# Packages VM checks for closure lifecycle workflows.
{
  testing,
  pkgs,
  fixtures,
  realLifecycleDeps,
  setupNixEnv,
}: {
  # -------------------------------------------------------------------------
  # 12. package-real-closure-lifecycle — Install/upgrade/rollback real closure
  # -------------------------------------------------------------------------
  package-real-closure-lifecycle = testing.mkVMTest {
    name = "apm-package-real-closure-lifecycle";
    rootfsDeps = realLifecycleDeps;
    memory = 2048;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixEnv}

      echo "==> Test: real package closure install, upgrade, rollback, remove"

      delete_store_path() {
        path="$1"
        label="$2"
        nix-store --delete --ignore-liveness "$path" > "/tmp/delete-$label.out" 2>&1 || {
          cat "/tmp/delete-$label.out"
          fail "deleted $label before apm download"
          return
        }
        if nix-store --check-validity "$path" > "/tmp/valid-$label.out" 2>&1; then
          cat "/tmp/valid-$label.out"
          fail "$label should be missing before apm download"
        else
          pass "$label missing before apm download"
        fi
      }

      try_delete_store_path() {
        path="$1"
        label="$2"
        if nix-store --delete --ignore-liveness "$path" > "/tmp/delete-$label.out" 2>&1; then
          if nix-store --check-validity "$path" > "/tmp/valid-$label.out" 2>&1; then
            cat "/tmp/valid-$label.out"
            fail "$label should be missing before apm download"
            return 1
          fi
          pass "$label missing before apm download"
          return 0
        fi

        cat "/tmp/delete-$label.out"
        pass "$label remains live; upgrade will reuse existing store path"
        return 1
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

      publish_version() {
        version="$1"
        runtime_store="$2"
        tool_store="$3"
        $APR publish "$runtime_store" \
          --name lifecycle-runtime \
          --version "$version" \
          --description "Runtime payload for lifecycle workflow" \
          --license MIT \
          --maintainer lifecycle@example.invalid \
          --registry lifecycle-reg \
          --no-commit
        $APR publish "$tool_store" \
          --name lifecycle-tool \
          --version "$version" \
          --description "Executable tool for lifecycle workflow" \
          --license MIT \
          --maintainer lifecycle@example.invalid \
          --registry lifecycle-reg \
          --no-commit
      }

      RUNTIME_V1_STORE="${pkgs.oniguruma}"
      TOOL_V1_STORE="${pkgs.jq}"
      RUNTIME_V2_STORE="${pkgs.pcre2}"
      TOOL_V2_STORE="${pkgs.git}"
      RUNTIME_V1_HASH=$(basename "$RUNTIME_V1_STORE" | cut -d- -f1)
      TOOL_V1_HASH=$(basename "$TOOL_V1_STORE" | cut -d- -f1)
      RUNTIME_V2_HASH=$(basename "$RUNTIME_V2_STORE" | cut -d- -f1)
      TOOL_V2_HASH=$(basename "$TOOL_V2_STORE" | cut -d- -f1)

      nix-store -q --references "$TOOL_V1_STORE" > /tmp/tool-v1-refs.out
      cat /tmp/tool-v1-refs.out
      assert_file_contains /tmp/tool-v1-refs.out "$RUNTIME_V1_STORE" \
        "v1 tool has a real Nix reference to runtime"
      nix-store -qR "$TOOL_V1_STORE" > /tmp/tool-v1-closure.out
      assert_file_contains /tmp/tool-v1-closure.out "$RUNTIME_V1_STORE" \
        "v1 tool closure includes runtime"
      assert_file_contains /tmp/tool-v1-closure.out "$TOOL_V1_STORE" \
        "v1 tool closure includes root"
      nix-store -q --references "$TOOL_V2_STORE" > /tmp/tool-v2-refs.out
      assert_file_contains /tmp/tool-v2-refs.out "$RUNTIME_V2_STORE" \
        "v2 tool has a real Nix reference to runtime"

      $APR create lifecycle-reg
      REG_DIR="$REG_STORAGE/lifecycle-reg"
      DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)
      publish_version 1.0.0 "$RUNTIME_V1_STORE" "$TOOL_V1_STORE"
      assert_file_contains "$REG_DIR/store/$(printf %.2s "$TOOL_V1_HASH")/$TOOL_V1_HASH" \
        "$RUNTIME_V1_HASH" "published v1 tool metadata records runtime reference"
      assert_file_contains "$REG_DIR/store/$(printf %.2s "$TOOL_V1_HASH")/$TOOL_V1_HASH" \
        "$RUNTIME_V1_HASH" "published v1 tool closure records runtime"

      $APR cache generate \
        --registry lifecycle-reg \
        --output /tmp/lifecycle-cache \
        --cache-url http://127.0.0.1:18083 \
        --priority 43 \
        --no-commit
      assert_file_exists "/tmp/lifecycle-cache/$TOOL_V1_HASH.narinfo" \
        "static cache has v1 tool narinfo"
      assert_file_exists "/tmp/lifecycle-cache/$RUNTIME_V1_HASH.narinfo" \
        "static cache has v1 runtime narinfo"

      git -C "$REG_DIR" add -A
      git -C "$REG_DIR" commit -m "release: lifecycle-tool 1.0.0"
      git init --bare --object-format=sha256 /tmp/lifecycle-origin.git
      git -C "$REG_DIR" remote add origin /tmp/lifecycle-origin.git
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true

      PYTHONUNBUFFERED=1 python3 -m http.server 18083 --bind 127.0.0.1 \
        --directory /tmp/lifecycle-cache > /tmp/lifecycle-cache-http.log 2>&1 &
      CACHE_PID=$!
      for _i in 1 2 3 4 5 6 7 8 9 10; do
        if curl -sf http://127.0.0.1:18083/nix-cache-info >/dev/null; then
          break
        fi
        sleep 1
      done
      if ! curl -sf http://127.0.0.1:18083/nix-cache-info >/dev/null; then
        cat /tmp/lifecycle-cache-http.log || true
        fail "static cache HTTP server started"
      else
        pass "static cache HTTP server started"
      fi

      export HOME=/tmp/lifecycle-consumer
      export USER=lifecycleuser
      APM_CONFIG="$HOME/.config/apm"
      PROFILE="/var/lib/profiles/per-user/$USER"
      mkdir -p "$HOME"
      $APM registry add --no-verify file:///tmp/lifecycle-origin.git \
        --name lifecycle-reg \
        --branch "$DEFAULT_BRANCH"

      mount -o remount,rw / || true
      delete_store_path "$TOOL_V1_STORE" "tool-v1"
      delete_store_path "$RUNTIME_V1_STORE" "runtime-v1"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"

      $APM install lifecycle-tool --registry lifecycle-reg --yes \
        > /tmp/lifecycle-install.out 2>&1 || {
        cat /tmp/lifecycle-install.out
        fail "apm install downloads and imports v1 closure"
      }
      cat /tmp/lifecycle-install.out
      assert_file_contains /tmp/lifecycle-install.out "Downloading" \
        "apm install performed v1 downloads"
      assert_file_contains /tmp/lifecycle-install.out "Installed 1 package" \
        "apm install completed v1 profile update"
      NAR_COUNT=$(find "$HOME/.cache/apm" -name '*.nar.zst' | wc -l | tr -d ' ')
      if [ "$NAR_COUNT" -ge 2 ]; then
        pass "apm install downloaded the v1 closure"
      else
        fail "apm install should download at least two NARs for v1 closure"
      fi
      assert_store_valid "$TOOL_V1_STORE" "tool-v1"
      assert_store_valid "$RUNTIME_V1_STORE" "runtime-v1"

      PROFILE_JQ="/var/lib/profiles/per-user/$USER/current/bin/jq"
      PROFILE_GIT="/var/lib/profiles/per-user/$USER/current/bin/git"
      printf '{"value":42}\n' > /tmp/lifecycle-input.json
      "$PROFILE_JQ" -r '.value' /tmp/lifecycle-input.json > /tmp/lifecycle-run-v1.out
      assert_file_contains /tmp/lifecycle-run-v1.out "^42$" \
        "installed v1 jq executable runs from profile"
      $APM verify lifecycle-tool > /tmp/lifecycle-verify-v1.out 2>&1 || {
        cat /tmp/lifecycle-verify-v1.out
        fail "apm verify succeeds for downloaded v1 package"
      }

      export HOME=/tmp
      APM_CONFIG="$HOME/.config/apm"
      publish_version 2.0.0 "$RUNTIME_V2_STORE" "$TOOL_V2_STORE"
      assert_file_contains "$REG_DIR/packages/l/lifecycle-tool.toml" \
        "$TOOL_V2_HASH" "published v2 tool metadata records new store path"
      assert_file_contains "$REG_DIR/store/$(printf %.2s "$TOOL_V2_HASH")/$TOOL_V2_HASH" \
        "$RUNTIME_V2_HASH" "published v2 tool metadata records runtime reference"
      $APR cache generate \
        --registry lifecycle-reg \
        --output /tmp/lifecycle-cache \
        --cache-url http://127.0.0.1:18083 \
        --priority 43 \
        --no-commit
      assert_file_exists "/tmp/lifecycle-cache/$TOOL_V2_HASH.narinfo" \
        "static cache has v2 tool narinfo"
      assert_file_exists "/tmp/lifecycle-cache/$RUNTIME_V2_HASH.narinfo" \
        "static cache has v2 runtime narinfo"
      git -C "$REG_DIR" add -A
      git -C "$REG_DIR" commit -m "release: lifecycle-tool 2.0.0"
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      export HOME=/tmp/lifecycle-consumer
      export USER=lifecycleuser
      APM_CONFIG="$HOME/.config/apm"
      V2_DELETED=0
      if try_delete_store_path "$TOOL_V2_STORE" "tool-v2"; then
        V2_DELETED=$((V2_DELETED + 1))
      fi
      if try_delete_store_path "$RUNTIME_V2_STORE" "runtime-v2"; then
        V2_DELETED=$((V2_DELETED + 1))
      fi
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"

      $APM update --registry lifecycle-reg > /tmp/lifecycle-update.out 2>&1 || {
        cat /tmp/lifecycle-update.out
        fail "apm update fetches v2 registry metadata"
      }
      $APM list --upgradable > /tmp/lifecycle-upgradable.out 2>&1 || {
        cat /tmp/lifecycle-upgradable.out
        fail "apm list --upgradable succeeds"
      }
      assert_file_contains /tmp/lifecycle-upgradable.out "lifecycle-tool" \
        "apm list --upgradable reports lifecycle tool"
      assert_file_contains /tmp/lifecycle-upgradable.out "2.0.0" \
        "apm list --upgradable reports v2 candidate"
      if grep -q "lifecycle-runtime" /tmp/lifecycle-upgradable.out; then
        cat /tmp/lifecycle-upgradable.out
        fail "apm list --upgradable should not advertise auto dependencies as independent upgrades"
      else
        pass "apm list --upgradable omits auto dependency roots"
      fi

      $APM upgrade --yes > /tmp/lifecycle-upgrade.out 2>&1 || {
        cat /tmp/lifecycle-upgrade.out
        fail "apm upgrade downloads and imports v2 closure"
      }
      cat /tmp/lifecycle-upgrade.out
      assert_file_contains /tmp/lifecycle-upgrade.out "Upgraded 1 package" \
        "apm upgrade completed profile update"
      if [ "$V2_DELETED" -gt 0 ]; then
        assert_file_contains /tmp/lifecycle-upgrade.out "Downloading" \
          "apm upgrade performed v2 downloads"
        NAR_COUNT=$(find "$HOME/.cache/apm" -name '*.nar.zst' | wc -l | tr -d ' ')
        if [ "$NAR_COUNT" -ge "$V2_DELETED" ]; then
          pass "apm upgrade downloaded missing v2 closure member(s)"
        else
          fail "apm upgrade should download missing v2 closure member(s)"
        fi
      else
        assert_file_contains /tmp/lifecycle-upgrade.out "All packages already in store" \
          "apm upgrade reuses live v2 closure when paths cannot be deleted"
      fi
      assert_store_valid "$TOOL_V2_STORE" "tool-v2"
      assert_store_valid "$RUNTIME_V2_STORE" "runtime-v2"
      "$PROFILE_GIT" --version > /tmp/lifecycle-run-v2.out
      assert_file_contains /tmp/lifecycle-run-v2.out "git version" \
        "upgraded v2 git executable runs from profile"
      if [ -e "$PROFILE_JQ" ]; then
        fail "upgraded profile should not keep v1 jq executable"
      else
        pass "upgraded profile removes v1 jq executable"
      fi
      $APM list --installed > /tmp/lifecycle-installed-v2.out 2>&1 || {
        cat /tmp/lifecycle-installed-v2.out
        fail "apm list --installed succeeds after upgrading lifecycle tool"
      }
      assert_file_contains /tmp/lifecycle-installed-v2.out "lifecycle-tool" \
        "apm list --installed reports lifecycle tool after upgrade"
      assert_file_contains "$PROFILE/meta/$TOOL_V2_HASH.json" '"explicit": true' \
        "upgraded tool remains explicit"
      assert_file_contains "$PROFILE/meta/$RUNTIME_V2_HASH.json" '"explicit": false' \
        "upgraded runtime remains auto-installed"
      assert_file_not_exists "$PROFILE/meta/$RUNTIME_V1_HASH.json" \
        "upgrade drops obsolete auto dependency metadata"
      if [ -L "$PROFILE/current/usr/$RUNTIME_V1_HASH" ]; then
        fail "upgrade should drop obsolete auto dependency profile root"
      else
        pass "upgrade drops obsolete auto dependency profile root"
      fi
      if [ -L "$PROFILE/current/usr/$RUNTIME_V2_HASH" ]; then
        pass "upgrade records new auto dependency profile root"
      else
        fail "upgrade should root the new auto dependency"
      fi
      if grep -q "lifecycle-tool/lifecycle-reg 1.0.0" /tmp/lifecycle-installed-v2.out; then
        cat /tmp/lifecycle-installed-v2.out
        fail "apm list --installed should not retain old explicit package metadata after upgrade"
      else
        pass "apm list --installed drops old explicit package metadata after upgrade"
      fi
      $APM verify lifecycle-tool > /tmp/lifecycle-verify-v2.out 2>&1 || {
        cat /tmp/lifecycle-verify-v2.out
        fail "apm verify succeeds for downloaded v2 package"
      }

      $APM rollback > /tmp/lifecycle-rollback.out 2>&1 || {
        cat /tmp/lifecycle-rollback.out
        fail "apm rollback switches back to v1 generation"
      }
      cat /tmp/lifecycle-rollback.out
      assert_file_contains /tmp/lifecycle-rollback.out "Rolled back to generation 1" \
        "apm rollback selects previous generation"
      "$PROFILE_JQ" -r '.value' /tmp/lifecycle-input.json > /tmp/lifecycle-run-rollback.out
      assert_file_contains /tmp/lifecycle-run-rollback.out "^42$" \
        "rolled-back v1 jq executable runs from profile"
      if [ -e "$PROFILE_GIT" ]; then
        fail "rolled-back profile should not keep v2 git executable"
      else
        pass "rolled-back profile removes v2 git executable"
      fi
      $APM list --installed > /tmp/lifecycle-installed-rollback.out 2>&1 || {
        cat /tmp/lifecycle-installed-rollback.out
        fail "apm list --installed succeeds after rolling back lifecycle tool"
      }
      assert_file_contains /tmp/lifecycle-installed-rollback.out "lifecycle-tool" \
        "apm list --installed reports lifecycle tool after rollback"
      assert_file_contains /tmp/lifecycle-installed-rollback.out "1.0.0" \
        "rollback metadata preserves v1 package version"
      if grep -q "lifecycle-tool/lifecycle-reg 2.0.0" /tmp/lifecycle-installed-rollback.out; then
        cat /tmp/lifecycle-installed-rollback.out
        fail "rollback metadata should not point v1 root at v2 package"
      else
        pass "rollback metadata matches v1 root"
      fi
      $APM verify lifecycle-tool > /tmp/lifecycle-verify-rollback.out 2>&1 || {
        cat /tmp/lifecycle-verify-rollback.out
        fail "apm verify succeeds for rolled-back v1 while registry advertises v2"
      }
      assert_file_contains /tmp/lifecycle-verify-rollback.out \
        "integrity verified" \
        "apm verify uses rolled-back installed package metadata"

      $APM remove lifecycle-tool --yes > /tmp/lifecycle-remove.out 2>&1 || {
        cat /tmp/lifecycle-remove.out
        fail "apm remove deletes rolled-back package"
      }
      cat /tmp/lifecycle-remove.out
      assert_file_contains /tmp/lifecycle-remove.out "Removed" \
        "apm remove reports removed packages"
      if [ -e "$PROFILE_JQ" ]; then
        fail "removed lifecycle executable should not remain in current profile"
      else
        pass "removed lifecycle executable is absent from current profile"
      fi
      $APM list --installed > /tmp/lifecycle-installed-removed.out 2>&1 || {
        cat /tmp/lifecycle-installed-removed.out
        fail "apm list --installed succeeds after removing lifecycle tool"
      }
      if grep -q "lifecycle-tool" /tmp/lifecycle-installed-removed.out; then
        cat /tmp/lifecycle-installed-removed.out
        fail "apm list --installed should not show removed lifecycle tool"
      else
        pass "apm list --installed omits removed lifecycle tool"
      fi

      kill "$CACHE_PID" 2>/dev/null || true
      wait "$CACHE_PID" 2>/dev/null || true
      check_fail
    '';
  };
}
