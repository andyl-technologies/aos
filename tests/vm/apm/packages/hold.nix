# Packages VM checks for hold workflows.
{
  testing,
  pkgs,
  fixtures,
  holdToolV1,
  holdToolV2,
  realHoldDeps,
  setupNixEnv,
}: {
  # -------------------------------------------------------------------------
  # 16. hold-prevent-upgrade — Hold/unhold prevents/allows upgrades
  # -------------------------------------------------------------------------
  hold-prevent-upgrade = testing.mkVMTest {
    name = "apm-hold-prevent-upgrade";
    rootfsDeps = realHoldDeps;
    memory = 1024;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixEnv}

      echo "==> Test: apm hold blocks real upgrade and unhold allows it"

      HOLD_V1_STORE="${holdToolV1}"
      HOLD_V2_STORE="${holdToolV2}"
      HOLD_V1_HASH=$(basename "$HOLD_V1_STORE" | cut -d- -f1)
      HOLD_V2_HASH=$(basename "$HOLD_V2_STORE" | cut -d- -f1)
      PROFILE="/var/lib/profiles/per-user/holduser"
      PROFILE_BIN="$PROFILE/current/bin/hold-tool"
      JQ="${pkgs.jq}/bin/jq"

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
        if nix-store --check-validity "$path" > "/tmp/valid-$label.out" 2>&1; then
          pass "$label valid in store"
        else
          cat "/tmp/valid-$label.out"
          fail "$label should be valid in store"
        fi
      }

      assert_store_missing() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/missing-$label.out" 2>&1; then
          cat "/tmp/missing-$label.out"
          fail "$label should be missing from store"
        else
          pass "$label missing from store"
        fi
      }

      delete_store_path() {
        path="$1"
        label="$2"
        if nix-store --delete --ignore-liveness "$path" > "/tmp/delete-$label.out" 2>&1; then
          pass "$label deleted before apm download"
        else
          cat "/tmp/delete-$label.out"
          fail "$label should be deletable before apm download"
          return 1
        fi
        assert_store_missing "$path" "$label"
      }

      wait_for_cache_server() {
        for _i in 1 2 3 4 5 6 7 8 9 10; do
          if curl -sf http://127.0.0.1:18085/nix-cache-info >/dev/null; then
            return 0
          fi
          sleep 1
        done
        return 1
      }

      publish_hold_tool() {
        version="$1"
        store="$2"
        $APR publish "$store" \
          --name hold-tool \
          --version "$version" \
          --description "Executable hold workflow fixture" \
          --license MIT \
          --maintainer hold-workflow@example.invalid \
          --registry hold-reg \
          --no-commit
      }

      mount -o remount,rw / || true
      assert_store_valid "$HOLD_V1_STORE" "hold-tool-v1"
      assert_store_valid "$HOLD_V2_STORE" "hold-tool-v2"

      echo "==> Maintainer: publish hold-tool 1.0.0 and static cache"
      $APR create hold-reg
      REG_DIR="$REG_STORAGE/hold-reg"
      DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)
      publish_hold_tool 1.0.0 "$HOLD_V1_STORE"
      assert_file_contains "$REG_DIR/packages/h/hold-tool.toml" \
        "$HOLD_V1_HASH" "published v1 metadata records store hash"

      $APR cache generate \
        --registry hold-reg \
        --output /tmp/hold-cache \
        --cache-url http://127.0.0.1:18085 \
        --priority 45 \
        --no-commit
      assert_file_exists "/tmp/hold-cache/$HOLD_V1_HASH.narinfo" \
        "static cache has hold-tool v1 narinfo"
      assert_file_contains "$REG_DIR/registry.toml" \
        "http://127.0.0.1:18085" "registry records hold cache URL"

      git -C "$REG_DIR" add -A
      git -C "$REG_DIR" commit -m "release: hold-tool 1.0.0"
      git init --bare --object-format=sha256 /tmp/hold-origin.git
      git -C "$REG_DIR" remote add origin /tmp/hold-origin.git
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
      PYTHONUNBUFFERED=1 python3 -m http.server 18085 --bind 127.0.0.1 \
        --directory /tmp/hold-cache > /tmp/hold-cache-http.log 2>&1 &
      CACHE_PID=$!
      if wait_for_cache_server; then
        pass "static cache HTTP server started"
      else
        cat /tmp/hold-cache-http.log || true
        fail "static cache HTTP server started"
      fi

      echo "==> Consumer: install hold-tool 1.0.0 through apm"
      export HOME=/tmp/hold-consumer
      export USER=holduser
      mkdir -p "$HOME"
      $APM registry add --no-verify file:///tmp/hold-origin.git \
        --name hold-reg \
        --branch "$DEFAULT_BRANCH" > /tmp/hold-registry-add.out 2>&1 || {
        cat /tmp/hold-registry-add.out
        fail "apm registry add syncs hold registry"
      }
      cat /tmp/hold-registry-add.out

      if $APM hold hold-tool > /tmp/hold-empty.out 2>&1; then
        cat /tmp/hold-empty.out
        fail "hold should fail before hold-tool is installed"
      else
        cat /tmp/hold-empty.out
        pass "hold fails before hold-tool is installed"
      fi
      assert_file_contains /tmp/hold-empty.out "package not found" \
        "empty hold reports missing installed package"
      if [ ! -e "$PROFILE" ]; then
        pass "empty hold leaves profile directory absent"
      else
        find "$PROFILE" -maxdepth 2 -print
        fail "empty hold should not initialize profile state"
      fi

      if $APM unhold hold-tool > /tmp/unhold-empty.out 2>&1; then
        cat /tmp/unhold-empty.out
        fail "unhold should fail before hold-tool is installed"
      else
        cat /tmp/unhold-empty.out
        pass "unhold fails before hold-tool is installed"
      fi
      assert_file_contains /tmp/unhold-empty.out "package not found" \
        "empty unhold reports missing installed package"
      if [ ! -e "$PROFILE" ]; then
        pass "empty unhold leaves profile directory absent"
      else
        find "$PROFILE" -maxdepth 2 -print
        fail "empty unhold should not initialize profile state"
      fi

      delete_store_path "$HOLD_V1_STORE" "hold-tool-v1"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM install hold-tool --registry hold-reg --yes > /tmp/hold-install.out 2>&1 || {
        cat /tmp/hold-install.out
        fail "apm installs hold-tool v1"
      }
      cat /tmp/hold-install.out
      assert_file_contains /tmp/hold-install.out "Downloading" \
        "apm install downloads held workflow v1"
      assert_file_contains /tmp/hold-install.out "Installed 1 package" \
        "apm install completes held workflow v1"
      "$PROFILE_BIN" > /tmp/hold-tool-v1.out
      assert_file_contains /tmp/hold-tool-v1.out "^hold-tool 1.0.0$" \
        "profile executable runs hold-tool v1"

      $APM --json hold hold-tool > /tmp/hold.json 2>&1 || {
        cat /tmp/hold.json
        fail "apm hold succeeds for installed hold-tool"
      }
      "$JQ" -e --arg store "$HOLD_V1_STORE" \
        '.action == "hold"
          and .status == "held"
          and .package == "hold-tool"
          and .name == "hold-tool"
          and .version == "1.0.0"
          and .registry == "hold-reg"
          and .store_path == $store
          and .held == true' \
        /tmp/hold.json >/dev/null || {
        cat /tmp/hold.json
        fail "apm --json hold reports installed hold-tool"
      }

      $APM held > /tmp/held.out 2>&1 || {
        cat /tmp/held.out
        fail "apm held succeeds"
      }
      cat /tmp/held.out
      assert_file_contains /tmp/held.out "hold-tool 1.0.0 (hold-reg)" \
        "apm held lists installed held package"

      echo "==> Consumer: reinstall held package preserves held metadata"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM reinstall hold-tool --yes > /tmp/hold-reinstall-held.out 2>&1 || {
        cat /tmp/hold-reinstall-held.out
        fail "apm reinstall succeeds for installed held package"
      }
      cat /tmp/hold-reinstall-held.out
      assert_file_contains /tmp/hold-reinstall-held.out "Downloading" \
        "apm reinstall downloads held package"
      assert_file_contains /tmp/hold-reinstall-held.out "Reinstalled 1 package" \
        "apm reinstall recreates held package generation"
      assert_file_contains \
        "/var/lib/profiles/per-user/holduser/current/meta/$HOLD_V1_HASH.json" \
        '"held": true' "apm reinstall preserves held metadata"
      $APM held > /tmp/held-after-reinstall.out 2>&1 || {
        cat /tmp/held-after-reinstall.out
        fail "apm held succeeds after reinstall"
      }
      cat /tmp/held-after-reinstall.out
      assert_file_contains /tmp/held-after-reinstall.out "hold-tool 1.0.0 (hold-reg)" \
        "apm held still lists package after reinstall"
      "$PROFILE_BIN" > /tmp/hold-tool-after-held-reinstall.out
      assert_file_contains /tmp/hold-tool-after-held-reinstall.out "^hold-tool 1.0.0$" \
        "reinstalled held executable still runs hold-tool v1"

      echo "==> Maintainer: publish hold-tool 2.0.0"
      export HOME=/tmp
      export USER=root
      publish_hold_tool 2.0.0 "$HOLD_V2_STORE"
      assert_file_contains "$REG_DIR/packages/h/hold-tool.toml" \
        "$HOLD_V2_HASH" "published v2 metadata records store hash"
      $APR cache generate \
        --registry hold-reg \
        --output /tmp/hold-cache \
        --cache-url http://127.0.0.1:18085 \
        --priority 45 \
        --no-commit
      assert_file_exists "/tmp/hold-cache/$HOLD_V2_HASH.narinfo" \
        "static cache has hold-tool v2 narinfo"
      git -C "$REG_DIR" add -A
      git -C "$REG_DIR" commit -m "release: hold-tool 2.0.0"
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      echo "==> Consumer: held upgrade does not import v2"
      export HOME=/tmp/hold-consumer
      export USER=holduser
      delete_store_path "$HOLD_V2_STORE" "hold-tool-v2"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"

      $APM update --registry hold-reg > /tmp/hold-update.out 2>&1 || {
        cat /tmp/hold-update.out
        fail "apm update fetches hold-tool v2 metadata"
      }
      cat /tmp/hold-update.out
      assert_file_contains /tmp/hold-update.out "done" \
        "apm update completes for hold registry"

      $APM --json upgrade hold-tool --yes > /tmp/hold-upgrade-held.out 2>&1 || {
        cat /tmp/hold-upgrade-held.out
        fail "held apm upgrade exits successfully"
      }
      "$JQ" -e --arg store "$HOLD_V2_STORE" \
        '.action == "upgrade"
          and .status == "held_back"
          and .requested == ["hold-tool"]
          and .exclude == []
          and .dry_run == false
          and .generation == null
          and .upgraded == 0
          and .upgrades == []
          and (.held_back | length == 1)
          and .held_back[0].name == "hold-tool"
          and .held_back[0].registry == "hold-reg"
          and .held_back[0].old_version == "1.0.0"
          and .held_back[0].new_version == "2.0.0"
          and .held_back[0].new_store_path == $store
          and .downloads.planned == 0
          and .downloads.downloaded == 0
          and .downloads.imported == 0' \
        /tmp/hold-upgrade-held.out >/dev/null || {
        cat /tmp/hold-upgrade-held.out
        fail "apm --json upgrade reports held-back package"
      }
      assert_store_missing "$HOLD_V2_STORE" "hold-tool-v2"
      "$PROFILE_BIN" > /tmp/hold-tool-after-held-upgrade.out
      assert_file_contains /tmp/hold-tool-after-held-upgrade.out "^hold-tool 1.0.0$" \
        "profile executable remains hold-tool v1 while held"

      $APM --json unhold hold-tool > /tmp/unhold.json 2>&1 || {
        cat /tmp/unhold.json
        fail "apm unhold succeeds for installed hold-tool"
      }
      "$JQ" -e --arg store "$HOLD_V1_STORE" \
        '.action == "unhold"
          and .status == "unheld"
          and .package == "hold-tool"
          and .name == "hold-tool"
          and .version == "1.0.0"
          and .registry == "hold-reg"
          and .store_path == $store
          and .held == false' \
        /tmp/unhold.json >/dev/null || {
        cat /tmp/unhold.json
        fail "apm --json unhold reports installed hold-tool"
      }

      $APM held > /tmp/held-after-unhold.out 2>&1 || {
        cat /tmp/held-after-unhold.out
        fail "apm held succeeds after unhold"
      }
      cat /tmp/held-after-unhold.out
      assert_file_contains /tmp/held-after-unhold.out "No packages are held" \
        "apm held is empty after unhold"

      echo "==> Consumer: unheld upgrade downloads and activates v2"
      $APM --json upgrade hold-tool --yes > /tmp/hold-upgrade-unheld.out 2>&1 || {
        cat /tmp/hold-upgrade-unheld.out
        fail "unheld apm upgrade installs v2"
      }
      "$JQ" -e --arg store "$HOLD_V2_STORE" \
        '.action == "upgrade"
          and .status == "upgraded"
          and .requested == ["hold-tool"]
          and .exclude == []
          and .dry_run == false
          and .generation == 3
          and .upgraded == 1
          and .held_back == []
          and (.upgrades | length == 1)
          and .upgrades[0].name == "hold-tool"
          and .upgrades[0].registry == "hold-reg"
          and .upgrades[0].old_version == "1.0.0"
          and .upgrades[0].new_version == "2.0.0"
          and .upgrades[0].new_store_path == $store
          and (.downloads.planned >= 1)
          and (.downloads.downloaded >= 1)
          and (.downloads.imported >= 1)' \
        /tmp/hold-upgrade-unheld.out >/dev/null || {
        cat /tmp/hold-upgrade-unheld.out
        fail "apm --json upgrade reports unheld package upgrade"
      }
      assert_store_valid "$HOLD_V2_STORE" "hold-tool-v2"
      "$PROFILE_BIN" > /tmp/hold-tool-v2.out
      assert_file_contains /tmp/hold-tool-v2.out "^hold-tool 2.0.0$" \
        "profile executable runs hold-tool v2 after unhold"

      if kill "$CACHE_PID" 2>/dev/null; then
        pass "static cache HTTP server stopped"
      fi
      wait "$CACHE_PID" 2>/dev/null || true

      check_fail
    '';
  };
}
