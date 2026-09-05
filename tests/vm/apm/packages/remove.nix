# Packages VM checks for remove workflows.
{
  testing,
  pkgs,
  fixtures,
  idempotentTool,
  removeLeftTool,
  removeRightTool,
  removeBasicTool,
  realRemoveDeps,
  setupNixEnv,
}: {
  # -------------------------------------------------------------------------
  # 7. remove-basic — Remove a real installed package
  # -------------------------------------------------------------------------
  remove-basic = testing.mkVMTest {
    name = "apm-remove-basic";
    rootfsDeps = realRemoveDeps;
    memory = 1024;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixEnv}

      echo "==> Test: real apm remove basic workflow"

      REMOVE_STORE="${removeBasicTool}"
      REMOVE_HASH=$(basename "$REMOVE_STORE" | cut -d- -f1)
      PROFILE="/var/lib/profiles/per-user/removebasicuser"
      REMOVE_BIN="$PROFILE/current/bin/remove-basic-tool"

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
        if nix-store --check-validity "$path" > "/tmp/remove-basic-valid-$label.out" 2>&1; then
          pass "$label valid in store"
        else
          cat "/tmp/remove-basic-valid-$label.out"
          fail "$label should be valid in store"
        fi
      }

      assert_store_missing() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/remove-basic-missing-$label.out" 2>&1; then
          cat "/tmp/remove-basic-missing-$label.out"
          fail "$label should be missing from store"
        else
          pass "$label missing from store"
        fi
      }

      delete_store_path() {
        path="$1"
        label="$2"
        if nix-store --delete --ignore-liveness "$path" > "/tmp/remove-basic-delete-$label.out" 2>&1; then
          pass "$label deleted before apm download"
        else
          cat "/tmp/remove-basic-delete-$label.out"
          fail "$label should be deletable before apm download"
          return 1
        fi
        assert_store_missing "$path" "$label"
      }

      generation_count() {
        find "$PROFILE" -maxdepth 1 -type d -name 'gen-*' | wc -l | tr -d ' '
      }

      wait_for_cache_server() {
        for _i in 1 2 3 4 5 6 7 8 9 10; do
          if curl -sf http://127.0.0.1:18095/nix-cache-info >/dev/null; then
            return 0
          fi
          sleep 1
        done
        return 1
      }

      mount -o remount,rw / || true
      assert_store_valid "$REMOVE_STORE" "remove-basic-tool"

      echo "==> Maintainer: publish remove-basic-tool and static cache"
      $APR create remove-basic-reg
      REG_DIR="$REG_STORAGE/remove-basic-reg"
      DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)
      $APR publish "$REMOVE_STORE" \
        --name remove-basic-tool \
        --version 1.0.0 \
        --description "Executable remove basic fixture" \
        --license MIT \
        --maintainer remove-basic@example.invalid \
        --registry remove-basic-reg \
        --no-commit
      assert_file_contains "$REG_DIR/packages/r/remove-basic-tool.toml" \
        "$REMOVE_HASH" "published remove-basic metadata records store hash"

      $APR cache generate \
        --registry remove-basic-reg \
        --output /tmp/remove-basic-cache \
        --cache-url http://127.0.0.1:18095 \
        --priority 55 \
        --no-commit
      assert_file_exists "/tmp/remove-basic-cache/$REMOVE_HASH.narinfo" \
        "static cache has remove-basic-tool narinfo"
      assert_file_contains "$REG_DIR/registry.toml" \
        "http://127.0.0.1:18095" "registry records remove-basic cache URL"

      git -C "$REG_DIR" add -A
      git -C "$REG_DIR" commit -m "release: remove-basic-tool 1.0.0"
      git init --bare --object-format=sha256 /tmp/remove-basic-origin.git
      git -C "$REG_DIR" remote add origin /tmp/remove-basic-origin.git
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
      PYTHONUNBUFFERED=1 python3 -m http.server 18095 --bind 127.0.0.1 \
        --directory /tmp/remove-basic-cache > /tmp/remove-basic-cache-http.log 2>&1 &
      CACHE_PID=$!
      if wait_for_cache_server; then
        pass "static cache HTTP server started"
      else
        cat /tmp/remove-basic-cache-http.log || true
        fail "static cache HTTP server started"
      fi

      echo "==> Consumer: install and remove remove-basic-tool"
      export HOME=/tmp/remove-basic-consumer
      export USER=removebasicuser
      mkdir -p "$HOME"
      $APM registry add --no-verify file:///tmp/remove-basic-origin.git \
        --name remove-basic-reg \
        --branch "$DEFAULT_BRANCH" > /tmp/remove-basic-registry-add.out 2>&1 || {
        cat /tmp/remove-basic-registry-add.out
        fail "apm registry add syncs remove-basic registry"
      }
      cat /tmp/remove-basic-registry-add.out

      if $APM remove remove-basic-tool --yes > /tmp/remove-basic-empty-remove.out 2>&1; then
        cat /tmp/remove-basic-empty-remove.out
        fail "remove should fail when no profile is installed"
      else
        cat /tmp/remove-basic-empty-remove.out
        pass "remove fails before any package is installed"
      fi
      assert_file_contains /tmp/remove-basic-empty-remove.out "nothing installed" \
        "empty remove reports no current generation"
      if [ ! -e "$PROFILE" ]; then
        pass "empty remove leaves profile directory absent"
      else
        find "$PROFILE" -maxdepth 2 -print
        fail "empty remove should not initialize profile state"
      fi

      if $APM autoremove --yes > /tmp/remove-basic-empty-autoremove.out 2>&1; then
        cat /tmp/remove-basic-empty-autoremove.out
        fail "autoremove should fail when no profile is installed"
      else
        cat /tmp/remove-basic-empty-autoremove.out
        pass "autoremove fails before any package is installed"
      fi
      assert_file_contains /tmp/remove-basic-empty-autoremove.out "nothing installed" \
        "empty autoremove reports no current generation"
      if [ ! -e "$PROFILE" ]; then
        pass "empty autoremove leaves profile directory absent"
      else
        find "$PROFILE" -maxdepth 2 -print
        fail "empty autoremove should not initialize profile state"
      fi

      if $APM remove remove-basic-tool --dry-run > /tmp/remove-basic-empty-dry-run.out 2>&1; then
        cat /tmp/remove-basic-empty-dry-run.out
        fail "remove dry-run should fail when no profile is installed"
      else
        cat /tmp/remove-basic-empty-dry-run.out
        pass "remove dry-run fails before any package is installed"
      fi
      assert_file_contains /tmp/remove-basic-empty-dry-run.out "nothing installed" \
        "empty remove dry-run reports no current generation"
      if [ ! -e "$PROFILE" ]; then
        pass "empty remove dry-run leaves profile directory absent"
      else
        find "$PROFILE" -maxdepth 2 -print
        fail "empty remove dry-run should not initialize profile state"
      fi

      if $APM autoremove --dry-run > /tmp/remove-basic-empty-autoremove-dry-run.out 2>&1; then
        cat /tmp/remove-basic-empty-autoremove-dry-run.out
        fail "autoremove dry-run should fail when no profile is installed"
      else
        cat /tmp/remove-basic-empty-autoremove-dry-run.out
        pass "autoremove dry-run fails before any package is installed"
      fi
      assert_file_contains /tmp/remove-basic-empty-autoremove-dry-run.out "nothing installed" \
        "empty autoremove dry-run reports no current generation"
      if [ ! -e "$PROFILE" ]; then
        pass "empty autoremove dry-run leaves profile directory absent"
      else
        find "$PROFILE" -maxdepth 2 -print
        fail "empty autoremove dry-run should not initialize profile state"
      fi

      delete_store_path "$REMOVE_STORE" "remove-basic-tool"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM install remove-basic-tool --registry remove-basic-reg --yes > /tmp/remove-basic-install.out 2>&1 || {
        cat /tmp/remove-basic-install.out
        fail "apm install remove-basic-tool succeeds"
      }
      cat /tmp/remove-basic-install.out
      assert_file_contains /tmp/remove-basic-install.out "Downloading 1 NAR" \
        "remove-basic install downloads package NAR"
      assert_file_contains /tmp/remove-basic-install.out "Installed 1 package" \
        "remove-basic install creates profile generation"
      "$REMOVE_BIN" > /tmp/remove-basic-run.out
      assert_file_contains /tmp/remove-basic-run.out "^remove-basic-tool 1.0.0$" \
        "remove-basic executable runs before removal"
      assert_file_contains "$PROFILE/meta/$REMOVE_HASH.json" '"explicit": true' \
        "remove-basic install writes explicit metadata"
      if [ "$(readlink "$PROFILE/current")" = "gen-1" ] && [ "$(generation_count)" = "1" ]; then
        pass "remove-basic install creates generation 1"
      else
        fail "remove-basic install should create gen-1"
      fi

      $APM remove remove-basic-tool --dry-run > /tmp/remove-basic-remove-dry-run.out 2>&1 || {
        cat /tmp/remove-basic-remove-dry-run.out
        fail "apm remove --dry-run remove-basic-tool succeeds"
      }
      cat /tmp/remove-basic-remove-dry-run.out
      assert_file_contains /tmp/remove-basic-remove-dry-run.out "will be REMOVED" \
        "remove dry-run prints removal plan"
      assert_file_contains /tmp/remove-basic-remove-dry-run.out "Dry run -- no changes made" \
        "remove dry-run reports no mutation"
      assert_file_not_contains /tmp/remove-basic-remove-dry-run.out "Creating new generation" \
        "remove dry-run does not create a generation"
      assert_file_exists "$PROFILE/meta/$REMOVE_HASH.json" \
        "remove dry-run preserves installed metadata"
      "$REMOVE_BIN" > /tmp/remove-basic-run-after-dry-run.out
      assert_file_contains /tmp/remove-basic-run-after-dry-run.out "^remove-basic-tool 1.0.0$" \
        "remove dry-run leaves executable active"
      if [ "$(readlink "$PROFILE/current")" = "gen-1" ] && [ "$(generation_count)" = "1" ]; then
        pass "remove dry-run keeps generation 1 active"
      else
        fail "remove dry-run should keep gen-1"
      fi

      $APM remove remove-basic-tool --yes > /tmp/remove-basic-remove.out 2>&1 || {
        cat /tmp/remove-basic-remove.out
        fail "apm remove remove-basic-tool succeeds"
      }
      cat /tmp/remove-basic-remove.out
      assert_file_contains /tmp/remove-basic-remove.out "will be REMOVED" \
        "remove prints removal plan"
      assert_file_contains /tmp/remove-basic-remove.out "Removed 1 package" \
        "remove reports package removal"
      assert_store_valid "$REMOVE_STORE" "remove-basic-tool remains in store"
      assert_file_not_exists "$PROFILE/meta/$REMOVE_HASH.json" \
        "remove deletes installed metadata"
      if [ ! -e "$REMOVE_BIN" ]; then
        pass "remove drops executable from active profile"
      else
        fail "remove should drop executable from active profile"
      fi
      if [ "$(readlink "$PROFILE/current")" = "gen-2" ] && [ "$(generation_count)" = "2" ]; then
        pass "remove creates generation 2"
      else
        fail "remove should create gen-2"
      fi

      $APM list --installed > /tmp/remove-basic-installed.out 2>&1 || {
        cat /tmp/remove-basic-installed.out
        fail "apm list --installed succeeds after remove"
      }
      assert_file_not_contains /tmp/remove-basic-installed.out "remove-basic-tool" \
        "removed package is absent from installed list"

      $APM remove remove-basic-tool --yes > /tmp/remove-basic-repeat.out 2>&1 && {
        cat /tmp/remove-basic-repeat.out
        fail "repeat remove should fail once package is absent"
      } || true
      cat /tmp/remove-basic-repeat.out
      assert_file_contains /tmp/remove-basic-repeat.out "not found" \
        "repeat remove reports package is absent"
      if [ "$(readlink "$PROFILE/current")" = "gen-2" ] && [ "$(generation_count)" = "2" ]; then
        pass "repeat failed remove does not create a generation"
      else
        fail "repeat failed remove should keep generation 2"
      fi

      if kill "$CACHE_PID" 2>/dev/null; then
        pass "static cache HTTP server stopped"
      fi
      wait "$CACHE_PID" 2>/dev/null || true

      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # 9. remove-autoremove — Remove with configured autoremove/gc
  # -------------------------------------------------------------------------
  remove-autoremove = testing.mkVMTest {
    name = "apm-remove-autoremove";
    rootfsDeps = realRemoveDeps;
    memory = 1024;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixEnv}

      echo "==> Test: real apm remove honors apm.conf autoremove settings"

      DEP_STORE="${idempotentTool}"
      LEFT_STORE="${removeLeftTool}"
      RIGHT_STORE="${removeRightTool}"
      DEP_HASH=$(basename "$DEP_STORE" | cut -d- -f1)
      LEFT_HASH=$(basename "$LEFT_STORE" | cut -d- -f1)
      RIGHT_HASH=$(basename "$RIGHT_STORE" | cut -d- -f1)
      PROFILE="/var/lib/profiles/per-user/removeuser"

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
        if nix-store --check-validity "$path" > "/tmp/remove-valid-$label.out" 2>&1; then
          pass "$label valid in store"
        else
          cat "/tmp/remove-valid-$label.out"
          fail "$label should be valid in store"
        fi
      }

      assert_store_missing() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/remove-missing-$label.out" 2>&1; then
          cat "/tmp/remove-missing-$label.out"
          fail "$label should be missing from store"
        else
          pass "$label missing from store"
        fi
      }

      delete_store_path() {
        path="$1"
        label="$2"
        if nix-store --delete --ignore-liveness "$path" > "/tmp/remove-delete-$label.out" 2>&1; then
          pass "$label deleted before apm download"
        else
          cat "/tmp/remove-delete-$label.out"
          fail "$label should be deletable before apm download"
          return 1
        fi
        assert_store_missing "$path" "$label"
      }

      generation_count() {
        find "$PROFILE" -maxdepth 1 -type d -name 'gen-*' | wc -l | tr -d ' '
      }

      wait_for_cache_server() {
        for _i in 1 2 3 4 5 6 7 8 9 10; do
          if curl -sf http://127.0.0.1:18087/nix-cache-info >/dev/null; then
            return 0
          fi
          sleep 1
        done
        return 1
      }

      mount -o remount,rw / || true
      assert_store_valid "$DEP_STORE" "idempkg dependency"
      assert_store_valid "$LEFT_STORE" "remove-left wrapper"
      assert_store_valid "$RIGHT_STORE" "remove-right wrapper"
      nix-store -q --references "$LEFT_STORE" > /tmp/remove-left-refs.out
      nix-store -q --references "$RIGHT_STORE" > /tmp/remove-right-refs.out
      assert_file_contains /tmp/remove-left-refs.out "$DEP_STORE" \
        "remove-left has a real Nix reference to idempkg"
      assert_file_contains /tmp/remove-right-refs.out "$DEP_STORE" \
        "remove-right has a real Nix reference to idempkg"

      echo "==> Maintainer: publish shared dependency and two wrappers"
      $APR create remove-reg
      REG_DIR="$REG_STORAGE/remove-reg"
      DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)
      $APR publish "$DEP_STORE" \
        --name idempkg \
        --version 1.0.0 \
        --description "Shared dependency for remove workflow" \
        --license MIT \
        --maintainer remove-workflow@example.invalid \
        --registry remove-reg \
        --no-commit
      $APR publish "$LEFT_STORE" \
        --name remove-left \
        --version 1.0.0 \
        --description "First explicit package sharing idempkg" \
        --license MIT \
        --maintainer remove-workflow@example.invalid \
        --registry remove-reg \
        --no-commit
      $APR publish "$RIGHT_STORE" \
        --name remove-right \
        --version 1.0.0 \
        --description "Second explicit package sharing idempkg" \
        --license MIT \
        --maintainer remove-workflow@example.invalid \
        --registry remove-reg \
        --no-commit
      assert_file_contains "$REG_DIR/store/$(printf %.2s "$LEFT_HASH")/$LEFT_HASH" \
        "$DEP_HASH" "published remove-left metadata records shared dependency"
      assert_file_contains "$REG_DIR/store/$(printf %.2s "$RIGHT_HASH")/$RIGHT_HASH" \
        "$DEP_HASH" "published remove-right metadata records shared dependency"
      assert_file_contains "$REG_DIR/store/$(printf %.2s "$LEFT_HASH")/$LEFT_HASH" \
        "$DEP_HASH" "published remove-left closure records shared dependency"
      assert_file_contains "$REG_DIR/store/$(printf %.2s "$RIGHT_HASH")/$RIGHT_HASH" \
        "$DEP_HASH" "published remove-right closure records shared dependency"

      $APR cache generate \
        --registry remove-reg \
        --output /tmp/remove-cache \
        --cache-url http://127.0.0.1:18087 \
        --priority 47 \
        --no-commit
      assert_file_exists "/tmp/remove-cache/$DEP_HASH.narinfo" \
        "static cache has shared dependency narinfo"
      assert_file_exists "/tmp/remove-cache/$LEFT_HASH.narinfo" \
        "static cache has remove-left narinfo"
      assert_file_exists "/tmp/remove-cache/$RIGHT_HASH.narinfo" \
        "static cache has remove-right narinfo"

      git -C "$REG_DIR" add -A
      git -C "$REG_DIR" commit -m "release: remove workflow packages"
      git init --bare --object-format=sha256 /tmp/remove-origin.git
      git -C "$REG_DIR" remote add origin /tmp/remove-origin.git
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
      PYTHONUNBUFFERED=1 python3 -m http.server 18087 --bind 127.0.0.1 \
        --directory /tmp/remove-cache > /tmp/remove-cache-http.log 2>&1 &
      CACHE_PID=$!
      if wait_for_cache_server; then
        pass "static cache HTTP server started"
      else
        cat /tmp/remove-cache-http.log || true
        fail "static cache HTTP server started"
      fi

      echo "==> Consumer: remove two explicit packages and their shared auto dep in one transaction"
      export HOME=/tmp/remove-multi-consumer
      export USER=removemultiuser
      PROFILE="/var/lib/profiles/per-user/removemultiuser"
      mkdir -p "$HOME/.config/apm"
      cat > "$HOME/.config/apm/apm.conf" << 'APMCONF'
      [settings]
      assume_yes = true
      auto_autoremove = true
      auto_gc = false
      APMCONF
      $APM registry add --no-verify file:///tmp/remove-origin.git \
        --name remove-reg \
        --branch "$DEFAULT_BRANCH" > /tmp/remove-multi-registry-add.out 2>&1 || {
        cat /tmp/remove-multi-registry-add.out
        fail "apm registry add syncs remove registry for multi-remove"
      }
      cat /tmp/remove-multi-registry-add.out

      delete_store_path "$LEFT_STORE" "remove-left"
      delete_store_path "$RIGHT_STORE" "remove-right"
      delete_store_path "$DEP_STORE" "idempkg"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM install remove-left remove-right --registry remove-reg > /tmp/remove-multi-install.out 2>&1 || {
        cat /tmp/remove-multi-install.out
        fail "apm install shared remove workflow succeeds for multi-remove"
      }
      cat /tmp/remove-multi-install.out
      assert_file_not_contains /tmp/remove-multi-install.out "Do you want to continue" \
        "configured assume_yes suppresses multi-remove install prompt"
      assert_file_contains /tmp/remove-multi-install.out "Downloading 3 NAR" \
        "multi-remove install downloads both roots and shared dependency"
      assert_file_contains /tmp/remove-multi-install.out "Installed 2 package" \
        "multi-remove install creates profile generation for both roots"
      "$PROFILE/current/bin/remove-left" > /tmp/remove-multi-left-run.out
      "$PROFILE/current/bin/remove-right" > /tmp/remove-multi-right-run.out
      "$PROFILE/current/bin/idempkg" > /tmp/remove-multi-dep-run.out
      assert_file_contains /tmp/remove-multi-left-run.out "^idempkg 1.0.0$" \
        "multi-remove left executable runs before removal"
      assert_file_contains /tmp/remove-multi-right-run.out "^idempkg 1.0.0$" \
        "multi-remove right executable runs before removal"
      assert_file_contains /tmp/remove-multi-dep-run.out "^idempkg 1.0.0$" \
        "multi-remove shared dependency executable is active"
      assert_file_contains "$PROFILE/meta/$LEFT_HASH.json" '"explicit": true' \
        "multi-remove left metadata is explicit"
      assert_file_contains "$PROFILE/meta/$RIGHT_HASH.json" '"explicit": true' \
        "multi-remove right metadata is explicit"
      assert_file_contains "$PROFILE/meta/$DEP_HASH.json" '"explicit": false' \
        "multi-remove shared dependency metadata is automatic"
      if [ "$(readlink "$PROFILE/current")" = "gen-1" ] && [ "$(generation_count)" = "1" ]; then
        pass "multi-remove install creates exactly generation 1"
      else
        fail "multi-remove install should create only gen-1"
      fi

      $APM remove remove-left remove-right > /tmp/remove-multi.out 2>&1 || {
        cat /tmp/remove-multi.out
        fail "apm remove removes both explicit packages in one transaction"
      }
      cat /tmp/remove-multi.out
      assert_file_not_contains /tmp/remove-multi.out "Do you want to continue" \
        "configured assume_yes suppresses multi-remove prompt"
      assert_file_contains /tmp/remove-multi.out "remove-left" \
        "multi-remove plan lists first explicit package"
      assert_file_contains /tmp/remove-multi.out "remove-right" \
        "multi-remove plan lists second explicit package"
      assert_file_contains /tmp/remove-multi.out "idempkg" \
        "multi-remove plan lists shared dependency as orphan"
      assert_file_contains /tmp/remove-multi.out "Removed 3 package" \
        "multi-remove removes both roots and their shared dependency"
      assert_file_not_contains /tmp/remove-multi.out "Running garbage collection" \
        "multi-remove honors configured auto_gc false"
      assert_file_not_exists "$PROFILE/meta/$LEFT_HASH.json" \
        "multi-remove deletes first explicit package metadata"
      assert_file_not_exists "$PROFILE/meta/$RIGHT_HASH.json" \
        "multi-remove deletes second explicit package metadata"
      assert_file_not_exists "$PROFILE/meta/$DEP_HASH.json" \
        "multi-remove deletes shared dependency metadata"
      if [ -e "$PROFILE/current/bin/remove-left" ] || [ -e "$PROFILE/current/bin/remove-right" ] || [ -e "$PROFILE/current/bin/idempkg" ]; then
        fail "multi-remove should drop all removed executables from active profile"
      else
        pass "multi-remove drops all removed executables from active profile"
      fi
      if [ "$(readlink "$PROFILE/current")" = "gen-2" ] && [ "$(generation_count)" = "2" ]; then
        pass "multi-remove creates generation 2"
      else
        fail "multi-remove should create gen-2"
      fi
      assert_store_valid "$DEP_STORE" "idempkg remains in store after multi-remove without GC"
      assert_store_valid "$LEFT_STORE" "remove-left remains in store after multi-remove without GC"
      assert_store_valid "$RIGHT_STORE" "remove-right remains in store after multi-remove without GC"
      rm -rf "$PROFILE"

      echo "==> Consumer: install two explicit packages with one shared auto dep"
      export HOME=/tmp/remove-consumer
      export USER=removeuser
      PROFILE="/var/lib/profiles/per-user/removeuser"
      mkdir -p "$HOME/.config/apm"
      cat > "$HOME/.config/apm/apm.conf" << 'APMCONF'
      [settings]
      assume_yes = true
      auto_autoremove = true
      auto_gc = true
      APMCONF
      $APM registry add --no-verify file:///tmp/remove-origin.git \
        --name remove-reg \
        --branch "$DEFAULT_BRANCH" > /tmp/remove-registry-add.out 2>&1 || {
        cat /tmp/remove-registry-add.out
        fail "apm registry add syncs remove registry"
      }
      cat /tmp/remove-registry-add.out

      delete_store_path "$LEFT_STORE" "remove-left"
      delete_store_path "$RIGHT_STORE" "remove-right"
      delete_store_path "$DEP_STORE" "idempkg"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM install remove-left remove-right --registry remove-reg > /tmp/remove-install.out 2>&1 || {
        cat /tmp/remove-install.out
        fail "apm install shared remove workflow succeeds with configured assume_yes"
      }
      cat /tmp/remove-install.out
      assert_file_not_contains /tmp/remove-install.out "Do you want to continue" \
        "configured assume_yes suppresses install prompt"
      assert_file_contains /tmp/remove-install.out "Downloading" \
        "install downloads shared remove workflow closure"
      assert_file_contains /tmp/remove-install.out "Installed 2 package" \
        "install creates profile generation for both explicit packages"
      assert_store_valid "$DEP_STORE" "idempkg"
      assert_store_valid "$LEFT_STORE" "remove-left"
      assert_store_valid "$RIGHT_STORE" "remove-right"
      "$PROFILE/current/bin/remove-left" > /tmp/remove-left-run-1.out
      "$PROFILE/current/bin/remove-right" > /tmp/remove-right-run-1.out
      "$PROFILE/current/bin/idempkg" > /tmp/remove-dep-run-1.out
      assert_file_contains /tmp/remove-left-run-1.out "^idempkg 1.0.0$" \
        "remove-left executable runs before removal"
      assert_file_contains /tmp/remove-right-run-1.out "^idempkg 1.0.0$" \
        "remove-right executable runs before removal"
      assert_file_contains /tmp/remove-dep-run-1.out "^idempkg 1.0.0$" \
        "shared dependency executable is active before removal"
      assert_file_contains "$PROFILE/meta/$LEFT_HASH.json" '"explicit": true' \
        "remove-left metadata is explicit"
      assert_file_contains "$PROFILE/meta/$RIGHT_HASH.json" '"explicit": true' \
        "remove-right metadata is explicit"
      assert_file_contains "$PROFILE/meta/$DEP_HASH.json" '"explicit": false' \
        "idempkg metadata is auto-installed"

      if [ "$(readlink "$PROFILE/current")" = "gen-1" ] && [ "$(generation_count)" = "1" ]; then
        pass "initial install creates exactly generation 1"
      else
        fail "initial install should create only gen-1"
      fi

      echo "==> Consumer: remove one explicit package with configured autoremove"
      $APM remove remove-left > /tmp/remove-left.out 2>&1 || {
        cat /tmp/remove-left.out
        fail "apm remove remove-left succeeds with configured autoremove"
      }
      cat /tmp/remove-left.out
      assert_file_not_contains /tmp/remove-left.out "Do you want to continue" \
        "configured assume_yes suppresses remove prompt"
      assert_file_contains /tmp/remove-left.out "Removed 1 package" \
        "configured autoremove removes only requested explicit package"
      assert_file_not_contains /tmp/remove-left.out "idempkg" \
        "shared dependency is not listed as orphan while remove-right remains"
      assert_file_not_contains /tmp/remove-left.out "Running garbage collection" \
        "configured auto_gc does not run when autoremove finds no orphan"
      assert_file_not_exists "$PROFILE/meta/$LEFT_HASH.json" \
        "remove-left metadata removed"
      assert_file_exists "$PROFILE/meta/$RIGHT_HASH.json" \
        "remove-right metadata remains"
      assert_file_exists "$PROFILE/meta/$DEP_HASH.json" \
        "shared dependency metadata remains after remove-left autoremove"
      if [ -x "$PROFILE/current/bin/remove-left" ]; then
        fail "remove-left executable should be absent after removal"
      else
        pass "remove-left executable absent after removal"
      fi
      "$PROFILE/current/bin/remove-right" > /tmp/remove-right-run-2.out
      "$PROFILE/current/bin/idempkg" > /tmp/remove-dep-run-2.out
      assert_file_contains /tmp/remove-right-run-2.out "^idempkg 1.0.0$" \
        "remaining explicit package still runs after remove-left autoremove"
      assert_file_contains /tmp/remove-dep-run-2.out "^idempkg 1.0.0$" \
        "shared dependency remains active after remove-left autoremove"

      if [ "$(readlink "$PROFILE/current")" = "gen-2" ] && [ "$(generation_count)" = "2" ]; then
        pass "remove-left creates generation 2"
      else
        fail "remove-left should create gen-2"
      fi

      echo "==> Consumer: remove final explicit package without automatic autoremove"
      export AOS_ROOT=/tmp/remove-auto-gc-root
      export AOS_NIX_STORE_DIR=/tmp/remove-auto-gc-store
      export AOS_NIX_STATE_DIR=/tmp/remove-auto-gc-root/var/nix
      mkdir -p "$AOS_NIX_STORE_DIR" "$AOS_NIX_STATE_DIR/db" "$AOS_NIX_STATE_DIR/gcroots"
      NIX_STORE_DIR="$AOS_NIX_STORE_DIR" NIX_STATE_DIR="$AOS_NIX_STATE_DIR" \
        nix-store --init || true
      cat > "$HOME/.config/apm/apm.conf" << 'APMCONF'
      [settings]
      assume_yes = true
      auto_autoremove = false
      auto_gc = true
      APMCONF
      $APM remove remove-right > /tmp/remove-right.out 2>&1 || {
        cat /tmp/remove-right.out
        fail "apm remove remove-right succeeds without configured autoremove"
      }
      cat /tmp/remove-right.out
      assert_file_not_contains /tmp/remove-right.out "Do you want to continue" \
        "configured assume_yes suppresses final remove prompt"
      assert_file_contains /tmp/remove-right.out "Removed 1 package" \
        "plain remove deletes only requested explicit package"
      assert_file_not_contains /tmp/remove-right.out "idempkg" \
        "plain remove leaves orphaned shared dependency for standalone autoremove"
      assert_file_not_contains /tmp/remove-right.out "Running garbage collection" \
        "configured auto_gc does not run when autoremove is disabled"
      assert_file_not_exists "$PROFILE/meta/$RIGHT_HASH.json" \
        "remove-right metadata removed"
      assert_file_exists "$PROFILE/meta/$DEP_HASH.json" \
        "shared dependency metadata remains until standalone autoremove"
      if [ -x "$PROFILE/current/bin/remove-right" ]; then
        fail "remove-right executable should be absent after removal"
      else
        pass "remove-right executable absent after removal"
      fi
      "$PROFILE/current/bin/idempkg" > /tmp/remove-dep-run-orphan.out
      assert_file_contains /tmp/remove-dep-run-orphan.out "^idempkg 1.0.0$" \
        "orphaned shared dependency remains active before standalone autoremove"

      if [ "$(readlink "$PROFILE/current")" = "gen-3" ] && [ "$(generation_count)" = "3" ]; then
        pass "plain remove creates generation 3 with orphaned dependency"
      else
        fail "plain remove should end at gen-3"
      fi

      echo "==> Consumer: dry-run then execute standalone autoremove with configured GC"
      $APM autoremove --dry-run > /tmp/remove-autoremove-dry-run.out 2>&1 || {
        cat /tmp/remove-autoremove-dry-run.out
        fail "apm autoremove --dry-run reports orphaned dependency"
      }
      cat /tmp/remove-autoremove-dry-run.out
      assert_file_contains /tmp/remove-autoremove-dry-run.out "idempkg" \
        "standalone autoremove dry-run lists orphaned dependency"
      assert_file_contains /tmp/remove-autoremove-dry-run.out "Dry run -- no changes made" \
        "standalone autoremove dry-run reports no mutation"
      assert_file_exists "$PROFILE/meta/$DEP_HASH.json" \
        "standalone autoremove dry-run preserves dependency metadata"
      "$PROFILE/current/bin/idempkg" > /tmp/remove-dep-run-after-dry-run.out
      assert_file_contains /tmp/remove-dep-run-after-dry-run.out "^idempkg 1.0.0$" \
        "standalone autoremove dry-run preserves executable"

      $APM autoremove > /tmp/remove-autoremove.out 2>&1 || {
        cat /tmp/remove-autoremove.out
        fail "apm autoremove removes orphaned dependency"
      }
      cat /tmp/remove-autoremove.out
      assert_file_not_contains /tmp/remove-autoremove.out "Do you want to continue" \
        "configured assume_yes suppresses standalone autoremove prompt"
      assert_file_contains /tmp/remove-autoremove.out "Removed 1 orphaned package" \
        "standalone autoremove removes orphaned shared dependency"
      assert_file_contains /tmp/remove-autoremove.out "idempkg" \
        "standalone autoremove lists orphaned shared dependency"
      assert_file_contains /tmp/remove-autoremove.out "Running garbage collection" \
        "configured auto_gc runs after standalone autoremove removes an orphan"
      assert_file_contains /tmp/remove-autoremove.out "Garbage collection complete" \
        "configured auto_gc completes after standalone autoremove"
      assert_file_not_exists "$PROFILE/meta/$DEP_HASH.json" \
        "shared dependency metadata removed by standalone autoremove"
      if [ -e "$PROFILE/current/bin/idempkg" ]; then
        fail "shared dependency executable should be absent after standalone autoremove"
      else
        pass "shared dependency executable absent after standalone autoremove"
      fi

      if [ "$(readlink "$PROFILE/current")" = "gen-4" ] && [ "$(generation_count)" = "4" ]; then
        pass "standalone autoremove creates generation 4"
      else
        fail "standalone autoremove should end at gen-4"
      fi

      if kill "$CACHE_PID" 2>/dev/null; then
        pass "static cache HTTP server stopped"
      fi
      wait "$CACHE_PID" 2>/dev/null || true

      check_fail
    '';
  };
}
