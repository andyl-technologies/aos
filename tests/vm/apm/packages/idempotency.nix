# Packages VM checks for idempotency workflows.
{
  testing,
  pkgs,
  fixtures,
  idempotentTool,
  idempotentWrapper,
  realIdempotentDeps,
  setupNixEnv,
}: {
  # -------------------------------------------------------------------------
  # 4. install-idempotent — Second install is a no-op
  # -------------------------------------------------------------------------
  install-idempotent = testing.mkVMTest {
    name = "apm-install-idempotent";
    rootfsDeps = realIdempotentDeps;
    memory = 1024;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixEnv}

      echo "==> Test: real apm install idempotency"

      IDEMP_STORE="${idempotentTool}"
      WRAPPER_STORE="${idempotentWrapper}"
      IDEMP_HASH=$(basename "$IDEMP_STORE" | cut -d- -f1)
      WRAPPER_HASH=$(basename "$WRAPPER_STORE" | cut -d- -f1)
      PROFILE="/var/lib/profiles/per-user/idempuser"
      PROFILE_IDEMP_BIN="$PROFILE/current/bin/idempkg"
      PROFILE_WRAPPER_BIN="$PROFILE/current/bin/idemp-wrapper"

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

      generation_count() {
        find "$PROFILE" -maxdepth 1 -type d -name 'gen-*' | wc -l | tr -d ' '
      }

      cache_nar_count() {
        find "$HOME/.cache/apm" -type f -name '*.nar.zst' 2>/dev/null | wc -l | tr -d ' '
      }

      wait_for_cache_server() {
        for _i in 1 2 3 4 5 6 7 8 9 10; do
          if curl -sf http://127.0.0.1:18086/nix-cache-info >/dev/null; then
            return 0
          fi
          sleep 1
        done
        return 1
      }

      mount -o remount,rw / || true
      assert_store_valid "$IDEMP_STORE" "idempkg"
      assert_store_valid "$WRAPPER_STORE" "idemp-wrapper"
      nix-store -q --references "$WRAPPER_STORE" > /tmp/idemp-wrapper-refs.out
      assert_file_contains /tmp/idemp-wrapper-refs.out "$IDEMP_STORE" \
        "idemp-wrapper has a real Nix reference to idempkg"

      echo "==> Maintainer: publish idempkg, wrapper, and static cache"
      $APR create idemp-reg
      REG_DIR="$REG_STORAGE/idemp-reg"
      DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)
      $APR publish "$IDEMP_STORE" \
        --name idempkg \
        --version 1.0.0 \
        --description "Executable idempotent install fixture" \
        --license MIT \
        --maintainer idempotent-workflow@example.invalid \
        --registry idemp-reg \
        --no-commit
      assert_file_contains "$REG_DIR/packages/i/idempkg.toml" \
        "$IDEMP_HASH" "published idempkg metadata records store hash"
      $APR publish "$WRAPPER_STORE" \
        --name idemp-wrapper \
        --version 1.0.0 \
        --description "Executable idempotent wrapper fixture" \
        --license MIT \
        --maintainer idempotent-workflow@example.invalid \
        --registry idemp-reg \
        --no-commit
      assert_file_contains "$REG_DIR/store/$(printf %.2s "$WRAPPER_HASH")/$WRAPPER_HASH" \
        "$IDEMP_HASH" "published wrapper metadata records idempkg reference"
      assert_file_contains "$REG_DIR/store/$(printf %.2s "$WRAPPER_HASH")/$WRAPPER_HASH" \
        "$IDEMP_HASH" "published wrapper closure records idempkg"

      $APR cache generate \
        --registry idemp-reg \
        --output /tmp/idemp-cache \
        --cache-url http://127.0.0.1:18086 \
        --priority 46 \
        --no-commit
      assert_file_exists "/tmp/idemp-cache/$IDEMP_HASH.narinfo" \
        "static cache has idempkg narinfo"
      assert_file_exists "/tmp/idemp-cache/$WRAPPER_HASH.narinfo" \
        "static cache has idemp-wrapper narinfo"
      assert_file_contains "$REG_DIR/registry.toml" \
        "http://127.0.0.1:18086" "registry records idemp cache URL"

      git -C "$REG_DIR" add -A
      git -C "$REG_DIR" commit -m "release: idempkg 1.0.0"
      git init --bare --object-format=sha256 /tmp/idemp-origin.git
      git -C "$REG_DIR" remote add origin /tmp/idemp-origin.git
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
      PYTHONUNBUFFERED=1 python3 -m http.server 18086 --bind 127.0.0.1 \
        --directory /tmp/idemp-cache > /tmp/idemp-cache-http.log 2>&1 &
      CACHE_PID=$!
      if wait_for_cache_server; then
        pass "static cache HTTP server started"
      else
        cat /tmp/idemp-cache-http.log || true
        fail "static cache HTTP server started"
      fi

      echo "==> Consumer: add registry and install idemp-wrapper without automatic deps"
      export HOME=/tmp/idemp-consumer
      export USER=idempuser
      mkdir -p "$HOME"
      $APM registry add --no-verify file:///tmp/idemp-origin.git \
        --name idemp-reg \
        --branch "$DEFAULT_BRANCH" > /tmp/idemp-registry-add.out 2>&1 || {
        cat /tmp/idemp-registry-add.out
        fail "apm registry add syncs idemp registry"
      }
      cat /tmp/idemp-registry-add.out

      delete_store_path "$WRAPPER_STORE" "idemp-wrapper"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM install idemp-wrapper \
        --registry idemp-reg \
        --no-deps \
        --yes > /tmp/idemp-no-deps.out 2>&1 || {
        cat /tmp/idemp-no-deps.out
        fail "apm install --no-deps idemp-wrapper succeeds"
      }
      cat /tmp/idemp-no-deps.out
      assert_file_contains /tmp/idemp-no-deps.out "Downloading 1 NAR" \
        "no-deps downloads only requested wrapper"
      assert_file_not_contains /tmp/idemp-no-deps.out "Additional dependencies" \
        "no-deps does not plan automatic dependencies"
      assert_file_contains /tmp/idemp-no-deps.out "Installed 1 package" \
        "no-deps creates profile generation"
      if [ "$(cache_nar_count)" = "1" ]; then
        pass "no-deps leaves one requested NAR in cache"
      else
        fail "no-deps should cache exactly one requested NAR"
      fi
      assert_store_valid "$IDEMP_STORE" "idempkg"
      assert_store_valid "$WRAPPER_STORE" "idemp-wrapper"
      "$PROFILE_WRAPPER_BIN" > /tmp/idemp-wrapper-nodeps-run.out
      assert_file_contains /tmp/idemp-wrapper-nodeps-run.out "^idempkg 1.0.0$" \
        "no-deps wrapper executable runs through its existing store reference"
      assert_file_contains "$PROFILE/meta/$WRAPPER_HASH.json" '"explicit": true' \
        "wrapper metadata is explicit after no-deps install"
      if [ ! -e "$PROFILE/meta/$IDEMP_HASH.json" ]; then
        pass "no-deps does not write dependency metadata"
      else
        fail "no-deps should not write dependency metadata"
      fi
      if [ ! -e "$PROFILE_IDEMP_BIN" ]; then
        pass "no-deps does not merge dependency executable into profile"
      else
        fail "no-deps should not expose dependency executable in profile"
      fi

      NODEPS_CURRENT=$(readlink "$PROFILE/current")
      NODEPS_COUNT=$(generation_count)
      if [ "$NODEPS_CURRENT" = "gen-1" ] && [ "$NODEPS_COUNT" = "1" ]; then
        pass "no-deps install creates exactly generation 1"
      else
        fail "no-deps install should create only gen-1 (current=$NODEPS_CURRENT count=$NODEPS_COUNT)"
      fi

      echo "==> Consumer: normal install after no-deps records automatic dependency"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM install idemp-wrapper --registry idemp-reg --yes > /tmp/idemp-install-1.out 2>&1 || {
        cat /tmp/idemp-install-1.out
        fail "normal apm install idemp-wrapper after no-deps succeeds"
      }
      cat /tmp/idemp-install-1.out
      assert_file_contains /tmp/idemp-install-1.out "Additional dependencies" \
        "normal install after no-deps plans dependency closure"
      assert_file_not_contains /tmp/idemp-install-1.out "Downloading" \
        "normal install after no-deps reuses valid store paths"
      assert_file_contains /tmp/idemp-install-1.out "Installed 1 package" \
        "normal install after no-deps creates profile generation"
      "$PROFILE_WRAPPER_BIN" > /tmp/idemp-wrapper-run-1.out
      assert_file_contains /tmp/idemp-wrapper-run-1.out "^idempkg 1.0.0$" \
        "wrapper executable runs after normal install"
      "$PROFILE_IDEMP_BIN" > /tmp/idemp-run-1.out
      assert_file_contains /tmp/idemp-run-1.out "^idempkg 1.0.0$" \
        "dependency executable is active after normal install"
      assert_file_contains "$PROFILE/meta/$WRAPPER_HASH.json" '"explicit": true' \
        "wrapper metadata stays explicit after normal install"
      assert_file_contains "$PROFILE/meta/$IDEMP_HASH.json" '"explicit": false' \
        "idempkg metadata starts as auto-installed dependency"

      FIRST_CURRENT=$(readlink "$PROFILE/current")
      FIRST_COUNT=$(generation_count)
      if [ "$FIRST_CURRENT" = "gen-2" ] && [ "$FIRST_COUNT" = "2" ]; then
        pass "normal install after no-deps creates generation 2"
      else
        fail "normal install after no-deps should create gen-2 (current=$FIRST_CURRENT count=$FIRST_COUNT)"
      fi

      echo "==> Consumer: explicit install promotes dependency without download"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM install idempkg --registry idemp-reg --yes > /tmp/idemp-promote.out 2>&1 || {
        cat /tmp/idemp-promote.out
        fail "explicit apm install idempkg succeeds"
      }
      cat /tmp/idemp-promote.out
      assert_file_not_contains /tmp/idemp-promote.out "Downloading" \
        "explicit dependency install reuses existing store path"
      assert_file_contains /tmp/idemp-promote.out "Installed 1 package" \
        "explicit dependency install creates promoted generation"
      "$PROFILE_IDEMP_BIN" > /tmp/idemp-run-2.out
      assert_file_contains /tmp/idemp-run-2.out "^idempkg 1.0.0$" \
        "profile executable runs after explicit install"
      assert_file_contains "$PROFILE/meta/$IDEMP_HASH.json" '"explicit": true' \
        "idempkg metadata is promoted to explicit"

      PROMOTED_CURRENT=$(readlink "$PROFILE/current")
      PROMOTED_COUNT=$(generation_count)
      if [ "$PROMOTED_CURRENT" = "gen-3" ] && [ "$PROMOTED_COUNT" = "3" ]; then
        pass "explicit dependency install creates generation 3"
      else
        fail "explicit dependency install should create gen-3 (current=$PROMOTED_CURRENT count=$PROMOTED_COUNT)"
      fi

      echo "==> Consumer: repeat explicit install is a no-op"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM install idempkg --registry idemp-reg --yes > /tmp/idemp-install-2.out 2>&1 || {
        cat /tmp/idemp-install-2.out
        fail "repeat apm install idempkg succeeds"
      }
      cat /tmp/idemp-install-2.out
      assert_file_contains /tmp/idemp-install-2.out "already installed\\|already in profile\\|No changes" \
        "repeat install reports idempotent no-op"
      assert_file_not_contains /tmp/idemp-install-2.out "Downloading" \
        "repeat install does not download idempkg"
      "$PROFILE_IDEMP_BIN" > /tmp/idemp-run-3.out
      assert_file_contains /tmp/idemp-run-3.out "^idempkg 1.0.0$" \
        "profile executable still runs after repeat install"

      SECOND_CURRENT=$(readlink "$PROFILE/current")
      SECOND_COUNT=$(generation_count)
      if [ "$SECOND_CURRENT" = "$PROMOTED_CURRENT" ] && [ "$SECOND_COUNT" = "$PROMOTED_COUNT" ]; then
        pass "repeat install does not create a new generation"
      else
        fail "repeat install should keep current=$PROMOTED_CURRENT count=$PROMOTED_COUNT (got current=$SECOND_CURRENT count=$SECOND_COUNT)"
      fi

      echo "==> Consumer: normal install repairs invalid installed store path"
      find "$PROFILE" -path "*/usr/$WRAPPER_HASH" -type l -exec rm -f {} \;
      delete_store_path "$WRAPPER_STORE" "idemp-wrapper-invalid-installed"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM install idemp-wrapper --registry idemp-reg --yes > /tmp/idemp-repair.out 2>&1 || {
        cat /tmp/idemp-repair.out
        fail "normal apm install repairs invalid installed store path"
      }
      cat /tmp/idemp-repair.out
      assert_file_contains /tmp/idemp-repair.out "Downloading 1 NAR" \
        "repair install downloads missing installed store path"
      assert_file_contains /tmp/idemp-repair.out "Importing packages" \
        "repair install imports missing installed store path"
      assert_store_valid "$WRAPPER_STORE" "idemp-wrapper repaired"
      "$PROFILE_WRAPPER_BIN" > /tmp/idemp-run-repaired.out
      assert_file_contains /tmp/idemp-run-repaired.out "^idempkg 1.0.0$" \
        "profile executable runs after repair install"
      assert_file_contains "$PROFILE/meta/$IDEMP_HASH.json" '"explicit": true' \
        "repair install preserves explicit dependency metadata"

      REPAIR_CURRENT=$(readlink "$PROFILE/current")
      REPAIR_COUNT=$(generation_count)
      if [ "$REPAIR_CURRENT" = "gen-4" ] && [ "$REPAIR_COUNT" = "4" ]; then
        pass "repair install creates generation 4"
      else
        fail "repair install should create gen-4 (current=$REPAIR_CURRENT count=$REPAIR_COUNT)"
      fi

      echo "==> Consumer: autoremove wrapper after repair keeps explicitly installed dependency"
      $APM remove idemp-wrapper --autoremove --yes \
        > /tmp/idemp-remove-wrapper-after-promotion.out 2>&1 || {
        cat /tmp/idemp-remove-wrapper-after-promotion.out
        fail "apm remove --autoremove idemp-wrapper succeeds after dependency promotion"
      }
      cat /tmp/idemp-remove-wrapper-after-promotion.out
      assert_file_contains /tmp/idemp-remove-wrapper-after-promotion.out "idemp-wrapper" \
        "remove names repaired wrapper"
      assert_file_not_contains /tmp/idemp-remove-wrapper-after-promotion.out "idempkg" \
        "autoremove does not remove explicitly installed dependency"
      if [ -e "$PROFILE_WRAPPER_BIN" ]; then
        fail "removed wrapper executable should not remain active"
      else
        pass "removed wrapper executable is absent"
      fi
      "$PROFILE_IDEMP_BIN" > /tmp/idemp-run-after-wrapper-remove.out
      assert_file_contains /tmp/idemp-run-after-wrapper-remove.out "^idempkg 1.0.0$" \
        "explicit dependency remains active after wrapper autoremove"
      assert_file_contains "$PROFILE/meta/$IDEMP_HASH.json" '"explicit": true' \
        "explicit dependency metadata remains after wrapper autoremove"

      echo "==> Consumer: no-deps fails without existing dependency store path"
      rm -rf "$PROFILE"
      delete_store_path "$WRAPPER_STORE" "idemp-wrapper-missing-nodeps"
      delete_store_path "$IDEMP_STORE" "idempkg-missing-nodeps"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      if $APM install idemp-wrapper --registry idemp-reg --no-deps --yes \
        > /tmp/idemp-no-deps-missing.out 2>&1; then
        cat /tmp/idemp-no-deps-missing.out
        fail "apm install --no-deps should fail when dependency store path is absent"
      else
        cat /tmp/idemp-no-deps-missing.out
        pass "apm install --no-deps fails when dependency store path is absent"
      fi
      assert_file_contains /tmp/idemp-no-deps-missing.out \
        "no-deps requested but dependency store path" \
        "failed no-deps install reports missing skipped dependency"
      assert_file_not_contains /tmp/idemp-no-deps-missing.out "Downloading" \
        "failed no-deps install does not download before dependency preflight"
      if [ "$(cache_nar_count)" = "0" ]; then
        pass "failed no-deps install leaves NAR cache empty"
      else
        fail "failed no-deps install should not cache requested wrapper"
      fi
      assert_store_missing "$WRAPPER_STORE" "idemp-wrapper"
      assert_store_missing "$IDEMP_STORE" "idempkg"
      if [ "$(generation_count)" = "0" ] && [ ! -e "$PROFILE/current" ]; then
        pass "failed no-deps install creates no profile generation"
      else
        fail "failed no-deps install should not create a profile generation"
      fi
      $APM list --installed > /tmp/idemp-installed-after-nodeps-fail.out 2>&1 || {
        cat /tmp/idemp-installed-after-nodeps-fail.out
        fail "apm list --installed succeeds after failed no-deps install"
      }
      assert_file_not_contains /tmp/idemp-installed-after-nodeps-fail.out "idemp-wrapper" \
        "failed no-deps install does not record wrapper metadata"
      assert_file_not_contains /tmp/idemp-installed-after-nodeps-fail.out "idempkg" \
        "failed no-deps install does not record dependency metadata"

      if kill "$CACHE_PID" 2>/dev/null; then
        pass "static cache HTTP server stopped"
      fi
      wait "$CACHE_PID" 2>/dev/null || true

      check_fail
    '';
  };
}
