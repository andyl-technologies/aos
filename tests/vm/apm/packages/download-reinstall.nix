# Packages VM checks for download reinstall workflows.
{
  testing,
  pkgs,
  fixtures,
  idempotentTool,
  downloadOnlyWrapper,
  reinstallTool,
  reinstallPeerTool,
  realDownloadOnlyDeps,
  realReinstallDeps,
  setupNixEnv,
}: {
  # -------------------------------------------------------------------------
  # 5. download-only-package — Download without importing or activating
  # -------------------------------------------------------------------------
  download-only-package = testing.mkVMTest {
    name = "apm-download-only-package";
    rootfsDeps = realDownloadOnlyDeps;
    memory = 1024;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixEnv}

      echo "==> Test: real apm install --download-only downloads without activation"

      DEP_STORE="${idempotentTool}"
      WRAPPER_STORE="${downloadOnlyWrapper}"
      DEP_HASH=$(basename "$DEP_STORE" | cut -d- -f1)
      WRAPPER_HASH=$(basename "$WRAPPER_STORE" | cut -d- -f1)
      PROFILE="/var/lib/profiles/per-user/downloaduser"

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
        if nix-store --check-validity "$path" > "/tmp/download-valid-$label.out" 2>&1; then
          pass "$label valid in store"
        else
          cat "/tmp/download-valid-$label.out"
          fail "$label should be valid in store"
        fi
      }

      assert_store_missing() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/download-missing-$label.out" 2>&1; then
          cat "/tmp/download-missing-$label.out"
          fail "$label should be missing from store"
        else
          pass "$label missing from store"
        fi
      }

      delete_store_path() {
        path="$1"
        label="$2"
        if nix-store --delete --ignore-liveness "$path" > "/tmp/download-delete-$label.out" 2>&1; then
          pass "$label deleted before apm download"
        else
          cat "/tmp/download-delete-$label.out"
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

      cache_nar_http_get_count() {
        grep -E 'GET /nar/.*\.nar\.zst HTTP/' /tmp/download-cache-http.log 2>/dev/null | wc -l | tr -d ' '
      }

      wait_for_cache_server() {
        for _i in 1 2 3 4 5 6 7 8 9 10; do
          if curl -sf http://127.0.0.1:18089/nix-cache-info >/dev/null; then
            return 0
          fi
          sleep 1
        done
        return 1
      }

      mount -o remount,rw / || true
      assert_store_valid "$DEP_STORE" "download-only dependency"
      assert_store_valid "$WRAPPER_STORE" "download-only wrapper"
      nix-store -q --references "$WRAPPER_STORE" > /tmp/download-wrapper-refs.out
      assert_file_contains /tmp/download-wrapper-refs.out "$DEP_STORE" \
        "download-only wrapper has a real Nix reference to dependency"

      echo "==> Maintainer: publish download-only wrapper and static cache"
      $APR create download-reg
      REG_DIR="$REG_STORAGE/download-reg"
      DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)
      $APR publish "$DEP_STORE" \
        --name idempkg \
        --version 1.0.0 \
        --description "Shared dependency for download-only workflow" \
        --license MIT \
        --maintainer download-workflow@example.invalid \
        --registry download-reg \
        --no-commit
      $APR publish "$WRAPPER_STORE" \
        --name download-only-wrapper \
        --version 1.0.0 \
        --description "Wrapper for download-only workflow" \
        --license MIT \
        --maintainer download-workflow@example.invalid \
        --registry download-reg \
        --no-commit
      assert_file_contains "$REG_DIR/store/$(printf %.2s "$WRAPPER_HASH")/$WRAPPER_HASH" \
        "$DEP_HASH" "published wrapper metadata records dependency"
      assert_file_contains "$REG_DIR/store/$(printf %.2s "$WRAPPER_HASH")/$WRAPPER_HASH" \
        "$DEP_HASH" "published wrapper closure records dependency"

      $APR cache generate \
        --registry download-reg \
        --output /tmp/download-cache \
        --cache-url http://127.0.0.1:18089 \
        --priority 49 \
        --no-commit
      assert_file_exists "/tmp/download-cache/$DEP_HASH.narinfo" \
        "static cache has dependency narinfo"
      assert_file_exists "/tmp/download-cache/$WRAPPER_HASH.narinfo" \
        "static cache has wrapper narinfo"

      git -C "$REG_DIR" add -A
      git -C "$REG_DIR" commit -m "release: download-only workflow package"
      git init --bare --object-format=sha256 /tmp/download-origin.git
      git -C "$REG_DIR" remote add origin /tmp/download-origin.git
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
      PYTHONUNBUFFERED=1 python3 -m http.server 18089 --bind 127.0.0.1 \
        --directory /tmp/download-cache > /tmp/download-cache-http.log 2>&1 &
      CACHE_PID=$!
      if wait_for_cache_server; then
        pass "static cache HTTP server started"
      else
        cat /tmp/download-cache-http.log || true
        fail "static cache HTTP server started"
      fi

      echo "==> Consumer: download closure without importing or activating"
      export HOME=/tmp/download-consumer
      export USER=downloaduser
      mkdir -p "$HOME"
      $APM registry add --no-verify file:///tmp/download-origin.git \
        --name download-reg \
        --branch "$DEFAULT_BRANCH" > /tmp/download-registry-add.out 2>&1 || {
        cat /tmp/download-registry-add.out
        fail "apm registry add syncs download registry"
      }
      cat /tmp/download-registry-add.out

      delete_store_path "$WRAPPER_STORE" "download-only-wrapper"
      delete_store_path "$DEP_STORE" "idempkg"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM install download-only-wrapper \
        --registry download-reg \
        --download-only \
        --yes > /tmp/download-only.out 2>&1 || {
        cat /tmp/download-only.out
        fail "apm install --download-only succeeds"
      }
      cat /tmp/download-only.out
      assert_file_contains /tmp/download-only.out "packages will be downloaded" \
        "download-only reports download plan"
      assert_file_contains /tmp/download-only.out "Downloading 2 NAR" \
        "download-only downloads wrapper closure"
      assert_file_contains /tmp/download-only.out "no profile changes made" \
        "download-only reports no profile mutation"
      assert_file_not_contains /tmp/download-only.out "Importing packages" \
        "download-only does not import packages"
      assert_file_not_contains /tmp/download-only.out "Updating profile" \
        "download-only does not update profile"
      if [ "$(cache_nar_count)" = "2" ]; then
        pass "download-only leaves two NARs in user cache"
      else
        fail "download-only should leave two NARs in user cache"
      fi
      if [ "$(cache_nar_http_get_count)" = "2" ]; then
        pass "download-only fetches exactly two NAR bodies"
      else
        cat /tmp/download-cache-http.log || true
        fail "download-only should fetch exactly two NAR bodies"
      fi
      assert_store_missing "$WRAPPER_STORE" "download-only-wrapper"
      assert_store_missing "$DEP_STORE" "idempkg"
      if [ "$(generation_count)" = "0" ] && [ ! -e "$PROFILE/current" ]; then
        pass "download-only creates no profile generation"
      else
        fail "download-only should not create profile generation"
      fi
      if [ ! -e "$PROFILE" ]; then
        pass "download-only leaves profile directory absent"
      else
        find "$PROFILE" -maxdepth 2 -print
        fail "download-only should not initialize profile state"
      fi

      echo "==> Consumer: normal install after download-only activates package"
      NAR_GETS_BEFORE_INSTALL=$(cache_nar_http_get_count)
      $APM install download-only-wrapper --registry download-reg --yes > /tmp/download-install.out 2>&1 || {
        cat /tmp/download-install.out
        fail "normal apm install after download-only succeeds"
      }
      cat /tmp/download-install.out
      assert_file_contains /tmp/download-install.out "Installed 1 package" \
        "normal install creates profile generation after download-only"
      assert_store_valid "$WRAPPER_STORE" "download-only-wrapper"
      assert_store_valid "$DEP_STORE" "idempkg"
      "$PROFILE/current/bin/download-only-wrapper" > /tmp/download-wrapper-run.out
      assert_file_contains /tmp/download-wrapper-run.out "^idempkg 1.0.0$" \
        "download-only wrapper executable runs after normal install"
      if [ "$(cache_nar_http_get_count)" = "$NAR_GETS_BEFORE_INSTALL" ]; then
        pass "normal install after download-only reuses cached NAR bodies"
      else
        cat /tmp/download-cache-http.log || true
        fail "normal install after download-only should not refetch NAR bodies"
      fi
      if [ "$(readlink "$PROFILE/current")" = "gen-1" ] && [ "$(generation_count)" = "1" ]; then
        pass "normal install after download-only creates generation 1"
      else
        fail "normal install after download-only should create gen-1"
      fi

      echo "==> Consumer: corrupt one prefetched NAR and repair during install"
      rm -rf "$PROFILE"
      delete_store_path "$WRAPPER_STORE" "download-only-wrapper-reset"
      delete_store_path "$DEP_STORE" "idempkg-reset"
      export HOME=/tmp/download-corrupt-consumer
      export USER=downloadcorrupt
      PROFILE="/var/lib/profiles/per-user/downloadcorrupt"
      mkdir -p "$HOME"
      $APM registry add --no-verify file:///tmp/download-origin.git \
        --name download-reg \
        --branch "$DEFAULT_BRANCH" > /tmp/download-corrupt-registry-add.out 2>&1 || {
        cat /tmp/download-corrupt-registry-add.out
        fail "apm registry add syncs download registry for corrupt-cache consumer"
      }
      cat /tmp/download-corrupt-registry-add.out

      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM install download-only-wrapper \
        --registry download-reg \
        --download-only \
        --yes > /tmp/download-corrupt-prefetch.out 2>&1 || {
        cat /tmp/download-corrupt-prefetch.out
        fail "apm install --download-only succeeds before corrupting cache"
      }
      cat /tmp/download-corrupt-prefetch.out
      if [ "$(cache_nar_count)" = "2" ]; then
        pass "corrupt-cache consumer prefetches two NARs"
      else
        fail "corrupt-cache consumer should prefetch two NARs"
      fi
      CORRUPT_NAR=$(find "$HOME/.cache/apm" -type f -name '*.nar.zst' | sort | head -n 1)
      if [ -n "$CORRUPT_NAR" ]; then
        printf '%s\n' "corrupted cached NAR" > "$CORRUPT_NAR"
        pass "test corrupted one cached NAR"
      else
        fail "test should find a cached NAR to corrupt"
      fi
      assert_store_missing "$WRAPPER_STORE" "download-only-wrapper"
      assert_store_missing "$DEP_STORE" "idempkg"

      NAR_GETS_BEFORE_CORRUPT_INSTALL=$(cache_nar_http_get_count)
      EXPECTED_NAR_GETS_AFTER_CORRUPT_INSTALL=$((NAR_GETS_BEFORE_CORRUPT_INSTALL + 1))
      $APM install download-only-wrapper --registry download-reg --yes \
        > /tmp/download-corrupt-install.out 2>&1 || {
        cat /tmp/download-corrupt-install.out
        fail "normal install repairs one corrupted cached NAR"
      }
      cat /tmp/download-corrupt-install.out
      assert_file_contains /tmp/download-corrupt-install.out "Installed 1 package" \
        "corrupt-cache install creates profile generation"
      assert_store_valid "$WRAPPER_STORE" "download-only-wrapper"
      assert_store_valid "$DEP_STORE" "idempkg"
      "$PROFILE/current/bin/download-only-wrapper" > /tmp/download-corrupt-run.out
      assert_file_contains /tmp/download-corrupt-run.out "^idempkg 1.0.0$" \
        "corrupt-cache repaired install executes wrapper"
      if [ "$(cache_nar_http_get_count)" = "$EXPECTED_NAR_GETS_AFTER_CORRUPT_INSTALL" ]; then
        pass "corrupt-cache install redownloads only the stale NAR body"
      else
        cat /tmp/download-cache-http.log || true
        fail "corrupt-cache install should redownload exactly one stale NAR body"
      fi
      if [ "$(cache_nar_count)" = "2" ]; then
        pass "corrupt-cache install leaves repaired NAR cache complete"
      else
        fail "corrupt-cache install should leave two cached NAR files"
      fi

      if kill "$CACHE_PID" 2>/dev/null; then
        pass "static cache HTTP server stopped"
      fi
      wait "$CACHE_PID" 2>/dev/null || true

      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # 6. reinstall-package — Reinstall downloads and creates a new generation
  # -------------------------------------------------------------------------
  reinstall-package = testing.mkVMTest {
    name = "apm-reinstall-package";
    rootfsDeps = realReinstallDeps;
    memory = 1024;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixEnv}

      echo "==> Test: real apm reinstall refreshes installed packages"

      TOOL_STORE="${reinstallTool}"
      PEER_STORE="${reinstallPeerTool}"
      TOOL_HASH=$(basename "$TOOL_STORE" | cut -d- -f1)
      PEER_HASH=$(basename "$PEER_STORE" | cut -d- -f1)
      PROFILE="/var/lib/profiles/per-user/reinstalluser"

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
        if nix-store --check-validity "$path" > "/tmp/reinstall-valid-$label.out" 2>&1; then
          pass "$label valid in store"
        else
          cat "/tmp/reinstall-valid-$label.out"
          fail "$label should be valid in store"
        fi
      }

      assert_store_missing() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/reinstall-missing-$label.out" 2>&1; then
          cat "/tmp/reinstall-missing-$label.out"
          fail "$label should be missing from store"
        else
          pass "$label missing from store"
        fi
      }

      delete_store_path() {
        path="$1"
        label="$2"
        if nix-store --delete --ignore-liveness "$path" > "/tmp/reinstall-delete-$label.out" 2>&1; then
          pass "$label deleted before initial apm download"
        else
          cat "/tmp/reinstall-delete-$label.out"
          fail "$label should be deletable before initial apm download"
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
          if curl -sf http://127.0.0.1:18088/nix-cache-info >/dev/null; then
            return 0
          fi
          sleep 1
        done
        return 1
      }

      mount -o remount,rw / || true
      assert_store_valid "$TOOL_STORE" "reinstall-tool"
      assert_store_valid "$PEER_STORE" "reinstall-peer"

      echo "==> Maintainer: publish reinstall packages and static cache"
      $APR create reinstall-reg
      REG_DIR="$REG_STORAGE/reinstall-reg"
      DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)
      $APR publish "$TOOL_STORE" \
        --name reinstall-tool \
        --version 1.0.0 \
        --description "Tool for reinstall workflow" \
        --license MIT \
        --maintainer reinstall-workflow@example.invalid \
        --registry reinstall-reg \
        --no-commit
      $APR publish "$PEER_STORE" \
        --name reinstall-peer \
        --version 1.0.0 \
        --description "Peer tool for reinstall workflow" \
        --license MIT \
        --maintainer reinstall-workflow@example.invalid \
        --registry reinstall-reg \
        --no-commit
      assert_file_contains "$REG_DIR/packages/r/reinstall-tool.toml" \
        "$TOOL_HASH" "published metadata records reinstall-tool store hash"
      assert_file_contains "$REG_DIR/packages/r/reinstall-peer.toml" \
        "$PEER_HASH" "published metadata records reinstall-peer store hash"

      $APR cache generate \
        --registry reinstall-reg \
        --output /tmp/reinstall-cache \
        --cache-url http://127.0.0.1:18088 \
        --priority 48 \
        --no-commit
      assert_file_exists "/tmp/reinstall-cache/$TOOL_HASH.narinfo" \
        "static cache has reinstall-tool narinfo"
      assert_file_exists "/tmp/reinstall-cache/$PEER_HASH.narinfo" \
        "static cache has reinstall-peer narinfo"

      git -C "$REG_DIR" add -A
      git -C "$REG_DIR" commit -m "release: reinstall workflow packages"
      git init --bare --object-format=sha256 /tmp/reinstall-origin.git
      git -C "$REG_DIR" remote add origin /tmp/reinstall-origin.git
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
      PYTHONUNBUFFERED=1 python3 -m http.server 18088 --bind 127.0.0.1 \
        --directory /tmp/reinstall-cache > /tmp/reinstall-cache-http.log 2>&1 &
      CACHE_PID=$!
      if wait_for_cache_server; then
        pass "static cache HTTP server started"
      else
        cat /tmp/reinstall-cache-http.log || true
        fail "static cache HTTP server started"
      fi

      echo "==> Consumer: install then force reinstall packages while store paths are still valid"
      export HOME=/tmp/reinstall-consumer
      export USER=reinstalluser
      mkdir -p "$HOME"
      $APM registry add --no-verify file:///tmp/reinstall-origin.git \
        --name reinstall-reg \
        --branch "$DEFAULT_BRANCH" > /tmp/reinstall-registry-add.out 2>&1 || {
        cat /tmp/reinstall-registry-add.out
        fail "apm registry add syncs reinstall registry"
      }
      cat /tmp/reinstall-registry-add.out

      if $APM reinstall reinstall-tool --yes > /tmp/reinstall-empty.out 2>&1; then
        cat /tmp/reinstall-empty.out
        fail "apm reinstall should fail before reinstall-tool is installed"
      else
        cat /tmp/reinstall-empty.out
        pass "apm reinstall fails before reinstall-tool is installed"
      fi
      assert_file_contains /tmp/reinstall-empty.out "package not installed" \
        "empty reinstall reports missing installed package"
      assert_file_not_contains /tmp/reinstall-empty.out "Downloading" \
        "empty reinstall does not download package bodies"
      assert_file_not_contains /tmp/reinstall-empty.out "Updating profile" \
        "empty reinstall does not update profile"
      if [ ! -e "$PROFILE" ]; then
        pass "empty reinstall leaves profile directory absent"
      else
        find "$PROFILE" -maxdepth 2 -print
        fail "empty reinstall should not initialize profile state"
      fi
      if [ "$(cache_nar_count)" = "0" ]; then
        pass "empty reinstall leaves NAR cache empty"
      else
        find "$HOME/.cache/apm" -type f -name '*.nar.zst' -print
        fail "empty reinstall should not cache package bodies"
      fi

      delete_store_path "$TOOL_STORE" "reinstall-tool"
      delete_store_path "$PEER_STORE" "reinstall-peer"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM install reinstall-tool reinstall-peer --registry reinstall-reg --yes > /tmp/reinstall-install.out 2>&1 || {
        cat /tmp/reinstall-install.out
        fail "initial apm install reinstall packages succeeds"
      }
      cat /tmp/reinstall-install.out
      assert_file_contains /tmp/reinstall-install.out "Downloading 2 NAR" \
        "initial install downloads both reinstall packages"
      assert_file_contains /tmp/reinstall-install.out "Installed 2 package" \
        "initial install creates profile generation for both packages"
      assert_store_valid "$TOOL_STORE" "reinstall-tool"
      assert_store_valid "$PEER_STORE" "reinstall-peer"
      "$PROFILE/current/bin/reinstall-tool" > /tmp/reinstall-run-1.out
      "$PROFILE/current/bin/reinstall-peer" > /tmp/reinstall-peer-run-1.out
      assert_file_contains /tmp/reinstall-run-1.out "^reinstall-tool 1.0.0$" \
        "installed executable runs before reinstall"
      assert_file_contains /tmp/reinstall-peer-run-1.out "^reinstall-peer 1.0.0$" \
        "installed peer executable runs before reinstall"
      assert_file_contains "$PROFILE/meta/$TOOL_HASH.json" '"explicit": true' \
        "reinstall-tool metadata is explicit"
      assert_file_contains "$PROFILE/meta/$PEER_HASH.json" '"explicit": true' \
        "reinstall-peer metadata is explicit"

      if [ "$(readlink "$PROFILE/current")" = "gen-1" ] && [ "$(generation_count)" = "1" ]; then
        pass "initial install creates exactly generation 1"
      else
        fail "initial install should create only gen-1"
      fi
      if [ "$(cache_nar_count)" = "2" ]; then
        pass "initial install retains two downloaded NARs"
      else
        fail "initial install should retain two downloaded NARs"
      fi

      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM reinstall reinstall-tool reinstall-peer --yes > /tmp/reinstall-command.out 2>&1 || {
        cat /tmp/reinstall-command.out
        fail "apm reinstall succeeds for installed packages"
      }
      cat /tmp/reinstall-command.out
      assert_file_not_contains /tmp/reinstall-command.out "already installed" \
        "apm reinstall does not no-op on installed packages"
      assert_file_contains /tmp/reinstall-command.out "Downloading 2 NAR" \
        "apm reinstall downloads both packages again"
      assert_file_contains /tmp/reinstall-command.out "packages will be reinstalled" \
        "apm reinstall reports reinstall plan"
      assert_file_contains /tmp/reinstall-command.out "Reinstalled 2 package" \
        "apm reinstall creates profile generation for both packages"
      if [ "$(readlink "$PROFILE/current")" = "gen-2" ] && [ "$(generation_count)" = "2" ]; then
        pass "apm reinstall creates generation 2"
      else
        fail "apm reinstall should create gen-2"
      fi
      if [ "$(cache_nar_count)" = "2" ]; then
        pass "apm reinstall repopulates NAR cache"
      else
        fail "apm reinstall should repopulate two downloaded NARs"
      fi
      "$PROFILE/current/bin/reinstall-tool" > /tmp/reinstall-run-2.out
      "$PROFILE/current/bin/reinstall-peer" > /tmp/reinstall-peer-run-2.out
      assert_file_contains /tmp/reinstall-run-2.out "^reinstall-tool 1.0.0$" \
        "reinstalled executable runs from generation 2"
      assert_file_contains /tmp/reinstall-peer-run-2.out "^reinstall-peer 1.0.0$" \
        "reinstalled peer executable runs from generation 2"
      assert_file_contains "$PROFILE/meta/$TOOL_HASH.json" '"explicit": true' \
        "apm reinstall preserves reinstall-tool explicit metadata"
      assert_file_contains "$PROFILE/meta/$PEER_HASH.json" '"explicit": true' \
        "apm reinstall preserves reinstall-peer explicit metadata"

      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM install reinstall-tool reinstall-peer --registry reinstall-reg --reinstall --yes > /tmp/install-reinstall-flag.out 2>&1 || {
        cat /tmp/install-reinstall-flag.out
        fail "apm install --reinstall succeeds for installed packages"
      }
      cat /tmp/install-reinstall-flag.out
      assert_file_not_contains /tmp/install-reinstall-flag.out "already installed" \
        "apm install --reinstall does not no-op on installed packages"
      assert_file_contains /tmp/install-reinstall-flag.out "Downloading 2 NAR" \
        "apm install --reinstall downloads both packages again"
      assert_file_contains /tmp/install-reinstall-flag.out "packages will be reinstalled" \
        "apm install --reinstall reports reinstall plan"
      assert_file_contains /tmp/install-reinstall-flag.out "Reinstalled 2 package" \
        "apm install --reinstall creates profile generation for both packages"
      if [ "$(readlink "$PROFILE/current")" = "gen-3" ] && [ "$(generation_count)" = "3" ]; then
        pass "apm install --reinstall creates generation 3"
      else
        fail "apm install --reinstall should create gen-3"
      fi
      if [ "$(cache_nar_count)" = "2" ]; then
        pass "apm install --reinstall repopulates NAR cache"
      else
        fail "apm install --reinstall should repopulate two downloaded NARs"
      fi
      "$PROFILE/current/bin/reinstall-tool" > /tmp/reinstall-run-3.out
      "$PROFILE/current/bin/reinstall-peer" > /tmp/reinstall-peer-run-3.out
      assert_file_contains /tmp/reinstall-run-3.out "^reinstall-tool 1.0.0$" \
        "install --reinstall executable runs from generation 3"
      assert_file_contains /tmp/reinstall-peer-run-3.out "^reinstall-peer 1.0.0$" \
        "install --reinstall peer executable runs from generation 3"
      assert_file_contains "$PROFILE/meta/$TOOL_HASH.json" '"explicit": true' \
        "apm install --reinstall preserves reinstall-tool explicit metadata"
      assert_file_contains "$PROFILE/meta/$PEER_HASH.json" '"explicit": true' \
        "apm install --reinstall preserves reinstall-peer explicit metadata"

      if kill "$CACHE_PID" 2>/dev/null; then
        pass "static cache HTTP server stopped"
      fi
      wait "$CACHE_PID" 2>/dev/null || true

      check_fail
    '';
  };
}
