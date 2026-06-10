# tests/vm/apm/cache.nix -- Binary cache push/pull/HTTP/integration/dedup/resume tests
#
# Five headless VM tests exercising the binary cache subsystem:
#   cache-push-pull        -- round-trip via file:// backend
#   cache-push-http        -- push to running aos serve, verify via HTTP GET
#   cache-registry-integration -- build -> push -> verify structure
#   cache-dedup            -- shared deps not re-downloaded
#   cache-resume           -- partial download recovery
{
  testing,
  self,
  pkgs,
}: let
  iproute2Bin = "${pkgs.iproute2}/sbin/ip";
  sqliteBin = "${pkgs.sqlite}/bin/sqlite3";
  socatBin = "${pkgs.socat}/bin/socat";
  jqBin = "${pkgs.jq}/bin/jq";
  curlBin = "${pkgs.curl}/bin/curl";
  grepBin = "${pkgs.grep}/bin/grep";
  findBin = "${pkgs.findutils}/bin/find";
  nixStoreBin = "${pkgs.nix}/bin/nix-store";
  sha256sumBin = "${pkgs.coreutils}/bin/sha256sum";
  statBin = "${pkgs.coreutils}/bin/stat";
  cutBin = "${pkgs.coreutils}/bin/cut";
  catBin = "${pkgs.coreutils}/bin/cat";
  aosBin = "${self}/bin/aos";

  # Shared preamble: loopback interface, mock Nix DB, server config.
  serverPreamble = ''
        ${iproute2Bin} link set lo up || true
        ${iproute2Bin} addr add 127.0.0.1/8 dev lo 2>/dev/null || true

        echo "==> Setting up test environment"
        export AOS_ROOT=/tmp/aos
        mkdir -p /tmp/run/aos

        init_mock_nix_db() {
          root="$1"
          mkdir -p "$root/var/nix/db"
          mkdir -p "$root/store"
          mkdir -p "$root/meta"

          ${sqliteBin} "$root/var/nix/db/db.sqlite" << 'SQL'
        CREATE TABLE IF NOT EXISTS ValidPaths (
          id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
          path TEXT UNIQUE NOT NULL,
          hash TEXT NOT NULL,
          registrationTime INTEGER NOT NULL,
          deriver TEXT,
          narSize INTEGER,
          ultimate INTEGER,
          sigs TEXT,
          ca TEXT
        );
        CREATE TABLE IF NOT EXISTS Refs (
          referrer INTEGER NOT NULL,
          reference INTEGER NOT NULL,
          PRIMARY KEY (referrer, reference),
          FOREIGN KEY (referrer) REFERENCES ValidPaths(id) ON DELETE CASCADE,
          FOREIGN KEY (reference) REFERENCES ValidPaths(id) ON DELETE CASCADE
        );
        PRAGMA journal_mode=WAL;
    SQL
          chmod 666 "$root/var/nix/db/db.sqlite"
          chmod 777 "$root/var/nix/db"
        }

        register_ca_store_path() {
          store_path="$1"
          root="$2"
          store_dir="''${3:-$root/store}"
          nar_tmp=$(mktemp)
          NIX_STORE_DIR="$store_dir" NIX_STATE_DIR="$root/var/nix" \
            ${nixStoreBin} --dump "$store_path" > "$nar_tmp"
          nar_hash=$(${sha256sumBin} "$nar_tmp" | ${cutBin} -d' ' -f1)
          nar_size=$(${statBin} -c%s "$nar_tmp")
          rm -f "$nar_tmp"
          ${sqliteBin} "$root/var/nix/db/db.sqlite" \
            "INSERT INTO ValidPaths (path, hash, registrationTime, narSize, ultimate, sigs, ca) VALUES ('$store_path', 'sha256:$nar_hash', 1000000, $nar_size, 1, NULL, 'fixed:r:sha256:$nar_hash');"
        }

        register_store_reference() {
          referrer="$1"
          reference="$2"
          root="$3"
          ${sqliteBin} "$root/var/nix/db/db.sqlite" \
            "INSERT OR IGNORE INTO Refs (referrer, reference)
             SELECT referrer.id, reference.id FROM ValidPaths referrer, ValidPaths reference
             WHERE referrer.path = '$referrer' AND reference.path = '$reference';"
        }

        promote_view_path() {
          root="$1"
          view="$2"
          namespace="$3"
          store_path="$4"
          store_basename="''${store_path##*/}"
          store_hash="''${store_basename%%-*}"
          mkdir -p "$root/gcroots/$view/$namespace"
          ln -sfn "$store_path" "$root/gcroots/$view/$namespace/$store_hash"
        }

        echo "==> Creating mock Nix store DB"
        init_mock_nix_db "$AOS_ROOT"
        echo "==> Test environment ready"
  '';

  serverConfig = ''
        cat > /tmp/aos-config.toml << 'CFGEOF'
        listen = "127.0.0.1:15000"

        [[views]]
        name = "default"
        anonymous_read = true

        [bootstrap]
        socket = "/tmp/run/aos/bootstrap.sock"
        socket_group = "root"
    CFGEOF
  '';

  startServer = ''
    AOS_ROOT="''${SERVER_AOS_ROOT:-$AOS_ROOT}" ${aosBin} serve --config /tmp/aos-config.toml &
    SERVER_PID=$!
    for _i in 1 2 3 4 5 6 7 8 9 10; do
      HTTP_CODE=$(${curlBin} -s -o /dev/null -w '%{http_code}' \
        http://127.0.0.1:15000/default/nix-cache-info 2>/dev/null) || true
      if [ "$HTTP_CODE" = "200" ]; then break; fi
      sleep 1
    done
    if [ "$HTTP_CODE" != "200" ]; then
      echo "FAIL: server not responding (HTTP $HTTP_CODE)"
      exit 1
    fi
    echo "==> Server is up"
  '';

  getAuthToken = ''
    RESPONSE=$(echo '{"action":"create","views":["default"],"permissions":["read","build","gc"]}' | \
      ${socatBin} - UNIX-CONNECT:/tmp/run/aos/bootstrap.sock)
    PROV_TOKEN=$(echo "$RESPONSE" | ${jqBin} -r '.data.token // empty')
    test -n "$PROV_TOKEN" || { echo "FAIL: no provisioning token"; exit 1; }

    JWT_RESPONSE=$(${curlBin} -s \
      -X POST -H "Authorization: Bearer $PROV_TOKEN" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "grant_type=client_credentials" \
      http://127.0.0.1:15000/oauth2/token)
    ACCESS_TOKEN=$(echo "$JWT_RESPONSE" | ${jqBin} -r '.access_token // empty')
    test -n "$ACCESS_TOKEN" || { echo "FAIL: no access token"; exit 1; }
    echo "==> Authenticated"
  '';

  stopServer = ''
    kill $SERVER_PID 2>/dev/null || true
    wait $SERVER_PID 2>/dev/null || true
  '';

  serverDeps = [
    self
    pkgs.curl
    pkgs.coreutils
    pkgs.socat
    pkgs.jq
    pkgs.sqlite
    pkgs.iproute2
    pkgs.grep
    pkgs.findutils
    pkgs.nix
  ];
in {
  # ---------------------------------------------------------------------------
  # Test 1: cache-push-pull -- round-trip via file:// backend
  # ---------------------------------------------------------------------------
  cache-push-pull = testing.mkVMTest {
    name = "cache-push-pull";
    rootfsDeps = serverDeps;
    memory = 1024;
    testScript = ''
      ${serverPreamble}

      FAIL=0

      # Create a test file cache directory
      mkdir -p /tmp/test-cache/nar

      # Create a small test store path fixture
      TEST_STORE_HASH="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      TEST_STORE_BASENAME="$TEST_STORE_HASH-test-pkg-1.0"
      TEST_STORE_PATH="$AOS_ROOT/store/$TEST_STORE_BASENAME"
      mkdir -p "$TEST_STORE_PATH/bin"
      echo '#!/bin/sh' > "$TEST_STORE_PATH/bin/hello"
      echo 'echo "Hello from test-pkg"' >> "$TEST_STORE_PATH/bin/hello"
      chmod +x "$TEST_STORE_PATH/bin/hello"

      # Register in mock Nix DB
      NAR_HASH="sha256:0000000000000000000000000000000000000000000000000000000000000001"
      ${sqliteBin} $AOS_ROOT/var/nix/db/db.sqlite \
        "INSERT INTO ValidPaths (path, hash, registrationTime, narSize, ultimate, sigs) VALUES ('$TEST_STORE_PATH', '$NAR_HASH', 1000000, 4096, 1, '''''');"

      echo "==> Test: cache push to file:// backend"
      if ! ${aosBin} cache push "$TEST_STORE_PATH" --to "file:///tmp/test-cache" \
        --compression none > /tmp/cache-push-pull-push.out 2>&1; then
        cat /tmp/cache-push-pull-push.out
        echo "FAIL: cache push failed"
        exit 1
      fi
      cat /tmp/cache-push-pull-push.out

      # Verify narinfo and NAR files exist and describe the uploaded path.
      NARINFO_COUNT=$(${findBin} /tmp/test-cache -maxdepth 1 -name '*.narinfo' 2>/dev/null | wc -l | tr -d ' ')
      echo "==> Found $NARINFO_COUNT narinfo files"
      test "$NARINFO_COUNT" -eq 1 || { echo "FAIL: expected exactly one narinfo"; FAIL=1; }

      NAR_COUNT=$(${findBin} /tmp/test-cache/nar -type f -name '*.nar*' 2>/dev/null | wc -l | tr -d ' ')
      echo "==> Found $NAR_COUNT NAR files"
      test "$NAR_COUNT" -eq 1 || { echo "FAIL: expected exactly one NAR"; FAIL=1; }

      NARINFO_PATH="/tmp/test-cache/$TEST_STORE_HASH.narinfo"
      test -f "$NARINFO_PATH" || { echo "FAIL: missing expected narinfo"; FAIL=1; }
      ${grepBin} -F -q "StorePath: $TEST_STORE_PATH" "$NARINFO_PATH" || \
        { echo "FAIL: narinfo missing store path"; cat "$NARINFO_PATH" 2>/dev/null || true; FAIL=1; }
      ${grepBin} -F -q "Compression: none" "$NARINFO_PATH" || \
        { echo "FAIL: narinfo missing compression"; cat "$NARINFO_PATH" 2>/dev/null || true; FAIL=1; }
      ${grepBin} -F -q "URL: nar/" "$NARINFO_PATH" || \
        { echo "FAIL: narinfo missing NAR URL"; cat "$NARINFO_PATH" 2>/dev/null || true; FAIL=1; }
      ${grepBin} -F -q "NarHash: sha256:" "$NARINFO_PATH" || \
        { echo "FAIL: narinfo missing NAR hash"; cat "$NARINFO_PATH" 2>/dev/null || true; FAIL=1; }

      echo "==> Test: cache list sees local and cached path"
      if ! ${aosBin} cache list "$TEST_STORE_PATH" --from "file:///tmp/test-cache" \
        > /tmp/cache-push-pull-list.out 2>&1; then
        cat /tmp/cache-push-pull-list.out
        echo "FAIL: cache list failed"
        exit 1
      fi
      cat /tmp/cache-push-pull-list.out
      ${grepBin} -F -q "$TEST_STORE_HASH" /tmp/cache-push-pull-list.out || \
        { echo "FAIL: cache list missing store path"; FAIL=1; }
      ${grepBin} -F -q "synced" /tmp/cache-push-pull-list.out || \
        { echo "FAIL: cache list did not report synced"; FAIL=1; }

      echo "==> Test: cache pull from file:// backend"
      if ! ${aosBin} cache pull "$TEST_STORE_PATH" --from "file:///tmp/test-cache" \
        --dry-run > /tmp/cache-push-pull-pull.out 2>&1; then
        cat /tmp/cache-push-pull-pull.out
        echo "FAIL: cache pull dry-run failed"
        exit 1
      fi
      cat /tmp/cache-push-pull-pull.out
      ${grepBin} -F -q "All paths already in local store." /tmp/cache-push-pull-pull.out || \
        { echo "FAIL: cache pull did not report local store hit"; FAIL=1; }

      # Verify the store path is still valid
      test -d "$TEST_STORE_PATH" || { echo "FAIL: store path missing after round-trip"; FAIL=1; }
      test -x "$TEST_STORE_PATH/bin/hello" || { echo "FAIL: binary not executable"; FAIL=1; }

      if [ "$FAIL" -ne 0 ]; then
        echo "==> cache-push-pull FAILED"
        exit 1
      fi
      echo "==> cache-push-pull passed"
    '';
  };

  # ---------------------------------------------------------------------------
  # Test 2: cache-push-http -- push to running server, verify via HTTP GET
  # ---------------------------------------------------------------------------
  cache-push-http = testing.mkVMTest {
    name = "cache-push-http";
    rootfsDeps = serverDeps;
    memory = 1024;
    testScript = ''
      ${serverPreamble}
      CLIENT_STATE_ROOT=/tmp/aos-http-client-state
      SERVER_AOS_ROOT=/tmp/aos-http-server
      init_mock_nix_db "$CLIENT_STATE_ROOT"
      init_mock_nix_db "$SERVER_AOS_ROOT"
      ${serverConfig}
      ${startServer}
      ${getAuthToken}

      FAIL=0

      # Register a test path in the store
      TEST_STORE_HASH="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
      TEST_STORE_BASENAME="$TEST_STORE_HASH-http-test-1.0"
      TEST_STORE_PATH="$SERVER_AOS_ROOT/store/$TEST_STORE_BASENAME"
      SERVER_STORE_PATH="$SERVER_AOS_ROOT/store/$TEST_STORE_BASENAME"
      mkdir -p "$TEST_STORE_PATH/bin"
      echo '#!/bin/sh' > "$TEST_STORE_PATH/bin/http-test"
      echo 'echo "http cache test executed"' >> "$TEST_STORE_PATH/bin/http-test"
      chmod +x "$TEST_STORE_PATH/bin/http-test"
      register_ca_store_path "$TEST_STORE_PATH" "$CLIENT_STATE_ROOT" "$SERVER_AOS_ROOT/store"

      echo "==> Test: server reports hash missing before upload"
      QM_BEFORE=$(${curlBin} -s \
        -X POST -H "Authorization: Bearer $ACCESS_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"paths\":[\"$TEST_STORE_HASH\"]}" \
        http://127.0.0.1:15000/default/query-missing)
      echo "query-missing before: $QM_BEFORE"
      echo "$QM_BEFORE" | ${jqBin} -e --arg hash "$TEST_STORE_HASH" \
        '.missing == [$hash]' >/dev/null || \
        { echo "FAIL: server did not report hash missing before upload"; FAIL=1; }

      echo "==> Test: push to HTTP cache server"
      if ! AOS_ROOT="$SERVER_AOS_ROOT" \
        AOS_NIX_STORE_DIR="$SERVER_AOS_ROOT/store" \
        AOS_NIX_STATE_DIR="$CLIENT_STATE_ROOT/var/nix" \
        ${aosBin} cache push "$TEST_STORE_PATH" \
        --to "http://127.0.0.1:15000/default" \
        --compression zstd \
        --token "$PROV_TOKEN" > /tmp/cache-push-http-first.out 2>&1; then
        cat /tmp/cache-push-http-first.out
        echo "FAIL: HTTP cache push failed"
        exit 1
      fi
      cat /tmp/cache-push-http-first.out
      ${grepBin} -F -q "1/1 paths need uploading" /tmp/cache-push-http-first.out || \
        { echo "FAIL: first push did not upload missing path"; FAIL=1; }
      test -d "$SERVER_STORE_PATH" || { echo "FAIL: server store path missing after upload"; FAIL=1; }
      test -x "$SERVER_STORE_PATH/bin/http-test" || \
        { echo "FAIL: server imported executable missing"; FAIL=1; }
      promote_view_path "$SERVER_AOS_ROOT" default bin "$SERVER_STORE_PATH"

      echo "==> Test: server reports hash present after upload"
      QM_AFTER=$(${curlBin} -s \
        -X POST -H "Authorization: Bearer $ACCESS_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"paths\":[\"$TEST_STORE_HASH\"]}" \
        http://127.0.0.1:15000/default/query-missing)
      echo "query-missing after: $QM_AFTER"
      echo "$QM_AFTER" | ${jqBin} -e '.missing == []' >/dev/null || \
        { echo "FAIL: server still reported hash missing after upload"; FAIL=1; }

      echo "==> Test: repeat push is a no-op"
      if ! AOS_ROOT="$SERVER_AOS_ROOT" \
        AOS_NIX_STORE_DIR="$SERVER_AOS_ROOT/store" \
        AOS_NIX_STATE_DIR="$CLIENT_STATE_ROOT/var/nix" \
        ${aosBin} cache push "$TEST_STORE_PATH" \
        --to "http://127.0.0.1:15000/default" \
        --compression zstd \
        --token "$PROV_TOKEN" > /tmp/cache-push-http-second.out 2>&1; then
        cat /tmp/cache-push-http-second.out
        echo "FAIL: repeat HTTP cache push failed"
        exit 1
      fi
      cat /tmp/cache-push-http-second.out
      ${grepBin} -F -q "All paths already cached." /tmp/cache-push-http-second.out || \
        { echo "FAIL: repeat push did not detect cached path"; FAIL=1; }

      echo "==> Test: verify narinfo queryable via HTTP GET"
      HTTP_CODE=$(${curlBin} -s -o /dev/null -w '%{http_code}' \
        "http://127.0.0.1:15000/default/$TEST_STORE_HASH.narinfo")
      echo "==> narinfo HTTP code: $HTTP_CODE"
      test "$HTTP_CODE" = "200" || { echo "FAIL: expected narinfo HTTP 200"; FAIL=1; }

      NARINFO=$(${curlBin} -sf "http://127.0.0.1:15000/default/$TEST_STORE_HASH.narinfo")
      echo "$NARINFO" > /tmp/cache-push-http.narinfo
      echo "$NARINFO"
      echo "$NARINFO" | ${grepBin} -F -q "StorePath: $SERVER_STORE_PATH" || \
        { echo "FAIL: narinfo missing server store path"; FAIL=1; }
      echo "$NARINFO" | ${grepBin} -F -q "URL: nar/" || \
        { echo "FAIL: narinfo missing NAR URL"; FAIL=1; }
      NAR_URL=$(echo "$NARINFO" | ${grepBin} "^URL:" | ${cutBin} -d' ' -f2)
      test -n "$NAR_URL" || { echo "FAIL: empty NAR URL"; FAIL=1; }
      ${curlBin} -sf "http://127.0.0.1:15000/default/$NAR_URL" \
        -o /tmp/cache-push-http.nar
      NAR_SIZE=$(${statBin} -c%s /tmp/cache-push-http.nar)
      test "$NAR_SIZE" -gt 0 || { echo "FAIL: downloaded NAR is empty"; FAIL=1; }

      OUTPUT=$("$SERVER_STORE_PATH/bin/http-test")
      echo "$OUTPUT" | ${grepBin} -q "http cache test executed" || \
        { echo "FAIL: unexpected imported executable output: $OUTPUT"; FAIL=1; }

      ${stopServer}

      if [ "$FAIL" -ne 0 ]; then
        echo "==> cache-push-http FAILED"
        exit 1
      fi
      echo "==> cache-push-http passed"
    '';
  };

  # ---------------------------------------------------------------------------
  # Test 3: cache-registry-integration -- build->push->verify structure
  # ---------------------------------------------------------------------------
  cache-registry-integration = testing.mkVMTest {
    name = "cache-registry-integration";
    rootfsDeps = serverDeps;
    memory = 1024;
    testScript = ''
      ${serverPreamble}
      CLIENT_STATE_ROOT=/tmp/aos-registry-cache-client-state
      SERVER_AOS_ROOT=/tmp/aos-registry-cache-server
      init_mock_nix_db "$CLIENT_STATE_ROOT"
      init_mock_nix_db "$SERVER_AOS_ROOT"
      ${serverConfig}
      ${startServer}
      ${getAuthToken}

      FAIL=0

      echo "==> Step 1: Create registry package closure"
      PKG_HASH="cccccccccccccccccccccccccccccccc"
      LIB_HASH="dddddddddddddddddddddddddddddddd"
      TEST_PKG="$SERVER_AOS_ROOT/store/$PKG_HASH-reg-test-1.0"
      TEST_LIB="$SERVER_AOS_ROOT/store/$LIB_HASH-libregtest-1.0"
      mkdir -p "$TEST_PKG/bin" "$TEST_PKG/share/reg-test" "$TEST_LIB/lib"
      echo "libregtest fixture" > "$TEST_LIB/lib/libregtest.so"
      echo '#!/bin/sh' > "$TEST_PKG/bin/reg-test"
      echo 'echo "registry test v1.0 using libregtest"' >> "$TEST_PKG/bin/reg-test"
      chmod +x "$TEST_PKG/bin/reg-test"
      echo "$TEST_LIB/lib/libregtest.so" > "$TEST_PKG/share/reg-test/lib-path"
      dd if=/dev/urandom of="$TEST_PKG/share/reg-test/large-payload.bin" bs=1024 count=1536 2>/dev/null
      register_ca_store_path "$TEST_LIB" "$CLIENT_STATE_ROOT" "$SERVER_AOS_ROOT/store"
      register_ca_store_path "$TEST_PKG" "$CLIENT_STATE_ROOT" "$SERVER_AOS_ROOT/store"
      register_store_reference "$TEST_PKG" "$TEST_LIB" "$CLIENT_STATE_ROOT"

      echo "==> Step 2: Push registry package closure to HTTP cache"
      if ! AOS_ROOT="$SERVER_AOS_ROOT" \
        AOS_NIX_STORE_DIR="$SERVER_AOS_ROOT/store" \
        AOS_NIX_STATE_DIR="$CLIENT_STATE_ROOT/var/nix" \
        ${aosBin} cache push "$TEST_PKG" \
        --to "http://127.0.0.1:15000/default" \
        --compression zstd \
        --token "$PROV_TOKEN" > /tmp/cache-registry-push.out 2>&1; then
        cat /tmp/cache-registry-push.out
        echo "FAIL: registry package cache push failed"
        exit 1
      fi
      cat /tmp/cache-registry-push.out
      ${grepBin} -F -q "2/2 paths need uploading" /tmp/cache-registry-push.out || \
        { echo "FAIL: registry closure was not uploaded from a single root path"; FAIL=1; }
      test -d "$TEST_PKG" || { echo "FAIL: server package path missing after upload"; FAIL=1; }
      test -d "$TEST_LIB" || { echo "FAIL: server library path missing after upload"; FAIL=1; }
      promote_view_path "$SERVER_AOS_ROOT" default bin "$TEST_PKG"
      promote_view_path "$SERVER_AOS_ROOT" default src "$TEST_LIB"

      echo "==> Step 3: Verify in cache"
      QUERY=$(${curlBin} -s \
        -X POST -H "Authorization: Bearer $ACCESS_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"paths\":[\"$PKG_HASH\",\"$LIB_HASH\"]}" \
        http://127.0.0.1:15000/default/query-missing)
      echo "query-missing: $QUERY"
      echo "$QUERY" | ${jqBin} -e '.missing == []' >/dev/null || \
        { echo "FAIL: pushed registry closure still reported missing"; FAIL=1; }

      for hash in "$PKG_HASH" "$LIB_HASH"; do
        HTTP_CODE=$(${curlBin} -s -o /dev/null -w '%{http_code}' \
          "http://127.0.0.1:15000/default/$hash.narinfo")
        echo "narinfo $hash: HTTP $HTTP_CODE"
        test "$HTTP_CODE" = "200" || { echo "FAIL: expected narinfo HTTP 200 for $hash"; FAIL=1; }
      done

      PKG_NARINFO=$(${curlBin} -sf "http://127.0.0.1:15000/default/$PKG_HASH.narinfo")
      LIB_NARINFO=$(${curlBin} -sf "http://127.0.0.1:15000/default/$LIB_HASH.narinfo")
      echo "$PKG_NARINFO" > /tmp/cache-registry-pkg.narinfo
      echo "$LIB_NARINFO" > /tmp/cache-registry-lib.narinfo
      echo "$PKG_NARINFO" | ${grepBin} -F -q "StorePath: $TEST_PKG" || \
        { echo "FAIL: package narinfo missing store path"; FAIL=1; }
      echo "$PKG_NARINFO" | ${grepBin} -F -q "$LIB_HASH-libregtest-1.0" || \
        { echo "FAIL: package narinfo missing library reference"; cat /tmp/cache-registry-pkg.narinfo; FAIL=1; }
      echo "$LIB_NARINFO" | ${grepBin} -F -q "StorePath: $TEST_LIB" || \
        { echo "FAIL: library narinfo missing store path"; FAIL=1; }

      PKG_NAR_URL=$(echo "$PKG_NARINFO" | ${grepBin} "^URL:" | ${cutBin} -d' ' -f2)
      LIB_NAR_URL=$(echo "$LIB_NARINFO" | ${grepBin} "^URL:" | ${cutBin} -d' ' -f2)
      test -n "$PKG_NAR_URL" || { echo "FAIL: package narinfo missing NAR URL"; FAIL=1; }
      test -n "$LIB_NAR_URL" || { echo "FAIL: library narinfo missing NAR URL"; FAIL=1; }
      ${curlBin} -sf "http://127.0.0.1:15000/default/$PKG_NAR_URL" \
        -o /tmp/cache-registry-pkg.nar
      ${curlBin} -sf "http://127.0.0.1:15000/default/$LIB_NAR_URL" \
        -o /tmp/cache-registry-lib.nar
      PKG_NAR_SIZE=$(${statBin} -c%s /tmp/cache-registry-pkg.nar)
      LIB_NAR_SIZE=$(${statBin} -c%s /tmp/cache-registry-lib.nar)
      test "$PKG_NAR_SIZE" -gt 0 || { echo "FAIL: downloaded package NAR is empty"; FAIL=1; }
      test "$PKG_NAR_SIZE" -gt 1048576 || { echo "FAIL: package NAR did not exercise large upload path"; FAIL=1; }
      test "$LIB_NAR_SIZE" -gt 0 || { echo "FAIL: downloaded library NAR is empty"; FAIL=1; }

      echo "==> Step 4: Repeat push is a no-op"
      if ! AOS_ROOT="$SERVER_AOS_ROOT" \
        AOS_NIX_STORE_DIR="$SERVER_AOS_ROOT/store" \
        AOS_NIX_STATE_DIR="$CLIENT_STATE_ROOT/var/nix" \
        ${aosBin} cache push "$TEST_PKG" \
        --to "http://127.0.0.1:15000/default" \
        --compression zstd \
        --token "$PROV_TOKEN" > /tmp/cache-registry-repeat.out 2>&1; then
        cat /tmp/cache-registry-repeat.out
        echo "FAIL: repeat registry cache push failed"
        exit 1
      fi
      cat /tmp/cache-registry-repeat.out
      ${grepBin} -F -q "All paths already cached." /tmp/cache-registry-repeat.out || \
        { echo "FAIL: repeat registry push did not detect cached closure"; FAIL=1; }

      echo "==> Step 5: Verify package structure"
      test -d "$TEST_PKG/bin" || { echo "FAIL: missing bin/"; FAIL=1; }
      test -f "$TEST_LIB/lib/libregtest.so" || { echo "FAIL: missing library payload"; FAIL=1; }
      ${grepBin} -F -q "$TEST_LIB/lib/libregtest.so" "$TEST_PKG/share/reg-test/lib-path" || \
        { echo "FAIL: package payload does not point at library payload"; FAIL=1; }
      test -x "$TEST_PKG/bin/reg-test" || { echo "FAIL: not executable"; FAIL=1; }

      echo "==> Step 6: Verify execution"
      OUTPUT=$("$TEST_PKG/bin/reg-test")
      echo "$OUTPUT" | ${grepBin} -q "registry test v1.0 using libregtest" || \
        { echo "FAIL: unexpected output: $OUTPUT"; FAIL=1; }

      ${stopServer}

      if [ "$FAIL" -ne 0 ]; then
        echo "==> cache-registry-integration FAILED"
        exit 1
      fi
      echo "==> cache-registry-integration passed"
    '';
  };

  # ---------------------------------------------------------------------------
  # Test 4: cache-dedup -- shared deps not re-downloaded
  # ---------------------------------------------------------------------------
  cache-dedup = testing.mkVMTest {
    name = "cache-dedup";
    rootfsDeps = serverDeps;
    memory = 1024;
    testScript = ''
      ${serverPreamble}
      CLIENT_STATE_ROOT=/tmp/aos-dedup-client-state
      SERVER_AOS_ROOT=/tmp/aos-dedup-server
      init_mock_nix_db "$CLIENT_STATE_ROOT"
      init_mock_nix_db "$SERVER_AOS_ROOT"
      ${serverConfig}
      ${startServer}
      ${getAuthToken}

      FAIL=0

      # Create shared deps
      LIBZ_HASH="dddddddddddddddddddddddddddddddd"
      LIBSSL_HASH="gggggggggggggggggggggggggggggggg"
      PKG_A_HASH="ffffffffffffffffffffffffffffffff"
      PKG_B_HASH="11111111111111111111111111111111"

      LIBZ="$SERVER_AOS_ROOT/store/$LIBZ_HASH-libz-1.0"
      mkdir -p "$LIBZ/lib"
      echo "libz stub" > "$LIBZ/lib/libz.so"
      register_ca_store_path "$LIBZ" "$CLIENT_STATE_ROOT" "$SERVER_AOS_ROOT/store"

      LIBSSL="$SERVER_AOS_ROOT/store/$LIBSSL_HASH-libssl-1.0"
      mkdir -p "$LIBSSL/lib"
      echo "libssl stub" > "$LIBSSL/lib/libssl.so"
      register_ca_store_path "$LIBSSL" "$CLIENT_STATE_ROOT" "$SERVER_AOS_ROOT/store"

      # Create packages A and B (both depend on libz, libssl)
      PKG_A="$SERVER_AOS_ROOT/store/$PKG_A_HASH-pkg-a-1.0"
      mkdir -p "$PKG_A/bin"
      echo '#!/bin/sh' > "$PKG_A/bin/pkg-a"
      echo 'echo "pkg-a executed"' >> "$PKG_A/bin/pkg-a"
      chmod +x "$PKG_A/bin/pkg-a"
      register_ca_store_path "$PKG_A" "$CLIENT_STATE_ROOT" "$SERVER_AOS_ROOT/store"

      PKG_B="$SERVER_AOS_ROOT/store/$PKG_B_HASH-pkg-b-1.0"
      mkdir -p "$PKG_B/bin"
      echo '#!/bin/sh' > "$PKG_B/bin/pkg-b"
      echo 'echo "pkg-b executed"' >> "$PKG_B/bin/pkg-b"
      chmod +x "$PKG_B/bin/pkg-b"
      register_ca_store_path "$PKG_B" "$CLIENT_STATE_ROOT" "$SERVER_AOS_ROOT/store"

      echo "==> Query-missing for A closure"
      QM_A=$(${curlBin} -s \
        -X POST -H "Authorization: Bearer $ACCESS_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"paths\":[\"$PKG_A_HASH\",\"$LIBZ_HASH\",\"$LIBSSL_HASH\"]}" \
        http://127.0.0.1:15000/default/query-missing)
      echo "query-missing A: $QM_A"
      MISSING_A=$(echo "$QM_A" | ${jqBin} '.missing | length')
      echo "Package A closure: $MISSING_A missing"
      echo "$QM_A" | ${jqBin} -e \
        --arg pkg "$PKG_A_HASH" \
        --arg libz "$LIBZ_HASH" \
        --arg libssl "$LIBSSL_HASH" \
        '(.missing | sort) == ([$pkg, $libz, $libssl] | sort)' >/dev/null || \
        { echo "FAIL: expected package A and shared deps missing before push"; FAIL=1; }

      echo "==> Push package A + deps"
      if ! AOS_ROOT="$SERVER_AOS_ROOT" \
        AOS_NIX_STORE_DIR="$SERVER_AOS_ROOT/store" \
        AOS_NIX_STATE_DIR="$CLIENT_STATE_ROOT/var/nix" \
        ${aosBin} cache push "$PKG_A" "$LIBZ" "$LIBSSL" \
        --to "http://127.0.0.1:15000/default" \
        --token "$PROV_TOKEN" > /tmp/cache-dedup-push-a.out 2>&1; then
        cat /tmp/cache-dedup-push-a.out
        echo "FAIL: package A cache push failed"
        exit 1
      fi
      cat /tmp/cache-dedup-push-a.out
      ${grepBin} -F -q "3/3 paths need uploading" /tmp/cache-dedup-push-a.out || \
        { echo "FAIL: package A push did not upload all initial paths"; FAIL=1; }

      echo "==> Query-missing for B closure (shared deps should be present)"
      QM_B=$(${curlBin} -s \
        -X POST -H "Authorization: Bearer $ACCESS_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"paths\":[\"$PKG_B_HASH\",\"$LIBZ_HASH\",\"$LIBSSL_HASH\"]}" \
        http://127.0.0.1:15000/default/query-missing)
      echo "query-missing B: $QM_B"
      MISSING_B=$(echo "$QM_B" | ${jqBin} '.missing | length')
      echo "Package B closure: $MISSING_B missing"
      echo "$QM_B" | ${jqBin} -e --arg pkg "$PKG_B_HASH" \
        '.missing == [$pkg]' >/dev/null || \
        { echo "FAIL: shared deps should be cached before package B push"; FAIL=1; }

      echo "==> Push package B + shared deps"
      if ! AOS_ROOT="$SERVER_AOS_ROOT" \
        AOS_NIX_STORE_DIR="$SERVER_AOS_ROOT/store" \
        AOS_NIX_STATE_DIR="$CLIENT_STATE_ROOT/var/nix" \
        ${aosBin} cache push "$PKG_B" "$LIBZ" "$LIBSSL" \
        --to "http://127.0.0.1:15000/default" \
        --token "$PROV_TOKEN" > /tmp/cache-dedup-push-b.out 2>&1; then
        cat /tmp/cache-dedup-push-b.out
        echo "FAIL: package B cache push failed"
        exit 1
      fi
      cat /tmp/cache-dedup-push-b.out
      ${grepBin} -F -q "1/3 paths need uploading" /tmp/cache-dedup-push-b.out || \
        { echo "FAIL: package B push did not skip cached shared deps"; FAIL=1; }

      echo "==> Verify all B closure paths are cached"
      QM_B_AFTER=$(${curlBin} -s \
        -X POST -H "Authorization: Bearer $ACCESS_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"paths\":[\"$PKG_B_HASH\",\"$LIBZ_HASH\",\"$LIBSSL_HASH\"]}" \
        http://127.0.0.1:15000/default/query-missing)
      echo "query-missing B after: $QM_B_AFTER"
      echo "$QM_B_AFTER" | ${jqBin} -e '.missing == []' >/dev/null || \
        { echo "FAIL: package B closure still missing after push"; FAIL=1; }

      promote_view_path "$SERVER_AOS_ROOT" default bin "$PKG_A"
      promote_view_path "$SERVER_AOS_ROOT" default bin "$PKG_B"
      promote_view_path "$SERVER_AOS_ROOT" default bin "$LIBZ"
      promote_view_path "$SERVER_AOS_ROOT" default bin "$LIBSSL"
      for hash in "$PKG_A_HASH" "$PKG_B_HASH" "$LIBZ_HASH" "$LIBSSL_HASH"; do
        HTTP_CODE=$(${curlBin} -s -o /dev/null -w '%{http_code}' \
          "http://127.0.0.1:15000/default/$hash.narinfo")
        echo "narinfo $hash: HTTP $HTTP_CODE"
        test "$HTTP_CODE" = "200" || { echo "FAIL: expected narinfo HTTP 200 for $hash"; FAIL=1; }
      done

      OUTPUT_A=$("$PKG_A/bin/pkg-a")
      echo "$OUTPUT_A" | ${grepBin} -q "pkg-a executed" || \
        { echo "FAIL: unexpected package A output: $OUTPUT_A"; FAIL=1; }
      OUTPUT_B=$("$PKG_B/bin/pkg-b")
      echo "$OUTPUT_B" | ${grepBin} -q "pkg-b executed" || \
        { echo "FAIL: unexpected package B output: $OUTPUT_B"; FAIL=1; }

      ${stopServer}

      if [ "$FAIL" -ne 0 ]; then
        echo "==> cache-dedup FAILED"
        exit 1
      fi
      echo "==> cache-dedup passed"
    '';
  };

  # ---------------------------------------------------------------------------
  # Test 5: cache-resume -- partial download recovery
  # ---------------------------------------------------------------------------
  cache-resume = testing.mkVMTest {
    name = "cache-resume";
    rootfsDeps = serverDeps;
    memory = 1024;
    testScript = ''
      ${serverPreamble}
      CLIENT_STATE_ROOT=/tmp/aos-resume-client-state
      SERVER_AOS_ROOT=/tmp/aos-resume-server
      init_mock_nix_db "$CLIENT_STATE_ROOT"
      init_mock_nix_db "$SERVER_AOS_ROOT"
      ${serverConfig}
      ${startServer}
      ${getAuthToken}

      FAIL=0

      # Create and push a test path
      HASH="22222222222222222222222222222222"
      TEST_PATH="$SERVER_AOS_ROOT/store/$HASH-resume-test-1.0"
      mkdir -p "$TEST_PATH/data"
      dd if=/dev/urandom of="$TEST_PATH/data/payload.bin" bs=1024 count=64 2>/dev/null
      register_ca_store_path "$TEST_PATH" "$CLIENT_STATE_ROOT" "$SERVER_AOS_ROOT/store"

      echo "==> Push test path to server"
      if ! AOS_ROOT="$SERVER_AOS_ROOT" \
        AOS_NIX_STORE_DIR="$SERVER_AOS_ROOT/store" \
        AOS_NIX_STATE_DIR="$CLIENT_STATE_ROOT/var/nix" \
        ${aosBin} cache push "$TEST_PATH" \
        --to "http://127.0.0.1:15000/default" \
        --token "$PROV_TOKEN" > /tmp/cache-resume-push.out 2>&1; then
        cat /tmp/cache-resume-push.out
        echo "FAIL: cache push failed"
        exit 1
      fi
      cat /tmp/cache-resume-push.out
      ${grepBin} -F -q "1/1 paths need uploading" /tmp/cache-resume-push.out || \
        { echo "FAIL: resume fixture was not uploaded"; FAIL=1; }
      promote_view_path "$SERVER_AOS_ROOT" default bin "$TEST_PATH"

      echo "==> Test: simulate partial download"
      NARINFO=$(${curlBin} -sf "http://127.0.0.1:15000/default/$HASH.narinfo")
      echo "narinfo: $NARINFO"
      echo "$NARINFO" | ${grepBin} -F -q "StorePath: $TEST_PATH" || \
        { echo "FAIL: narinfo missing store path"; FAIL=1; }
      echo "$NARINFO" | ${grepBin} -F -q "URL: nar/" || \
        { echo "FAIL: narinfo missing NAR URL"; FAIL=1; }

      NAR_URL=$(echo "$NARINFO" | ${grepBin} "^URL:" | ${cutBin} -d' ' -f2)
      test -n "$NAR_URL" || { echo "FAIL: empty NAR URL"; FAIL=1; }
      echo "==> NAR URL: $NAR_URL"

      FULL_CODE=$(${curlBin} -s -w '%{http_code}' \
        "http://127.0.0.1:15000/default/$NAR_URL" \
        -o /tmp/full.nar)
      echo "==> Full download HTTP $FULL_CODE"
      test "$FULL_CODE" = "200" || { echo "FAIL: full NAR download failed"; FAIL=1; }
      FULL_SIZE=$(${statBin} -c%s /tmp/full.nar)
      echo "==> Full: $FULL_SIZE bytes"
      test "$FULL_SIZE" -gt 1024 || { echo "FAIL: full NAR too small for range test"; FAIL=1; }

      # Download first 1024 bytes (partial)
      PARTIAL_CODE=$(${curlBin} -s -D /tmp/partial.headers -r 0-1023 \
        -w '%{http_code}' "http://127.0.0.1:15000/default/$NAR_URL" \
        -o /tmp/partial.nar)
      echo "==> Partial download HTTP $PARTIAL_CODE"
      test "$PARTIAL_CODE" = "206" || { echo "FAIL: partial NAR download did not return 206"; FAIL=1; }
      PARTIAL_SIZE=$(${statBin} -c%s /tmp/partial.nar)
      echo "==> Partial: $PARTIAL_SIZE bytes"
      test "$PARTIAL_SIZE" -eq 1024 || { echo "FAIL: expected 1024-byte partial"; FAIL=1; }
      ${grepBin} -i -q '^content-range: bytes 0-1023/' /tmp/partial.headers || \
        { echo "FAIL: partial response missing Content-Range"; cat /tmp/partial.headers; FAIL=1; }

      # Resume from partial offset.
      REST_CODE=$(${curlBin} -s -D /tmp/rest.headers -r "$PARTIAL_SIZE-" \
        -w '%{http_code}' "http://127.0.0.1:15000/default/$NAR_URL" \
        -o /tmp/rest.nar)
      echo "==> Resume download HTTP $REST_CODE"
      test "$REST_CODE" = "206" || { echo "FAIL: resume NAR download did not return 206"; FAIL=1; }
      ${grepBin} -i -q "^content-range: bytes $PARTIAL_SIZE-" /tmp/rest.headers || \
        { echo "FAIL: resume response missing Content-Range"; cat /tmp/rest.headers; FAIL=1; }

      ${catBin} /tmp/partial.nar /tmp/rest.nar > /tmp/resumed.nar
      RESUMED_SIZE=$(${statBin} -c%s /tmp/resumed.nar)
      echo "==> Resumed: $RESUMED_SIZE bytes"
      test "$RESUMED_SIZE" -eq "$FULL_SIZE" || \
        { echo "FAIL: resumed NAR size does not match full download"; FAIL=1; }
      FULL_HASH=$(${sha256sumBin} /tmp/full.nar | ${cutBin} -d' ' -f1)
      RESUMED_HASH=$(${sha256sumBin} /tmp/resumed.nar | ${cutBin} -d' ' -f1)
      test "$RESUMED_HASH" = "$FULL_HASH" || \
        { echo "FAIL: resumed NAR hash does not match full download"; FAIL=1; }
      echo "==> Resume simulation complete"

      echo "==> Verify content-range capability"
      CACHE_INFO=$(${curlBin} -s http://127.0.0.1:15000/default/nix-cache-info)
      echo "$CACHE_INFO" | ${grepBin} -q "content-range" || \
        { echo "FAIL: content-range not in capabilities"; FAIL=1; }

      ${stopServer}

      if [ "$FAIL" -ne 0 ]; then
        echo "==> cache-resume FAILED"
        exit 1
      fi
      echo "==> cache-resume passed"
    '';
  };
}
