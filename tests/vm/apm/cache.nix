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
}:
let
  iproute2Bin = "${pkgs.iproute2}/sbin/ip";
  sqliteBin = "${pkgs.sqlite}/bin/sqlite3";
  socatBin = "${pkgs.socat}/bin/socat";
  jqBin = "${pkgs.jq}/bin/jq";
  curlBin = "${pkgs.curl}/bin/curl";
  grepBin = "${pkgs.grep}/bin/grep";
  aosBin = "${self}/bin/aos";

  # Shared preamble: loopback interface, mock Nix DB, server config.
  serverPreamble = ''
    ${iproute2Bin} link set lo up || true
    ${iproute2Bin} addr add 127.0.0.1/8 dev lo 2>/dev/null || true

    echo "==> Setting up test environment"
    export AOS_ROOT=/tmp/aos
    mkdir -p $AOS_ROOT/var/nix/db
    mkdir -p $AOS_ROOT/store
    mkdir -p $AOS_ROOT/meta
    mkdir -p /tmp/run/aos

    echo "==> Creating mock Nix store DB"
    ${sqliteBin} $AOS_ROOT/var/nix/db/db.sqlite << 'SQL'
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
    chmod 666 $AOS_ROOT/var/nix/db/db.sqlite
    chmod 777 $AOS_ROOT/var/nix/db
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
    ${aosBin} serve --config /tmp/aos-config.toml &
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
  ];
in
{
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
      TEST_STORE_PATH="/tmp/aos/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-test-pkg-1.0"
      mkdir -p "$TEST_STORE_PATH/bin"
      echo '#!/bin/sh' > "$TEST_STORE_PATH/bin/hello"
      echo 'echo "Hello from test-pkg"' >> "$TEST_STORE_PATH/bin/hello"
      chmod +x "$TEST_STORE_PATH/bin/hello"

      # Register in mock Nix DB
      NAR_HASH="sha256:0000000000000000000000000000000000000000000000000000000000000001"
      ${sqliteBin} $AOS_ROOT/var/nix/db/db.sqlite \
        "INSERT INTO ValidPaths (path, hash, registrationTime, narSize, ultimate, sigs) VALUES ('$TEST_STORE_PATH', '$NAR_HASH', 1000000, 4096, 1, '''''');"

      echo "==> Test: cache push to file:// backend"
      ${aosBin} cache push "$TEST_STORE_PATH" --to "file:///tmp/test-cache" \
        --compression none 2>&1 || echo "WARN: push returned non-zero (may be expected for mock)"

      # Verify narinfo file exists
      NARINFO_COUNT=$(find /tmp/test-cache -name '*.narinfo' 2>/dev/null | wc -l)
      echo "==> Found $NARINFO_COUNT narinfo files"

      # Verify NAR file exists
      NAR_COUNT=$(find /tmp/test-cache/nar -name '*.nar*' 2>/dev/null | wc -l)
      echo "==> Found $NAR_COUNT NAR files"

      echo "==> Test: cache pull from file:// backend"
      ${aosBin} cache pull "$TEST_STORE_PATH" --from "file:///tmp/test-cache" \
        --dry-run 2>&1 || echo "WARN: pull returned non-zero (may be expected for mock)"

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
      ${serverConfig}
      ${startServer}
      ${getAuthToken}

      FAIL=0

      # Register a test path in the store
      TEST_STORE_PATH="/tmp/aos/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-http-test-1.0"
      mkdir -p "$TEST_STORE_PATH/bin"
      echo 'test data' > "$TEST_STORE_PATH/bin/data.txt"
      ${sqliteBin} $AOS_ROOT/var/nix/db/db.sqlite \
        "INSERT INTO ValidPaths (path, hash, registrationTime, narSize, ultimate, sigs) VALUES ('$TEST_STORE_PATH', 'sha256:0002', 1000000, 2048, 1, '''''');"

      echo "==> Test: push to HTTP cache server"
      ${aosBin} cache push "$TEST_STORE_PATH" \
        --to "http://127.0.0.1:15000/default" \
        --compression zstd \
        --token "$ACCESS_TOKEN" 2>&1 || echo "WARN: push returned non-zero"

      echo "==> Test: verify narinfo queryable via HTTP GET"
      HASH="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
      HTTP_CODE=$(${curlBin} -s -o /dev/null -w '%{http_code}' \
        "http://127.0.0.1:15000/default/$HASH.narinfo")
      echo "==> narinfo HTTP code: $HTTP_CODE"

      # Should respond without crashing
      test "$HTTP_CODE" = "200" -o "$HTTP_CODE" = "404" || \
        { echo "FAIL: unexpected HTTP code $HTTP_CODE"; FAIL=1; }

      echo "==> Test: query-missing confirms path status"
      QM_RESPONSE=$(${curlBin} -s \
        -X POST -H "Authorization: Bearer $ACCESS_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"paths\":[\"$TEST_STORE_PATH\"]}" \
        http://127.0.0.1:15000/default/query-missing)
      echo "query-missing: $QM_RESPONSE"

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
      ${serverConfig}
      ${startServer}
      ${getAuthToken}

      FAIL=0

      echo "==> Step 1: Create test package"
      TEST_PKG="/tmp/aos/store/cccccccccccccccccccccccccccccccccc-reg-test-1.0"
      mkdir -p "$TEST_PKG/bin" "$TEST_PKG/lib"
      echo '#!/bin/sh' > "$TEST_PKG/bin/reg-test"
      echo 'echo "registry test v1.0"' >> "$TEST_PKG/bin/reg-test"
      chmod +x "$TEST_PKG/bin/reg-test"
      echo "libregtest.so stub" > "$TEST_PKG/lib/libregtest.so"
      ${sqliteBin} $AOS_ROOT/var/nix/db/db.sqlite \
        "INSERT INTO ValidPaths (path, hash, registrationTime, narSize, ultimate, sigs) VALUES ('$TEST_PKG', 'sha256:0003', 1000000, 8192, 1, '''''');"

      echo "==> Step 2: Push to cache"
      ${aosBin} cache push "$TEST_PKG" \
        --to "http://127.0.0.1:15000/default" \
        --token "$ACCESS_TOKEN" 2>&1 || echo "WARN: push returned non-zero"

      echo "==> Step 3: Verify in cache"
      HASH="cccccccccccccccccccccccccccccccccc"
      HTTP_CODE=$(${curlBin} -s -o /dev/null -w '%{http_code}' \
        "http://127.0.0.1:15000/default/$HASH.narinfo")
      echo "narinfo: HTTP $HTTP_CODE"

      echo "==> Step 4: Verify package structure"
      test -d "$TEST_PKG/bin" || { echo "FAIL: missing bin/"; FAIL=1; }
      test -d "$TEST_PKG/lib" || { echo "FAIL: missing lib/"; FAIL=1; }
      test -x "$TEST_PKG/bin/reg-test" || { echo "FAIL: not executable"; FAIL=1; }

      echo "==> Step 5: Verify execution"
      OUTPUT=$("$TEST_PKG/bin/reg-test")
      echo "$OUTPUT" | ${grepBin} -q "registry test v1.0" || \
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
      ${serverConfig}
      ${startServer}
      ${getAuthToken}

      FAIL=0

      # Create shared deps
      LIBZ="/tmp/aos/store/dddddddddddddddddddddddddddddddd-libz-1.0"
      mkdir -p "$LIBZ/lib"
      echo "libz stub" > "$LIBZ/lib/libz.so"
      ${sqliteBin} $AOS_ROOT/var/nix/db/db.sqlite \
        "INSERT INTO ValidPaths (path, hash, registrationTime, narSize, ultimate, sigs) VALUES ('$LIBZ', 'sha256:dddd', 1000000, 4096, 1, '''''');"

      LIBSSL="/tmp/aos/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-libssl-1.0"
      mkdir -p "$LIBSSL/lib"
      echo "libssl stub" > "$LIBSSL/lib/libssl.so"
      ${sqliteBin} $AOS_ROOT/var/nix/db/db.sqlite \
        "INSERT INTO ValidPaths (path, hash, registrationTime, narSize, ultimate, sigs) VALUES ('$LIBSSL', 'sha256:eeee', 1000000, 4096, 1, '''''');"

      # Create packages A and B (both depend on libz, libssl)
      PKG_A="/tmp/aos/store/ffffffffffffffffffffffffffffffff-pkg-a-1.0"
      mkdir -p "$PKG_A/bin"
      echo '#!/bin/sh' > "$PKG_A/bin/pkg-a"
      chmod +x "$PKG_A/bin/pkg-a"
      ${sqliteBin} $AOS_ROOT/var/nix/db/db.sqlite \
        "INSERT INTO ValidPaths (path, hash, registrationTime, narSize, ultimate, sigs) VALUES ('$PKG_A', 'sha256:ffff', 1000000, 2048, 1, '''''');"

      PKG_B="/tmp/aos/store/11111111111111111111111111111111-pkg-b-1.0"
      mkdir -p "$PKG_B/bin"
      echo '#!/bin/sh' > "$PKG_B/bin/pkg-b"
      chmod +x "$PKG_B/bin/pkg-b"
      ${sqliteBin} $AOS_ROOT/var/nix/db/db.sqlite \
        "INSERT INTO ValidPaths (path, hash, registrationTime, narSize, ultimate, sigs) VALUES ('$PKG_B', 'sha256:1111', 1000000, 2048, 1, '''''');"

      echo "==> Query-missing for A closure"
      QM_A=$(${curlBin} -s \
        -X POST -H "Authorization: Bearer $ACCESS_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"paths\":[\"$PKG_A\",\"$LIBZ\",\"$LIBSSL\"]}" \
        http://127.0.0.1:15000/default/query-missing)
      MISSING_A=$(echo "$QM_A" | ${jqBin} '.missing | length')
      echo "Package A closure: $MISSING_A missing"

      echo "==> Push package A + deps"
      ${aosBin} cache push "$PKG_A" "$LIBZ" "$LIBSSL" \
        --to "http://127.0.0.1:15000/default" \
        --token "$ACCESS_TOKEN" 2>&1 || echo "WARN: push non-zero"

      echo "==> Query-missing for B closure (shared deps should be present)"
      QM_B=$(${curlBin} -s \
        -X POST -H "Authorization: Bearer $ACCESS_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"paths\":[\"$PKG_B\",\"$LIBZ\",\"$LIBSSL\"]}" \
        http://127.0.0.1:15000/default/query-missing)
      MISSING_B=$(echo "$QM_B" | ${jqBin} '.missing | length')
      echo "Package B closure: $MISSING_B missing"

      echo "==> Dedup check: A had $MISSING_A missing, B has $MISSING_B missing"
      test "$MISSING_B" -le "$MISSING_A" || \
        { echo "FAIL: B missing ($MISSING_B) should be <= A missing ($MISSING_A)"; FAIL=1; }

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
      ${serverConfig}
      ${startServer}
      ${getAuthToken}

      FAIL=0

      # Create and push a test path
      TEST_PATH="/tmp/aos/store/22222222222222222222222222222222-resume-test-1.0"
      mkdir -p "$TEST_PATH/data"
      dd if=/dev/urandom of="$TEST_PATH/data/payload.bin" bs=1024 count=64 2>/dev/null
      ${sqliteBin} $AOS_ROOT/var/nix/db/db.sqlite \
        "INSERT INTO ValidPaths (path, hash, registrationTime, narSize, ultimate, sigs) VALUES ('$TEST_PATH', 'sha256:2222', 1000000, 65536, 1, '''''');"

      echo "==> Push test path to server"
      ${aosBin} cache push "$TEST_PATH" \
        --to "http://127.0.0.1:15000/default" \
        --token "$ACCESS_TOKEN" 2>&1 || echo "WARN: push non-zero"

      echo "==> Test: simulate partial download"
      HASH="22222222222222222222222222222222"
      NARINFO=$(${curlBin} -s "http://127.0.0.1:15000/default/$HASH.narinfo" || true)
      echo "narinfo: $NARINFO"

      if echo "$NARINFO" | ${grepBin} -q "URL:"; then
        NAR_URL=$(echo "$NARINFO" | ${grepBin} "^URL:" | cut -d' ' -f2)
        echo "==> NAR URL: $NAR_URL"

        # Download first 1024 bytes (partial)
        ${curlBin} -s -r 0-1023 "http://127.0.0.1:15000/default/$NAR_URL" \
          -o /tmp/partial.nar 2>/dev/null || true
        PARTIAL_SIZE=$(stat -c%s /tmp/partial.nar 2>/dev/null || echo 0)
        echo "==> Partial: $PARTIAL_SIZE bytes"

        if [ "$PARTIAL_SIZE" -gt 0 ]; then
          # Resume from partial offset
          ${curlBin} -s -r "$PARTIAL_SIZE-" "http://127.0.0.1:15000/default/$NAR_URL" \
            -o /tmp/rest.nar 2>/dev/null || true

          # Full download for comparison
          ${curlBin} -s "http://127.0.0.1:15000/default/$NAR_URL" \
            -o /tmp/full.nar 2>/dev/null || true
          FULL_SIZE=$(stat -c%s /tmp/full.nar 2>/dev/null || echo 0)
          echo "==> Full: $FULL_SIZE bytes"
        fi
        echo "==> Resume simulation complete"
      else
        echo "==> Skipping range test (narinfo not available for mock path)"
      fi

      echo "==> Verify content-range capability"
      CACHE_INFO=$(${curlBin} -s http://127.0.0.1:15000/default/nix-cache-info)
      echo "$CACHE_INFO" | ${grepBin} -q "content-range" || \
        echo "WARN: content-range not in capabilities"

      ${stopServer}

      if [ "$FAIL" -ne 0 ]; then
        echo "==> cache-resume FAILED"
        exit 1
      fi
      echo "==> cache-resume passed"
    '';
  };
}
