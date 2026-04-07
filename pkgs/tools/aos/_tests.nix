# pkgs/tools/aos/_tests.nix — Integration tests for the aos CLI and cache server
#
# Prefixed with _ so discoverPackages skips it (not a package).
# Called from aos.nix via: import ./_tests.nix { inherit testing self pkgs; }
{
  testing,
  self,
  pkgs,
}:
let
  # Shared preamble for server tests: bring up loopback, create mock Nix DB,
  # write server config, start aos serve in background.
  serverPreamble = ''
    # Bring up loopback interface (needed for 127.0.0.1 binding)
    ${pkgs.iproute2}/sbin/ip link set lo up
    ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo

    # Use /tmp (tmpfs, writable) for all server state.
    # The rootfs is mounted read-only so /run and other paths on the
    # root filesystem are not writable.
    export AOS_ROOT=/tmp/aos
    mkdir -p $AOS_ROOT/var/nix/db
    mkdir -p $AOS_ROOT/store
    mkdir -p $AOS_ROOT/meta
    mkdir -p /tmp/run/aos

    # Create a minimal SQLite DB matching the Nix schema
    ${pkgs.sqlite}/bin/sqlite3 $AOS_ROOT/var/nix/db/db.sqlite << 'SQL'
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
  '';

  # Common rootfsDeps for server tests
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
  # CLI basics
  # ---------------------------------------------------------------------------

  help = testing.mkVMTest {
    name = "aos-help";
    rootfsDeps = [ self ];
    memory = 1024;
    testScript = ''
      echo "==> Testing aos --help"
      ${self}/bin/aos --help
      echo "==> aos --help passed"
    '';
  };

  version = testing.mkVMTest {
    name = "aos-describe";
    rootfsDeps = [
      self
      pkgs.git
    ];
    testScript = ''
      echo "==> Testing aos describe"
      ${self}/bin/aos describe
      echo "==> aos describe passed"
    '';
  };

  fmt-check = testing.mkVMTest {
    name = "aos-fmt-check";
    rootfsDeps = [
      self
    ];
    testScript = ''
      mkdir -p /tmp/proj
      cat > /tmp/proj/test.nix << 'EOF'
      { pkgs }: pkgs.hello
      EOF

      echo "==> Testing aos fmt --check on valid file"
      ${self}/bin/aos fmt --check /tmp/proj/test.nix
      echo "==> aos fmt --check passed"
    '';
  };

  # ---------------------------------------------------------------------------
  # Cache server — startup, HTTP endpoints, token management
  # ---------------------------------------------------------------------------

  server-startup = testing.mkVMTest {
    name = "aos-server-startup";
    rootfsDeps = serverDeps;
    memory = 1024;
    testScript = ''
      ${serverPreamble}

      cat > /tmp/aos-config.toml << 'EOF'
      listen = "127.0.0.1:15000"

      [[views]]
      name = "test"
      anonymous_read = true

      [bootstrap]
      socket = "/tmp/run/aos/bootstrap.sock"
      socket_group = "root"
      EOF

      # Start server and verify it responds
      ${self}/bin/aos serve --config /tmp/aos-config.toml &
      SERVER_PID=$!
      sleep 2

      HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
        http://127.0.0.1:15000/test/nix-cache-info)
      echo "==> nix-cache-info HTTP code: $HTTP_CODE"

      kill $SERVER_PID 2>/dev/null || true
      wait $SERVER_PID 2>/dev/null || true

      test "$HTTP_CODE" = "200" || { echo "FAIL: expected 200, got $HTTP_CODE"; exit 1; }
      echo "==> Server startup test passed"
    '';
  };

  cache-info = testing.mkVMTest {
    name = "aos-cache-info";
    rootfsDeps = serverDeps;
    memory = 1024;
    testScript = ''
      ${serverPreamble}

      cat > /tmp/aos-config.toml << 'EOF'
      listen = "127.0.0.1:15000"

      [[views]]
      name = "test"
      anonymous_read = true
      max_concurrent_builds = 2

      [bootstrap]
      socket = "/tmp/run/aos/bootstrap.sock"
      socket_group = "root"
      EOF

      # Start the server
      ${self}/bin/aos serve --config /tmp/aos-config.toml &
      SERVER_PID=$!
      sleep 2

      FAIL=0

      # Test 1: nix-cache-info returns 200 with expected fields
      echo "==> Test: nix-cache-info endpoint"
      BODY=$(curl -sf http://127.0.0.1:15000/test/nix-cache-info)
      echo "$BODY"

      echo "$BODY" | grep -q "StoreDir:" || { echo "FAIL: missing StoreDir"; FAIL=1; }
      echo "$BODY" | grep -q "WantMassQuery:" || { echo "FAIL: missing WantMassQuery"; FAIL=1; }
      echo "$BODY" | grep -q "Capabilities:" || { echo "FAIL: missing Capabilities"; FAIL=1; }
      echo "$BODY" | grep -q "pack-upload" || { echo "FAIL: missing pack-upload capability"; FAIL=1; }
      echo "$BODY" | grep -q "sse-logs" || { echo "FAIL: missing sse-logs capability"; FAIL=1; }

      # Test 2: unknown view returns 404
      echo "==> Test: unknown view returns 404"
      HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
        http://127.0.0.1:15000/nonexistent/nix-cache-info)
      test "$HTTP_CODE" = "404" || { echo "FAIL: expected 404, got $HTTP_CODE"; FAIL=1; }

      # Test 3: narinfo for non-existent path returns 404
      echo "==> Test: narinfo for missing path returns 404"
      HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
        http://127.0.0.1:15000/test/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.narinfo)
      test "$HTTP_CODE" = "404" || { echo "FAIL: expected 404, got $HTTP_CODE"; FAIL=1; }

      # Test 4: query-missing without auth returns 401
      echo "==> Test: query-missing requires auth"
      HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
        -X POST -H 'Content-Type: application/json' \
        -d '{"paths":[]}' \
        http://127.0.0.1:15000/test/query-missing)
      test "$HTTP_CODE" = "401" || { echo "FAIL: expected 401, got $HTTP_CODE"; FAIL=1; }

      # Test 5: build endpoint without auth returns 401
      echo "==> Test: build endpoint requires auth"
      HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
        -X POST http://127.0.0.1:15000/test/build?drv=/nix/store/fake.drv)
      test "$HTTP_CODE" = "401" || { echo "FAIL: expected 401, got $HTTP_CODE"; FAIL=1; }

      # Test 6: oauth2 token endpoint without credentials returns 401
      echo "==> Test: token exchange requires credentials"
      HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
        -X POST http://127.0.0.1:15000/oauth2/token)
      test "$HTTP_CODE" = "401" || { echo "FAIL: expected 401, got $HTTP_CODE"; FAIL=1; }

      kill $SERVER_PID 2>/dev/null || true
      wait $SERVER_PID 2>/dev/null || true

      if [ "$FAIL" -ne 0 ]; then
        echo "==> Cache protocol tests FAILED"
        exit 1
      fi
      echo "==> All cache protocol tests passed"
    '';
  };

  token-management = testing.mkVMTest {
    name = "aos-token-management";
    rootfsDeps = serverDeps;
    memory = 1024;
    testScript = ''
      ${serverPreamble}

      cat > /tmp/aos-config.toml << 'EOF'
      listen = "127.0.0.1:15000"

      [[views]]
      name = "test"
      anonymous_read = true
      max_concurrent_builds = 2

      [bootstrap]
      socket = "/tmp/run/aos/bootstrap.sock"
      socket_group = "root"
      EOF

      # Start the server
      ${self}/bin/aos serve --config /tmp/aos-config.toml &
      SERVER_PID=$!
      sleep 2

      FAIL=0

      # Test 1: Create a token via bootstrap socket
      echo "==> Test: create token via bootstrap socket"
      RESPONSE=$(echo '{"command":"create","views":["test"],"permissions":["read","build"],"comment":"integration test"}' | \
        ${pkgs.socat}/bin/socat - UNIX-CONNECT:/tmp/run/aos/bootstrap.sock)
      echo "Create response: $RESPONSE"

      TOKEN=$(echo "$RESPONSE" | ${pkgs.jq}/bin/jq -r '.token // empty')
      TOKEN_ID=$(echo "$RESPONSE" | ${pkgs.jq}/bin/jq -r '.id // empty')

      test -n "$TOKEN" || { echo "FAIL: no token in create response"; FAIL=1; }
      test -n "$TOKEN_ID" || { echo "FAIL: no token ID in create response"; FAIL=1; }
      echo "==> Token created: id=$TOKEN_ID"

      # Test 2: List tokens via bootstrap socket
      echo "==> Test: list tokens via bootstrap socket"
      LIST_RESPONSE=$(echo '{"command":"list"}' | \
        ${pkgs.socat}/bin/socat - UNIX-CONNECT:/tmp/run/aos/bootstrap.sock)
      echo "List response: $LIST_RESPONSE"

      COUNT=$(echo "$LIST_RESPONSE" | ${pkgs.jq}/bin/jq '.tokens | length')
      test "$COUNT" -ge 1 || { echo "FAIL: expected at least 1 token, got $COUNT"; FAIL=1; }

      # Test 3: Exchange token for JWT via oauth2 endpoint
      echo "==> Test: exchange token for JWT"
      JWT_RESPONSE=$(curl -sf \
        -X POST \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials" \
        http://127.0.0.1:15000/oauth2/token)
      echo "JWT response: $JWT_RESPONSE"

      ACCESS_TOKEN=$(echo "$JWT_RESPONSE" | ${pkgs.jq}/bin/jq -r '.access_token // empty')
      test -n "$ACCESS_TOKEN" || { echo "FAIL: no access_token in JWT response"; FAIL=1; }
      echo "==> Got JWT access token"

      # Test 4: Use JWT to call authenticated endpoint (query-missing)
      echo "==> Test: query-missing with JWT auth"
      QM_RESPONSE=$(curl -sf \
        -X POST \
        -H "Authorization: Bearer $ACCESS_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"paths":["/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-fake"]}' \
        http://127.0.0.1:15000/test/query-missing)
      echo "query-missing response: $QM_RESPONSE"

      MISSING=$(echo "$QM_RESPONSE" | ${pkgs.jq}/bin/jq '.missing | length')
      test "$MISSING" -eq 1 || { echo "FAIL: expected 1 missing path, got $MISSING"; FAIL=1; }

      # Test 5: Revoke token via bootstrap socket
      echo "==> Test: revoke token via bootstrap socket"
      REVOKE_RESPONSE=$(echo "{\"command\":\"revoke\",\"token_id\":\"$TOKEN_ID\"}" | \
        ${pkgs.socat}/bin/socat - UNIX-CONNECT:/tmp/run/aos/bootstrap.sock)
      echo "Revoke response: $REVOKE_RESPONSE"

      # Test 6: Revoked token should fail JWT exchange
      echo "==> Test: revoked token rejected"
      HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
        -X POST \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials" \
        http://127.0.0.1:15000/oauth2/token)
      test "$HTTP_CODE" = "401" || { echo "FAIL: expected 401 after revoke, got $HTTP_CODE"; FAIL=1; }

      kill $SERVER_PID 2>/dev/null || true
      wait $SERVER_PID 2>/dev/null || true

      if [ "$FAIL" -ne 0 ]; then
        echo "==> Token management tests FAILED"
        exit 1
      fi
      echo "==> All token management tests passed"
    '';
  };

  auth-enforcement = testing.mkVMTest {
    name = "aos-auth-enforcement";
    rootfsDeps = serverDeps;
    memory = 1024;
    testScript = ''
      ${serverPreamble}

      # Configure two views: "public" (anon read) and "private" (no anon read)
      cat > /tmp/aos-config.toml << 'EOF'
      listen = "127.0.0.1:15000"

      [[views]]
      name = "public"
      anonymous_read = true

      [[views]]
      name = "private"
      anonymous_read = false

      [bootstrap]
      socket = "/tmp/run/aos/bootstrap.sock"
      socket_group = "root"
      EOF

      ${self}/bin/aos serve --config /tmp/aos-config.toml &
      SERVER_PID=$!
      sleep 2

      FAIL=0

      # Test 1: Public view allows anonymous cache-info
      echo "==> Test: public view anonymous read"
      HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
        http://127.0.0.1:15000/public/nix-cache-info)
      test "$HTTP_CODE" = "200" || { echo "FAIL: expected 200 for public cache-info, got $HTTP_CODE"; FAIL=1; }

      # Test 2: Private view denies anonymous cache-info
      echo "==> Test: private view requires auth"
      HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
        http://127.0.0.1:15000/private/nix-cache-info)
      test "$HTTP_CODE" = "401" || { echo "FAIL: expected 401 for private cache-info, got $HTTP_CODE"; FAIL=1; }

      # Test 3: Create token scoped to "public" only
      echo "==> Test: view-scoped token"
      RESPONSE=$(echo '{"command":"create","views":["public"],"permissions":["read","build"]}' | \
        ${pkgs.socat}/bin/socat - UNIX-CONNECT:/tmp/run/aos/bootstrap.sock)
      TOKEN=$(echo "$RESPONSE" | ${pkgs.jq}/bin/jq -r '.token')

      JWT_RESPONSE=$(curl -sf \
        -X POST -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials" \
        http://127.0.0.1:15000/oauth2/token)
      ACCESS_TOKEN=$(echo "$JWT_RESPONSE" | ${pkgs.jq}/bin/jq -r '.access_token')

      # Test 4: Token can access authorized view
      echo "==> Test: token can access authorized view"
      HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
        -X POST -H "Authorization: Bearer $ACCESS_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"paths":[]}' \
        http://127.0.0.1:15000/public/query-missing)
      test "$HTTP_CODE" = "200" || { echo "FAIL: expected 200 for authorized view, got $HTTP_CODE"; FAIL=1; }

      # Test 5: Token cannot access unauthorized view
      echo "==> Test: token rejected for unauthorized view"
      HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
        -X POST -H "Authorization: Bearer $ACCESS_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"paths":[]}' \
        http://127.0.0.1:15000/private/query-missing)
      test "$HTTP_CODE" = "403" || { echo "FAIL: expected 403 for unauthorized view, got $HTTP_CODE"; FAIL=1; }

      # Test 6: Create read-only token (no build permission)
      echo "==> Test: read-only token cannot upload"
      RESPONSE2=$(echo '{"command":"create","views":["public"],"permissions":["read"]}' | \
        ${pkgs.socat}/bin/socat - UNIX-CONNECT:/tmp/run/aos/bootstrap.sock)
      TOKEN2=$(echo "$RESPONSE2" | ${pkgs.jq}/bin/jq -r '.token')

      JWT2_RESPONSE=$(curl -sf \
        -X POST -H "Authorization: Bearer $TOKEN2" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials" \
        http://127.0.0.1:15000/oauth2/token)
      ACCESS_TOKEN2=$(echo "$JWT2_RESPONSE" | ${pkgs.jq}/bin/jq -r '.access_token')

      HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
        -X PUT -H "Authorization: Bearer $ACCESS_TOKEN2" \
        -H "Content-Type: application/octet-stream" \
        -d 'fake-nar-data' \
        http://127.0.0.1:15000/public/store/fakehash)
      test "$HTTP_CODE" = "403" || { echo "FAIL: expected 403 for read-only upload, got $HTTP_CODE"; FAIL=1; }

      kill $SERVER_PID 2>/dev/null || true
      wait $SERVER_PID 2>/dev/null || true

      if [ "$FAIL" -ne 0 ]; then
        echo "==> Auth enforcement tests FAILED"
        exit 1
      fi
      echo "==> All auth enforcement tests passed"
    '';
  };

  drain = testing.mkVMTest {
    name = "aos-drain";
    rootfsDeps = serverDeps;
    memory = 1024;
    testScript = ''
      ${serverPreamble}

      cat > /tmp/aos-config.toml << 'EOF'
      listen = "127.0.0.1:15000"

      [[views]]
      name = "test"
      anonymous_read = true

      [bootstrap]
      socket = "/tmp/run/aos/bootstrap.sock"
      socket_group = "root"
      EOF

      ${self}/bin/aos serve --config /tmp/aos-config.toml &
      SERVER_PID=$!
      sleep 2

      FAIL=0

      # Verify server is responding
      echo "==> Verify server is up"
      HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
        http://127.0.0.1:15000/test/nix-cache-info)
      test "$HTTP_CODE" = "200" || { echo "FAIL: server not responding"; FAIL=1; }

      # Get a token for build requests
      RESPONSE=$(echo '{"command":"create","views":["test"],"permissions":["read","build"]}' | \
        ${pkgs.socat}/bin/socat - UNIX-CONNECT:/tmp/run/aos/bootstrap.sock)
      TOKEN=$(echo "$RESPONSE" | ${pkgs.jq}/bin/jq -r '.token')
      JWT_RESPONSE=$(curl -sf \
        -X POST -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials" \
        http://127.0.0.1:15000/oauth2/token)
      ACCESS_TOKEN=$(echo "$JWT_RESPONSE" | ${pkgs.jq}/bin/jq -r '.access_token')

      # Send SIGTERM to trigger drain
      echo "==> Sending SIGTERM to trigger drain"
      kill -TERM $SERVER_PID

      # Give drain time to activate
      sleep 1

      # Build requests during drain should return 503
      echo "==> Test: build rejected during drain"
      HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
        -X POST -H "Authorization: Bearer $ACCESS_TOKEN" \
        http://127.0.0.1:15000/test/build?drv=/nix/store/fake.drv)
      # Server may have already shut down (no in-flight builds to drain)
      if [ "$HTTP_CODE" = "503" ] || [ "$HTTP_CODE" = "000" ]; then
        echo "==> Drain behavior correct (HTTP $HTTP_CODE)"
      else
        echo "FAIL: expected 503 or connection refused during drain, got $HTTP_CODE"
        FAIL=1
      fi

      wait $SERVER_PID 2>/dev/null || true

      if [ "$FAIL" -ne 0 ]; then
        echo "==> Drain tests FAILED"
        exit 1
      fi
      echo "==> All drain tests passed"
    '';
  };
}
