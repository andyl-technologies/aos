# pkgs/tools/aos/_tests.nix — Integration tests for the aos CLI and cache server
#
# Prefixed with _ so discoverPackages skips it (not a package).
# Called from aos.nix via: import ./_tests.nix { inherit testing self pkgs; }
{
  testing,
  self,
  pkgs,
}: let
  # Shared preamble for server tests: bring up loopback, create mock Nix DB,
  # write server config, start aos serve in background.
  serverPreamble = ''
    # Bring up loopback interface (needed for 127.0.0.1 binding)
    ${pkgs.iproute2}/sbin/ip link set lo up || true
    ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true

    # Use /tmp (tmpfs, writable) for all server state.
    # The rootfs is mounted read-only so /run and other paths on the
    # root filesystem are not writable.
    echo "==> Setting up test environment"
    export AOS_ROOT=/tmp/aos
    mkdir -p $AOS_ROOT/var/nix/db
    mkdir -p $AOS_ROOT/store
    mkdir -p $AOS_ROOT/meta
    mkdir -p /tmp/run/aos

    # Create a minimal SQLite DB matching the Nix schema
    echo "==> Creating mock Nix store DB"
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
    echo "==> Test environment ready"
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
in {
  # ---------------------------------------------------------------------------
  # CLI basics
  # ---------------------------------------------------------------------------

  help = testing.mkVMTest {
    name = "aos-help";
    rootfsDeps = [self];
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

  host-apr-apm-command-surface = pkgs.mkDerivation {
    pname = "aos-host-apr-apm-command-surface";
    version = "0";
    src = null;

    buildDeps = [
      self
      pkgs.coreutils
      pkgs.git
      pkgs.grep
    ];

    phases = [
      {
        name = "check";
        script = ''
          set -eu

          work="$TMPDIR/aos-host-command-surface"
          home="$work/home"
          config="$work/config"
          data="$work/share"
          cache="$work/cache"
          mkdir -p "$home" "$config" "$data" "$cache"

          run_clean() {
            env -i \
              HOME="$home" \
              XDG_CONFIG_HOME="$config" \
              XDG_DATA_HOME="$data" \
              XDG_CACHE_HOME="$cache" \
              GIT_CONFIG_NOSYSTEM=1 \
              GIT_AUTHOR_NAME="Host Command Test" \
              GIT_AUTHOR_EMAIL="host-command@example.invalid" \
              GIT_COMMITTER_NAME="Host Command Test" \
              GIT_COMMITTER_EMAIL="host-command@example.invalid" \
              PATH="${pkgs.coreutils}/bin:${pkgs.git}/bin" \
              "$@"
          }

          run_clean ${self}/bin/apr --help > "$work/apr-help.out"
          grep -q "Usage:" "$work/apr-help.out"
          run_clean ${self}/bin/apm --help > "$work/apm-help.out"
          grep -q "Usage:" "$work/apm-help.out"

          run_clean ${self}/bin/apr create host-reg > "$work/apr-create.out" 2>&1
          reg="$data/apm/registries/host-reg"
          test -f "$reg/registry.toml"
          test -d "$reg/.git"

          git -C "$reg" log -1 --format=%an > "$work/author-name.out"
          git -C "$reg" log -1 --format=%ae > "$work/author-email.out"
          grep -qx "Host Command Test" "$work/author-name.out"
          grep -qx "host-command@example.invalid" "$work/author-email.out"

          run_clean ${self}/bin/apr status --registry host-reg > "$work/apr-status.out" 2>&1
          if grep -q '[^[:space:]]' "$work/apr-status.out"; then
            cat "$work/apr-status.out"
            exit 1
          fi
          run_clean ${self}/bin/apr branch create host-feature --registry host-reg > "$work/apr-branch-create.out" 2>&1
          grep -q "Created branch 'host-feature'" "$work/apr-branch-create.out"
          run_clean ${self}/bin/apr branch switch host-feature --registry host-reg > "$work/apr-branch-switch.out" 2>&1
          grep -q "Switched to branch 'host-feature'" "$work/apr-branch-switch.out"
          run_clean ${self}/bin/apr branch switch stable --registry host-reg > "$work/apr-branch-switch-stable.out" 2>&1
          grep -q "Switched to branch 'stable'" "$work/apr-branch-switch-stable.out"

          pkg_hash="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
          mkdir -p "$reg/packages/h" "$reg/closures"
          printf '%s\n' \
            '[package]' \
            'name = "hostpkg"' \
            'description = "Host-authored package metadata"' \
            'homepage = "https://example.invalid/hostpkg"' \
            'license = "MIT"' \
            'maintainer = "host@example.invalid"' \
            "" \
            '[[versions]]' \
            'version = "1.0.0"' \
            "" \
            '[versions.platforms.x86_64-linux]' \
            "store_path = \"/nix/store/$pkg_hash-hostpkg-1.0.0\"" \
            'nar_hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="' \
            'nar_size = 1234' \
            'closure_size = 1234' \
            'source_drv = ""' \
            'source_nar_hash = ""' \
            'references = []' \
            > "$reg/packages/h/hostpkg.toml"
          printf '%s\n' "$pkg_hash" > "$reg/closures/$pkg_hash"
          printf '%s\n' \
            "" \
            '[[caches]]' \
            'url = "https://cache.example.invalid/host"' \
            'priority = 42' \
            >> "$reg/registry.toml"

          run_clean ${self}/bin/apr status --registry host-reg > "$work/apr-status-dirty.out" 2>&1
          grep -q "registry.toml" "$work/apr-status-dirty.out"
          grep -q "packages/h/hostpkg.toml" "$work/apr-status-dirty.out"
          grep -q "closures/$pkg_hash" "$work/apr-status-dirty.out"

          run_clean ${self}/bin/apr diff --registry host-reg --stat > "$work/apr-diff-stat.out" 2>&1
          grep -q "registry.toml" "$work/apr-diff-stat.out"

          git -C "$reg" add -A
          git -C "$reg" commit -m "release: hostpkg 1.0.0" > "$work/git-commit-package.out" 2>&1

          run_clean ${self}/bin/apr packages --registry host-reg > "$work/apr-packages.out" 2>&1
          grep -q "hostpkg 1.0.0" "$work/apr-packages.out"
          run_clean ${self}/bin/apr show hostpkg --registry host-reg > "$work/apr-show.out" 2>&1
          grep -q "Host-authored package metadata" "$work/apr-show.out"
          run_clean ${self}/bin/apr show hostpkg --registry host-reg --raw > "$work/apr-show-raw.out" 2>&1
          grep -q "store_path = \"/nix/store/$pkg_hash-hostpkg-1.0.0\"" "$work/apr-show-raw.out"
          run_clean ${self}/bin/apr verify --registry host-reg > "$work/apr-verify.out" 2>&1
          grep -q "Verified 1 package(s), 1 closure(s), no errors" "$work/apr-verify.out"
          run_clean ${self}/bin/apr log --registry host-reg --package hostpkg -n 1 > "$work/apr-log-package.out" 2>&1
          grep -q "release: hostpkg 1.0.0" "$work/apr-log-package.out"

          git init --bare --object-format=sha256 "$work/host-origin.git" > "$work/git-init-origin.out" 2>&1
          git -C "$reg" remote add origin "$work/host-origin.git"
          run_clean ${self}/bin/apr push --registry host-reg --branch stable --set-upstream > "$work/apr-push.out" 2>&1
          grep -q "Pushed." "$work/apr-push.out"
          run_clean ${self}/bin/apr diff --registry host-reg --remote --stat > "$work/apr-diff-remote.out" 2>&1
          grep -q "No pending changes" "$work/apr-diff-remote.out"

          run_clean ${self}/bin/apm registry add "file://$reg" --name host-reg-client > "$work/apm-registry-add.out" 2>&1
          grep -q "Registry 'host-reg-client' added" "$work/apm-registry-add.out"
          run_clean ${self}/bin/apm registry list > "$work/apm-registry-list.out" 2>&1
          grep -q "host-reg-client" "$work/apm-registry-list.out"
          run_clean ${self}/bin/apm search hostpkg --registry host-reg-client > "$work/apm-search.out" 2>&1
          grep -q "hostpkg/host-reg-client 1.0.0" "$work/apm-search.out"
          run_clean ${self}/bin/apm search hostpkg --installed > "$work/apm-search-installed.out" 2>&1
          if grep -q "hostpkg" "$work/apm-search-installed.out"; then
            cat "$work/apm-search-installed.out"
            exit 1
          fi
          run_clean ${self}/bin/apm show hostpkg --registry host-reg-client > "$work/apm-show.out" 2>&1
          grep -q "Host-authored package metadata" "$work/apm-show.out"
          run_clean ${self}/bin/apm list --registry host-reg-client > "$work/apm-list.out" 2>&1
          grep -q "hostpkg/host-reg-client 1.0.0" "$work/apm-list.out"
          run_clean ${self}/bin/apm policy hostpkg > "$work/apm-policy.out" 2>&1
          grep -q "Candidate: 1.0.0" "$work/apm-policy.out"
          if run_clean ${self}/bin/apm files hostpkg > "$work/apm-files.out" 2>&1; then
            cat "$work/apm-files.out"
            exit 1
          fi
          grep -q "package not installed: hostpkg" "$work/apm-files.out"
          run_clean ${self}/bin/apm orphans > "$work/apm-orphans.out" 2>&1
          grep -q "No orphaned packages" "$work/apm-orphans.out"
          run_clean ${self}/bin/apm registry remove host-reg-client --keep-local > "$work/apm-registry-remove.out" 2>&1
          grep -q "Registry 'host-reg-client' removed" "$work/apm-registry-remove.out"
          test -d "$data/apm/registries/host-reg-client"

          mkdir -p "$out"
          echo "PASS" > "$out/result"
        '';
      }
    ];
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
      BODY=$(curl -s http://127.0.0.1:15000/test/nix-cache-info)
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
      RESPONSE=$(echo '{"action":"create","views":["test"],"permissions":["read","build"],"comment":"integration test"}' | \
        ${pkgs.socat}/bin/socat - UNIX-CONNECT:/tmp/run/aos/bootstrap.sock)
      echo "Create response: $RESPONSE"

      TOKEN=$(echo "$RESPONSE" | ${pkgs.jq}/bin/jq -r '.data.token // empty')
      TOKEN_ID=$(echo "$RESPONSE" | ${pkgs.jq}/bin/jq -r '.data.id // empty')

      test -n "$TOKEN" || { echo "FAIL: no token in create response"; FAIL=1; }
      test -n "$TOKEN_ID" || { echo "FAIL: no token ID in create response"; FAIL=1; }
      echo "==> Token created: id=$TOKEN_ID"

      # Test 2: List tokens via bootstrap socket
      echo "==> Test: list tokens via bootstrap socket"
      LIST_RESPONSE=$(echo '{"action":"list"}' | \
        ${pkgs.socat}/bin/socat - UNIX-CONNECT:/tmp/run/aos/bootstrap.sock)
      echo "List response: $LIST_RESPONSE"

      COUNT=$(echo "$LIST_RESPONSE" | ${pkgs.jq}/bin/jq '.data.tokens | length')
      test "$COUNT" -ge 1 || { echo "FAIL: expected at least 1 token, got $COUNT"; FAIL=1; }

      # Test 3: Exchange token for JWT via oauth2 endpoint
      echo "==> Test: exchange token for JWT"
      JWT_RESPONSE=$(curl -s \
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
      QM_RESPONSE=$(curl -s \
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
      REVOKE_RESPONSE=$(echo "{\"action\":\"revoke\",\"token_id\":\"$TOKEN_ID\"}" | \
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
      RESPONSE=$(echo '{"action":"create","views":["public"],"permissions":["read","build"]}' | \
        ${pkgs.socat}/bin/socat - UNIX-CONNECT:/tmp/run/aos/bootstrap.sock)
      TOKEN=$(echo "$RESPONSE" | ${pkgs.jq}/bin/jq -r '.data.token // empty')

      JWT_RESPONSE=$(curl -s \
        -X POST -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials" \
        http://127.0.0.1:15000/oauth2/token)
      echo "JWT response: $JWT_RESPONSE"
      ACCESS_TOKEN=$(echo "$JWT_RESPONSE" | ${pkgs.jq}/bin/jq -r '.access_token // empty')
      echo "ACCESS_TOKEN length: ''${#ACCESS_TOKEN}"

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
      RESPONSE2=$(echo '{"action":"create","views":["public"],"permissions":["read"]}' | \
        ${pkgs.socat}/bin/socat - UNIX-CONNECT:/tmp/run/aos/bootstrap.sock)
      TOKEN2=$(echo "$RESPONSE2" | ${pkgs.jq}/bin/jq -r '.data.token // empty')

      JWT2_RESPONSE=$(curl -s \
        -X POST -H "Authorization: Bearer $TOKEN2" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials" \
        http://127.0.0.1:15000/oauth2/token)
      ACCESS_TOKEN2=$(echo "$JWT2_RESPONSE" | ${pkgs.jq}/bin/jq -r '.access_token // empty')

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
      RESPONSE=$(echo '{"action":"create","views":["test"],"permissions":["read","build"]}' | \
        ${pkgs.socat}/bin/socat - UNIX-CONNECT:/tmp/run/aos/bootstrap.sock)
      TOKEN=$(echo "$RESPONSE" | ${pkgs.jq}/bin/jq -r '.data.token // empty')
      JWT_RESPONSE=$(curl -s \
        -X POST -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials" \
        http://127.0.0.1:15000/oauth2/token)
      ACCESS_TOKEN=$(echo "$JWT_RESPONSE" | ${pkgs.jq}/bin/jq -r '.access_token // empty')

      # Send SIGTERM to trigger drain
      echo "==> Sending SIGTERM to trigger drain"
      kill -TERM $SERVER_PID || true

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
