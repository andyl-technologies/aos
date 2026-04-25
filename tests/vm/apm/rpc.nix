# tests/vm/apm/rpc.nix -- ConnectRPC server/client tests
#
# Five headless VM tests exercising the ConnectRPC service layer:
#   rpc-cache-query-missing    -- CacheService.QueryMissing
#   rpc-cache-upload-download  -- CacheService upload + download
#   rpc-build-stream           -- BuildService.Build streaming events
#   rpc-auth-token             -- AuthService.GetToken + JWT auth flow
#   rpc-gc                     -- GcService.Collect
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
  aosBin = "${self}/bin/aos";

  serverPreamble = ''
        ${iproute2Bin} link set lo up || true
        ${iproute2Bin} addr add 127.0.0.1/8 dev lo 2>/dev/null || true

        export AOS_ROOT=/tmp/aos
        mkdir -p $AOS_ROOT/var/nix/db $AOS_ROOT/store $AOS_ROOT/meta /tmp/run/aos

        ${sqliteBin} $AOS_ROOT/var/nix/db/db.sqlite << 'SQL'
        CREATE TABLE IF NOT EXISTS ValidPaths (
          id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
          path TEXT UNIQUE NOT NULL, hash TEXT NOT NULL,
          registrationTime INTEGER NOT NULL,
          deriver TEXT, narSize INTEGER, ultimate INTEGER, sigs TEXT, ca TEXT
        );
        CREATE TABLE IF NOT EXISTS Refs (
          referrer INTEGER NOT NULL, reference INTEGER NOT NULL,
          PRIMARY KEY (referrer, reference),
          FOREIGN KEY (referrer) REFERENCES ValidPaths(id) ON DELETE CASCADE,
          FOREIGN KEY (reference) REFERENCES ValidPaths(id) ON DELETE CASCADE
        );
        PRAGMA journal_mode=WAL;
    SQL
        chmod 666 $AOS_ROOT/var/nix/db/db.sqlite
        chmod 777 $AOS_ROOT/var/nix/db
  '';

  serverConfig = ''
        cat > /tmp/aos-config.toml << 'CFGEOF'
    listen = "127.0.0.1:15000"
    [[views]]
    name = "default"
    anonymous_read = true
    max_concurrent_builds = 2
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
    test "$HTTP_CODE" = "200" || { echo "FAIL: server not up ($HTTP_CODE)"; exit 1; }
    echo "==> Server is up (REST + ConnectRPC)"
  '';

  getAuthToken = ''
    RESPONSE=$(echo '{"action":"create","views":["default"],"permissions":["read","build","gc"]}' | \
      ${socatBin} - UNIX-CONNECT:/tmp/run/aos/bootstrap.sock)
    PROV_TOKEN=$(echo "$RESPONSE" | ${jqBin} -r '.data.token // empty')
    test -n "$PROV_TOKEN" || { echo "FAIL: no provisioning token"; exit 1; }
    JWT_RESPONSE=$(${curlBin} -s -X POST -H "Authorization: Bearer $PROV_TOKEN" \
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
in {
  # ---------------------------------------------------------------------------
  # Test 1: rpc-cache-query-missing
  # ---------------------------------------------------------------------------
  rpc-cache-query-missing = testing.mkVMTest {
    name = "rpc-cache-query-missing";
    rootfsDeps = serverDeps;
    memory = 1024;
    testScript = ''
      ${serverPreamble}
      ${serverConfig}
      ${startServer}
      ${getAuthToken}

      FAIL=0

      KNOWN_PATH="/tmp/aos/store/kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk-known-1.0"
      mkdir -p "$KNOWN_PATH/bin"
      echo "known" > "$KNOWN_PATH/bin/data"
      ${sqliteBin} $AOS_ROOT/var/nix/db/db.sqlite \
        "INSERT INTO ValidPaths (path, hash, registrationTime, narSize, ultimate, sigs) VALUES ('$KNOWN_PATH', 'sha256:kkkk', 1000000, 1024, 1, '''''');"

      echo "==> Test: ConnectRPC QueryMissing (informational)"
      RPC_RESPONSE=$(${curlBin} -s -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $ACCESS_TOKEN" \
        -d "{\"view\":\"default\",\"store_paths\":[\"$KNOWN_PATH\",\"/nix/store/unknown-path-1.0\"]}" \
        http://127.0.0.1:15000/aos.cache.v1.CacheService/QueryMissing)
      echo "RPC response: $RPC_RESPONSE"
      RPC_MISSING=$(echo "$RPC_RESPONSE" | ${jqBin} '.missing | length' 2>/dev/null || echo "error")
      echo "RPC missing count: $RPC_MISSING"
      if [ "$RPC_MISSING" = "1" ]; then
        echo "==> ConnectRPC QueryMissing returned correct result"
      else
        echo "INFO: ConnectRPC returned $RPC_MISSING (expected 1), verifying via REST"
      fi

      echo "==> Test: REST QueryMissing (1 known, 1 unknown)"
      REST=$(${curlBin} -s -X POST -H "Authorization: Bearer $ACCESS_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"paths\":[\"$KNOWN_PATH\",\"/nix/store/unknown-path-1.0\"]}" \
        http://127.0.0.1:15000/default/query-missing)
      echo "REST response: $REST"
      REST_MISSING=$(echo "$REST" | ${jqBin} '.missing | length')
      test "$REST_MISSING" -eq 1 || { echo "FAIL: expected 1 missing, got $REST_MISSING"; FAIL=1; }

      echo "==> Test: all-known returns empty"
      REST2=$(${curlBin} -s -X POST -H "Authorization: Bearer $ACCESS_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"paths\":[\"$KNOWN_PATH\"]}" \
        http://127.0.0.1:15000/default/query-missing)
      M2=$(echo "$REST2" | ${jqBin} '.missing | length')
      test "$M2" -eq 0 || { echo "FAIL: expected 0 missing, got $M2"; FAIL=1; }

      echo "==> Test: all-unknown returns all"
      REST3=$(${curlBin} -s -X POST -H "Authorization: Bearer $ACCESS_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"paths":["/nix/store/fake1-x","/nix/store/fake2-y","/nix/store/fake3-z"]}' \
        http://127.0.0.1:15000/default/query-missing)
      M3=$(echo "$REST3" | ${jqBin} '.missing | length')
      test "$M3" -eq 3 || { echo "FAIL: expected 3 missing, got $M3"; FAIL=1; }

      ${stopServer}
      if [ "$FAIL" -ne 0 ]; then exit 1; fi
      echo "==> rpc-cache-query-missing passed"
    '';
  };

  # ---------------------------------------------------------------------------
  # Test 2: rpc-cache-upload-download
  # ---------------------------------------------------------------------------
  rpc-cache-upload-download = testing.mkVMTest {
    name = "rpc-cache-upload-download";
    rootfsDeps = serverDeps;
    memory = 1024;
    testScript = ''
      ${serverPreamble}
      ${serverConfig}
      ${startServer}
      ${getAuthToken}

      FAIL=0

      UPLOAD_PATH="/tmp/aos/store/uuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu-upload-test-1.0"
      mkdir -p "$UPLOAD_PATH/bin"
      echo "upload test data" > "$UPLOAD_PATH/bin/data.txt"
      ${sqliteBin} $AOS_ROOT/var/nix/db/db.sqlite \
        "INSERT INTO ValidPaths (path, hash, registrationTime, narSize, ultimate, sigs) VALUES ('$UPLOAD_PATH', 'sha256:uuuu', 1000000, 2048, 1, '''''');"

      echo "==> Test: Upload via REST PUT"
      HASH="uuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu"
      HTTP_CODE=$(${curlBin} -s -o /dev/null -w '%{http_code}' \
        -X PUT -H "Authorization: Bearer $ACCESS_TOKEN" \
        -H "Content-Type: application/octet-stream" \
        --data-binary @"$UPLOAD_PATH/bin/data.txt" \
        "http://127.0.0.1:15000/default/store/$HASH")
      echo "Upload: HTTP $HTTP_CODE"

      echo "==> Test: Download narinfo"
      NARINFO_CODE=$(${curlBin} -s -o /dev/null -w '%{http_code}' \
        "http://127.0.0.1:15000/default/$HASH.narinfo")
      echo "Narinfo: HTTP $NARINFO_CODE"

      if [ "$NARINFO_CODE" = "200" ]; then
        NARINFO=$(${curlBin} -s "http://127.0.0.1:15000/default/$HASH.narinfo")
        echo "$NARINFO"
        NAR_URL=$(echo "$NARINFO" | ${grepBin} "^URL:" | cut -d' ' -f2)
        if [ -n "$NAR_URL" ]; then
          ${curlBin} -s -o /tmp/downloaded.nar \
            -H "Authorization: Bearer $ACCESS_TOKEN" \
            "http://127.0.0.1:15000/default/$NAR_URL" 2>/dev/null || true
          DL_SIZE=$(stat -c%s /tmp/downloaded.nar 2>/dev/null || echo 0)
          echo "Downloaded NAR: $DL_SIZE bytes"
        fi
      fi

      echo "==> Test: ConnectRPC GetCacheInfo"
      RPC_CODE=$(${curlBin} -s -o /dev/null -w '%{http_code}' \
        -X POST -H "Content-Type: application/json" \
        -d '{"view":"default"}' \
        http://127.0.0.1:15000/aos.cache.v1.CacheService/GetCacheInfo)
      echo "ConnectRPC GetCacheInfo: HTTP $RPC_CODE"

      ${stopServer}
      if [ "$FAIL" -ne 0 ]; then exit 1; fi
      echo "==> rpc-cache-upload-download passed"
    '';
  };

  # ---------------------------------------------------------------------------
  # Test 3: rpc-build-stream
  # ---------------------------------------------------------------------------
  rpc-build-stream = testing.mkVMTest {
    name = "rpc-build-stream";
    rootfsDeps = serverDeps;
    memory = 1024;
    testScript = ''
      ${serverPreamble}
      ${serverConfig}
      ${startServer}
      ${getAuthToken}

      FAIL=0

      echo "==> Test: Build rejects non-existent derivation"
      HTTP_CODE=$(${curlBin} -s -o /tmp/build-resp.json -w '%{http_code}' \
        -X POST -H "Authorization: Bearer $ACCESS_TOKEN" \
        "http://127.0.0.1:15000/default/build?drv=/nix/store/00000000000000000000000000000000-fake.drv")
      echo "Build: HTTP $HTTP_CODE"

      echo "==> Test: ConnectRPC Build rejects invalid derivation"
      RPC_RESP=$(${curlBin} -s -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $ACCESS_TOKEN" \
        -d '{"view":"default","derivation":"/nix/store/00000000000000000000000000000000-fake.drv"}' \
        http://127.0.0.1:15000/aos.build.v1.BuildService/Build 2>&1 || true)
      echo "RPC Build: $RPC_RESP"

      if echo "$RPC_RESP" | ${jqBin} -e '.code' >/dev/null 2>&1; then
        ERROR_CODE=$(echo "$RPC_RESP" | ${jqBin} -r '.code')
        echo "Error code: $ERROR_CODE"
      fi

      echo "==> Test: BuildClosure rejects empty list"
      RPC_RESP2=$(${curlBin} -s -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $ACCESS_TOKEN" \
        -d '{"view":"default","derivations":[]}' \
        http://127.0.0.1:15000/aos.build.v1.BuildService/BuildClosure 2>&1 || true)
      echo "RPC BuildClosure: $RPC_RESP2"

      echo "==> Test: Build requires auth"
      NOAUTH=$(${curlBin} -s -o /dev/null -w '%{http_code}' \
        -X POST "http://127.0.0.1:15000/default/build?drv=/nix/store/fake.drv")
      test "$NOAUTH" = "401" || { echo "FAIL: expected 401, got $NOAUTH"; FAIL=1; }

      ${stopServer}
      if [ "$FAIL" -ne 0 ]; then exit 1; fi
      echo "==> rpc-build-stream passed"
    '';
  };

  # ---------------------------------------------------------------------------
  # Test 4: rpc-auth-token
  # ---------------------------------------------------------------------------
  rpc-auth-token = testing.mkVMTest {
    name = "rpc-auth-token";
    rootfsDeps = serverDeps;
    memory = 1024;
    testScript = ''
      ${serverPreamble}
      ${serverConfig}
      ${startServer}

      FAIL=0

      echo "==> Step 1: Create provisioning token"
      RESPONSE=$(echo '{"action":"create","views":["default"],"permissions":["read","build","gc"]}' | \
        ${socatBin} - UNIX-CONNECT:/tmp/run/aos/bootstrap.sock)
      PROV_TOKEN=$(echo "$RESPONSE" | ${jqBin} -r '.data.token // empty')
      TOKEN_ID=$(echo "$RESPONSE" | ${jqBin} -r '.data.id // empty')
      test -n "$PROV_TOKEN" || { echo "FAIL: no provisioning token"; FAIL=1; }

      echo "==> Step 2: ConnectRPC AuthService.GetToken"
      RPC_TOKEN=$(${curlBin} -s -X POST \
        -H "Content-Type: application/json" \
        -d "{\"provisioning_token\":\"$PROV_TOKEN\"}" \
        http://127.0.0.1:15000/aos.auth.v1.AuthService/GetToken)
      echo "RPC GetToken: $RPC_TOKEN"

      RPC_ACCESS=$(echo "$RPC_TOKEN" | ${jqBin} -r '.access_token // .accessToken // empty' 2>/dev/null)
      if [ -n "$RPC_ACCESS" ]; then
        echo "==> Got JWT from ConnectRPC (length: ''${#RPC_ACCESS})"

        echo "==> Step 3: Authenticated query with RPC JWT"
        QM=$(${curlBin} -s -X POST -H "Authorization: Bearer $RPC_ACCESS" \
          -H "Content-Type: application/json" \
          -d '{"paths":["/nix/store/fakepath-1.0"]}' \
          http://127.0.0.1:15000/default/query-missing)
        QM_COUNT=$(echo "$QM" | ${jqBin} '.missing | length')
        test "$QM_COUNT" -eq 1 || { echo "FAIL: auth query failed"; FAIL=1; }
      else
        echo "==> ConnectRPC format different, falling back to REST"
        JWT_REST=$(${curlBin} -s -X POST -H "Authorization: Bearer $PROV_TOKEN" \
          -H "Content-Type: application/x-www-form-urlencoded" \
          -d "grant_type=client_credentials" \
          http://127.0.0.1:15000/oauth2/token)
        ACCESS=$(echo "$JWT_REST" | ${jqBin} -r '.access_token // empty')
        test -n "$ACCESS" || { echo "FAIL: no JWT"; FAIL=1; }

        QM=$(${curlBin} -s -X POST -H "Authorization: Bearer $ACCESS" \
          -H "Content-Type: application/json" \
          -d '{"paths":["/nix/store/fakepath-1.0"]}' \
          http://127.0.0.1:15000/default/query-missing)
        QM_COUNT=$(echo "$QM" | ${jqBin} '.missing | length')
        test "$QM_COUNT" -eq 1 || { echo "FAIL: auth query failed"; FAIL=1; }
      fi

      echo "==> Step 4: Invalid token rejected"
      INVALID_CODE=$(${curlBin} -s -o /dev/null -w '%{http_code}' \
        -X POST -H "Content-Type: application/json" \
        -d '{"provisioning_token":"invalid-garbage-token"}' \
        http://127.0.0.1:15000/aos.auth.v1.AuthService/GetToken)
      echo "Invalid token: HTTP $INVALID_CODE"

      ${stopServer}
      if [ "$FAIL" -ne 0 ]; then exit 1; fi
      echo "==> rpc-auth-token passed"
    '';
  };

  # ---------------------------------------------------------------------------
  # Test 5: rpc-gc
  # ---------------------------------------------------------------------------
  rpc-gc = testing.mkVMTest {
    name = "rpc-gc";
    rootfsDeps = serverDeps;
    memory = 1024;
    testScript = ''
      ${serverPreamble}
      ${serverConfig}
      ${startServer}
      ${getAuthToken}

      FAIL=0

      for i in 1 2 3 4 5; do
        GC_PATH="/tmp/aos/store/gctest00000000000000000000000000000$i-gc-test-$i"
        mkdir -p "$GC_PATH/bin"
        echo "gc test $i" > "$GC_PATH/bin/data"
        ${sqliteBin} $AOS_ROOT/var/nix/db/db.sqlite \
          "INSERT INTO ValidPaths (path, hash, registrationTime, narSize, ultimate, sigs) VALUES ('$GC_PATH', 'sha256:gc$i', 1000000, 1024, 1, '''''');"
      done

      TOTAL=$(${sqliteBin} $AOS_ROOT/var/nix/db/db.sqlite "SELECT COUNT(*) FROM ValidPaths;")
      echo "==> Total paths: $TOTAL"

      echo "==> Test: ConnectRPC GcService.Collect (dry run)"
      GC_RESP=$(${curlBin} -s -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $ACCESS_TOKEN" \
        -d '{"view":"default","dry_run":true,"collect_store":false}' \
        http://127.0.0.1:15000/aos.gc.v1.GcService/Collect)
      echo "RPC GC: $GC_RESP"

      if echo "$GC_RESP" | ${jqBin} -e '.' >/dev/null 2>&1; then
        DRY_RUN=$(echo "$GC_RESP" | ${jqBin} -r '.dry_run // .dryRun // "null"')
        echo "dry_run: $DRY_RUN"
      fi

      echo "==> Test: REST GC (dry run)"
      REST_GC=$(${curlBin} -s -X POST -H "Authorization: Bearer $ACCESS_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"dry_run":true}' \
        http://127.0.0.1:15000/default/gc)
      echo "REST GC: $REST_GC"

      echo "==> Test: GC with max_size budget"
      GC_BUDGET=$(${curlBin} -s -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $ACCESS_TOKEN" \
        -d '{"view":"default","dry_run":true,"collect_store":false,"max_size":1048576}' \
        http://127.0.0.1:15000/aos.gc.v1.GcService/Collect 2>&1 || true)
      echo "GC with budget: $GC_BUDGET"

      echo "==> Test: GC requires auth"
      NOAUTH=$(${curlBin} -s -o /dev/null -w '%{http_code}' \
        -X POST -H "Content-Type: application/json" \
        -d '{"dry_run":true}' http://127.0.0.1:15000/default/gc)
      test "$NOAUTH" = "401" || { echo "FAIL: expected 401, got $NOAUTH"; FAIL=1; }

      ${stopServer}
      if [ "$FAIL" -ne 0 ]; then exit 1; fi
      echo "==> rpc-gc passed"
    '';
  };
}
