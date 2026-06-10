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
  nixStoreBin = "${pkgs.nix}/bin/nix-store";
  sha256sumBin = "${pkgs.coreutils}/bin/sha256sum";
  statBin = "${pkgs.coreutils}/bin/stat";
  cutBin = "${pkgs.coreutils}/bin/cut";
  catBin = "${pkgs.coreutils}/bin/cat";
  tailBin = "${pkgs.coreutils}/bin/tail";
  aosBin = "${self}/bin/aos";

  serverPreamble = ''
        ${iproute2Bin} link set lo up || true
        ${iproute2Bin} addr add 127.0.0.1/8 dev lo 2>/dev/null || true

        export AOS_ROOT=/tmp/aos
        mkdir -p /tmp/run/aos

        init_mock_nix_db() {
          root="$1"
          mkdir -p "$root/var/nix/db" "$root/store" "$root/meta"
          ${sqliteBin} "$root/var/nix/db/db.sqlite" << 'SQL'
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

        write_octal_byte() {
          octal=$(printf '%03o' "$1")
          printf "\\$octal"
        }

        write_connect_json_request() {
          body="$1"
          out="$2"
          len=''${#body}
          b1=$(((len >> 24) & 255))
          b2=$(((len >> 16) & 255))
          b3=$(((len >> 8) & 255))
          b4=$((len & 255))
          {
            printf '\000'
            write_octal_byte "$b1"
            write_octal_byte "$b2"
            write_octal_byte "$b3"
            write_octal_byte "$b4"
            printf '%s' "$body"
          } > "$out"
        }

        connect_json_payload() {
          ${tailBin} -c +6 "$1"
        }

        init_mock_nix_db "$AOS_ROOT"
  '';

  serverConfig = ''
        ${catBin} > /tmp/aos-config.toml << 'CFGEOF'
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
    pkgs.nix
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

      echo "==> Test: ConnectRPC QueryMissing"
      RPC_RESPONSE=$(${curlBin} -s -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $ACCESS_TOKEN" \
        -d "{\"view\":\"default\",\"store_paths\":[\"$KNOWN_PATH\",\"/nix/store/unknown-path-1.0\"]}" \
        http://127.0.0.1:15000/aos.cache.v1.CacheService/QueryMissing)
      echo "RPC response: $RPC_RESPONSE"
      RPC_MISSING=$(echo "$RPC_RESPONSE" | ${jqBin} '.missing | length' 2>/dev/null || echo "error")
      echo "RPC missing count: $RPC_MISSING"
      test "$RPC_MISSING" = "1" || { echo "FAIL: expected RPC missing count 1, got $RPC_MISSING"; FAIL=1; }

      echo "==> Test: ConnectRPC QueryMissing requires auth"
      RPC_NOAUTH_CODE=$(${curlBin} -s -o /tmp/rpc-query-missing-noauth.json -w '%{http_code}' \
        -X POST -H "Content-Type: application/json" \
        -d "{\"view\":\"default\",\"store_paths\":[\"$KNOWN_PATH\"]}" \
        http://127.0.0.1:15000/aos.cache.v1.CacheService/QueryMissing)
      RPC_NOAUTH=$(${catBin} /tmp/rpc-query-missing-noauth.json)
      echo "RPC no-auth QueryMissing: HTTP $RPC_NOAUTH_CODE $RPC_NOAUTH"
      test "$RPC_NOAUTH_CODE" = "401" || { echo "FAIL: expected RPC QueryMissing HTTP 401"; FAIL=1; }
      RPC_NOAUTH_ERROR=$(echo "$RPC_NOAUTH" | ${jqBin} -r '.code // empty')
      test "$RPC_NOAUTH_ERROR" = "unauthenticated" || \
        { echo "FAIL: expected unauthenticated RPC QueryMissing error, got $RPC_NOAUTH_ERROR"; FAIL=1; }

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

      CLIENT_STATE_ROOT=/tmp/aos-rpc-client-state
      init_mock_nix_db "$CLIENT_STATE_ROOT"

      HASH="abababababababababababababababab"
      UPLOAD_PATH="$AOS_ROOT/store/$HASH-rpc-upload-test-1.0"
      mkdir -p "$UPLOAD_PATH/bin"
      echo '#!/bin/sh' > "$UPLOAD_PATH/bin/rpc-upload-test"
      echo 'echo "rpc upload executed"' >> "$UPLOAD_PATH/bin/rpc-upload-test"
      chmod +x "$UPLOAD_PATH/bin/rpc-upload-test"
      echo "upload test data" > "$UPLOAD_PATH/bin/data.txt"
      register_ca_store_path "$UPLOAD_PATH" "$CLIENT_STATE_ROOT" "$AOS_ROOT/store"

      echo "==> Test: path is missing before import"
      BEFORE=$(${curlBin} -s -X POST -H "Authorization: Bearer $ACCESS_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"paths\":[\"$HASH\"]}" \
        http://127.0.0.1:15000/default/query-missing)
      echo "query-missing before: $BEFORE"
      echo "$BEFORE" | ${jqBin} -e '.missing == ["'"$HASH"'"]' >/dev/null || \
        { echo "FAIL: RPC upload fixture should be missing before import"; FAIL=1; }

      echo "==> Test: Upload real Nix export via REST PUT"
      NIX_STORE_DIR="$AOS_ROOT/store" NIX_STATE_DIR="$CLIENT_STATE_ROOT/var/nix" \
        ${nixStoreBin} --export "$UPLOAD_PATH" > /tmp/rpc-upload.export
      HTTP_CODE=$(${curlBin} -s -o /tmp/rpc-upload-response.json -w '%{http_code}' \
        -X PUT -H "Authorization: Bearer $ACCESS_TOKEN" \
        -H "Content-Type: application/octet-stream" \
        --data-binary @/tmp/rpc-upload.export \
        "http://127.0.0.1:15000/default/store/$HASH")
      echo "Upload: HTTP $HTTP_CODE"
      ${catBin} /tmp/rpc-upload-response.json
      test "$HTTP_CODE" = "200" || { echo "FAIL: expected upload HTTP 200"; FAIL=1; }
      echo "$(${catBin} /tmp/rpc-upload-response.json)" | ${jqBin} -e '.path == "'"$UPLOAD_PATH"'"' >/dev/null || \
        { echo "FAIL: upload response did not report imported store path"; FAIL=1; }
      promote_view_path "$AOS_ROOT" default bin "$UPLOAD_PATH"

      echo "==> Test: path is present after import"
      AFTER=$(${curlBin} -s -X POST -H "Authorization: Bearer $ACCESS_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"paths\":[\"$HASH\"]}" \
        http://127.0.0.1:15000/default/query-missing)
      echo "query-missing after: $AFTER"
      echo "$AFTER" | ${jqBin} -e '.missing == []' >/dev/null || \
        { echo "FAIL: imported path should not be missing"; FAIL=1; }

      echo "==> Test: Download narinfo via REST"
      NARINFO_CODE=$(${curlBin} -s -o /dev/null -w '%{http_code}' \
        "http://127.0.0.1:15000/default/$HASH.narinfo")
      echo "Narinfo: HTTP $NARINFO_CODE"
      test "$NARINFO_CODE" = "200" || { echo "FAIL: expected REST narinfo HTTP 200"; FAIL=1; }
      NARINFO=$(${curlBin} -sf "http://127.0.0.1:15000/default/$HASH.narinfo")
      echo "$NARINFO"
      echo "$NARINFO" | ${grepBin} -F -q "StorePath: $UPLOAD_PATH" || \
        { echo "FAIL: REST narinfo missing store path"; FAIL=1; }
      echo "$NARINFO" | ${grepBin} -F -q "URL: nar/" || \
        { echo "FAIL: REST narinfo missing NAR URL"; FAIL=1; }

      echo "==> Test: ConnectRPC GetNarInfo exposes download metadata"
      RPC_NARINFO=$(${curlBin} -s -X POST \
        -H "Content-Type: application/json" \
        -d "{\"view\":\"default\",\"store_hash\":\"$HASH\"}" \
        http://127.0.0.1:15000/aos.cache.v1.CacheService/GetNarInfo)
      echo "RPC GetNarInfo: $RPC_NARINFO"
      RPC_STORE_PATH=$(echo "$RPC_NARINFO" | ${jqBin} -r '.store_path // .storePath // empty')
      RPC_URL=$(echo "$RPC_NARINFO" | ${jqBin} -r '.url // empty')
      RPC_COMPRESSION=$(echo "$RPC_NARINFO" | ${jqBin} -r '.compression // empty')
      RPC_FILE_HASH=$(echo "$RPC_NARINFO" | ${jqBin} -r '.file_hash // .fileHash // empty')
      RPC_FILE_SIZE=$(echo "$RPC_NARINFO" | ${jqBin} -r '.file_size // .fileSize // 0')
      RPC_NAR_HASH=$(echo "$RPC_NARINFO" | ${jqBin} -r '.nar_hash // .narHash // empty')
      RPC_NAR_SIZE=$(echo "$RPC_NARINFO" | ${jqBin} -r '.nar_size // .narSize // 0')
      test "$RPC_STORE_PATH" = "$UPLOAD_PATH" || { echo "FAIL: RPC narinfo store path mismatch"; FAIL=1; }
      echo "$RPC_URL" | ${grepBin} -q '^nar/' || { echo "FAIL: RPC narinfo missing NAR URL"; FAIL=1; }
      test "$RPC_COMPRESSION" = "zstd" || { echo "FAIL: RPC narinfo compression mismatch: $RPC_COMPRESSION"; FAIL=1; }
      echo "$RPC_FILE_HASH" | ${grepBin} -q '^sha256:' || { echo "FAIL: RPC narinfo missing file hash"; FAIL=1; }
      test "$RPC_FILE_SIZE" -gt 0 || { echo "FAIL: RPC narinfo file size missing"; FAIL=1; }
      echo "$RPC_NAR_HASH" | ${grepBin} -q '^sha256:' || { echo "FAIL: RPC narinfo missing NAR hash"; FAIL=1; }
      test "$RPC_NAR_SIZE" -gt 0 || { echo "FAIL: RPC narinfo NAR size missing"; FAIL=1; }

      echo "==> Test: Download NAR URL from RPC metadata"
      ${curlBin} -sf -o /tmp/downloaded.nar \
        -H "Authorization: Bearer $ACCESS_TOKEN" \
        "http://127.0.0.1:15000/default/$RPC_URL"
      DL_SIZE=$(${statBin} -c%s /tmp/downloaded.nar)
      echo "Downloaded NAR: $DL_SIZE bytes"
      test "$DL_SIZE" -gt 0 || { echo "FAIL: downloaded NAR is empty"; FAIL=1; }

      echo "==> Test: ConnectRPC GetCacheInfo"
      RPC_CODE=$(${curlBin} -s -o /dev/null -w '%{http_code}' \
        -X POST -H "Content-Type: application/json" \
        -d '{"view":"default"}' \
        http://127.0.0.1:15000/aos.cache.v1.CacheService/GetCacheInfo)
      echo "ConnectRPC GetCacheInfo: HTTP $RPC_CODE"
      test "$RPC_CODE" = "200" || { echo "FAIL: expected GetCacheInfo HTTP 200"; FAIL=1; }

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
      test "$HTTP_CODE" = "400" || { echo "FAIL: expected REST build HTTP 400"; FAIL=1; }

      echo "==> Test: ConnectRPC Build rejects invalid derivation"
      write_connect_json_request \
        '{"view":"default","derivation":"/nix/store/00000000000000000000000000000000-fake.drv"}' \
        /tmp/rpc-build-invalid.req
      RPC_CODE=$(${curlBin} -s -o /tmp/rpc-build-invalid.json -w '%{http_code}' \
        -X POST \
        -H "Content-Type: application/connect+json" \
        -H "Connect-Protocol-Version: 1" \
        -H "Authorization: Bearer $ACCESS_TOKEN" \
        --data-binary @/tmp/rpc-build-invalid.req \
        http://127.0.0.1:15000/aos.build.v1.BuildService/Build)
      RPC_RESP=$(connect_json_payload /tmp/rpc-build-invalid.json)
      echo "RPC Build: HTTP $RPC_CODE $RPC_RESP"
      test "$RPC_CODE" = "200" || { echo "FAIL: expected RPC build streaming HTTP 200"; FAIL=1; }
      ERROR_CODE=$(echo "$RPC_RESP" | ${jqBin} -r '.error.code // empty')
      test "$ERROR_CODE" = "invalid_argument" || { echo "FAIL: expected invalid_argument, got $ERROR_CODE"; FAIL=1; }

      echo "==> Test: BuildClosure rejects empty list"
      write_connect_json_request '{"view":"default","derivations":[]}' /tmp/rpc-build-closure-empty.req
      RPC_CODE2=$(${curlBin} -s -o /tmp/rpc-build-closure-empty.json -w '%{http_code}' \
        -X POST \
        -H "Content-Type: application/connect+json" \
        -H "Connect-Protocol-Version: 1" \
        -H "Authorization: Bearer $ACCESS_TOKEN" \
        --data-binary @/tmp/rpc-build-closure-empty.req \
        http://127.0.0.1:15000/aos.build.v1.BuildService/BuildClosure)
      RPC_RESP2=$(connect_json_payload /tmp/rpc-build-closure-empty.json)
      echo "RPC BuildClosure: HTTP $RPC_CODE2 $RPC_RESP2"
      test "$RPC_CODE2" = "200" || { echo "FAIL: expected RPC build-closure streaming HTTP 200"; FAIL=1; }
      ERROR_CODE2=$(echo "$RPC_RESP2" | ${jqBin} -r '.error.code // empty')
      test "$ERROR_CODE2" = "invalid_argument" || { echo "FAIL: expected invalid_argument, got $ERROR_CODE2"; FAIL=1; }

      echo "==> Test: ConnectRPC Build requires auth"
      write_connect_json_request \
        '{"view":"default","derivation":"/nix/store/00000000000000000000000000000000-fake.drv"}' \
        /tmp/rpc-build-noauth.req
      RPC_NOAUTH_CODE=$(${curlBin} -s -o /tmp/rpc-build-noauth.json -w '%{http_code}' \
        -X POST \
        -H "Content-Type: application/connect+json" \
        -H "Connect-Protocol-Version: 1" \
        --data-binary @/tmp/rpc-build-noauth.req \
        http://127.0.0.1:15000/aos.build.v1.BuildService/Build)
      RPC_NOAUTH=$(connect_json_payload /tmp/rpc-build-noauth.json)
      echo "RPC Build no-auth: HTTP $RPC_NOAUTH_CODE $RPC_NOAUTH"
      test "$RPC_NOAUTH_CODE" = "200" || { echo "FAIL: expected RPC build no-auth streaming HTTP 200"; FAIL=1; }
      RPC_NOAUTH_ERROR=$(echo "$RPC_NOAUTH" | ${jqBin} -r '.error.code // empty')
      test "$RPC_NOAUTH_ERROR" = "unauthenticated" || \
        { echo "FAIL: expected unauthenticated RPC build error, got $RPC_NOAUTH_ERROR"; FAIL=1; }

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
      RPC_TYPE=$(echo "$RPC_TOKEN" | ${jqBin} -r '.token_type // .tokenType // empty' 2>/dev/null)
      RPC_EXPIRES=$(echo "$RPC_TOKEN" | ${jqBin} -r '.expires_in // .expiresIn // 0' 2>/dev/null)
      RPC_SCOPE=$(echo "$RPC_TOKEN" | ${jqBin} -r '.scope // empty' 2>/dev/null)
      test -n "$RPC_ACCESS" || { echo "FAIL: no JWT from ConnectRPC"; FAIL=1; }
      test "$RPC_TYPE" = "Bearer" || { echo "FAIL: expected Bearer token type, got $RPC_TYPE"; FAIL=1; }
      test "$RPC_EXPIRES" -gt 0 || { echo "FAIL: expected positive token expiry"; FAIL=1; }
      echo "$RPC_SCOPE" | ${grepBin} -F -q "read" || { echo "FAIL: RPC token scope missing read"; FAIL=1; }
      echo "$RPC_SCOPE" | ${grepBin} -F -q "build" || { echo "FAIL: RPC token scope missing build"; FAIL=1; }
      echo "$RPC_SCOPE" | ${grepBin} -F -q "gc" || { echo "FAIL: RPC token scope missing gc"; FAIL=1; }

      echo "==> Step 3: Authenticated query with RPC JWT"
      QM=$(${curlBin} -s -X POST -H "Authorization: Bearer $RPC_ACCESS" \
        -H "Content-Type: application/json" \
        -d '{"paths":["/nix/store/fakepath-1.0"]}' \
        http://127.0.0.1:15000/default/query-missing)
      QM_COUNT=$(echo "$QM" | ${jqBin} '.missing | length')
      test "$QM_COUNT" -eq 1 || { echo "FAIL: auth query failed"; FAIL=1; }

      echo "==> Step 4: Invalid token rejected"
      INVALID_CODE=$(${curlBin} -s -o /dev/null -w '%{http_code}' \
        -X POST -H "Content-Type: application/json" \
        -d '{"provisioning_token":"invalid-garbage-token"}' \
        http://127.0.0.1:15000/aos.auth.v1.AuthService/GetToken)
      echo "Invalid token: HTTP $INVALID_CODE"
      test "$INVALID_CODE" = "401" || { echo "FAIL: expected invalid token HTTP 401"; FAIL=1; }

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
      GC_CODE=$(${curlBin} -s -o /tmp/rpc-gc-dry-run.json -w '%{http_code}' \
        -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $ACCESS_TOKEN" \
        -d '{"view":"default","dry_run":true,"collect_store":false}' \
        http://127.0.0.1:15000/aos.gc.v1.GcService/Collect)
      GC_RESP=$(${catBin} /tmp/rpc-gc-dry-run.json)
      echo "RPC GC: HTTP $GC_CODE $GC_RESP"
      test "$GC_CODE" = "200" || { echo "FAIL: expected RPC GC HTTP 200"; FAIL=1; }
      DRY_RUN=$(echo "$GC_RESP" | ${jqBin} -r '.dry_run // .dryRun // "null"')
      test "$DRY_RUN" = "true" || { echo "FAIL: expected RPC GC dry_run true, got $DRY_RUN"; FAIL=1; }

      echo "==> Test: REST GC (dry run)"
      REST_GC=$(${curlBin} -s -X POST -H "Authorization: Bearer $ACCESS_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"dry_run":true}' \
        http://127.0.0.1:15000/default/gc)
      echo "REST GC: $REST_GC"
      echo "$REST_GC" | ${jqBin} -e '.dry_run == true' >/dev/null || { echo "FAIL: REST GC dry_run mismatch"; FAIL=1; }

      echo "==> Test: GC with max_size budget"
      GC_BUDGET_CODE=$(${curlBin} -s -o /tmp/rpc-gc-budget.json -w '%{http_code}' \
        -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $ACCESS_TOKEN" \
        -d '{"view":"default","dry_run":true,"collect_store":false,"max_size":1048576}' \
        http://127.0.0.1:15000/aos.gc.v1.GcService/Collect)
      GC_BUDGET=$(${catBin} /tmp/rpc-gc-budget.json)
      echo "GC with budget: HTTP $GC_BUDGET_CODE $GC_BUDGET"
      test "$GC_BUDGET_CODE" = "200" || { echo "FAIL: expected RPC GC budget HTTP 200"; FAIL=1; }
      GC_BUDGET_DRY_RUN=$(echo "$GC_BUDGET" | ${jqBin} -r '.dry_run // .dryRun // "null"')
      test "$GC_BUDGET_DRY_RUN" = "true" || { echo "FAIL: expected RPC GC budget dry_run true"; FAIL=1; }

      echo "==> Test: ConnectRPC GC requires auth"
      RPC_GC_NOAUTH_CODE=$(${curlBin} -s -o /tmp/rpc-gc-noauth.json -w '%{http_code}' \
        -X POST -H "Content-Type: application/json" \
        -d '{"view":"default","dry_run":true,"collect_store":false}' \
        http://127.0.0.1:15000/aos.gc.v1.GcService/Collect)
      RPC_GC_NOAUTH=$(${catBin} /tmp/rpc-gc-noauth.json)
      echo "RPC GC no-auth: HTTP $RPC_GC_NOAUTH_CODE $RPC_GC_NOAUTH"
      test "$RPC_GC_NOAUTH_CODE" = "401" || { echo "FAIL: expected RPC GC HTTP 401"; FAIL=1; }
      RPC_GC_NOAUTH_ERROR=$(echo "$RPC_GC_NOAUTH" | ${jqBin} -r '.code // empty')
      test "$RPC_GC_NOAUTH_ERROR" = "unauthenticated" || \
        { echo "FAIL: expected unauthenticated RPC GC error, got $RPC_GC_NOAUTH_ERROR"; FAIL=1; }

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
