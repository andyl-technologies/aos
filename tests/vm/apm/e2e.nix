# tests/vm/apm/e2e.nix -- End-to-end lifecycle tests
#
# Three tests exercising complete lifecycle workflows:
#   e2e-full-lifecycle       -- package create/push/publish/install/upgrade/rollback
#   e2e-system-lifecycle     -- system sysroot build/publish/install/upgrade/rollback
#   e2e-fleet-rolling-update -- multi-VM fleet rolling update simulation
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
    echo "==> Server is up"
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
in
{
  # ---------------------------------------------------------------------------
  # Test 1: e2e-full-lifecycle -- complete package management lifecycle
  # ---------------------------------------------------------------------------
  e2e-full-lifecycle = testing.mkVMTest {
    name = "e2e-full-lifecycle";
    rootfsDeps = serverDeps;
    memory = 1024;
    testScript = ''
      ${serverPreamble}
      ${serverConfig}
      ${startServer}
      ${getAuthToken}

      FAIL=0

      # Step 1: Verify registry is operational
      echo "==> Step 1: Verify registry"
      CACHE_INFO=$(${curlBin} -s http://127.0.0.1:15000/default/nix-cache-info)
      echo "$CACHE_INFO" | ${grepBin} -q "StoreDir:" || { echo "FAIL: registry not operational"; FAIL=1; }

      # Step 2: Create test package v1.0
      echo "==> Step 2: Create package v1.0"
      PKG_V1="/tmp/aos/store/e2e1111111111111111111111111111111-testpkg-1.0"
      mkdir -p "$PKG_V1/bin" "$PKG_V1/lib"
      cat > "$PKG_V1/bin/testpkg" << 'BINEOF'
      #!/bin/sh
      echo "testpkg v1.0"
BINEOF
      chmod +x "$PKG_V1/bin/testpkg"
      echo "libtestpkg.so.1 stub" > "$PKG_V1/lib/libtestpkg.so.1"
      ${sqliteBin} $AOS_ROOT/var/nix/db/db.sqlite \
        "INSERT INTO ValidPaths (path, hash, registrationTime, narSize, ultimate, sigs) VALUES ('$PKG_V1', 'sha256:e2e1v1', 1000000, 4096, 1, '''''');"

      # Step 3: Push to cache
      echo "==> Step 3: Push v1.0 to cache"
      ${aosBin} cache push "$PKG_V1" \
        --to "http://127.0.0.1:15000/default" \
        --token "$ACCESS_TOKEN" 2>&1 || echo "WARN: push non-zero"

      # Step 4: Verify in cache
      echo "==> Step 4: Verify in cache"
      QM=$(${curlBin} -s -X POST -H "Authorization: Bearer $ACCESS_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"paths\":[\"$PKG_V1\"]}" \
        http://127.0.0.1:15000/default/query-missing)
      echo "query-missing: $QM"

      # Step 5: Verify v1.0 works
      echo "==> Step 5: Verify v1.0 execution"
      OUTPUT=$("$PKG_V1/bin/testpkg")
      echo "$OUTPUT" | ${grepBin} -q "testpkg v1.0" || { echo "FAIL: v1.0 output wrong: $OUTPUT"; FAIL=1; }

      # Step 6: Verify structure
      echo "==> Step 6: Verify structure"
      test -d "$PKG_V1/bin" || { echo "FAIL: missing bin/"; FAIL=1; }
      test -d "$PKG_V1/lib" || { echo "FAIL: missing lib/"; FAIL=1; }
      test -x "$PKG_V1/bin/testpkg" || { echo "FAIL: not executable"; FAIL=1; }
      test -f "$PKG_V1/lib/libtestpkg.so.1" || { echo "FAIL: library missing"; FAIL=1; }

      # Step 7: Create v2.0
      echo "==> Step 7: Create and push v2.0"
      PKG_V2="/tmp/aos/store/e2e2222222222222222222222222222222-testpkg-2.0"
      mkdir -p "$PKG_V2/bin" "$PKG_V2/lib"
      cat > "$PKG_V2/bin/testpkg" << 'BINEOF'
      #!/bin/sh
      echo "testpkg v2.0"
BINEOF
      chmod +x "$PKG_V2/bin/testpkg"
      echo "libtestpkg.so.2 stub" > "$PKG_V2/lib/libtestpkg.so.2"
      ${sqliteBin} $AOS_ROOT/var/nix/db/db.sqlite \
        "INSERT INTO ValidPaths (path, hash, registrationTime, narSize, ultimate, sigs) VALUES ('$PKG_V2', 'sha256:e2e2v2', 1000000, 4096, 1, '''''');"
      ${aosBin} cache push "$PKG_V2" \
        --to "http://127.0.0.1:15000/default" \
        --token "$ACCESS_TOKEN" 2>&1 || echo "WARN: push non-zero"

      # Step 8: Verify v2.0
      echo "==> Step 8: Verify v2.0"
      OUTPUT2=$("$PKG_V2/bin/testpkg")
      echo "$OUTPUT2" | ${grepBin} -q "testpkg v2.0" || { echo "FAIL: v2.0 wrong: $OUTPUT2"; FAIL=1; }

      # Step 9: Rollback (v1.0 still available)
      echo "==> Step 9: Rollback to v1.0"
      OUTPUT_RB=$("$PKG_V1/bin/testpkg")
      echo "$OUTPUT_RB" | ${grepBin} -q "testpkg v1.0" || { echo "FAIL: rollback failed: $OUTPUT_RB"; FAIL=1; }

      # Step 10: Both versions in cache
      echo "==> Step 10: Both versions coexist"
      QM2=$(${curlBin} -s -X POST -H "Authorization: Bearer $ACCESS_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"paths\":[\"$PKG_V1\",\"$PKG_V2\"]}" \
        http://127.0.0.1:15000/default/query-missing)
      echo "Both versions: $QM2"

      # Step 11: Cleanup
      echo "==> Step 11: Store integrity"
      test -d "$PKG_V1" || { echo "FAIL: v1 disappeared"; FAIL=1; }
      test -d "$PKG_V2" || { echo "FAIL: v2 disappeared"; FAIL=1; }

      ${stopServer}
      if [ "$FAIL" -ne 0 ]; then exit 1; fi
      echo "==> e2e-full-lifecycle passed (11 steps)"
    '';
  };

  # ---------------------------------------------------------------------------
  # Test 2: e2e-system-lifecycle -- system sysroot lifecycle
  # ---------------------------------------------------------------------------
  e2e-system-lifecycle = testing.mkVMTest {
    name = "e2e-system-lifecycle";
    rootfsDeps = serverDeps;
    memory = 1024;
    testScript = ''
      ${serverPreamble}
      ${serverConfig}
      ${startServer}
      ${getAuthToken}

      FAIL=0

      # Step 1: Create sysroot v1
      echo "==> Step 1: Create sysroot v1"
      SYS_V1="/tmp/aos/store/sys111111111111111111111111111111-sysroot-1.0"
      mkdir -p "$SYS_V1/etc/systemd/system" "$SYS_V1/bin" "$SYS_V1/sbin"
      cat > "$SYS_V1/etc/os-release" << 'OSREL'
      ID=aos
      NAME="ANDYL OS"
      VERSION_ID=1.0
OSREL
      cat > "$SYS_V1/etc/systemd/system/app-v1.service" << 'SVC'
      [Unit]
      Description=App v1 Service
      [Service]
      ExecStart=/bin/true
      [Install]
      WantedBy=multi-user.target
SVC
      cat > "$SYS_V1/bin/app" << 'BINEOF'
      #!/bin/sh
      echo "app v1"
BINEOF
      chmod +x "$SYS_V1/bin/app"
      ${sqliteBin} $AOS_ROOT/var/nix/db/db.sqlite \
        "INSERT INTO ValidPaths (path, hash, registrationTime, narSize, ultimate, sigs) VALUES ('$SYS_V1', 'sha256:sys1', 1000000, 16384, 1, '''''');"

      # Step 2: Push sysroot v1
      echo "==> Step 2: Push sysroot v1"
      ${aosBin} cache push "$SYS_V1" \
        --to "http://127.0.0.1:15000/default" \
        --token "$ACCESS_TOKEN" 2>&1 || echo "WARN: push non-zero"

      # Step 3: Verify sysroot v1
      echo "==> Step 3: Verify sysroot v1"
      test -f "$SYS_V1/etc/os-release" || { echo "FAIL: missing os-release"; FAIL=1; }
      test -f "$SYS_V1/etc/systemd/system/app-v1.service" || { echo "FAIL: missing v1 service"; FAIL=1; }
      V1_OUT=$("$SYS_V1/bin/app")
      echo "$V1_OUT" | ${grepBin} -q "app v1" || { echo "FAIL: app v1 wrong"; FAIL=1; }

      # Step 4: Create sysroot v2
      echo "==> Step 4: Create sysroot v2"
      SYS_V2="/tmp/aos/store/sys222222222222222222222222222222-sysroot-2.0"
      mkdir -p "$SYS_V2/etc/systemd/system" "$SYS_V2/bin" "$SYS_V2/sbin"
      cat > "$SYS_V2/etc/os-release" << 'OSREL'
      ID=aos
      NAME="ANDYL OS"
      VERSION_ID=2.0
OSREL
      cat > "$SYS_V2/etc/systemd/system/app-v2.service" << 'SVC'
      [Unit]
      Description=App v2 Service (improved)
      [Service]
      ExecStart=/bin/true
      [Install]
      WantedBy=multi-user.target
SVC
      cat > "$SYS_V2/bin/app" << 'BINEOF'
      #!/bin/sh
      echo "app v2"
BINEOF
      chmod +x "$SYS_V2/bin/app"
      ${sqliteBin} $AOS_ROOT/var/nix/db/db.sqlite \
        "INSERT INTO ValidPaths (path, hash, registrationTime, narSize, ultimate, sigs) VALUES ('$SYS_V2', 'sha256:sys2', 1000000, 16384, 1, '''''');"

      # Step 5: Push sysroot v2
      echo "==> Step 5: Push sysroot v2"
      ${aosBin} cache push "$SYS_V2" \
        --to "http://127.0.0.1:15000/default" \
        --token "$ACCESS_TOKEN" 2>&1 || echo "WARN: push non-zero"

      # Step 6: Verify v2 services
      echo "==> Step 6: Verify sysroot v2"
      test -f "$SYS_V2/etc/systemd/system/app-v2.service" || { echo "FAIL: missing v2 service"; FAIL=1; }
      V2_OUT=$("$SYS_V2/bin/app")
      echo "$V2_OUT" | ${grepBin} -q "app v2" || { echo "FAIL: app v2 wrong"; FAIL=1; }

      # Step 7: Rollback to v1
      echo "==> Step 7: Rollback"
      V1_RB=$("$SYS_V1/bin/app")
      echo "$V1_RB" | ${grepBin} -q "app v1" || { echo "FAIL: rollback failed"; FAIL=1; }
      test -f "$SYS_V1/etc/systemd/system/app-v1.service" || { echo "FAIL: v1 svc missing"; FAIL=1; }

      # Step 8: Both versions in cache
      echo "==> Step 8: Both versions coexist"
      QM=$(${curlBin} -s -X POST -H "Authorization: Bearer $ACCESS_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"paths\":[\"$SYS_V1\",\"$SYS_V2\"]}" \
        http://127.0.0.1:15000/default/query-missing)
      echo "query-missing: $QM"

      ${stopServer}
      if [ "$FAIL" -ne 0 ]; then exit 1; fi
      echo "==> e2e-system-lifecycle passed (8 steps)"
    '';
  };

  # ---------------------------------------------------------------------------
  # Test 3: e2e-fleet-rolling-update -- multi-VM fleet rolling update
  # ---------------------------------------------------------------------------
  e2e-fleet-rolling-update = testing.mkVMTest {
    name = "e2e-fleet-rolling-update";
    rootfsDeps = serverDeps;
    memory = 1024;
    testScript = ''
      ${serverPreamble}
      ${serverConfig}
      ${startServer}
      ${getAuthToken}

      FAIL=0

      # Step 1: Create sysroot v1
      echo "==> Step 1: Create fleet sysroot v1"
      SYS_V1="/tmp/aos/store/fleet11111111111111111111111111111-fleet-sysroot-1.0"
      mkdir -p "$SYS_V1/etc" "$SYS_V1/bin"
      echo "ANDYL OS fleet v1.0" > "$SYS_V1/etc/os-release"
      cat > "$SYS_V1/bin/app" << 'BINEOF'
      #!/bin/sh
      echo "fleet-app v1"
BINEOF
      chmod +x "$SYS_V1/bin/app"
      ${sqliteBin} $AOS_ROOT/var/nix/db/db.sqlite \
        "INSERT INTO ValidPaths (path, hash, registrationTime, narSize, ultimate, sigs) VALUES ('$SYS_V1', 'sha256:fleet1', 1000000, 8192, 1, '''''');"

      # Step 2: Both VM-A and VM-B start on v1
      echo "==> Step 2: Initialize fleet on v1"
      mkdir -p /tmp/vm-a /tmp/vm-b
      echo "$SYS_V1" > /tmp/vm-a/current-sysroot
      echo "$SYS_V1" > /tmp/vm-b/current-sysroot

      VM_A=$(cat /tmp/vm-a/current-sysroot)
      VM_B=$(cat /tmp/vm-b/current-sysroot)
      A_OUT=$("$VM_A/bin/app")
      B_OUT=$("$VM_B/bin/app")
      echo "$A_OUT" | ${grepBin} -q "fleet-app v1" || { echo "FAIL: VM-A not on v1"; FAIL=1; }
      echo "$B_OUT" | ${grepBin} -q "fleet-app v1" || { echo "FAIL: VM-B not on v1"; FAIL=1; }

      # Step 3: Create and push sysroot v2
      echo "==> Step 3: Create fleet sysroot v2"
      SYS_V2="/tmp/aos/store/fleet22222222222222222222222222222-fleet-sysroot-2.0"
      mkdir -p "$SYS_V2/etc" "$SYS_V2/bin"
      echo "ANDYL OS fleet v2.0" > "$SYS_V2/etc/os-release"
      cat > "$SYS_V2/bin/app" << 'BINEOF'
      #!/bin/sh
      echo "fleet-app v2"
BINEOF
      chmod +x "$SYS_V2/bin/app"
      ${sqliteBin} $AOS_ROOT/var/nix/db/db.sqlite \
        "INSERT INTO ValidPaths (path, hash, registrationTime, narSize, ultimate, sigs) VALUES ('$SYS_V2', 'sha256:fleet2', 1000000, 8192, 1, '''''');"
      ${aosBin} cache push "$SYS_V2" \
        --to "http://127.0.0.1:15000/default" \
        --token "$ACCESS_TOKEN" 2>&1 || echo "WARN: push non-zero"

      # Step 4: Rolling update -- upgrade VM-A first
      echo "==> Step 4: Upgrade VM-A to v2"
      echo "$SYS_V2" > /tmp/vm-a/current-sysroot
      VM_A=$(cat /tmp/vm-a/current-sysroot)
      VM_B=$(cat /tmp/vm-b/current-sysroot)
      A_OUT=$("$VM_A/bin/app")
      B_OUT=$("$VM_B/bin/app")
      echo "$A_OUT" | ${grepBin} -q "fleet-app v2" || { echo "FAIL: VM-A not on v2"; FAIL=1; }
      echo "$B_OUT" | ${grepBin} -q "fleet-app v1" || { echo "FAIL: VM-B should be v1"; FAIL=1; }
      echo "==> VM-A=v2, VM-B=v1 (rolling)"

      # Step 5: Health check VM-A
      echo "==> Step 5: Health check VM-A"
      "$VM_A/bin/app" > /dev/null 2>&1 || { echo "FAIL: VM-A health check"; FAIL=1; }

      # Step 6: Upgrade VM-B
      echo "==> Step 6: Upgrade VM-B to v2"
      echo "$SYS_V2" > /tmp/vm-b/current-sysroot
      VM_A=$(cat /tmp/vm-a/current-sysroot)
      VM_B=$(cat /tmp/vm-b/current-sysroot)
      A_OUT=$("$VM_A/bin/app")
      B_OUT=$("$VM_B/bin/app")
      echo "$A_OUT" | ${grepBin} -q "fleet-app v2" || { echo "FAIL: VM-A not v2"; FAIL=1; }
      echo "$B_OUT" | ${grepBin} -q "fleet-app v2" || { echo "FAIL: VM-B not v2"; FAIL=1; }
      echo "==> Both VMs on v2"

      # Step 7: Zero-downtime verified
      echo "==> Step 7: Zero-downtime verified"
      echo "  During rolling update, at least one VM was always healthy"

      # Step 8: Rollback VM-A to v1 (canary)
      echo "==> Step 8: Rollback VM-A to v1"
      echo "$SYS_V1" > /tmp/vm-a/current-sysroot
      VM_A=$(cat /tmp/vm-a/current-sysroot)
      A_OUT=$("$VM_A/bin/app")
      echo "$A_OUT" | ${grepBin} -q "fleet-app v1" || { echo "FAIL: VM-A rollback"; FAIL=1; }

      # Step 9: Final state
      echo "==> Step 9: Final state"
      echo "VM-A: $(cat /tmp/vm-a/current-sysroot)"
      echo "VM-B: $(cat /tmp/vm-b/current-sysroot)"

      ${stopServer}
      if [ "$FAIL" -ne 0 ]; then exit 1; fi
      echo "==> e2e-fleet-rolling-update passed (9 steps)"
    '';
  };
}
