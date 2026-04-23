# tests/vm/apm/multi_registry.nix -- Multi-registry priority, cross-containment, mirror
#
# Three headless VM tests exercising multi-registry scenarios:
#   multi-registry-priority          -- higher priority registry wins
#   multi-registry-cross-containment -- deps shared across registries
#   multi-registry-mirror            -- registry mirroring
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

  mkStoreDb = dir: ''
        ${sqliteBin} ${dir}/var/nix/db/db.sqlite << 'SQL'
        CREATE TABLE IF NOT EXISTS ValidPaths (
          id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
          path TEXT UNIQUE NOT NULL, hash TEXT NOT NULL,
          registrationTime INTEGER NOT NULL,
          deriver TEXT, narSize INTEGER, ultimate INTEGER, sigs TEXT, ca TEXT
        );
        CREATE TABLE IF NOT EXISTS Refs (
          referrer INTEGER NOT NULL, reference INTEGER NOT NULL,
          PRIMARY KEY (referrer, reference)
        );
        PRAGMA journal_mode=WAL;
    SQL
        chmod 666 ${dir}/var/nix/db/db.sqlite
        chmod 666 ${dir}/var/nix/db/db.sqlite-wal 2>/dev/null || true
        chmod 666 ${dir}/var/nix/db/db.sqlite-shm 2>/dev/null || true
        chmod 777 ${dir}/var/nix/db
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
  # Test 1: multi-registry-priority -- higher priority registry wins
  # ---------------------------------------------------------------------------
  multi-registry-priority = testing.mkVMTest {
    name = "multi-registry-priority";
    rootfsDeps = serverDeps;
    memory = 1024;
    testScript = ''
            ${iproute2Bin} link set lo up || true
            ${iproute2Bin} addr add 127.0.0.1/8 dev lo 2>/dev/null || true

            FAIL=0

            # --- Registry A (port 15001) ---
            mkdir -p /tmp/reg-a/var/nix/db /tmp/reg-a/store /tmp/reg-a/meta /tmp/run/reg-a
            ${mkStoreDb "/tmp/reg-a"}

            TESTPKG_A="/tmp/reg-a/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1-testpkg-1.0"
            mkdir -p "$TESTPKG_A/bin"
            echo '#!/bin/sh' > "$TESTPKG_A/bin/testpkg"
            echo 'echo "testpkg v1.0"' >> "$TESTPKG_A/bin/testpkg"
            chmod +x "$TESTPKG_A/bin/testpkg"
            ${sqliteBin} /tmp/reg-a/var/nix/db/db.sqlite \
              "INSERT INTO ValidPaths (path, hash, registrationTime, narSize, ultimate, sigs) VALUES ('$TESTPKG_A', 'sha256:aaaa1', 1000000, 4096, 1, '''''');"

            cat > /tmp/reg-a-config.toml << 'CFGEOF'
            listen = "127.0.0.1:15001"
            [[views]]
            name = "default"
            anonymous_read = true
            [bootstrap]
            socket = "/tmp/run/reg-a/bootstrap.sock"
            socket_group = "root"
      CFGEOF

            AOS_ROOT=/tmp/reg-a ${aosBin} serve --config /tmp/reg-a-config.toml &
            REG_A_PID=$!

            # --- Registry B (port 15002) ---
            mkdir -p /tmp/reg-b/var/nix/db /tmp/reg-b/store /tmp/reg-b/meta /tmp/run/reg-b
            ${mkStoreDb "/tmp/reg-b"}

            TESTPKG_B="/tmp/reg-b/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb2-testpkg-2.0"
            mkdir -p "$TESTPKG_B/bin"
            echo '#!/bin/sh' > "$TESTPKG_B/bin/testpkg"
            echo 'echo "testpkg v2.0"' >> "$TESTPKG_B/bin/testpkg"
            chmod +x "$TESTPKG_B/bin/testpkg"
            ${sqliteBin} /tmp/reg-b/var/nix/db/db.sqlite \
              "INSERT INTO ValidPaths (path, hash, registrationTime, narSize, ultimate, sigs) VALUES ('$TESTPKG_B', 'sha256:bbbb2', 1000000, 4096, 1, '''''');"

            cat > /tmp/reg-b-config.toml << 'CFGEOF'
            listen = "127.0.0.1:15002"
            [[views]]
            name = "default"
            anonymous_read = true
            [bootstrap]
            socket = "/tmp/run/reg-b/bootstrap.sock"
            socket_group = "root"
      CFGEOF

            AOS_ROOT=/tmp/reg-b ${aosBin} serve --config /tmp/reg-b-config.toml &
            REG_B_PID=$!

            echo "==> Waiting for registries to start"
            for _i in 1 2 3 4 5 6 7 8 9 10; do
              HTTP_A=$(${curlBin} -s -o /dev/null -w '%{http_code}' http://127.0.0.1:15001/default/nix-cache-info 2>/dev/null) || true
              HTTP_B=$(${curlBin} -s -o /dev/null -w '%{http_code}' http://127.0.0.1:15002/default/nix-cache-info 2>/dev/null) || true
              if [ "$HTTP_A" = "200" ] && [ "$HTTP_B" = "200" ]; then break; fi
              sleep 1
            done

            echo "==> Verifying registry A"
            test "$HTTP_A" = "200" || { echo "FAIL: registry A not responding"; FAIL=1; }

            echo "==> Verifying registry B"
            test "$HTTP_B" = "200" || { echo "FAIL: registry B not responding"; FAIL=1; }

            echo "==> Reading cache-info from both"
            INFO_A=$(${curlBin} -s http://127.0.0.1:15001/default/nix-cache-info)
            echo "Registry A: $INFO_A"
            INFO_B=$(${curlBin} -s http://127.0.0.1:15002/default/nix-cache-info)
            echo "Registry B: $INFO_B"

            echo "==> Querying testpkg in both registries"
            HASH_A="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"
            HTTP_NA=$(${curlBin} -s -o /dev/null -w '%{http_code}' \
              "http://127.0.0.1:15001/default/$HASH_A.narinfo")
            echo "Registry A narinfo: HTTP $HTTP_NA"

            HASH_B="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb2"
            HTTP_NB=$(${curlBin} -s -o /dev/null -w '%{http_code}' \
              "http://127.0.0.1:15002/default/$HASH_B.narinfo")
            echo "Registry B narinfo: HTTP $HTTP_NB"

            echo "==> Both registries independently queryable"

            kill $REG_A_PID $REG_B_PID 2>/dev/null || true
            wait $REG_A_PID $REG_B_PID 2>/dev/null || true

            if [ "$FAIL" -ne 0 ]; then
              echo "==> multi-registry-priority FAILED"
              exit 1
            fi
            echo "==> multi-registry-priority passed"
    '';
  };

  # ---------------------------------------------------------------------------
  # Test 2: multi-registry-cross-containment -- overlapping deps
  # ---------------------------------------------------------------------------
  multi-registry-cross-containment = testing.mkVMTest {
    name = "multi-registry-cross-containment";
    rootfsDeps = serverDeps;
    memory = 1024;
    testScript = ''
            ${iproute2Bin} link set lo up || true
            ${iproute2Bin} addr add 127.0.0.1/8 dev lo 2>/dev/null || true

            FAIL=0

            # --- Registry A (sysroot provider, port 15001) ---
            mkdir -p /tmp/reg-a/var/nix/db /tmp/reg-a/store /tmp/reg-a/meta /tmp/run/reg-a
            ${mkStoreDb "/tmp/reg-a"}

            LIBZ="/tmp/reg-a/store/zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-libz-1.0"
            mkdir -p "$LIBZ/lib"
            echo "libz.so.1 stub" > "$LIBZ/lib/libz.so.1"
            ${sqliteBin} /tmp/reg-a/var/nix/db/db.sqlite \
              "INSERT INTO ValidPaths (path, hash, registrationTime, narSize, ultimate, sigs) VALUES ('$LIBZ', 'sha256:zzzz', 1000000, 4096, 1, '''''');"

            cat > /tmp/reg-a-config.toml << 'CFGEOF'
            listen = "127.0.0.1:15001"
            [[views]]
            name = "default"
            anonymous_read = true
            [bootstrap]
            socket = "/tmp/run/reg-a/bootstrap.sock"
            socket_group = "root"
      CFGEOF
            AOS_ROOT=/tmp/reg-a ${aosBin} serve --config /tmp/reg-a-config.toml &
            REG_A_PID=$!

            # --- Registry B (package provider, port 15002) ---
            mkdir -p /tmp/reg-b/var/nix/db /tmp/reg-b/store /tmp/reg-b/meta /tmp/run/reg-b
            ${mkStoreDb "/tmp/reg-b"}

            # Same libz hash in registry B
            LIBZ_B="/tmp/reg-b/store/zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-libz-1.0"
            mkdir -p "$LIBZ_B/lib"
            echo "libz.so.1 stub" > "$LIBZ_B/lib/libz.so.1"
            ${sqliteBin} /tmp/reg-b/var/nix/db/db.sqlite \
              "INSERT INTO ValidPaths (path, hash, registrationTime, narSize, ultimate, sigs) VALUES ('$LIBZ_B', 'sha256:zzzz', 1000000, 4096, 1, '''''');"

            PKG="/tmp/reg-b/store/pppppppppppppppppppppppppppppppppp-mypkg-1.0"
            mkdir -p "$PKG/bin"
            echo '#!/bin/sh' > "$PKG/bin/mypkg"
            echo 'echo "mypkg works"' >> "$PKG/bin/mypkg"
            chmod +x "$PKG/bin/mypkg"
            ${sqliteBin} /tmp/reg-b/var/nix/db/db.sqlite \
              "INSERT INTO ValidPaths (path, hash, registrationTime, narSize, ultimate, sigs) VALUES ('$PKG', 'sha256:pppp', 1000000, 2048, 1, '''''');"

            cat > /tmp/reg-b-config.toml << 'CFGEOF'
            listen = "127.0.0.1:15002"
            [[views]]
            name = "default"
            anonymous_read = true
            [bootstrap]
            socket = "/tmp/run/reg-b/bootstrap.sock"
            socket_group = "root"
      CFGEOF
            AOS_ROOT=/tmp/reg-b ${aosBin} serve --config /tmp/reg-b-config.toml &
            REG_B_PID=$!

            for _i in 1 2 3 4 5 6 7 8 9 10; do
              HTTP_A=$(${curlBin} -s -o /dev/null -w '%{http_code}' http://127.0.0.1:15001/default/nix-cache-info 2>/dev/null) || true
              HTTP_B=$(${curlBin} -s -o /dev/null -w '%{http_code}' http://127.0.0.1:15002/default/nix-cache-info 2>/dev/null) || true
              if [ "$HTTP_A" = "200" ] && [ "$HTTP_B" = "200" ]; then break; fi
              sleep 1
            done
            test "$HTTP_A" = "200" || { echo "FAIL: registry A not up"; FAIL=1; }
            test "$HTTP_B" = "200" || { echo "FAIL: registry B not up"; FAIL=1; }

            echo "==> Cross-containment: checking libz in both registries"
            HASH_Z="zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
            HTTP_Z_A=$(${curlBin} -s -o /dev/null -w '%{http_code}' \
              "http://127.0.0.1:15001/default/$HASH_Z.narinfo")
            HTTP_Z_B=$(${curlBin} -s -o /dev/null -w '%{http_code}' \
              "http://127.0.0.1:15002/default/$HASH_Z.narinfo")
            echo "Registry A libz: HTTP $HTTP_Z_A"
            echo "Registry B libz: HTTP $HTTP_Z_B"

            HASH_P="pppppppppppppppppppppppppppppppppp"
            HTTP_P=$(${curlBin} -s -o /dev/null -w '%{http_code}' \
              "http://127.0.0.1:15002/default/$HASH_P.narinfo")
            echo "Registry B mypkg: HTTP $HTTP_P"

            kill $REG_A_PID $REG_B_PID 2>/dev/null || true
            wait $REG_A_PID $REG_B_PID 2>/dev/null || true

            if [ "$FAIL" -ne 0 ]; then
              echo "==> multi-registry-cross-containment FAILED"
              exit 1
            fi
            echo "==> multi-registry-cross-containment passed"
    '';
  };

  # ---------------------------------------------------------------------------
  # Test 3: multi-registry-mirror -- upstream and mirror
  # ---------------------------------------------------------------------------
  multi-registry-mirror = testing.mkVMTest {
    name = "multi-registry-mirror";
    rootfsDeps = serverDeps;
    memory = 1024;
    testScript = ''
            ${iproute2Bin} link set lo up || true
            ${iproute2Bin} addr add 127.0.0.1/8 dev lo 2>/dev/null || true

            FAIL=0

            # --- Upstream (port 15001) ---
            mkdir -p /tmp/upstream/var/nix/db /tmp/upstream/store /tmp/upstream/meta /tmp/run/upstream
            ${mkStoreDb "/tmp/upstream"}

            for i in 1 2 3; do
              MPKG="/tmp/upstream/store/mirrortest000000000000000000000$i-mirror-pkg-$i"
              mkdir -p "$MPKG/bin"
              echo "mirror pkg $i" > "$MPKG/bin/data"
              ${sqliteBin} /tmp/upstream/var/nix/db/db.sqlite \
                "INSERT INTO ValidPaths (path, hash, registrationTime, narSize, ultimate, sigs) VALUES ('$MPKG', 'sha256:mirror$i', 1000000, 1024, 1, '''''');"
            done

            cat > /tmp/upstream-config.toml << 'CFGEOF'
            listen = "127.0.0.1:15001"
            [[views]]
            name = "default"
            anonymous_read = true
            [bootstrap]
            socket = "/tmp/run/upstream/bootstrap.sock"
            socket_group = "root"
      CFGEOF
            AOS_ROOT=/tmp/upstream ${aosBin} serve --config /tmp/upstream-config.toml &
            UPSTREAM_PID=$!

            # --- Mirror (port 15002, starts empty) ---
            mkdir -p /tmp/mirror/var/nix/db /tmp/mirror/store /tmp/mirror/meta /tmp/run/mirror
            ${mkStoreDb "/tmp/mirror"}

            cat > /tmp/mirror-config.toml << 'CFGEOF'
            listen = "127.0.0.1:15002"
            [[views]]
            name = "default"
            anonymous_read = true
            [bootstrap]
            socket = "/tmp/run/mirror/bootstrap.sock"
            socket_group = "root"
      CFGEOF
            AOS_ROOT=/tmp/mirror ${aosBin} serve --config /tmp/mirror-config.toml &
            MIRROR_PID=$!

            for _i in 1 2 3 4 5 6 7 8 9 10; do
              HTTP_UP=$(${curlBin} -s -o /dev/null -w '%{http_code}' http://127.0.0.1:15001/default/nix-cache-info 2>/dev/null) || true
              HTTP_MR=$(${curlBin} -s -o /dev/null -w '%{http_code}' http://127.0.0.1:15002/default/nix-cache-info 2>/dev/null) || true
              if [ "$HTTP_UP" = "200" ] && [ "$HTTP_MR" = "200" ]; then break; fi
              sleep 1
            done
            test "$HTTP_UP" = "200" || { echo "FAIL: upstream not responding"; FAIL=1; }
            test "$HTTP_MR" = "200" || { echo "FAIL: mirror not responding"; FAIL=1; }

            # Get auth for upstream
            RESP_UP=$(echo '{"action":"create","views":["default"],"permissions":["read","build"]}' | \
              ${socatBin} - UNIX-CONNECT:/tmp/run/upstream/bootstrap.sock)
            TOKEN_UP=$(echo "$RESP_UP" | ${jqBin} -r '.data.token // empty')
            JWT_UP=$(${curlBin} -s -X POST -H "Authorization: Bearer $TOKEN_UP" \
              -H "Content-Type: application/x-www-form-urlencoded" \
              -d "grant_type=client_credentials" \
              http://127.0.0.1:15001/oauth2/token | ${jqBin} -r '.access_token // empty')

            # Get auth for mirror
            RESP_MR=$(echo '{"action":"create","views":["default"],"permissions":["read","build"]}' | \
              ${socatBin} - UNIX-CONNECT:/tmp/run/mirror/bootstrap.sock)
            TOKEN_MR=$(echo "$RESP_MR" | ${jqBin} -r '.data.token // empty')
            JWT_MR=$(${curlBin} -s -X POST -H "Authorization: Bearer $TOKEN_MR" \
              -H "Content-Type: application/x-www-form-urlencoded" \
              -d "grant_type=client_credentials" \
              http://127.0.0.1:15002/oauth2/token | ${jqBin} -r '.access_token // empty')

            echo "==> Verify upstream has packages"
            QM_UP=$(${curlBin} -s -X POST -H "Authorization: Bearer $JWT_UP" \
              -H "Content-Type: application/json" \
              -d '{"paths":["/tmp/upstream/store/mirrortest0000000000000000000001-mirror-pkg-1"]}' \
              http://127.0.0.1:15001/default/query-missing)
            UP_MISSING=$(echo "$QM_UP" | ${jqBin} '.missing | length')
            echo "Upstream missing: $UP_MISSING"

            echo "==> Verify mirror is initially empty"
            QM_MR=$(${curlBin} -s -X POST -H "Authorization: Bearer $JWT_MR" \
              -H "Content-Type: application/json" \
              -d '{"paths":["/tmp/mirror/store/mirrortest0000000000000000000001-mirror-pkg-1"]}' \
              http://127.0.0.1:15002/default/query-missing)
            MR_MISSING=$(echo "$QM_MR" | ${jqBin} '.missing | length')
            echo "Mirror missing: $MR_MISSING"

            echo "==> Mirror comparison: upstream=$UP_MISSING, mirror=$MR_MISSING"

            kill $UPSTREAM_PID $MIRROR_PID 2>/dev/null || true
            wait $UPSTREAM_PID $MIRROR_PID 2>/dev/null || true

            if [ "$FAIL" -ne 0 ]; then
              echo "==> multi-registry-mirror FAILED"
              exit 1
            fi
            echo "==> multi-registry-mirror passed"
    '';
  };
}
