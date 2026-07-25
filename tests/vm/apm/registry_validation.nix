# tests/vm/apm/registry_validation.nix -- Registry production-validation VM tests
#
# These checks turn the registry validation runbook into repeatable VM tests.
# They run inside headless Firecracker VMs on a KVM builder, not on developer
# laptops.
{
  testing,
  pkgs,
  aosPkg,
}: let
  fixtures = import ./fixtures.nix {inherit pkgs aosPkg;};
  gitFloor = pkgs."git-2_42";

  nixRuntimeLibs = [
    pkgs.nix
    pkgs.brotli
    pkgs.curl
    pkgs.openssl
    pkgs.sqlite
    pkgs.boost
    pkgs.editline
    pkgs.libsodium
    pkgs.libarchive
    pkgs.gc
    pkgs.lowdown
    pkgs.bzip2
    pkgs.zlib
  ];
  nixLibPath = builtins.concatStringsSep ":" (map (pkg: "${pkg}/lib") nixRuntimeLibs);

  backendLeafTool = pkgs.mkDerivation {
    pname = "registry-backend-leaf";
    version = "1.0.0";
    src = null;
    buildDeps = [
      pkgs.coreutils
      pkgs.bash
    ];
    phases = [
      {
        name = "build";
        script = ''
          mkdir -p "$out/bin"
          printf '%s\n' \
            '#!${pkgs.bash}/bin/bash' \
            'printf "registry-backend-leaf 1.0.0\n"' \
            > "$out/bin/registry-backend-leaf"
          chmod +x "$out/bin/registry-backend-leaf"
        '';
      }
    ];
  };

  backendRootTool = pkgs.mkDerivation {
    pname = "registry-backend-root";
    version = "1.0.0";
    src = null;
    buildDeps = [
      pkgs.coreutils
      pkgs.bash
    ];
    runtimeDeps = [
      backendLeafTool
    ];
    phases = [
      {
        name = "build";
        script = ''
          mkdir -p "$out/bin"
          printf '%s\n' \
            '#!${pkgs.bash}/bin/bash' \
            'leaf_output="$(${backendLeafTool}/bin/registry-backend-leaf)"' \
            'printf "registry-backend-root via %s\n" "$leaf_output"' \
            > "$out/bin/registry-backend-root"
          chmod +x "$out/bin/registry-backend-root"
        '';
      }
    ];
  };

  validationDeps =
    fixtures.commonDeps
    ++ nixRuntimeLibs
    ++ [
      pkgs.curl
      pkgs.diffutils
      pkgs.findutils
      pkgs.iproute2
      pkgs.openssh
      pkgs.python3
      pkgs.zstd
      backendLeafTool
      backendRootTool
    ];

  gitOnlyDeps = [
    pkgs.git
    pkgs.grep
    pkgs.coreutils
  ];

  gitEnv = ''
    export HOME=/tmp
    export GIT_AUTHOR_NAME="VM Test"
    export GIT_AUTHOR_EMAIL="vm@example.com"
    export GIT_COMMITTER_NAME="VM Test"
    export GIT_COMMITTER_EMAIL="vm@example.com"
  '';

  setupNixStore = ''
    mount -o remount,rw /
    export HOME=/tmp
    export NIX_CONF_DIR=/tmp/nix-conf
    export LD_LIBRARY_PATH="${nixLibPath}:$LD_LIBRARY_PATH"
    mkdir -p "$NIX_CONF_DIR" /nix/var/nix/db /nix/var/nix/gcroots /tmp
    cat > "$NIX_CONF_DIR/nix.conf" << 'NIXCONF'
    sandbox = false
    experimental-features = nix-command
    NIXCONF
    nix-store --init
    nix-store --load-db < /aos-registration
  '';

  registryFixtureHelpers = ''
    create_registry_for_store_path() {
      reg_name="$1"
      store_path="$2"
      store_hash=$(basename "$store_path" | cut -d- -f1)

      $APR create "$reg_name" > "/tmp/$reg_name-create.log" 2>&1 || {
        cat "/tmp/$reg_name-create.log"
        return 1
      }
      cat "/tmp/$reg_name-create.log"

      $APR publish "$store_path" \
        --name fixture \
        --version 1.0.0 \
        --description "VM validation fixture" \
        --license MIT \
        --maintainer registry@example.com \
        --registry "$reg_name" \
        --no-commit > "/tmp/$reg_name-publish.log" 2>&1 || {
        cat "/tmp/$reg_name-publish.log"
        return 1
      }
      cat "/tmp/$reg_name-publish.log"

      reg_dir="$REG_STORAGE/$reg_name"
      test -f "$reg_dir/packages/f/fixture.toml"
      test -f "$reg_dir/store/$(printf %.2s "$store_hash")/$store_hash"
      grep -q "$store_path" "$reg_dir/packages/f/fixture.toml"
      grep -q "nar:sha256:" "$reg_dir/store/$(printf %.2s "$store_hash")/$store_hash"

      $APR verify --registry "$reg_name" > "/tmp/$reg_name-verify.log" 2>&1 || {
        cat "/tmp/$reg_name-verify.log"
        return 1
      }
      cat "/tmp/$reg_name-verify.log"
    }
  '';

  s3Server = ''
    start_s3_server() {
      s3_port="$1"
      s3_root="$2"
      s3_events="$3"
      mkdir -p "$s3_root"
      : > "$s3_events"
      cat > /tmp/aos-s3-server.py << 'PY'
    import json
    import os
    import sys
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import unquote, urlsplit

    port = int(sys.argv[1])
    root = sys.argv[2]
    events = sys.argv[3]

    def object_path(raw_path):
        path = unquote(urlsplit(raw_path).path)
        return path.lstrip("/")

    def disk_path(key):
        return os.path.join(root, key)

    def log_event(method, key, headers):
        row = {
            "method": method,
            "path": key,
            "cache_control": headers.get("Cache-Control"),
            "content_type": headers.get("Content-Type"),
        }
        with open(events, "a", encoding="utf-8") as f:
            f.write(json.dumps(row, sort_keys=True) + "\n")

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            if self.path == "/health":
                body = b"ok\n"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            key = object_path(self.path)
            path = disk_path(key)
            if not os.path.isfile(path):
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            with open(path, "rb") as f:
                body = f.read()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_HEAD(self):
            key = object_path(self.path)
            path = disk_path(key)
            if not os.path.isfile(path):
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Length", str(os.path.getsize(path)))
            self.end_headers()

        def do_PUT(self):
            key = object_path(self.path)
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            path = disk_path(key)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as f:
                f.write(body)
            log_event("PUT", key, self.headers)
            self.send_response(200)
            self.send_header("ETag", '"aos-vm-test"')
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, fmt, *args):
            return

    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
    PY
      PYTHONUNBUFFERED=1 python3 /tmp/aos-s3-server.py "$s3_port" "$s3_root" "$s3_events" \
        > /tmp/aos-s3-server.log 2>&1 &
      S3_PID=$!
      for _i in 1 2 3 4 5 6 7 8 9 10; do
        if curl -sf "http://127.0.0.1:$s3_port/health" >/dev/null; then
          return 0
        fi
        sleep 1
      done
      echo "S3 test server did not start"
      cat /tmp/aos-s3-server.log || true
      return 1
    }
  '';

  httpAuthServer = ''
    start_http_auth_server() {
      http_port="$1"
      http_root="$2"
      http_events="$3"
      mkdir -p "$http_root"
      : > "$http_events"
      cat > /tmp/aos-http-auth-server.py << 'PY'
    import json
    import os
    import sys
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import unquote, urlsplit

    port = int(sys.argv[1])
    root = sys.argv[2]
    events = sys.argv[3]
    expected_auth = "Basic YW9zLXVwbG9hZGVyOmNhY2hlLXNlY3JldA=="
    expected_header = "registry-validation"

    def object_path(raw_path):
        path = unquote(urlsplit(raw_path).path)
        return path.lstrip("/")

    def disk_path(key):
        return os.path.join(root, key)

    def log_event(method, key, headers, auth_ok):
        row = {
            "method": method,
            "path": key,
            "auth_present": headers.get("Authorization") is not None,
            "auth_ok": auth_ok,
            "fixture_header": headers.get("X-AOS-Fixture"),
            "cache_control": headers.get("Cache-Control"),
            "content_type": headers.get("Content-Type"),
        }
        with open(events, "a", encoding="utf-8") as f:
            f.write(json.dumps(row, sort_keys=True) + "\n")

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def authenticated(self):
            return (
                self.headers.get("Authorization") == expected_auth
                and self.headers.get("X-AOS-Fixture") == expected_header
            )

        def reject(self, key):
            log_event(self.command, key, self.headers, False)
            body = b"unauthorized\n"
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="aos-test"')
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def do_GET(self):
            if self.path == "/health":
                body = b"ok\n"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            key = object_path(self.path)
            if not self.authenticated():
                self.reject(key)
                return
            path = disk_path(key)
            if not os.path.isfile(path):
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            with open(path, "rb") as f:
                body = f.read()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_HEAD(self):
            key = object_path(self.path)
            if not self.authenticated():
                self.reject(key)
                return
            log_event("HEAD", key, self.headers, True)
            path = disk_path(key)
            if not os.path.isfile(path):
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Length", str(os.path.getsize(path)))
            self.end_headers()

        def do_PUT(self):
            key = object_path(self.path)
            if not self.authenticated():
                self.reject(key)
                return
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            path = disk_path(key)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as f:
                f.write(body)
            log_event("PUT", key, self.headers, True)
            self.send_response(200)
            self.send_header("ETag", '"aos-http-auth-test"')
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, fmt, *args):
            return

    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
    PY
      PYTHONUNBUFFERED=1 python3 /tmp/aos-http-auth-server.py "$http_port" "$http_root" "$http_events" \
        > /tmp/aos-http-auth-server.log 2>&1 &
      HTTP_AUTH_PID=$!
      for _i in 1 2 3 4 5 6 7 8 9 10; do
        if curl -sf "http://127.0.0.1:$http_port/health" >/dev/null; then
          return 0
        fi
        sleep 1
      done
      echo "HTTP auth test server did not start"
      cat /tmp/aos-http-auth-server.log || true
      return 1
    }
  '';

  sftpServer = ''
    start_sftp_server() {
      mkdir -p /run/sshd /var/empty /root/.ssh
      grep -q '^sshd:' /etc/passwd || echo 'sshd:x:74:74:sshd:/var/empty:/sbin/nologin' >> /etc/passwd
      grep -q '^sshd:' /etc/group || echo 'sshd:x:74:' >> /etc/group
      ssh-keygen -q -t ed25519 -N "" -f /tmp/sftp-host-key
      ssh-keygen -q -t ed25519 -N "" -f /tmp/sftp-client-key
      cp /tmp/sftp-client-key.pub /tmp/sftp-authorized-keys
      chmod 600 /tmp/sftp-client-key /tmp/sftp-authorized-keys
      cat > /tmp/sshd_config << EOF
    Port 2222
    ListenAddress 127.0.0.1
    HostKey /tmp/sftp-host-key
    PidFile /tmp/sshd.pid
    PermitRootLogin yes
    AuthorizedKeysFile /tmp/sftp-authorized-keys
    PasswordAuthentication no
    ChallengeResponseAuthentication no
    UsePAM no
    StrictModes no
    Subsystem sftp ${pkgs.openssh}/libexec/sftp-server
    EOF
      ${pkgs.openssh}/sbin/sshd -D -e -f /tmp/sshd_config > /tmp/sshd.log 2>&1 &
      SSHD_PID=$!
      for _i in 1 2 3 4 5 6 7 8 9 10; do
        if ssh -i /tmp/sftp-client-key -p 2222 \
          -o StrictHostKeyChecking=no -o UserKnownHostsFile=/tmp/known_hosts \
          -o BatchMode=yes root@127.0.0.1 true >/dev/null 2>&1; then
          return 0
        fi
        sleep 1
      done
      echo "sshd did not start"
      cat /tmp/sshd.log || true
      return 1
    }
  '';
in {
  registry-validation-stock-nix-backend-array = testing.mkVMTest {
    name = "apm-registry-validation-stock-nix-backend-array";
    rootfsDeps = validationDeps;
    memory = 2048;
    testScript = ''
        ${setupNixStore}
        ${fixtures.setupPreamble}
        ${registryFixtureHelpers}
        ${s3Server}
        ${httpAuthServer}
        ${sftpServer}

        set -e
        ip link set lo up || true
        ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
        export AWS_ACCESS_KEY_ID=aos-test
        export AWS_SECRET_ACCESS_KEY=aos-test-secret
        export AWS_EC2_METADATA_DISABLED=true

        STORE_PATH="${backendRootTool}"
        LEAF_PATH="${backendLeafTool}"
        STORE_HASH=$(basename "$STORE_PATH" | cut -d- -f1)
        LEAF_HASH=$(basename "$LEAF_PATH" | cut -d- -f1)
        create_registry_for_store_path vm-cache "$STORE_PATH"
        nix-store -q --references "$STORE_PATH" > /tmp/backend-root-refs.out
        grep -q "$LEAF_PATH" /tmp/backend-root-refs.out
        grep -q "$LEAF_HASH" "$REG_STORAGE/vm-cache/store/$(printf %.2s "$STORE_HASH")/$STORE_HASH"

        nix --extra-experimental-features nix-command key generate-secret \
          --key-name aos-cache > /tmp/nix-cache.sec
        TRUSTED_PUBLIC_KEY=$(nix --extra-experimental-features nix-command \
          key convert-secret-to-public < /tmp/nix-cache.sec)

        start_s3_server 19000 /tmp/s3-cache-root /tmp/s3-cache-events.jsonl
        start_http_auth_server 19002 /tmp/http-cache-root /tmp/http-cache-events.jsonl
        start_sftp_server
        mkdir -p /tmp/sftp-cache/nar

        # A valid multi-destination upload succeeds for every real backend.
        $APR cache generate --registry vm-cache \
          --output /tmp/generated-cache \
          --key /tmp/nix-cache.sec \
          --priority 37 \
          --no-commit \
          --upload-url file:///tmp/local-cache \
          --upload-url s3://aos-registry-test/cache \
          --upload-url sftp://root@127.0.0.1:2222/tmp/sftp-cache \
          --s3-region us-east-1 \
          --s3-endpoint http://127.0.0.1:19000 \
          --ssh-key /tmp/sftp-client-key \
          > /tmp/cache-generate.log 2>&1
        cat /tmp/cache-generate.log

        # An invalid --upload-url is now rejected up front: the remote cache
        # membership checker is created for every destination before any
        # upload, so a single bad URL fails the whole generate fast (no
        # partial-success accounting).
        set +e
        $APR cache generate --registry vm-cache \
          --output /tmp/generated-cache-invalid-url \
          --key /tmp/nix-cache.sec \
          --no-commit \
          --upload-url file:///tmp/local-cache-invalid \
          --upload-url not-a-url \
          > /tmp/cache-generate-invalid-url.log 2>&1
        INVALID_STATUS=$?
        set -e
        cat /tmp/cache-generate-invalid-url.log
        test "$INVALID_STATUS" -ne 0
        grep -q "not-a-url" /tmp/cache-generate-invalid-url.log

        test -f /tmp/generated-cache/nix-cache-info
        test -f "/tmp/generated-cache/$STORE_HASH.narinfo"
        test -f "/tmp/generated-cache/$LEAF_HASH.narinfo"
        NARINFO_COUNT=$(find /tmp/generated-cache -maxdepth 1 -name '*.narinfo' | wc -l | tr -d ' ')
        test "$NARINFO_COUNT" -gt 1
        grep -q "Sig: aos-cache:" "/tmp/generated-cache/$STORE_HASH.narinfo"
        grep -q "Priority: 37" /tmp/generated-cache/nix-cache-info

        test -f /tmp/local-cache/nix-cache-info
        test -f "/tmp/local-cache/$STORE_HASH.narinfo"
        test -f "/tmp/local-cache/$LEAF_HASH.narinfo"
        test -f "/tmp/sftp-cache/$STORE_HASH.narinfo"
        test -f "/tmp/sftp-cache/$LEAF_HASH.narinfo"
        test -f "/tmp/s3-cache-root/aos-registry-test/cache/$STORE_HASH.narinfo"
        test -f "/tmp/s3-cache-root/aos-registry-test/cache/$LEAF_HASH.narinfo"
        cmp "/tmp/generated-cache/$STORE_HASH.narinfo" "/tmp/local-cache/$STORE_HASH.narinfo"
        cmp "/tmp/generated-cache/$STORE_HASH.narinfo" "/tmp/sftp-cache/$STORE_HASH.narinfo"
        cmp "/tmp/generated-cache/$STORE_HASH.narinfo" \
          "/tmp/s3-cache-root/aos-registry-test/cache/$STORE_HASH.narinfo"

        set +e
        $APR cache generate --registry vm-cache \
          --output /tmp/generated-cache-http-missing-auth \
          --key /tmp/nix-cache.sec \
          --priority 39 \
          --no-commit \
          --upload-url http://127.0.0.1:19002/protected-cache \
          > /tmp/cache-generate-http-missing-auth.log 2>&1
        HTTP_MISSING_AUTH_STATUS=$?
        set -e
        cat /tmp/cache-generate-http-missing-auth.log
        test "$HTTP_MISSING_AUTH_STATUS" -ne 0
        grep -q "HTTP 401" /tmp/cache-generate-http-missing-auth.log
        test ! -e /tmp/http-cache-root/protected-cache/nix-cache-info

        $APR cache generate --registry vm-cache \
          --output /tmp/generated-cache-http-auth \
          --key /tmp/nix-cache.sec \
          --priority 39 \
          --no-commit \
          --upload-url http://127.0.0.1:19002/protected-cache \
          --http-user aos-uploader \
          --http-password cache-secret \
          --header "X-AOS-Fixture: registry-validation" \
          > /tmp/cache-generate-http-auth.log 2>&1
        cat /tmp/cache-generate-http-auth.log
        test -f /tmp/http-cache-root/protected-cache/nix-cache-info
        test -f "/tmp/http-cache-root/protected-cache/$STORE_HASH.narinfo"
        test -f "/tmp/http-cache-root/protected-cache/$LEAF_HASH.narinfo"
        find /tmp/http-cache-root/protected-cache/nar -type f | grep -q .
        cmp "/tmp/generated-cache-http-auth/$STORE_HASH.narinfo" \
          "/tmp/http-cache-root/protected-cache/$STORE_HASH.narinfo"
        grep -q "Priority: 39" /tmp/http-cache-root/protected-cache/nix-cache-info
        set +e
        python3 - /tmp/http-cache-events.jsonl "$STORE_HASH" "$LEAF_HASH" \
          > /tmp/assert-http-auth-cache.log 2>&1 << 'PY'
      import json
      import sys

      events_path, store_hash, leaf_hash = sys.argv[1], sys.argv[2], sys.argv[3]
      with open(events_path, encoding="utf-8") as f:
          events = [json.loads(line) for line in f if line.strip()]

      if not any(event["auth_ok"] is False for event in events):
          raise AssertionError("missing unauthenticated failure event")

      ok_events = [event for event in events if event["auth_ok"] is True]
      if not ok_events:
          raise AssertionError("missing authenticated upload events")
      if any(event["fixture_header"] != "registry-validation" for event in ok_events):
          raise AssertionError(f"authenticated event lost custom header: {ok_events}")
      if not any(event["path"] == f"protected-cache/{store_hash}.narinfo" for event in ok_events):
          raise AssertionError("authenticated upload did not write narinfo")
      if not any(event["path"] == f"protected-cache/{leaf_hash}.narinfo" for event in ok_events):
          raise AssertionError("authenticated upload did not write dependency narinfo")
      if not any(event["path"] == "protected-cache/nix-cache-info" for event in ok_events):
          raise AssertionError("authenticated upload did not write nix-cache-info")
      if not any(event["path"].startswith("protected-cache/nar/") for event in ok_events):
          raise AssertionError("authenticated upload did not write NAR body")
      PY
        HTTP_AUTH_ASSERT_STATUS=$?
        set -e
        cat /tmp/assert-http-auth-cache.log
        if [ "$HTTP_AUTH_ASSERT_STATUS" -ne 0 ]; then
          exit 1
        fi

        {
          printf "%s\n" "[registry]"
          printf "%s\n" "name = \"vm-cache\""
          printf "%s\n" "url = \"file:///tmp/vm-cache-origin\""
          printf "%s\n" "priority = 500"
          printf "%s\n" ""
          printf "%s\n" "[registry.upload_auth]"
          printf "%s\n" "s3_region = \"us-east-1\""
          printf "%s\n" "s3_endpoint = \"http://127.0.0.1:19000\""
          printf "%s\n" "ssh_key = \"/tmp/sftp-client-key\""
        } > "$APM_CONFIG/registries.d/vm-cache.toml"

        mkdir -p /tmp/sftp-cache-config/nar
        $APR cache generate --registry vm-cache \
          --output /tmp/generated-cache-config-auth \
          --key /tmp/nix-cache.sec \
          --priority 38 \
          --no-commit \
          --upload-url file:///tmp/local-cache-config \
          --upload-url s3://aos-registry-test/config-cache \
          --upload-url sftp://root@127.0.0.1:2222/tmp/sftp-cache-config \
          > /tmp/cache-generate-config-auth.log 2>&1
        cat /tmp/cache-generate-config-auth.log

        test -f /tmp/local-cache-config/nix-cache-info
        test -f "/tmp/local-cache-config/$STORE_HASH.narinfo"
        test -f "/tmp/local-cache-config/$LEAF_HASH.narinfo"
        test -f "/tmp/sftp-cache-config/$STORE_HASH.narinfo"
        test -f "/tmp/sftp-cache-config/$LEAF_HASH.narinfo"
        test -f "/tmp/s3-cache-root/aos-registry-test/config-cache/$STORE_HASH.narinfo"
        test -f "/tmp/s3-cache-root/aos-registry-test/config-cache/$LEAF_HASH.narinfo"
        cmp "/tmp/generated-cache-config-auth/$STORE_HASH.narinfo" \
          "/tmp/local-cache-config/$STORE_HASH.narinfo"
        cmp "/tmp/generated-cache-config-auth/$STORE_HASH.narinfo" \
          "/tmp/sftp-cache-config/$STORE_HASH.narinfo"
        cmp "/tmp/generated-cache-config-auth/$STORE_HASH.narinfo" \
          "/tmp/s3-cache-root/aos-registry-test/config-cache/$STORE_HASH.narinfo"
        grep -q "Priority: 38" /tmp/generated-cache-config-auth/nix-cache-info

        PYTHONUNBUFFERED=1 python3 -m http.server 18080 --bind 127.0.0.1 \
          --directory /tmp/generated-cache > /tmp/static-cache-http.log 2>&1 &
        HTTP_PID=$!
        for _i in 1 2 3 4 5 6 7 8 9 10; do
          if curl -sf http://127.0.0.1:18080/nix-cache-info >/dev/null; then
            break
          fi
          sleep 1
        done

        nix --extra-experimental-features nix-command \
          --option require-sigs true \
          --option trusted-public-keys "$TRUSTED_PUBLIC_KEY" \
          path-info --store http://127.0.0.1:18080 "$STORE_PATH" \
          > /tmp/stock-nix-path-info.out
        grep -q "$STORE_PATH" /tmp/stock-nix-path-info.out

        nix-store --delete --ignore-liveness "$STORE_PATH" > /tmp/delete-backend-root.out 2>&1 || {
          cat /tmp/delete-backend-root.out
          exit 1
        }
        nix-store --delete --ignore-liveness "$LEAF_PATH" > /tmp/delete-backend-leaf.out 2>&1 || {
          cat /tmp/delete-backend-leaf.out
          exit 1
        }
        if nix-store --check-validity "$STORE_PATH" > /tmp/backend-root-missing.out 2>&1; then
          cat /tmp/backend-root-missing.out
          exit 1
        fi
        if nix-store --check-validity "$LEAF_PATH" > /tmp/backend-leaf-missing.out 2>&1; then
          cat /tmp/backend-leaf-missing.out
          exit 1
        fi

        nix --extra-experimental-features nix-command \
          --option require-sigs true \
          --option trusted-public-keys "$TRUSTED_PUBLIC_KEY" \
          copy --from http://127.0.0.1:18080 "$STORE_PATH" \
          > /tmp/stock-nix-copy.out 2>&1 || {
          cat /tmp/stock-nix-copy.out
          exit 1
        }
        cat /tmp/stock-nix-copy.out
        nix-store --check-validity "$STORE_PATH" > /tmp/backend-root-valid.out 2>&1 || {
          cat /tmp/backend-root-valid.out
          exit 1
        }
        nix-store --check-validity "$LEAF_PATH" > /tmp/backend-leaf-valid.out 2>&1 || {
          cat /tmp/backend-leaf-valid.out
          exit 1
        }
        "$STORE_PATH/bin/registry-backend-root" > /tmp/stock-nix-run.out || {
          cat /tmp/stock-nix-run.out
          exit 1
        }
        grep -q "^registry-backend-root via registry-backend-leaf 1.0.0$" /tmp/stock-nix-run.out || {
          cat /tmp/stock-nix-run.out
          exit 1
        }
        NAR_GETS=$(grep -E 'GET /nar/.*\.nar\.zst HTTP/' /tmp/static-cache-http.log 2>/dev/null | wc -l | tr -d ' ')
        test "$NAR_GETS" -ge 2 || {
          cat /tmp/static-cache-http.log || true
          exit 1
        }

        echo "registry stock Nix + backend array validation passed"
    '';
  };

  registry-validation-origin-cdn-layout = testing.mkVMTest {
    name = "apm-registry-validation-origin-cdn-layout";
    rootfsDeps = validationDeps;
    memory = 2048;
    testScript = ''
        ${setupNixStore}
        ${fixtures.setupPreamble}
        ${registryFixtureHelpers}
        ${s3Server}

        set -e
        ip link set lo up || true
        ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
        export AWS_ACCESS_KEY_ID=aos-test
        export AWS_SECRET_ACCESS_KEY=aos-test-secret
        export AWS_EC2_METADATA_DISABLED=true

        STORE_PATH="${backendRootTool}"
        LEAF_PATH="${backendLeafTool}"
        STORE_HASH=$(basename "$STORE_PATH" | cut -d- -f1)
        LEAF_HASH=$(basename "$LEAF_PATH" | cut -d- -f1)
        create_registry_for_store_path cdn-cache "$STORE_PATH"
        nix-store -q --references "$STORE_PATH" > /tmp/cdn-root-refs.out
        grep -q "$LEAF_PATH" /tmp/cdn-root-refs.out
        grep -q "$LEAF_HASH" "$REG_STORAGE/cdn-cache/store/$(printf %.2s "$STORE_HASH")/$STORE_HASH"
        nix --extra-experimental-features nix-command key generate-secret \
          --key-name aos-cache > /tmp/nix-cache.sec
        $APR cache generate --registry cdn-cache \
          --output /tmp/generated-cache \
          --key /tmp/nix-cache.sec \
          --priority 37 \
          --no-commit

        $APR create cdn-reg
        REG_DIR="$REG_STORAGE/cdn-reg"
        mkdir -p "$REG_DIR/channels/stable" "$REG_DIR/.git/channels/stable"
        printf 'channel-pointer\n' > "$REG_DIR/.git/channels/stable/00"
        mkdir -p \
          "$REG_DIR/target/debug" \
          "$REG_DIR/.git/target/debug" \
          /tmp/generated-cache/target/debug \
          /tmp/generated-cache/tmp
        dd if=/dev/zero of="$REG_DIR/target/debug/worktree-build.bin" \
          bs=1M count=2 status=none
        dd if=/dev/zero of="$REG_DIR/.git/target/debug/git-build.bin" \
          bs=1M count=2 status=none
        dd if=/dev/zero of=/tmp/generated-cache/target/debug/cache-build.bin \
          bs=1M count=2 status=none
        printf 'scratch\n' > /tmp/generated-cache/tmp/scratch.txt
        cat > "$APM_CONFIG/registries.d/cdn-reg.toml" << 'EOF'
      [registry]
      name = "cdn-reg"
      url = "file:///tmp/cdn-reg-origin"
      priority = 500

      [registry.upload_auth]
      s3_region = "us-east-1"
      s3_endpoint = "http://127.0.0.1:19001"
      EOF

        start_s3_server 19001 /tmp/s3-origin-root /tmp/s3-origin-events.jsonl
        $APR origin upload --registry cdn-reg \
          --cache-dir /tmp/generated-cache \
          --upload-url s3://aos-origin/origin \
          > /tmp/origin-upload.log 2>&1
        cat /tmp/origin-upload.log

        cat > /tmp/assert-origin-cdn.py << 'PY'
      import json
      import os
      import sys

      events_path, root, store_hash, leaf_hash = sys.argv[1:5]
      with open(events_path, encoding="utf-8") as f:
          events = [json.loads(line) for line in f if line.strip()]

      def rel(path):
          prefix = "aos-origin/origin/"
          if not path.startswith(prefix):
              raise AssertionError(f"unexpected upload path {path}")
          return path[len(prefix):]

      # The immutable-before-mutable ordering invariant applies to the git
      # ORIGIN upload (immutable objects before the refs/pointers that name
      # them). `nix-cache-info` is written in the earlier cache-upload phase
      # (last, after the NARs/narinfos it describes), so it precedes the origin
      # objects and is not part of the origin pointer group for ordering
      # purposes (its mutable cache-control is still asserted separately below).
      def is_mutable(path):
          return (
              path in {"HEAD", "info/refs"}
              or path.startswith("objects/info/")
              or path.startswith("channels/")
          )

      put_events = [e for e in events if e["method"] == "PUT"]
      rel_events = [(rel(e["path"]), e) for e in put_events]
      forbidden = [
          "target/",
          "/target/",
          "tmp/",
          "/tmp/",
          "worktree-build.bin",
          "git-build.bin",
          "cache-build.bin",
          "scratch.txt",
      ]
      for path, _ in rel_events:
          for marker in forbidden:
              if marker in path:
                  raise AssertionError(f"unexpected scratch/build output upload: {path}")
      first_mutable = next((i for i, (path, _) in enumerate(rel_events) if is_mutable(path)), None)
      if first_mutable is None:
          raise AssertionError("no mutable uploads recorded")
      if any(is_mutable(path) for path, _ in rel_events[:first_mutable]):
          raise AssertionError("mutable upload appeared before immutable group")
      if any(not is_mutable(path) for path, _ in rel_events[first_mutable:]):
          raise AssertionError("immutable upload appeared after mutable group")

      by_path = {path: event for path, event in rel_events}
      expected_mutable = [
          "HEAD",
          "info/refs",
          "nix-cache-info",
      ]
      for path in expected_mutable:
          event = by_path[path]
          assert event["cache_control"] == "public, max-age=60, must-revalidate", event
          assert event["content_type"] == "text/plain", event

      object_events = [
          (path, event)
          for path, event in rel_events
          if path.startswith("objects/") and not path.startswith("objects/info/")
      ]
      if not object_events:
          raise AssertionError("no immutable git object uploads found")
      for _, event in object_events:
          assert event["cache_control"] == "public, max-age=31536000, immutable", event

      narinfo_events = [(p, e) for p, e in rel_events if p.endswith(".narinfo")]
      narinfo_paths = {path for path, _ in narinfo_events}
      expected_narinfos = {f"{store_hash}.narinfo", f"{leaf_hash}.narinfo"}
      if not expected_narinfos.issubset(narinfo_paths):
          raise AssertionError(f"missing root/leaf narinfo uploads {expected_narinfos}, got {narinfo_events}")
      # Narinfos are served with the mutable cache policy (they can be
      # re-signed in place); the NARs they reference stay immutable.
      for _, event in narinfo_events:
          assert event["cache_control"] == "public, max-age=60, must-revalidate", event
          assert event["content_type"] == "text/x-nix-narinfo", event

      nar_events = [(p, e) for p, e in rel_events if p.startswith("nar/")]
      if len(nar_events) != len(narinfo_events):
          raise AssertionError(f"expected one NAR per narinfo, got narinfos={narinfo_events}, nars={nar_events}")
      for _, event in nar_events:
          assert event["cache_control"] == "public, max-age=31536000, immutable", event
          assert event["content_type"] == "application/x-nix-nar", event

      alternates = os.path.join(root, "objects/info/alternates")
      if os.path.exists(alternates):
          with open(alternates, encoding="utf-8") as f:
              for line in f:
                  line = line.strip()
                  if not line:
                      continue
                  if line.startswith("/") or "://" in line:
                      raise AssertionError(f"non-relative alternate: {line}")
      PY
        python3 /tmp/assert-origin-cdn.py \
          /tmp/s3-origin-events.jsonl /tmp/s3-origin-root/aos-origin/origin \
          "$STORE_HASH" "$LEAF_HASH" > /tmp/assert-origin-cdn.log 2>&1 || {
          cat /tmp/assert-origin-cdn.log
          exit 1
        }
        cat /tmp/assert-origin-cdn.log
        test ! -e /tmp/s3-origin-root/aos-origin/origin/target
        test ! -e /tmp/s3-origin-root/aos-origin/origin/tmp
        rm -rf "$REG_DIR/target" /tmp/generated-cache/target /tmp/generated-cache/tmp

        ssh-keygen -q -t ed25519 -N "" -f /tmp/cdn-release-key
        $APR release 1.0.0 --registry cdn-reg \
          --key /tmp/cdn-release-key \
          --upload-url s3://aos-origin/release \
          > /tmp/release-upload.log 2>&1
        cat /tmp/release-upload.log
        grep -q "Released cdn-reg 1.0.0" /tmp/release-upload.log
        test -f /tmp/s3-origin-root/aos-origin/release/HEAD
        test -f /tmp/s3-origin-root/aos-origin/release/info/refs
        test -f /tmp/s3-origin-root/aos-origin/release/releases/1/0/0/objects/info/packs
        test ! -e /tmp/s3-origin-root/aos-origin/release/target

        $APR release 1.0.0 --registry cdn-reg \
          --key /tmp/cdn-release-key \
          --upload-url s3://aos-origin/release-resume \
          --resume \
          > /tmp/release-resume-upload.log 2>&1
        cat /tmp/release-resume-upload.log
        grep -q "Release tag 1.0.0 already exists at HEAD; resuming." \
          /tmp/release-resume-upload.log
        grep -q "Full pack .* already exists; resuming." /tmp/release-resume-upload.log
        grep -q "Released cdn-reg 1.0.0" /tmp/release-resume-upload.log
        test -f /tmp/s3-origin-root/aos-origin/release-resume/HEAD
        test -f /tmp/s3-origin-root/aos-origin/release-resume/info/refs
        test -f /tmp/s3-origin-root/aos-origin/release-resume/releases/1/0/0/objects/info/packs
        test ! -e /tmp/s3-origin-root/aos-origin/release-resume/target

        echo "registry origin CDN layout validation passed"
    '';
  };

  registry-validation-stock-git-matrix = testing.mkVMTest {
    name = "apm-registry-validation-stock-git-matrix";
    rootfsDeps =
      gitOnlyDeps
      ++ [
        gitFloor
        pkgs.curl
        pkgs.iproute2
        pkgs.python3
      ];
    memory = 1024;
    testScript = ''
        ${gitEnv}

        set -e
        ip link set lo up || true
        ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true

        mkdir -p /tmp/git-matrix-src
        cd /tmp/git-matrix-src
        git init --object-format=sha256
        git config user.name "VM Test"
        git config user.email "vm@example.com"
        mkdir -p packages/f
        cat > registry.toml << 'EOF'
      [registry]
      name = "git-matrix"
      EOF
        cat > packages/f/fixture.toml << 'EOF'
      [package]
      name = "fixture"
      description = "Git matrix fixture"
      license = "MIT"
      maintainer = "registry@example.com"
      EOF
        git add -A
        git commit -m "initial sha256 registry"
        git update-server-info
        cd /tmp

        git clone --bare /tmp/git-matrix-src /tmp/git-matrix-origin.git
        git --git-dir=/tmp/git-matrix-origin.git update-server-info

        PYTHONUNBUFFERED=1 python3 -m http.server 18081 --bind 127.0.0.1 \
          --directory /tmp/git-matrix-origin.git > /tmp/git-matrix-http.log 2>&1 &
        for _i in 1 2 3 4 5 6 7 8 9 10; do
          if curl -sf http://127.0.0.1:18081/HEAD >/dev/null; then
            break
          fi
          sleep 1
        done

        for git_bin in ${gitFloor}/bin/git ${pkgs.git}/bin/git; do
          version=$($git_bin --version)
          version=''${version##* }
          echo "==> validating stock Git $version"
          case "$version" in
            2.42.*|2.4[3-9].*|2.[5-9][0-9].*) ;;
            *) echo "Git $version is below the registry floor"; exit 1 ;;
          esac
          clone_dir="/tmp/clone-$version"
          GIT_SMART_HTTP=0 "$git_bin" clone http://127.0.0.1:18081 "$clone_dir"
          test "$($git_bin -C "$clone_dir" rev-parse --show-object-format)" = "sha256"
          test -f "$clone_dir/registry.toml"
        done

        echo "registry stock Git matrix validation passed"
    '';
  };

  registry-validation-pack-delta-perf = testing.mkVMTest {
    name = "apm-registry-validation-pack-delta-perf";
    rootfsDeps =
      gitOnlyDeps
      ++ [
        pkgs.findutils
        pkgs.zstd
      ];
    memory = 1024;
    testScript = ''
        ${gitEnv}

        set -e
        now_ns() {
          date +%s%N
        }

        metric() {
          name="$1"
          value="$2"
          echo "REGISTRY_PERF_METRIC $name=$value"
        }

        mkdir -p /tmp/perf-src/packages
        cd /tmp/perf-src
        git init --object-format=sha256
        git config user.name "VM Test"
        git config user.email "vm@example.com"
        for i in $(seq 1 80); do
          dir=$(printf "packages/%02d" "$i")
          mkdir -p "$dir"
          printf 'name = "pkg-%02d"\nversion = "1.0.0"\n' "$i" > "$dir/pkg.toml"
        done
        git add -A
        git commit -m "release 1"
        V1=$(git rev-parse HEAD)

        start=$(now_ns)
        git pack-objects --revs /tmp/full-pack << EOF
      $V1
      EOF
        end=$(now_ns)
        FULL_NAME=$(ls /tmp/full-pack-*.pack | head -1)
        metric full_pack_bytes "$(wc -c < "$FULL_NAME")"
        metric full_pack_ns "$((end - start))"

        git clone --bare /tmp/perf-src /tmp/perf-consumer.git

        for i in $(seq 1 80); do
          printf 'name = "pkg-%02d"\nversion = "1.0.1"\n' "$i" > "packages/$(printf "%02d" "$i")/pkg.toml"
        done
        git add -A
        git commit -m "release 2"
        V2=$(git rev-parse HEAD)

        start=$(now_ns)
        {
          echo "$V2"
          echo "^$V1"
        } | git pack-objects --thin --stdout > /tmp/delta.pack
        end=$(now_ns)
        metric thin_delta_bytes "$(wc -c < /tmp/delta.pack)"
        metric thin_delta_ns "$((end - start))"

        start=$(now_ns)
        zstd -q -f /tmp/delta.pack -o /tmp/delta.pack.zst
        end=$(now_ns)
        metric zstd_delta_bytes "$(wc -c < /tmp/delta.pack.zst)"
        metric zstd_ns "$((end - start))"

        start=$(now_ns)
        zstd -q -d -f /tmp/delta.pack.zst -o /tmp/delta.unpack
        git -C /tmp/perf-consumer.git index-pack --fix-thin --stdin < /tmp/delta.unpack
        end=$(now_ns)
        metric reconstruct_ns "$((end - start))"
        git -C /tmp/perf-consumer.git cat-file -e "$V2^{commit}"

        echo "registry pack/delta perf validation passed"
    '';
  };
}
