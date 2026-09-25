##! Hybrid Hub transport qualification across separate Native, Worker, and client VMs.
##!
##! Wrangler runs the deployable Worker under local workerd with a persistent
##! emulated R2 binding. Native uses PostgreSQL on its own VM and has no R2
##! credentials. This first slice exercises startup, signed routing, and the
##! browser surface; storage workflows are added as their hybrid paths land.
{
  lib,
  mkSystem,
  pkgs,
}: let
  fixture = import ./_native-hub-production.nix {inherit lib mkSystem pkgs;};
  caCertificate = builtins.readFile ../fixtures/release-fleet-ca.crt;
  writeFixture = name: text:
    pkgs.writeTextFile {
      inherit name text;
      destination = "/value";
    };

  serverCertificate = writeFixture "hub-hybrid-fleet-certificate" (
    builtins.readFile ../fixtures/release-fleet-server.crt
  );
  serverPrivateKey = writeFixture "hub-hybrid-fleet-private-key" (
    builtins.readFile ../fixtures/release-fleet-server.key
  );
  databaseUrl = writeFixture
    "hub-hybrid-fleet-database-url"
    "postgresql://postgres@127.0.0.1:5432/postgres\n";
  ingressKey = writeFixture
    "hub-hybrid-fleet-ingress-key"
    "hybrid-fleet-ingress-key-with-at-least-thirty-two-bytes";
  storageKey = writeFixture
    "hub-hybrid-fleet-storage-key"
    "hybrid-fleet-storage-key-with-at-least-thirty-two-bytes";

  nativeSystem = fixture.hubSystem.extendModules {
    modules = [
      {
        aos.registry-hub = {
          deploymentId = "fleet-hybrid-v1";
          externalUrl = "https://aos.andyl.org";
          listen = "0.0.0.0:443";
          hybrid = {
            enable = true;
            workerUrl = "https://aos.andyl.org";
          };
          credentials = {
            databaseUrl = "hybrid-fleet-database-url";
            hybridIngressKey = "hybrid-fleet-ingress-key";
            storageWorkKey = "hybrid-fleet-storage-key";
            tlsCertificate = "hybrid-fleet-certificate";
            tlsPrivateKey = "hybrid-fleet-private-key";
          };
        };
        aos.security.pki.certificates = [caCertificate];
        aos.firewall.allowedTCP = [443];
        aos.kernel.modules = ["9pnet_virtio" "9p"];
        environment.etc."tmpfiles.d/hub-hybrid-fleet-credentials.conf".text = ''
          d /run/credentials/@system 0700 root root -
          C /run/credentials/@system/hybrid-fleet-database-url 0600 root root - ${databaseUrl}/value
          C /run/credentials/@system/hybrid-fleet-ingress-key 0600 root root - ${ingressKey}/value
          C /run/credentials/@system/hybrid-fleet-storage-key 0600 root root - ${storageKey}/value
          C /run/credentials/@system/hybrid-fleet-certificate 0600 root root - ${serverCertificate}/value
          C /run/credentials/@system/hybrid-fleet-private-key 0600 root root - ${serverPrivateKey}/value
        '';
      }
    ];
  };

  edgeSystem = mkSystem [
    ../../systems/server-test.nix
    {
      aos.security.pki.certificates = [caCertificate];
      aos.firewall.allowedTCP = [443];
      aos.kernel.modules = ["9pnet_virtio" "9p"];
    }
  ];
  clientSystem = mkSystem [
    ../../systems/server-test.nix
    {
      aos.security.pki.certificates = [caCertificate];
      aos.kernel.modules = ["9pnet_virtio" "9p"];
    }
  ];

  wranglerConfig = writeFixture "hub-hybrid-fleet-wrangler.toml" ''
    name = "hub-hybrid-fleet"
    main = "${pkgs.aos-hub-worker-dist}/shim.mjs"
    compatibility_date = "2024-09-23"

    [vars]
    HUB_TOPOLOGY = "hybrid"
    HUB_DEPLOYMENT_ID = "fleet-hybrid-v1"
    HUB_HYBRID_ORIGIN_URL = "https://aos.staging.andyl.org"

    [[r2_buckets]]
    binding = "REGISTRY_BUCKET"
    bucket_name = "hybrid-fleet-r2"
  '';
  workerSecrets = writeFixture "hub-hybrid-fleet-dev-vars" ''
    HUB_HYBRID_INGRESS_KEY=hybrid-fleet-ingress-key-with-at-least-thirty-two-bytes
    HUB_STORAGE_WORK_KEY=hybrid-fleet-storage-key-with-at-least-thirty-two-bytes
  '';
in {
  name = "hub-hybrid";
  timeout = 2400;
  bootTimeout = 600;

  machines = {
    client = {
      system = clientSystem;
      bootMode = "image";
      hostStoreMount = true;
      imageDiskMiB = 8192;
      memoryMiB = 2048;
      varProvisioning = "repart";
    };
    native = {
      system = nativeSystem;
      bootMode = "image";
      hostStoreMount = true;
      hostAliases = ["aos.staging.andyl.org"];
      imageDiskMiB = 16384;
      memoryMiB = 4096;
      varProvisioning = "repart";
    };
    worker = {
      system = edgeSystem;
      bootMode = "image";
      hostStoreMount = true;
      hostAliases = ["aos.andyl.org"];
      imageDiskMiB = 8192;
      memoryMiB = 4096;
      varProvisioning = "repart";
    };
  };

  testScript =
    # python
    ''
      import hashlib
      import hmac
      import json
      import shlex
      import textwrap
      import time

      CURL = "${pkgs.curl}/bin/curl --noproxy '*' --cacert /etc/ssl/certs/ca-certificates.crt"
      GREP = "${pkgs.grep}/bin/grep"
      CHROOT = "${pkgs.coreutils}/bin/chroot --userspec=802:802 /"
      POSTGRES = "${pkgs.postgresql}/bin"

      for machine in (client, native, worker):
          machine.wait_for_unit("multi-user.target", timeout=240)

      native.succeed("systemctl stop aos-hub.service")
      native.succeed(textwrap.dedent(f"""
          install -d -m 0700 -o aos-hub -g aos-hub /var/lib/hybrid-postgres
          {CHROOT} {POSTGRES}/initdb -D /var/lib/hybrid-postgres \\
            --username=postgres --auth-local=trust --auth-host=trust \\
            --encoding=UTF8 --locale=C
          cat > /var/lib/hybrid-postgres/fleet.conf <<'EOF'
          data_directory = '/var/lib/hybrid-postgres'
          listen_addresses = '127.0.0.1'
          port = 5432
          unix_socket_directories = '/tmp'
          shared_buffers = '32MB'
          dynamic_shared_memory_type = 'mmap'
          logging_collector = off
          EOF
          chown aos-hub:aos-hub /var/lib/hybrid-postgres/fleet.conf
          {CHROOT} {POSTGRES}/pg_ctl -D /var/lib/hybrid-postgres \\
            -l /var/lib/hybrid-postgres/server.log -w start \\
            -o '-c config_file=/var/lib/hybrid-postgres/fleet.conf'
          {POSTGRES}/psql -h 127.0.0.1 -U postgres -d postgres -Atc 'select 1'
      """), timeout=180)

      worker.succeed(textwrap.dedent("""
          install -d -m 0700 /var/lib/hybrid-worker
          cp ${wranglerConfig}/value /var/lib/hybrid-worker/wrangler.toml
          cp ${workerSecrets}/value /var/lib/hybrid-worker/.dev.vars
          cd /var/lib/hybrid-worker
          SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \\
            ${pkgs.miniflare}/bin/wrangler dev --local \\
            --config /var/lib/hybrid-worker/wrangler.toml \\
            --ip 0.0.0.0 --port 443 --local-protocol https \\
            --https-cert-path ${serverCertificate}/value \\
            --https-key-path ${serverPrivateKey}/value \\
            > /var/lib/hybrid-worker/wrangler.log 2>&1 < /dev/null &
      """), timeout=30)
      worker.wait_until_succeeds(
          f"{CURL} -s -o /dev/null -w '%{{http_code}}' -X POST https://aos.andyl.org/_internal/storage/v1/capabilities | {GREP} -qx 401",
          timeout=180,
      )

      now = int(time.time())
      plan = {
          "version": 1,
          "plan_id": "0" * 32,
          "deployment_id": "fleet-hybrid-v1",
          "issued_at": now,
          "expires_at": now + 30,
          "placement_id": 1,
          "placement_resource_version": 1,
          "binding_id": 1,
          "binding_resource_version": 1,
          "binding_kind": "deployment_r2",
          "placement_prefix": "fleet-probe",
          "operation": {"kind": "head", "path": "absent-object"},
      }
      body = json.dumps(plan, separators=(",", ":")).encode()
      signature = hmac.new(
          b"hybrid-fleet-storage-key-with-at-least-thirty-two-bytes",
          b"aos-storage-work-v1\0" + body,
          hashlib.sha256,
      ).hexdigest()
      command = (
          f"{CURL} -fsS -X POST "
          f"-H 'content-type: application/json' "
          f"-H 'x-aos-storage-work-signature: {signature}' "
          f"--data-binary {shlex.quote(body.decode())} "
          "https://aos.andyl.org/_internal/storage/v1/execute"
      )
      result = json.loads(client.succeed(command, timeout=60))
      assert result["outcome"]["kind"] == "not_found", result
      assert result["source_bytes"] == 0, result

      native.succeed(textwrap.dedent("""
          HUB_DATABASE_URL_FILE=${databaseUrl}/value \\
            ${pkgs.aos-hub}/bin/aos-hub --root /var/lib/aos-hub init \\
            --root-email fleet-root@example.test \\
            --root-password fleet-root-password
          systemctl start aos-hub.service
      """), timeout=180)
      client.wait_until_succeeds(
          f"{CURL} -fsS -H 'cf-connecting-ip: 192.0.2.10' https://aos.andyl.org/healthz",
          timeout=180,
      )
      client.succeed(
          f"test \"$({CURL} -fsS -H 'cf-connecting-ip: 192.0.2.10' https://aos.andyl.org/.well-known/aos-deployment)\" = fleet-hybrid-v1"
      )
      client.succeed(
          f"{CURL} -fsS -H 'cf-connecting-ip: 192.0.2.10' https://aos.andyl.org/login | {GREP} -q '<html'"
      )
      client.succeed(textwrap.dedent(f"""
          set -eu
          {CURL} -sS -D /tmp/hybrid-login.headers -o /dev/null -X POST \\
            -H 'cf-connecting-ip: 192.0.2.10' \\
            --data-urlencode 'email=fleet-root@example.test' \\
            --data-urlencode 'password=fleet-root-password' \\
            https://aos.andyl.org/login/password
          cookie=$(sed -n 's/^set-cookie: \\([^;]*\\).*/\\1/ip' /tmp/hybrid-login.headers | head -n1)
          test -n "$cookie"
          {CURL} -fsS -H 'cf-connecting-ip: 192.0.2.10' \\
            -H "Cookie: $cookie" \\
            https://aos.andyl.org/-/instance | {GREP} -q '<html'
      """), timeout=120)
      client.succeed(
          f"test \"$({CURL} -s -o /dev/null -w '%{{http_code}}' https://aos.staging.andyl.org/-/instance)\" = 401"
      )
    '';
}
