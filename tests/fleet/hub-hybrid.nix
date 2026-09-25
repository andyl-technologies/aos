##! Hybrid Hub transport qualification across separate Native, Worker, and client VMs.
##!
##! Wrangler runs the deployable Worker under local workerd with a persistent
##! emulated R2 binding. Native uses PostgreSQL on its own VM and has no R2
##! credentials. This first slice exercises startup, signed routing, and the
##! browser, control, and Worker-local storage paths.
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
        systemd.services.aos-hub.serviceConfig.Environment = [
          "HUB_OCI_PULL_ENABLED=true"
          "HUB_OCI_PUSH_ENABLED=true"
        ];
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
      import re
      import shlex
      import statistics
      import textwrap
      import time

      CURL = "${pkgs.curl}/bin/curl --noproxy '*' --cacert /etc/ssl/certs/ca-certificates.crt"
      GREP = "${pkgs.grep}/bin/grep"
      AOS = "${pkgs.aos}/bin/aos"
      APR = "${pkgs.aos.apr}/bin/apr"
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

      def sign_storage_plan(plan):
          body = json.dumps(plan, separators=(",", ":")).encode()
          signature = hmac.new(
              b"hybrid-fleet-storage-key-with-at-least-thirty-two-bytes",
              b"aos-storage-work-v1\0" + body,
              hashlib.sha256,
          ).hexdigest()
          return body, signature

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
      body, signature = sign_storage_plan(plan)
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

      expired_plan = {
          **plan,
          "plan_id": "e" * 32,
          "issued_at": now - 61,
          "expires_at": now - 31,
      }
      expired_body, expired_signature = sign_storage_plan(expired_plan)
      expired_status = client.succeed(
          f"{CURL} -sS -o /dev/null -w '%{{http_code}}' -X POST "
          f"-H 'content-type: application/json' "
          f"-H 'x-aos-storage-work-signature: {expired_signature}' "
          f"--data-binary {shlex.quote(expired_body.decode())} "
          "https://aos.andyl.org/_internal/storage/v1/execute",
          timeout=60,
      ).strip()
      assert expired_status == "401", expired_status

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
      oci_creation_body_status = client.succeed(
          f"{CURL} -sS -o /dev/null -w '%{{http_code}}' -X POST "
          "--data-binary 'unexpected-oci-upload-body' "
          "https://aos.andyl.org/team/containers/v2/aos/blobs/uploads/",
          timeout=60,
      ).strip()
      assert oci_creation_body_status == "400", oci_creation_body_status
      client.succeed(textwrap.dedent(f"""
          set -eu
          {CURL} -sS -D /tmp/hybrid-login.headers -o /dev/null -X POST \\
            -H 'cf-connecting-ip: 192.0.2.10' \\
            --data-urlencode 'email=fleet-root@example.test' \\
            --data-urlencode 'password=fleet-root-password' \\
            https://aos.andyl.org/login/password
          cookie=$(sed -n 's/^set-cookie: \\([^;]*\\).*/\\1/ip' /tmp/hybrid-login.headers | head -n1)
          test -n "$cookie"
          printf '%s' "$cookie" > /tmp/hybrid-cookie
          {CURL} -fsS -H 'cf-connecting-ip: 192.0.2.10' \\
            -H "Cookie: $cookie" \\
            https://aos.andyl.org/-/instance | {GREP} -q '<html'
      """), timeout=120)
      client.succeed(
          f"test \"$({CURL} -s -o /dev/null -w '%{{http_code}}' https://aos.staging.andyl.org/-/instance)\" = 401"
      )

      samples = client.succeed(textwrap.dedent(f"""
          set -eu
          cookie=$(cat /tmp/hybrid-cookie)
          attempt=0
          while test "$attempt" -lt 25; do
            {CURL} -sS -o /dev/null -w '%{{time_starttransfer}} %{{http_code}}\\n' \\
              -H 'cf-connecting-ip: 192.0.2.10' -H "Cookie: $cookie" \\
              https://aos.andyl.org/-/instance
            attempt=$((attempt + 1))
          done
      """), timeout=180).splitlines()
      assert len(samples) == 25, samples
      assert all(sample.split()[1] == "200" for sample in samples), samples
      first_bytes = sorted(float(sample.split()[0]) for sample in samples)
      print("hybrid authenticated page TTFB seconds:", {
          "p50": statistics.median(first_bytes),
          "p95": first_bytes[23],
          "p99": first_bytes[24],
      })

      session_token = json.loads(client.succeed(textwrap.dedent(f"""
          set -eu
          cookie=$(cat /tmp/hybrid-cookie)
          {CURL} -fsS -H 'cf-connecting-ip: 192.0.2.10' \\
            -H "Cookie: $cookie" https://aos.andyl.org/-/instance \\
            > /tmp/hybrid-instance.html
          csrf=$(sed -n 's/.*name="aos-session-csrf" content="\\([^"]*\\)".*/\\1/p' \\
            /tmp/hybrid-instance.html | head -n1)
          test -n "$csrf"
          {CURL} -fsS -X POST -H 'cf-connecting-ip: 192.0.2.10' \\
            -H "Cookie: $cookie" -H 'Origin: https://aos.andyl.org' \\
            -H "x-aos-csrf: $csrf" -H 'x-aos-console-route: /-/instance' \\
            https://aos.andyl.org/-/auth/session-token
      """), timeout=120))["accessToken"]
      whoami = json.loads(client.succeed(
          f"{CURL} -fsS -X POST -H 'cf-connecting-ip: 192.0.2.10' "
          f"-H 'Content-Type: application/json' -H 'Connect-Protocol-Version: 1' "
          f"-H 'Authorization: Bearer {session_token}' --data '{{}}' "
          "https://aos.andyl.org/aos.hub.v1.IdentityService/WhoAmI",
          timeout=60,
      ))
      assert whoami["principalRef"] == "fleet-root@example.test", whoami

      def hub_command(subcommand, mutation=""):
          return (
              f"{AOS} --json hub {subcommand} --hub https://aos.andyl.org "
              f"--token {shlex.quote(session_token)} {mutation}"
          )

      def reviewed(label, subcommand, timeout=120):
          planned = json.loads(client.succeed(hub_command(
              subcommand,
              f"--plan --idempotency-key {shlex.quote(label + '-plan')}",
          ), timeout=timeout))
          plan = planned["data"]["plan"]
          assert plan["effects"], plan
          return json.loads(client.succeed(hub_command(
              subcommand,
              " ".join([
                  "--plan-id", shlex.quote(plan["plan_id"]),
                  "--confirm-hash", shlex.quote(plan["confirmation_hash"]),
                  "--yes --idempotency-key", shlex.quote(label + "-apply"),
              ]),
          ), timeout=timeout))

      reviewed("hybrid-org", "org create --slug fleet --display-name 'Hybrid fleet'")
      org = json.loads(client.succeed(hub_command("org show fleet")))["data"]["organization"]
      reviewed(
          "hybrid-binding-grant",
          f"binding grant instance:default --consumer-scope {shlex.quote(org['stable_id'])}",
      )
      reviewed(
          "hybrid-public-network-grant",
          f"network-policy grant instance:public --consumer-scope {shlex.quote(org['stable_id'])}",
      )
      reviewed(
          "hybrid-cache",
          "cache create fleet/objects --name 'Hybrid objects' --visibility private",
      )
      reviewed(
          "hybrid-cache-placement",
          "placement add cache:fleet/objects primary --binding instance-default "
          "--prefix caches/fleet-objects --kind complete --desired-state active --read enabled",
      )
      placement = json.loads(client.succeed(hub_command(
          "placement show cache:fleet/objects primary"
      )))["data"]["placement"]
      reviewed(
          "hybrid-cache-scan",
          "placement scan cache:fleet/objects primary --wait --timeout 2m "
          f"--if-version {shlex.quote(placement['resource_version'])}",
          timeout=180,
      )
      placement = json.loads(client.succeed(hub_command(
          "placement show cache:fleet/objects primary"
      )))["data"]["placement"]
      reviewed(
          "hybrid-cache-promote",
          "placement promote cache:fleet/objects primary "
          f"--if-version {shlex.quote(placement['resource_version'])}",
      )

      trust_key = client.succeed(textwrap.dedent(f"""
          set -eu
          export HOME=/tmp/hybrid-apr-home
          mkdir -p "$HOME"
          {APR} keys generate initial --registry containers 2>&1 | \\
            ${pkgs.gawk}/bin/awk '/Public key:/ {{print $NF; exit}}'
      """), timeout=120).strip()
      assert trust_key.startswith("containers:Ed25519:"), trust_key
      reviewed(
          "hybrid-oci-registry",
          f"registry create --org fleet --name containers --visibility public "
          f"--trust-key {shlex.quote(trust_key)}",
      )
      reviewed(
          "hybrid-oci-placement",
          "placement add registry:fleet/containers primary --binding instance-default "
          "--prefix registries/fleet-containers --kind complete "
          "--desired-state active --read enabled",
      )
      oci_placement = json.loads(client.succeed(hub_command(
          "placement show registry:fleet/containers primary"
      )))["data"]["placement"]
      reviewed(
          "hybrid-oci-placement-scan",
          "placement scan registry:fleet/containers primary --wait --timeout 2m "
          f"--if-version {shlex.quote(oci_placement['resource_version'])}",
          timeout=180,
      )
      oci_placement = json.loads(client.succeed(hub_command(
          "placement show registry:fleet/containers primary"
      )))["data"]["placement"]
      reviewed(
          "hybrid-oci-placement-promote",
          "placement promote registry:fleet/containers primary "
          f"--if-version {shlex.quote(oci_placement['resource_version'])}",
      )
      reviewed(
          "hybrid-oci-endpoint",
          "endpoint add https://aos.andyl.org --stable-id hybrid-oci --org fleet "
          "--network-policy instance:public@1 --ingress layer7 "
          "--listener-provider layer7 --listener-resource-id hybrid-worker "
          "--tls-provider external --certificate-ref hybrid-fleet "
          "--probe-provider native-file --probe-signer-secret-ref fleet-probe-v1 "
          "--probe-public-key ${fixture.probePublicKey}",
      )
      oci_endpoint = json.loads(client.succeed(hub_command(
          "endpoint show hybrid-oci"
      )))["data"]["endpoint"]
      oci_generation = int(oci_endpoint["desired_generation"])
      observation = {
          "stableId": "hybrid-oci",
          "expectedObservationVersion": oci_endpoint["resource_version"],
          "controllerLeaseId": "hybrid-fleet-controller",
          "controllerGeneration": 1,
          "observation": {
              "observedGeneration": oci_generation,
              "boundaryRevision": oci_endpoint["desired"]["boundary_revision"],
              "state": "healthy",
              "listenerObserved": True,
              "tlsObserved": True,
          },
      }
      client.succeed(
          f"{CURL} -fsS -X POST -H 'Content-Type: application/json' "
          "-H 'Connect-Protocol-Version: 1' "
          f"-H 'Authorization: Bearer {session_token}' "
          f"--data {shlex.quote(json.dumps(observation))} "
          "https://aos.andyl.org/aos.hub.v1.DeliveryControllerService/ReportEndpoint",
          timeout=60,
      )
      reviewed(
          "hybrid-oci-route",
          "route add registry:fleet/containers --stable-id hybrid-oci-route "
          f"--endpoint hybrid-oci@{oci_generation} --base-path /fleet/containers "
          "--mode hub-proxy --placement primary --serves oci --access public",
      )
      oci_routes = json.loads(client.succeed(hub_command(
          "route list registry:fleet/containers"
      )))["data"]["routes"]
      oci_route = next(route for route in oci_routes if route["stable_id"] == "hybrid-oci-route")
      reviewed(
          "hybrid-oci-route-enable",
          "route enable hybrid-oci-route "
          f"--if-version {shlex.quote(oci_route['resource_version'])}",
      )
      client.wait_until_succeeds(
          f"{CURL} -fsS https://aos.andyl.org/fleet/containers/v2/",
          timeout=180,
      )

      cache_size = 1024 * 1024
      cache_path = "web/fleet-probe.bin"
      cache_digest = hashlib.sha256(bytes(cache_size)).hexdigest()
      client.succeed(
          f"${pkgs.coreutils}/bin/head -c {cache_size} /dev/zero > /tmp/hybrid-cache-object"
      )
      cache_upload = json.loads(client.succeed(
          f"{CURL} -fsS -X POST -H 'cf-connecting-ip: 192.0.2.10' "
          f"-H 'Content-Type: application/json' -H 'Connect-Protocol-Version: 1' "
          f"-H 'Authorization: Bearer {session_token}' "
          f"--data {shlex.quote(json.dumps({'cacheId': 'fleet/objects', 'path': cache_path, 'size': cache_size}))} "
          "https://aos.andyl.org/aos.hub.v1.BinaryCacheService/CreateCacheObjectUploads",
          timeout=60,
      ))
      assert cache_upload["uploadUrl"].startswith(
          "https://aos.andyl.org/aos.hub.v1.BinaryCacheService/UploadObject/"
      ), cache_upload
      assert cache_upload["uploadTicketId"], cache_upload
      client.succeed(
          f"{CURL} -fsS -X PUT -H 'cf-connecting-ip: 192.0.2.10' "
          f"-H 'Authorization: Bearer {session_token}' "
          f"--data-binary @/tmp/hybrid-cache-object {shlex.quote(cache_upload['uploadUrl'])}",
          timeout=120,
      )
      ticket_id = cache_upload["uploadTicketId"]
      assert ticket_id.isascii() and all(character.isalnum() or character == "-" for character in ticket_id)
      ticket_query = f"SELECT state FROM cache_write_tickets WHERE ticket_id = '{ticket_id}'"
      ticket_state = native.succeed(
          f"{POSTGRES}/psql -h 127.0.0.1 -U postgres -d postgres -At "
          f"-c {shlex.quote(ticket_query)}"
      ).strip()
      assert ticket_state == "completed", ticket_state
      replay_status = client.succeed(
          f"{CURL} -sS -o /dev/null -w '%{{http_code}}' -X PUT "
          f"-H 'cf-connecting-ip: 192.0.2.10' "
          f"-H 'Authorization: Bearer {session_token}' "
          f"--data-binary @/tmp/hybrid-cache-object {shlex.quote(cache_upload['uploadUrl'])}",
          timeout=120,
      ).strip()
      assert replay_status == "201", replay_status
      client.succeed(
          "${pkgs.coreutils}/bin/cp /tmp/hybrid-cache-object /tmp/hybrid-cache-conflict && "
          "printf x | ${pkgs.coreutils}/bin/dd of=/tmp/hybrid-cache-conflict "
          "bs=1 count=1 conv=notrunc status=none"
      )
      conflict_status = client.succeed(
          f"{CURL} -sS -o /dev/null -w '%{{http_code}}' -X PUT "
          f"-H 'cf-connecting-ip: 192.0.2.10' "
          f"-H 'Authorization: Bearer {session_token}' "
          f"--data-binary @/tmp/hybrid-cache-conflict {shlex.quote(cache_upload['uploadUrl'])}",
          timeout=120,
      ).strip()
      assert conflict_status == "400", conflict_status

      parallel_paths = [f"web/parallel-{index}.bin" for index in range(8)]
      parallel_uploads = json.loads(client.succeed(
          f"{CURL} -fsS -X POST -H 'cf-connecting-ip: 192.0.2.10' "
          f"-H 'Content-Type: application/json' -H 'Connect-Protocol-Version: 1' "
          f"-H 'Authorization: Bearer {session_token}' "
          f"--data {shlex.quote(json.dumps({'cacheId': 'fleet/objects', 'paths': parallel_paths, 'sizes': [cache_size] * len(parallel_paths)}))} "
          "https://aos.andyl.org/aos.hub.v1.BinaryCacheService/CreateCacheObjectUploads",
          timeout=60,
      ))["uploads"]
      assert [upload["path"] for upload in parallel_uploads] == parallel_paths, parallel_uploads
      assert all(upload["uploadUrl"] and upload["uploadTicketId"] for upload in parallel_uploads), parallel_uploads

      parallel_commands = ["set -eu", 'pids=""']
      for index, upload in enumerate(parallel_uploads):
          parallel_commands.append(
              f"{CURL} -fsS -X PUT -H 'cf-connecting-ip: 192.0.2.10' "
              f"-H 'Authorization: Bearer {session_token}' "
              f"-o /tmp/hybrid-parallel-{index}.response "
              f"-w '%{{time_total}}\\n' "
              f"--data-binary @/tmp/hybrid-cache-object "
              f"{shlex.quote(upload['uploadUrl'])} "
              f"> /tmp/hybrid-parallel-{index}.time &"
          )
          parallel_commands.append('pids="$pids $!"')
      parallel_commands.append('for pid in $pids; do wait "$pid"; done')
      client.succeed("\n".join(parallel_commands), timeout=180)

      parallel_ticket_ids = [upload["uploadTicketId"] for upload in parallel_uploads]
      assert all(
          ticket_id.isascii()
          and all(character.isalnum() or character == "-" for character in ticket_id)
          for ticket_id in parallel_ticket_ids
      )
      ticket_list = ", ".join(f"'{ticket_id}'" for ticket_id in parallel_ticket_ids)
      parallel_query = f"SELECT COUNT(*) FROM cache_write_tickets WHERE state = 'completed' AND ticket_id IN ({ticket_list})"
      completed = int(native.succeed(
          f"{POSTGRES}/psql -h 127.0.0.1 -U postgres -d postgres -At "
          f"-c {shlex.quote(parallel_query)}"
      ).strip())
      assert completed == len(parallel_paths), completed

      oci_token = json.loads(client.succeed(
          f"{CURL} -fsS -H 'Authorization: Bearer {session_token}' "
          "'https://aos.andyl.org/fleet/containers/v2/token?"
          "service=aos.andyl.org&scope=repository:aos:pull,push'",
          timeout=60,
      ))["token"]
      client.succeed(
          f"{CURL} -fsS -X POST -D /tmp/hybrid-oci-start.headers "
          f"-H 'Authorization: Bearer {oci_token}' -H 'Content-Length: 0' "
          "https://aos.andyl.org/fleet/containers/v2/aos/blobs/uploads/ "
          "-o /dev/null",
          timeout=60,
      )
      location = client.succeed(
          "sed -n 's/^location: *//ip' /tmp/hybrid-oci-start.headers | tr -d '\\r' | tail -n1"
      ).strip()
      assert "/blobs/uploads/" in location, location
      upload_id = location.rsplit("/", 1)[-1]
      assert re.fullmatch(r"[0-9a-f-]{32,36}", upload_id), upload_id
      upload_url = f"https://aos.andyl.org/fleet/containers/v2/aos/blobs/uploads/{upload_id}"
      client.succeed(
          f"{CURL} -fsS -X PATCH -H 'Authorization: Bearer {oci_token}' "
          f"--data-binary @/tmp/hybrid-cache-object {shlex.quote(upload_url)} "
          "-o /dev/null",
          timeout=180,
      )
      client.succeed(
          f"{CURL} -fsS -X PUT -H 'Authorization: Bearer {oci_token}' "
          f"-H 'Content-Length: 0' "
          f"{shlex.quote(upload_url + '?digest=sha256:' + cache_digest)} -o /dev/null",
          timeout=180,
      )
      client.succeed(
          f"{CURL} -fsS -H 'Authorization: Bearer {oci_token}' "
          f"'https://aos.andyl.org/fleet/containers/v2/aos/blobs/sha256:{cache_digest}' "
          "-o /tmp/hybrid-oci-downloaded",
          timeout=180,
      )
      downloaded_digest = client.succeed(
          "${pkgs.coreutils}/bin/sha256sum /tmp/hybrid-oci-downloaded | cut -d' ' -f1"
      ).strip()
      assert downloaded_digest == cache_digest, downloaded_digest
      upload_state = native.succeed(
          f"{POSTGRES}/psql -h 127.0.0.1 -U postgres -d postgres -At "
          f"-c \"SELECT state || ':' || cleanup_state FROM oci_upload_sessions "
          f"WHERE id = '{upload_id}'\""
      ).strip()
      assert upload_state == "complete:complete", upload_state

      durations = [
          float(client.succeed(f"cat /tmp/hybrid-parallel-{index}.time").strip())
          for index in range(len(parallel_paths))
      ]
      print("hybrid parallel cache upload seconds:", {
          "count": len(durations),
          "p50": statistics.median(durations),
          "max": max(durations),
      })

      boundary_log = native.succeed(
          f"journalctl -u aos-hub.service -o cat --no-pager | "
          f"{GREP} 'hybrid storage boundary'"
      )
      transferred = [
          (int(response), int(source))
          for response, source in re.findall(
              r"response_bytes=(\d+) source_bytes=(\d+)", boundary_log
          )
      ]
      compact_verifications = [
          response for response, source in transferred
          if source == cache_size and response < 2048
      ]
      assert len(compact_verifications) >= len(parallel_paths) + 1, transferred
      origin_log = worker.succeed(
          f"{GREP} 'hybrid_origin_request' /var/lib/hybrid-worker/wrangler.log"
      )
      origin_request_bytes = [
          int(size) for size in re.findall(r"request_bytes=(\d+)", origin_log)
      ]
      assert origin_request_bytes and max(origin_request_bytes) < 64 * 1024, origin_request_bytes

      selector = native.succeed(
          f"{POSTGRES}/psql -h 127.0.0.1 -U postgres -d postgres -At -F ' ' "
          "-c \"SELECT p.id, p.resource_version, b.id, b.resource_version, p.prefix "
          "FROM surface_placements p JOIN bindings b ON b.id = p.binding_id "
          "WHERE p.name = 'primary' AND p.cache_id IS NOT NULL\""
      ).strip().split()
      assert len(selector) == 5, selector
      now = int(time.time())
      cache_verification_plan = {
          "version": 1,
          "plan_id": "1" * 32,
          "deployment_id": "fleet-hybrid-v1",
          "issued_at": now,
          "expires_at": now + 30,
          "placement_id": int(selector[0]),
          "placement_resource_version": int(selector[1]),
          "binding_id": int(selector[2]),
          "binding_resource_version": int(selector[3]),
          "binding_kind": "deployment_r2",
          "placement_prefix": selector[4],
          "operation": {
              "kind": "inspect_sha256",
              "path": cache_path,
              "expected_sha256": cache_digest,
              "max_source_bytes": cache_size,
          },
      }
      body, signature = sign_storage_plan(cache_verification_plan)
      cache_verification_bytes = client.succeed(
          f"{CURL} -fsS -X POST -H 'content-type: application/json' "
          f"-H 'x-aos-storage-work-signature: {signature}' "
          f"--data-binary {shlex.quote(body.decode())} "
          "https://aos.andyl.org/_internal/storage/v1/execute",
          timeout=60,
      )
      assert len(cache_verification_bytes) < 2048, len(cache_verification_bytes)
      cache_verification = json.loads(cache_verification_bytes)
      assert cache_verification["outcome"]["kind"] == "sha256_evidence", cache_verification
      assert cache_verification["outcome"]["object"]["size"] == cache_size, cache_verification
      assert cache_verification["outcome"]["object"]["key"] == f"{selector[4]}/{cache_path}", cache_verification
      assert cache_verification["outcome"]["sha256"] == cache_digest, cache_verification
      assert cache_verification["source_bytes"] == cache_size, cache_verification

      native.succeed("systemctl stop aos-hub.service")
      outage_now = int(time.time())
      outage_plan = {
          **cache_verification_plan,
          "plan_id": "2" * 32,
          "issued_at": outage_now,
          "expires_at": outage_now + 30,
      }
      outage_body, outage_signature = sign_storage_plan(outage_plan)
      outage_result = json.loads(client.succeed(
          f"{CURL} -fsS -X POST -H 'content-type: application/json' "
          f"-H 'x-aos-storage-work-signature: {outage_signature}' "
          f"--data-binary {shlex.quote(outage_body.decode())} "
          "https://aos.andyl.org/_internal/storage/v1/execute",
          timeout=60,
      ))
      assert outage_result["outcome"]["kind"] == "sha256_evidence", outage_result
      assert outage_result["outcome"]["sha256"] == cache_digest, outage_result

      client.succeed(textwrap.dedent(f"""
          set -eu
          {CURL} -fsS https://aos.andyl.org/_assets/style.css \
            > /tmp/hybrid-origin-outage.css
          {GREP} -q 'Geist Sans' /tmp/hybrid-origin-outage.css
          asset_code=$({CURL} -sS -I -o /tmp/hybrid-origin-outage-font.headers \
            -w '%{{http_code}}' \
            https://aos.andyl.org/_assets/geist-sans-variable.woff2)
          test "$asset_code" = 200
          {GREP} -qi '^content-type: font/woff2' \
            /tmp/hybrid-origin-outage-font.headers
          cookie=$(cat /tmp/hybrid-cookie)
          code=$({CURL} -sS -o /tmp/hybrid-origin-outage.html -w '%{{http_code}}' \\
            -H 'cf-connecting-ip: 192.0.2.10' -H "Cookie: $cookie" \\
            https://aos.andyl.org/-/instance)
          test "$code" -ge 500
          code=$({CURL} -sS -o /dev/null -w '%{{http_code}}' -X PUT \\
            --data-binary 'storage-body-must-stay-at-worker' \\
            https://aos.andyl.org/aos.hub.v1.PublishService/UploadPart/missing/1)
          test "$code" = 503
          code=$({CURL} -sS -o /dev/null -w '%{{http_code}}' -X PATCH \\
            --data-binary 'oci-chunk-must-stay-at-worker' \\
            https://aos.andyl.org/team/containers/v2/aos/blobs/uploads/missing)
          test "$code" = 503
          code=$({CURL} -sS -o /dev/null -w '%{{http_code}}' -X DELETE \\
            --data-binary 'delete-body-must-stay-at-worker' \\
            https://aos.andyl.org/team/containers/v2/aos/blobs/uploads/missing)
          test "$code" = 400
      """), timeout=60)
      native.succeed("systemctl start aos-hub.service")
      client.wait_until_succeeds(
          f"{CURL} -fsS -H 'cf-connecting-ip: 192.0.2.10' https://aos.andyl.org/healthz",
          timeout=180,
      )
    '';
}
