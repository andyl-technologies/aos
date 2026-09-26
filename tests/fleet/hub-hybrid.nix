##! Hybrid Hub transport qualification across separate Native, Worker, and client VMs.
##!
##! Wrangler runs the deployable Worker under local workerd with a persistent
##! emulated R2 binding. Native uses PostgreSQL on its own VM and has no R2
##! credentials. The suite exercises signed routing, browser and control APIs,
##! storage-local work, concurrent uploads, failure recovery, and byte budgets.
{
  lib,
  mkSystem,
  pkgs,
}: let
  fixture = import ./_native-hub-production.nix {inherit lib mkSystem pkgs;};
  caCertificate = builtins.readFile ../fixtures/hub-hybrid-fleet-ca.crt;
  writeFixture = name: text:
    pkgs.writeTextFile {
      inherit name text;
      destination = "/value";
    };

  serverCertificate = writeFixture "hub-hybrid-fleet-certificate" (
    builtins.readFile ../fixtures/hub-hybrid-fleet-server.crt
  );
  serverPrivateKey = writeFixture "hub-hybrid-fleet-private-key" (
    builtins.readFile ../fixtures/hub-hybrid-fleet-server.key
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
  releaseReceiptKey = writeFixture
    "hub-hybrid-fleet-release-receipt-key"
    "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=";
  channelReceiptKey = writeFixture
    "hub-hybrid-fleet-channel-receipt-key"
    "CgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgo=";
  releasePublicationKeys = writeFixture
    "hub-hybrid-fleet-release-publication-keys"
    (builtins.toJSON {
      "staging-publication-v1" = "/RckOFqgx1tk+3jNYC+h2ZH96/drE8WO1wLqyDXp9hg=";
    });
  qualificationKeys = writeFixture
    "hub-hybrid-fleet-qualification-keys"
    (builtins.toJSON {
      "qualification-v1" = "E5j2LG0aRXxRumpLXz29L2n8qTIWIY3ImX5Ba9F9k8o=";
    });

  nativeSystem = fixture.hubSystem.extendModules {
    modules = [
      {
        aos.registry-hub = {
          deploymentId = "fleet-hybrid-v1";
          externalUrl = "https://aos.andyl.org";
          listen = "0.0.0.0:443";
          releaseReceiptKeyId = "staging-publication-v1";
          channelReceiptKeyId = "staging-channel-v1";
          hybrid = {
            enable = true;
            workerUrl = "https://aos.andyl.org";
            originUrl = "https://aos.staging.andyl.org";
          };
          credentials = {
            databaseUrl = "hybrid-fleet-database-url";
            hybridIngressKey = "hybrid-fleet-ingress-key";
            storageWorkKey = "hybrid-fleet-storage-key";
            releaseReceiptKey = "hybrid-fleet-release-receipt-key";
            channelReceiptKey = "hybrid-fleet-channel-receipt-key";
            releasePublicationKeys = "hybrid-fleet-release-publication-keys";
            qualificationKeys = "hybrid-fleet-qualification-keys";
            tlsCertificate = "hybrid-fleet-certificate";
            tlsPrivateKey = "hybrid-fleet-private-key";
          };
        };
        aos.security.pki.certificates = [caCertificate];
        aos.firewall.allowedTCP = [443];
        aos.kernel.modules = ["9pnet_virtio" "9p"];
        environment.systemPackages = [pkgs.util-linux];
        systemd.services.aos-hub.serviceConfig.Environment = [
          "HUB_OCI_PULL_ENABLED=true"
          "HUB_OCI_PUSH_ENABLED=true"
          "HUB_OCI_GC_ENABLED=true"
        ];
        environment.etc."tmpfiles.d/hub-hybrid-fleet-credentials.conf".text = ''
          d /run/credentials/@system 0700 root root -
          C /run/credentials/@system/hybrid-fleet-database-url 0600 root root - ${databaseUrl}/value
          C /run/credentials/@system/hybrid-fleet-ingress-key 0600 root root - ${ingressKey}/value
          C /run/credentials/@system/hybrid-fleet-storage-key 0600 root root - ${storageKey}/value
          C /run/credentials/@system/hybrid-fleet-release-receipt-key 0600 root root - ${releaseReceiptKey}/value
          C /run/credentials/@system/hybrid-fleet-channel-receipt-key 0600 root root - ${channelReceiptKey}/value
          C /run/credentials/@system/hybrid-fleet-release-publication-keys 0600 root root - ${releasePublicationKeys}/value
          C /run/credentials/@system/hybrid-fleet-qualification-keys 0600 root root - ${qualificationKeys}/value
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
      environment.systemPackages = [pkgs.util-linux];
    }
  ];
  clientSystem = mkSystem [
    ../../systems/server-test.nix
    {
      aos.security.pki.certificates = [caCertificate];
      aos.kernel.modules = ["9pnet_virtio" "9p"];
      environment.systemPackages = [pkgs.util-linux];
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

    [[durable_objects.bindings]]
    name = "HYBRID_OBJECT_GUARD"
    class_name = "HybridObjectGuard"

    [[migrations]]
    tag = "hybrid-object-guard-v1"
    new_sqlite_classes = ["HybridObjectGuard"]
  '';
  workerSecrets = writeFixture "hub-hybrid-fleet-dev-vars" ''
    HUB_HYBRID_INGRESS_KEY=hybrid-fleet-ingress-key-with-at-least-thirty-two-bytes
    HUB_STORAGE_WORK_KEY=hybrid-fleet-storage-key-with-at-least-thirty-two-bytes
  '';
  toolClosureInfo = import ../../lib/build/closure-info.nix {inherit lib pkgs;} {
    pname = "hub-hybrid-fleet-tool-closure-info";
    rootPaths = [
      pkgs.aos
      pkgs.aos.apr
      pkgs.aos-hub
      pkgs.aos-hub-worker-dist
      pkgs.coreutils
      pkgs.curl
      pkgs.gawk
      pkgs.git
      pkgs.grep
      pkgs.jq
      pkgs.miniflare
      pkgs.nix
      pkgs.postgresql
      pkgs.sed
      pkgs.util-linux
      databaseUrl
      ingressKey
      storageKey
      releaseReceiptKey
      channelReceiptKey
      releasePublicationKeys
      qualificationKeys
      serverCertificate
      serverPrivateKey
      wranglerConfig
      workerSecrets
    ];
  };
in {
  name = "hub-hybrid";
  timeout = 2400;
  bootTimeout = 600;

  machines = {
    client = {
      system = clientSystem;
      bootMode = "image";
      hostStoreMount = true;
      imageDiskMiB = 16384;
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
      imageDiskMiB = 16384;
      memoryMiB = 8192;
      vcpuCount = 4;
      varProvisioning = "repart";
    };
  };

  testScript =
    # python
    ''
      import base64
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
      SED = "${pkgs.sed}/bin/sed"
      AOS = "${pkgs.aos}/bin/aos"
      APR = "${pkgs.aos.apr}/bin/apr"
      CHROOT = "${pkgs.coreutils}/bin/chroot --userspec=802:802 /"
      POSTGRES = "${pkgs.postgresql}/bin"

      for machine in (client, native, worker):
          machine.wait_for_unit("multi-user.target", timeout=240)
          machine.succeed(textwrap.dedent("""
              set -eu
              mkdir -p /run/aos-host-store
              ${pkgs.util-linux}/bin/mount -t 9p -o trans=virtio,version=9p2000.L,msize=1048576,ro \\
                aos-host-store /run/aos-host-store
              while IFS= read -r store_path; do
                test -e "$store_path" && continue
                source_path="/run/aos-host-store/$(basename "$store_path")"
                if [ -d "$source_path" ]; then
                  mkdir "$store_path"
                  ${pkgs.util-linux}/bin/mount --bind "$source_path" "$store_path"
                elif [ -f "$source_path" ]; then
                  touch "$store_path"
                  ${pkgs.util-linux}/bin/mount --bind "$source_path" "$store_path"
                elif [ -L "$source_path" ]; then
                  ln -s "$(readlink "$source_path")" "$store_path"
                else
                  exit 1
                fi
              done < "/run/aos-host-store/$(basename ${toolClosureInfo})/store-paths"
              ${pkgs.nix}/bin/nix-store --load-db \\
                < "/run/aos-host-store/$(basename ${toolClosureInfo})/registration"
              ${pkgs.util-linux}/bin/findmnt -rn -t 9p -o OPTIONS \\
                /run/aos-host-store | ${pkgs.grep}/bin/grep -qw ro
          """), timeout=180)

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
      native.succeed(textwrap.dedent("""
          HUB_DATABASE_URL_FILE=${databaseUrl}/value \\
            ${pkgs.aos-hub}/bin/aos-hub --root /var/lib/aos-hub init \\
            --root-email fleet-root@example.test \\
            --root-password fleet-root-password
      """), timeout=180)

      worker.succeed(textwrap.dedent("""
          install -d -m 0700 /var/lib/hybrid-worker \\
            /var/lib/hybrid-worker/config /var/lib/hybrid-worker/cache
          cp ${wranglerConfig}/value /var/lib/hybrid-worker/wrangler.toml
          cp ${workerSecrets}/value /var/lib/hybrid-worker/.dev.vars
          cd /var/lib/hybrid-worker
          XDG_CONFIG_HOME=/var/lib/hybrid-worker/config \\
            XDG_CACHE_HOME=/var/lib/hybrid-worker/cache \\
            WRANGLER_LOG_PATH=/var/lib/hybrid-worker/config/logs \\
            WRANGLER_REGISTRY_PATH=/var/lib/hybrid-worker/config/registry \\
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

      challenge = b"aos-storage-capabilities-v1"
      challenge_signature = hmac.new(
          b"hybrid-fleet-storage-key-with-at-least-thirty-two-bytes",
          b"aos-storage-work-v1\0" + challenge,
          hashlib.sha256,
      ).hexdigest()
      capabilities = json.loads(client.succeed(
          f"{CURL} -fsS -X POST "
          f"-H 'x-aos-storage-work-signature: {challenge_signature}' "
          f"--data-binary {shlex.quote(challenge.decode())} "
          "https://aos.andyl.org/_internal/storage/v1/capabilities",
          timeout=60,
      ))
      assert capabilities["deployment_id"] == "fleet-hybrid-v1", capabilities
      duplicate_signature_status = client.succeed(
          f"{CURL} -sS -o /dev/null -w '%{{http_code}}' -X POST "
          f"-H 'x-aos-storage-work-signature: {challenge_signature}' "
          f"-H 'x-aos-storage-work-signature: {challenge_signature}' "
          f"--data-binary {shlex.quote(challenge.decode())} "
          "https://aos.andyl.org/_internal/storage/v1/capabilities",
          timeout=60,
      ).strip()
      assert duplicate_signature_status == "401", duplicate_signature_status

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

      worker.wait_until_succeeds(
          f"{CURL} -sS -o /dev/null -w '%{{http_code}}' "
          "https://aos.staging.andyl.org/healthz | "
          f"{GREP} -qx 401",
          timeout=180,
      )
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
          cookie=$({SED} -n 's/^set-cookie: \\([^;]*\\).*/\\1/ip' /tmp/hybrid-login.headers | head -n1)
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
          while test "$attempt" -lt 100; do
            {CURL} -sS -o /dev/null -w '%{{time_starttransfer}} %{{http_code}} %{{time_connect}} %{{time_appconnect}}\\n' \\
              -H 'cf-connecting-ip: 192.0.2.10' -H "Cookie: $cookie" \\
              https://aos.andyl.org/-/instance
            attempt=$((attempt + 1))
          done
      """), timeout=180).splitlines()
      assert len(samples) == 100, samples
      assert all(sample.split()[1] == "200" for sample in samples), samples
      first_bytes = sorted(float(sample.split()[0]) for sample in samples)
      baseline_tls = sorted(float(sample.split()[3]) for sample in samples)
      print("hybrid authenticated page TTFB seconds:", {
          "p50": statistics.median(first_bytes),
          "p95": first_bytes[94],
          "p99": first_bytes[98],
          "max": first_bytes[99],
          "tls_p95": baseline_tls[94],
      })
      assert first_bytes[94] < 0.5, first_bytes

      session_token = json.loads(client.succeed(textwrap.dedent(f"""
          set -eu
          cookie=$(cat /tmp/hybrid-cookie)
          {CURL} -fsS -H 'cf-connecting-ip: 192.0.2.10' \\
            -H "Cookie: $cookie" https://aos.andyl.org/-/instance \\
            > /tmp/hybrid-instance.html
          csrf=$({SED} -n 's/.*name="aos-session-csrf" content="\\([^"]*\\)".*/\\1/p' \\
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

      def reviewed_control(label, plan_command, apply_command, timeout=120):
          planned = json.loads(client.succeed(hub_command(
              plan_command,
              f"--idempotency-key {shlex.quote(label + '-plan')}",
          ), timeout=timeout))
          plan = planned["data"]["plan"]
          assert plan["effects"], plan
          return json.loads(client.succeed(hub_command(
              apply_command,
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
          "hybrid-oci-domain",
          "domain add aos.andyl.org --org fleet",
      )
      reviewed_control(
          "hybrid-oci-controller-account",
          "org service-account create plan fleet hybrid-controller",
          "org service-account create apply",
      )
      reviewed_control(
          "hybrid-oci-controller-membership",
          "org member set-role plan --principal-kind service_account "
          "--principal fleet/hybrid-controller "
          f"--scope {shlex.quote(org['stable_id'])} "
          "--role owner --if-version absent",
          "org member set-role apply",
      )
      controller_token_response = reviewed_control(
          "hybrid-oci-controller-token",
          f"access-token issue plan {shlex.quote(org['stable_id'])} "
          "--owner service_account:fleet/hybrid-controller "
          "--permission endpoint.read --permission endpoint.manage "
          "--ttl-secs 3600 --comment 'Hybrid fleet endpoint controller'",
          "access-token issue apply",
      )
      controller_secret = controller_token_response["data"]["result"]["secret"]
      controller_token = json.loads(client.succeed(
          f"{CURL} -fsS -X POST "
          "-H 'Content-Type: application/x-www-form-urlencoded' "
          f"-H 'Authorization: Bearer {controller_secret}' "
          "--data-urlencode "
          "'grant_type=urn:aos:params:oauth:grant-type:provisioning-token' "
          "https://aos.andyl.org/oauth2/token",
          timeout=60,
      ))["access_token"]
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
          f"-H 'Authorization: Bearer {controller_token}' "
          f"--data {shlex.quote(json.dumps(observation))} "
          "https://aos.andyl.org/aos.hub.v1.DeliveryControllerService/ReportEndpoint",
          timeout=60,
      )
      reviewed(
          "hybrid-oci-route",
          "route add registry:fleet/containers --stable-id hybrid-oci-route "
          f"--endpoint hybrid-oci@{oci_generation} --base-path / "
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
          f"{CURL} -fsS https://aos.andyl.org/v2/",
          timeout=180,
      )
      print("hybrid OCI route ready through public Worker")

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

      multipart_part_size = 8 * 1024 * 1024
      multipart_final_size = 13
      multipart_size = multipart_part_size + multipart_final_size
      multipart_digest = hashlib.sha256(bytes(multipart_size)).hexdigest()
      client.succeed(
          f"${pkgs.coreutils}/bin/head -c {multipart_part_size} /dev/zero "
          "> /tmp/hybrid-cache-multipart-part-1"
      )
      client.succeed(
          f"${pkgs.coreutils}/bin/head -c {multipart_final_size} /dev/zero "
          "> /tmp/hybrid-cache-multipart-part-2"
      )
      multipart_upload = json.loads(client.succeed(
          f"{CURL} -fsS -X POST -H 'cf-connecting-ip: 192.0.2.10' "
          f"-H 'Content-Type: application/json' -H 'Connect-Protocol-Version: 1' "
          f"-H 'Authorization: Bearer {session_token}' "
          f"--data {shlex.quote(json.dumps({'cacheId': 'fleet/objects', 'path': 'web/multipart.bin', 'byteSize': multipart_size, 'sha256': multipart_digest}))} "
          "https://aos.andyl.org/aos.hub.v1.BinaryCacheService/BeginCacheMultipartUpload",
          timeout=60,
      ))
      assert int(multipart_upload["partSize"]) == multipart_part_size, multipart_upload
      assert multipart_upload["partUploadUrl"].startswith(
          "https://aos.andyl.org/aos.hub.v1.BinaryCacheService/UploadPart/"
      ), multipart_upload
      multipart_parts = []
      for part_number in (1, 2):
          multipart_parts.append(json.loads(client.succeed(
              f"{CURL} -fsS -X PUT -H 'Expect: 100-continue' "
              "-H 'cf-connecting-ip: 192.0.2.10' "
              f"-H 'Authorization: Bearer {session_token}' "
              f"--data-binary @/tmp/hybrid-cache-multipart-part-{part_number} "
              f"{shlex.quote(multipart_upload['partUploadUrl'] + '/' + str(part_number))}",
              timeout=180,
          )))
      assert [part["partNumber"] for part in multipart_parts] == [1, 2], multipart_parts
      multipart_retry = json.loads(client.succeed(
          f"{CURL} -fsS -X PUT -H 'cf-connecting-ip: 192.0.2.10' "
          f"-H 'Authorization: Bearer {session_token}' "
          "--data-binary @/tmp/hybrid-cache-multipart-part-1 "
          f"{shlex.quote(multipart_upload['partUploadUrl'] + '/1')}",
          timeout=180,
      ))
      assert multipart_retry == multipart_parts[0], multipart_retry
      multipart_completion = json.loads(client.succeed(
          f"{CURL} -fsS -X POST -H 'cf-connecting-ip: 192.0.2.10' "
          f"-H 'Content-Type: application/json' -H 'Connect-Protocol-Version: 1' "
          f"-H 'Authorization: Bearer {session_token}' "
          f"--data {shlex.quote(json.dumps({'uploadId': multipart_upload['uploadId'], 'parts': multipart_parts}))} "
          "https://aos.andyl.org/aos.hub.v1.BinaryCacheService/CompleteCacheMultipartUpload",
          timeout=180,
      ))
      assert multipart_completion["state"] == "completed", multipart_completion
      multipart_ticket_id = multipart_upload["uploadId"]
      assert re.fullmatch(r"[0-9a-f-]{32,36}", multipart_ticket_id), multipart_ticket_id
      multipart_state = native.succeed(
          f"{POSTGRES}/psql -h 127.0.0.1 -U postgres -d postgres -At "
          f"-c \"SELECT state FROM cache_write_tickets "
          f"WHERE ticket_id = '{multipart_ticket_id}'\""
      ).strip()
      assert multipart_state == "completed", multipart_state

      publication_size = multipart_part_size + 13
      publication_path = "web/fleet-large.bin"
      publication_digest = hashlib.sha256(bytes(publication_size)).hexdigest()
      client.succeed(textwrap.dedent(f"""
          set -eu
          export HOME=/tmp/hybrid-apr-home USER=fleet-publisher
          export PATH=${pkgs.git}/bin:$PATH
          git config --global user.name 'Hybrid Fleet Publisher'
          git config --global user.email 'fleet-publisher@example.test'
          key="$HOME/.config/apm/keys/containers-initial.key"
          {APR} create containers --trust-key {shlex.quote(trust_key)} \\
            --trust-key-id initial --key "$key"
          registry="$HOME/.local/share/apm/registries/containers"
          mkdir -p "$HOME/.config/apm/registries.d"
          printf '[registry]\\nname = "containers"\\nurl = "file://%s"\\n\\n[registry.signing_keys]\\ninitial = "%s"\\n' \\
            "$registry" "$key" > "$HOME/.config/apm/registries.d/containers.toml"
          {APR} origin upload --registry containers \\
            --upload-url file:///tmp/hybrid-publication-surface
          mkdir -p /tmp/hybrid-publication-surface/web
          ${pkgs.coreutils}/bin/head -c {publication_size} /dev/zero \\
            > /tmp/hybrid-publication-surface/{publication_path}
      """), timeout=180)
      publication = json.loads(client.succeed(hub_command(
          "registry publish upload fleet/containers "
          "--root /tmp/hybrid-publication-surface"
      ), timeout=600))["data"]
      assert publication["state"] == "ready", publication
      large_object = next(
          obj for obj in publication["objects"] if obj["path"] == publication_path
      )
      assert large_object["verified"], large_object
      assert int(large_object["byte_size"]) == publication_size, large_object
      assert large_object["sha256"] == publication_digest, large_object
      publication_multipart = native.succeed(
          f"{POSTGRES}/psql -h 127.0.0.1 -U postgres -d postgres -At "
          f"-c \"SELECT state FROM registry_publication_multipart_uploads "
          f"WHERE publication_id = '{publication['publication_id']}' "
          f"AND surface_object_id = {large_object['object_id']}\""
      ).strip()
      assert publication_multipart == "completed", publication_multipart
      client.wait_until_succeeds(
          hub_command("registry show fleet/containers")
          + " | ${pkgs.jq}/bin/jq -e '.data.registry.index_state == \"fresh\"' "
          "> /dev/null",
          timeout=180,
      )

      parallel_size = 4 * 1024 * 1024
      client.succeed(
          f"${pkgs.coreutils}/bin/head -c {parallel_size} "
          "/tmp/hybrid-cache-multipart-part-1 > /tmp/hybrid-parallel-object"
      )
      parallel_paths = [f"web/parallel-{index}.bin" for index in range(8)]
      parallel_uploads = json.loads(client.succeed(
          f"{CURL} -fsS -X POST -H 'cf-connecting-ip: 192.0.2.10' "
          f"-H 'Content-Type: application/json' -H 'Connect-Protocol-Version: 1' "
          f"-H 'Authorization: Bearer {session_token}' "
          f"--data {shlex.quote(json.dumps({'cacheId': 'fleet/objects', 'paths': parallel_paths, 'sizes': [parallel_size] * len(parallel_paths)}))} "
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
              f"--data-binary @/tmp/hybrid-parallel-object "
              f"{shlex.quote(upload['uploadUrl'])} "
              f"> /tmp/hybrid-parallel-{index}.time &"
          )
          parallel_commands.append('pids="$pids $!"')
      native_page_commands = []
      for index in range(25):
          issued_at = int(time.time())
          assertion = {
              "version": 1,
              "deployment_id": "fleet-hybrid-v1",
              "issued_at": issued_at,
              "expires_at": issued_at + 30,
              "request_id": f"fleet-native-load-{issued_at}-{index}",
              "scheme": "https",
              "authority": "aos.andyl.org",
              "method": "GET",
              "path_and_query": "/-/instance",
              "body_sha256": hashlib.sha256(b"").hexdigest(),
              "client_ip": "192.0.2.10",
          }
          payload = base64.urlsafe_b64encode(
              json.dumps(assertion, separators=(",", ":")).encode()
          ).rstrip(b"=").decode()
          signature = base64.urlsafe_b64encode(hmac.new(
              b"hybrid-fleet-ingress-key-with-at-least-thirty-two-bytes",
              payload.encode(), hashlib.sha256,
          ).digest()).rstrip(b"=").decode()
          compact = payload + "." + signature
          native_page_commands.append(
              f"{CURL} -sS -o /dev/null -w '%{{time_starttransfer}} %{{http_code}} %{{time_connect}} %{{time_appconnect}}\\n' "
              f"-H 'x-aos-hybrid-ingress: {compact}' -H \"Cookie: $cookie\" "
              "https://aos.staging.andyl.org/-/instance"
          )

      parallel_commands.extend([
          'cookie=$(cat /tmp/hybrid-cookie)',
          "(\n" + "\n".join(native_page_commands) + "\n) > /tmp/hybrid-native-pages &",
          'native_pid=$!',
          'attempt=0',
          'while test "$attempt" -lt 25; do',
          f"{CURL} -sS -o /dev/null -w '%{{time_starttransfer}} %{{http_code}} %{{time_connect}} %{{time_appconnect}}\\n' "
          "-H 'cf-connecting-ip: 192.0.2.10' -H \"Cookie: $cookie\" "
          "https://aos.andyl.org/-/instance >> /tmp/hybrid-parallel-pages",
          'attempt=$((attempt + 1))',
          'done',
      ])
      parallel_commands.append('wait "$native_pid"')
      parallel_commands.append('for pid in $pids; do wait "$pid"; done')
      try:
          client.succeed("\n".join(parallel_commands), timeout=180)
      except Exception:
          print("hybrid Worker memory after parallel upload failure:", worker.succeed(
              "cat /proc/meminfo | head -n 8"
          ))
          print("hybrid Worker processes after parallel upload failure:", worker.succeed(
              "ps -eo pid,rss,comm,args | tail -n 25 || true"
          ))
          print("hybrid Worker logs after parallel upload failure:", worker.succeed(
              "tail -n 120 /var/lib/hybrid-worker/wrangler.log"
          ))
          print("hybrid Worker kernel logs after parallel upload failure:", worker.succeed(
              "journalctl -k --no-pager -n 60"
          ))
          raise

      loaded_samples = client.succeed("cat /tmp/hybrid-parallel-pages").splitlines()
      assert len(loaded_samples) == 25, loaded_samples
      assert all(sample.split()[1] == "200" for sample in loaded_samples), loaded_samples
      loaded_first_bytes = sorted(float(sample.split()[0]) for sample in loaded_samples)
      loaded_tls = sorted(float(sample.split()[3]) for sample in loaded_samples)
      print("hybrid authenticated page TTFB during parallel uploads:", {
          "p50": statistics.median(loaded_first_bytes),
          "p95": loaded_first_bytes[23],
          "max": loaded_first_bytes[24],
          "p95_ratio": loaded_first_bytes[23] / first_bytes[94],
          "tls_p95": loaded_tls[23],
      })
      native_samples = client.succeed("cat /tmp/hybrid-native-pages").splitlines()
      assert len(native_samples) == 25, native_samples
      assert all(sample.split()[1] == "200" for sample in native_samples), native_samples
      native_first_bytes = sorted(float(sample.split()[0]) for sample in native_samples)
      print("hybrid direct Native page TTFB during parallel uploads:", {
          "p50": statistics.median(native_first_bytes),
          "p95": native_first_bytes[23],
          "max": native_first_bytes[24],
      })

      # Local Wrangler serializes R2 emulation and Worker execution in one VM.
      # The signed direct probe isolates Native and PostgreSQL responsiveness.
      assert native_first_bytes[23] < 0.5, native_first_bytes
      loaded_page_gate = (
          loaded_first_bytes[23] < 0.5
          and loaded_first_bytes[23] <= first_bytes[94] * 1.25
      )

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

      reviewed(
          "hybrid-cache-replica-placement",
          "placement add cache:fleet/objects replica --binding instance-default "
          "--prefix caches/fleet-objects-replica --kind complete "
          "--desired-state active --read enabled",
      )
      replica = json.loads(client.succeed(hub_command(
          "placement show cache:fleet/objects replica"
      )))["data"]["placement"]
      reviewed(
          "hybrid-cache-replicate",
          "placement replicate cache:fleet/objects --from primary --to replica "
          "--wait --timeout 5m "
          f"--if-version {shlex.quote(replica['resource_version'])}",
          timeout=360,
      )
      replica = json.loads(client.succeed(hub_command(
          "placement show cache:fleet/objects replica"
      )))["data"]["placement"]
      assert replica["observation"]["state"] == "ready", replica
      assert replica["observation"]["completeness"] == "complete", replica

      oci_token = json.loads(client.succeed(
          f"{CURL} -fsS -H 'Authorization: Bearer {session_token}' "
          "'https://aos.andyl.org/v2/token?"
          "service=aos.andyl.org&scope=repository:aos:pull,push'",
          timeout=60,
      ))["token"]
      client.succeed(
          f"{CURL} -fsS -X POST -D /tmp/hybrid-oci-start.headers "
          f"-H 'Authorization: Bearer {oci_token}' -H 'Content-Length: 0' "
          "https://aos.andyl.org/v2/aos/blobs/uploads/ "
          "-o /dev/null",
          timeout=60,
      )
      location = client.succeed(
          f"{SED} -n 's/^location: *//ip' /tmp/hybrid-oci-start.headers | tr -d '\\r' | tail -n1"
      ).strip()
      assert "/blobs/uploads/" in location, location
      upload_id = location.rsplit("/", 1)[-1]
      assert re.fullmatch(r"[0-9a-f-]{32,36}", upload_id), upload_id
      upload_url = f"https://aos.andyl.org/v2/aos/blobs/uploads/{upload_id}"
      invalid_range_status = client.succeed(
          f"{CURL} -sS -o /dev/null -w '%{{http_code}}' -X PATCH "
          f"-H 'Authorization: Bearer {oci_token}' "
          "-H 'Content-Range: bytes 2-5' --data-binary 'abcd' "
          f"{shlex.quote(upload_url)}",
          timeout=60,
      ).strip()
      assert invalid_range_status == "416", invalid_range_status
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
          f"'https://aos.andyl.org/v2/aos/blobs/sha256:{cache_digest}' "
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

      final_bytes = b"hybrid-final-oci-chunk"
      final_digest = hashlib.sha256(bytes(cache_size) + final_bytes).hexdigest()
      client.succeed(
          f"printf %s {shlex.quote(final_bytes.decode())} > /tmp/hybrid-oci-final-chunk"
      )
      client.succeed(
          f"{CURL} -fsS -X POST -D /tmp/hybrid-oci-final-start.headers "
          f"-H 'Authorization: Bearer {oci_token}' -H 'Content-Length: 0' "
          "https://aos.andyl.org/v2/aos/blobs/uploads/ "
          "-o /dev/null",
          timeout=60,
      )
      final_location = client.succeed(
          f"{SED} -n 's/^location: *//ip' /tmp/hybrid-oci-final-start.headers | tr -d '\\r' | tail -n1"
      ).strip()
      final_upload_id = final_location.rsplit("/", 1)[-1]
      assert re.fullmatch(r"[0-9a-f-]{32,36}", final_upload_id), final_upload_id
      final_upload_url = (
          f"https://aos.andyl.org/v2/aos/blobs/uploads/{final_upload_id}"
      )
      client.succeed(
          f"{CURL} -fsS -X PATCH -H 'Authorization: Bearer {oci_token}' "
          f"--data-binary @/tmp/hybrid-cache-object {shlex.quote(final_upload_url)} "
          "-o /dev/null",
          timeout=180,
      )
      client.succeed(
          f"{CURL} -fsS -X PUT -H 'Authorization: Bearer {oci_token}' "
          f"--data-binary @/tmp/hybrid-oci-final-chunk "
          f"{shlex.quote(final_upload_url + '?digest=sha256:' + final_digest)} "
          "-o /dev/null",
          timeout=180,
      )
      client.succeed(
          f"{CURL} -fsS -H 'Authorization: Bearer {oci_token}' "
          f"{shlex.quote('https://aos.andyl.org/v2/aos/blobs/sha256:' + final_digest)} "
          "-o /tmp/hybrid-oci-final-downloaded",
          timeout=180,
      )
      final_downloaded_digest = client.succeed(
          "${pkgs.coreutils}/bin/sha256sum /tmp/hybrid-oci-final-downloaded | cut -d' ' -f1"
      ).strip()
      assert final_downloaded_digest == final_digest, final_downloaded_digest
      final_upload_state = native.succeed(
          f"{POSTGRES}/psql -h 127.0.0.1 -U postgres -d postgres -At "
          f"-c \"SELECT state || ':' || cleanup_state FROM oci_upload_sessions "
          f"WHERE id = '{final_upload_id}'\""
      ).strip()
      assert final_upload_state == "complete:complete", final_upload_state

      client.succeed(
          f"{CURL} -fsS -X POST -D /tmp/hybrid-oci-large-start.headers "
          f"-H 'Authorization: Bearer {oci_token}' -H 'Content-Length: 0' "
          "https://aos.andyl.org/v2/aos/blobs/uploads/ -o /dev/null",
          timeout=60,
      )
      large_location = client.succeed(
          f"{SED} -n 's/^location: *//ip' /tmp/hybrid-oci-large-start.headers "
          "| tr -d '\\r' | tail -n1"
      ).strip()
      large_upload_id = large_location.rsplit("/", 1)[-1]
      assert re.fullmatch(r"[0-9a-f-]{32,36}", large_upload_id), large_upload_id
      large_upload_url = f"https://aos.andyl.org/v2/aos/blobs/uploads/{large_upload_id}"
      try:
          client.succeed(
              f"{CURL} -fsS -X PATCH -H 'Authorization: Bearer {oci_token}' "
              f"--data-binary @/tmp/hybrid-publication-surface/{publication_path} "
              f"{shlex.quote(large_upload_url)} -o /dev/null",
              timeout=180,
          )
      except Exception:
          print("hybrid Worker logs after large OCI part failure:", worker.succeed(
              "tail -n 120 /var/lib/hybrid-worker/wrangler.log"
          ))
          print("hybrid Native logs after large OCI part failure:", native.succeed(
              "journalctl -u aos-hub --no-pager -n 100"
          ))
          print("hybrid Worker memory after large OCI part failure:", worker.succeed(
              "cat /proc/meminfo | head -n 8"
          ))
          raise
      client.succeed(
          f"{CURL} -fsS -X PUT -H 'Authorization: Bearer {oci_token}' "
          f"-H 'Content-Length: 0' "
          f"{shlex.quote(large_upload_url + '?digest=sha256:' + publication_digest)} "
          "-o /dev/null",
          timeout=180,
      )
      client.succeed(
          f"{CURL} -fsS -H 'Authorization: Bearer {oci_token}' "
          f"{shlex.quote('https://aos.andyl.org/v2/aos/blobs/sha256:' + publication_digest)} "
          "-o /tmp/hybrid-oci-large-downloaded",
          timeout=180,
      )
      large_downloaded_digest = client.succeed(
          "${pkgs.coreutils}/bin/sha256sum /tmp/hybrid-oci-large-downloaded | cut -d' ' -f1"
      ).strip()
      assert large_downloaded_digest == publication_digest, large_downloaded_digest
      large_downloaded_size = int(client.succeed(
          "${pkgs.coreutils}/bin/stat -c %s /tmp/hybrid-oci-large-downloaded"
      ).strip())
      assert large_downloaded_size == publication_size, large_downloaded_size
      inventory_query = (
          "SELECT COUNT(*) FROM oci_provider_inventory_entries entry "
          "JOIN oci_provider_inventory_heads head "
          "ON head.generation_id = entry.generation_id "
          f"WHERE entry.object_key = 'oci/blobs/sha256/{publication_digest}' "
          f"AND entry.observed_hash = 'sha256:{publication_digest}' "
          f"AND entry.byte_size = {publication_size}"
      )
      native.wait_until_succeeds(
          f"test \"$({POSTGRES}/psql -h 127.0.0.1 -U postgres -d postgres -At "
          f"-c {shlex.quote(inventory_query)})\" = 1",
          timeout=240,
      )
      inventory_pages = int(native.succeed(
          f"{POSTGRES}/psql -h 127.0.0.1 -U postgres -d postgres -At "
          "-c \"SELECT generation.checkpoint_ordinal "
          "FROM oci_provider_inventory_generations generation "
          "JOIN oci_provider_inventory_heads head "
          "ON head.generation_id = generation.id "
          "JOIN oci_provider_inventory_entries entry "
          "ON entry.generation_id = generation.id "
          f"WHERE entry.object_key = 'oci/blobs/sha256/{publication_digest}'\""
      ).strip())
      assert inventory_pages <= 16, inventory_pages

      durations = [
          float(client.succeed(f"cat /tmp/hybrid-parallel-{index}.time").strip())
          for index in range(len(parallel_paths))
      ]
      print("hybrid parallel cache upload seconds:", {
          "count": len(durations),
          "p50": statistics.median(durations),
          "max": max(durations),
      })

      pool_log = native.succeed(
          f"journalctl -u aos-hub.service -o cat --no-pager | "
          f"{GREP} 'hybrid SQL pool'"
      )
      pool_samples = []
      for line in pool_log.splitlines():
          fields = {
              name: int(value)
              for name, value in re.findall(r"\b(open|idle|maximum)=(\d+)", line)
          }
          if {"open", "idle", "maximum"} <= fields.keys():
              pool_samples.append((fields["open"], fields["idle"], fields["maximum"]))
      assert pool_samples, pool_log
      assert all(0 <= idle <= opened <= maximum for opened, idle, maximum in pool_samples), pool_samples
      print("hybrid SQL pool:", {
          "maximum": max(maximum for _, _, maximum in pool_samples),
          "max_open": max(opened for opened, _, _ in pool_samples),
          "max_busy": max(opened - idle for opened, idle, _ in pool_samples),
      })

      boundary_log = native.succeed(
          f"journalctl -u aos-hub.service -o cat --no-pager | "
          f"{GREP} 'hybrid storage boundary'"
      )
      assert "inspect_git_object" in boundary_log, boundary_log
      assert "hash_oci_range" in boundary_log, boundary_log
      assert "copy_object" in boundary_log, boundary_log
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
      assert compact_verifications, transferred
      parallel_verifications = [
          response for response, source in transferred
          if source == parallel_size and response < 2048
      ]
      assert len(parallel_verifications) >= len(parallel_paths), transferred
      large_verifications = [
          response for response, source in transferred
          if source == publication_size and response < 2048
      ]
      assert large_verifications, transferred
      inventory_hashes = [
          (int(response), int(source))
          for line in boundary_log.splitlines()
          if 'operation="hash_oci_range"' in line
          for response, source in re.findall(
              r"response_bytes=(\d+) source_bytes=(\d+)", line
          )
      ]
      assert sum(source for _, source in inventory_hashes) >= publication_size, inventory_hashes
      assert all(response < 2048 for response, _ in inventory_hashes), inventory_hashes
      placement_copies = [
          (int(response), int(source))
          for line in boundary_log.splitlines()
          if 'operation="copy_object"' in line
          for response, source in re.findall(
              r"response_bytes=(\d+) source_bytes=(\d+)", line
          )
      ]
      assert sum(source for _, source in placement_copies) >= multipart_size, placement_copies
      assert all(response < 2048 for response, _ in placement_copies), placement_copies
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

      probe_path = ".aos-internal/conditional-delete-probes/900-1"
      probe_sequence = 0
      def probe_work(operation):
          global probe_sequence
          probe_sequence += 1
          issued = int(time.time())
          plan = {
              **cache_verification_plan,
              "plan_id": f"{probe_sequence:032x}",
              "issued_at": issued,
              "expires_at": issued + 30,
              "operation": operation,
          }
          request_body, request_signature = sign_storage_plan(plan)
          return json.loads(client.succeed(
              f"{CURL} -fsS -X POST -H 'content-type: application/json' "
              f"-H 'x-aos-storage-work-signature: {request_signature}' "
              f"--data-binary {shlex.quote(request_body.decode())} "
              "https://aos.andyl.org/_internal/storage/v1/execute",
              timeout=60,
          ))["outcome"]

      def write_probe(contents):
          outcome = probe_work({
              "kind": "put_probe",
              "path": probe_path,
              "content_base64": base64.b64encode(contents).decode(),
          })
          assert outcome["kind"] == "probe_acknowledged", outcome
          observed = probe_work({"kind": "head", "path": probe_path})
          assert observed["kind"] == "head", observed
          return observed["object"]

      first_probe = write_probe(b"reviewed identity")
      second_probe = write_probe(b"replacement identity")
      assert first_probe["etag"] != second_probe["etag"]
      rejected_delete = probe_work({
          "kind": "delete_if_matches",
          "path": probe_path,
          "claim_id": "fleet-mismatched-claim",
          "expected_etag": first_probe["etag"],
          "expected_size": first_probe["size"],
          "expected_hash": None,
      })
      assert rejected_delete["kind"] == "delete_precondition_failed", rejected_delete
      assert probe_work({"kind": "head", "path": probe_path})["object"] == second_probe
      reviewed_delete = {
          "kind": "delete_if_matches",
          "path": probe_path,
          "claim_id": "fleet-reviewed-claim",
          "expected_etag": second_probe["etag"],
          "expected_size": second_probe["size"],
          "expected_hash": None,
      }
      removed = probe_work(reviewed_delete)
      assert removed == {"kind": "object_deleted", "etag": second_probe["etag"]}, removed
      later_probe = write_probe(b"later physical object")
      assert probe_work(reviewed_delete) == removed
      assert probe_work({"kind": "head", "path": probe_path})["object"] == later_probe
      cleanup = probe_work({"kind": "delete_probe", "path": probe_path})
      assert cleanup["kind"] == "probe_acknowledged", cleanup
      assert probe_work({"kind": "head", "path": probe_path})["kind"] == "not_found"

      for _ in range(90):
          capability_state = native.succeed(
              f"{POSTGRES}/psql -h 127.0.0.1 -U postgres -d postgres -At "
              "-c \"SELECT state FROM oci_conditional_delete_capabilities "
              "WHERE binding_id = (SELECT id FROM bindings "
              "WHERE kind = 'deployment_r2')\""
          ).strip()
          if capability_state == "valid":
              break
          time.sleep(2)
      assert capability_state == "valid", capability_state

      reviewed(
          "hybrid-oci-retention",
          "registry container retention set fleet/containers --untagged-grace 0s "
          "--deleted-tag-history 0s --recent-manual-tag-revisions 0 "
          "--retain-referrers disabled",
      )
      retention = json.loads(client.succeed(hub_command(
          "registry container retention show fleet/containers"
      )))["data"]["policy"]
      # A retention update advances the OCI mutation epoch. GC must review a
      # provider enumeration sealed against that new epoch.
      current_inventory_query = (
          "SELECT COUNT(*) FROM oci_provider_inventory_heads head "
          "JOIN oci_provider_inventory_generations generation "
          "ON generation.id = head.generation_id "
          "JOIN surface_placements placement ON placement.id = head.placement_id "
          "JOIN surface_placement_observations observation "
          "ON observation.placement_id = placement.id "
          "JOIN bindings binding ON binding.id = placement.binding_id "
          "JOIN binding_write_state write_state ON write_state.binding_id = binding.id "
          "JOIN oci_registry_state state ON state.registry_id = head.registry_id "
          "WHERE placement.prefix = 'registries/fleet-containers' "
          "AND generation.state = 'complete' "
          "AND generation.captured_mutation_epoch = state.mutation_epoch "
          "AND generation.placement_resource_version = placement.resource_version "
          "AND generation.placement_write_spec_version = placement.write_spec_version "
          "AND generation.placement_observation_version = observation.observation_version "
          "AND generation.binding_resource_version = binding.resource_version "
          "AND generation.binding_write_revision = write_state.current_write_revision"
      )
      native.wait_until_succeeds(
          f"test \"$({POSTGRES}/psql -h 127.0.0.1 -U postgres -d postgres -At "
          f"-c {shlex.quote(current_inventory_query)})\" = 1",
          timeout=180,
      )
      gc_result = json.loads(client.succeed(hub_command(
          "registry container gc plan fleet/containers "
          f"--if-version {shlex.quote(retention['resource_version'])} "
          "--idempotency-key hybrid-oci-gc-plan"
      ), timeout=180))["data"]
      gc_plan = gc_result["plan"]
      gc_run = gc_result["run"]
      assert not gc_result.get("blockers", []), gc_result
      candidate_count = int(gc_run["candidate_object_count"])
      assert candidate_count >= 1, gc_run
      assert int(gc_run["placement_action_count"]) >= 1, gc_run
      client.succeed(hub_command(
          "registry container gc apply",
          " ".join([
              "--plan-id", shlex.quote(gc_plan["plan_id"]),
              "--confirm-hash", shlex.quote(gc_plan["confirmation_hash"]),
              "--idempotency-key hybrid-oci-gc-apply --yes",
          ]),
      ), timeout=120)
      gc_run_id = gc_run["run_id"]
      gc_status_query = (
          "SELECT state || ':' || deleted_object_count FROM oci_gc_runs "
          f"WHERE id = '{gc_run_id}'"
      )
      try:
          native.wait_until_succeeds(
              f"test \"$({POSTGRES}/psql -h 127.0.0.1 -U postgres -d postgres -At "
              f"-c {shlex.quote(gc_status_query)})\" = "
              f"'complete:{candidate_count}'",
              timeout=240,
          )
      except Exception:
          run_status_sql = (
              "SELECT state, last_error FROM oci_gc_runs "
              f"WHERE id = {repr(gc_run_id)}"
          )
          action_status_sql = (
              "SELECT state, last_error FROM oci_gc_placement_actions "
              f"WHERE run_id = {repr(gc_run_id)}"
          )
          print("hybrid OCI GC run after timeout:", native.succeed(
              f"{POSTGRES}/psql -h 127.0.0.1 -U postgres -d postgres -c "
              f"{shlex.quote(run_status_sql)}"
          ))
          print("hybrid OCI GC actions after timeout:", native.succeed(
              f"{POSTGRES}/psql -h 127.0.0.1 -U postgres -d postgres -c "
              f"{shlex.quote(action_status_sql)}"
          ))
          raise

      registry_selector = native.succeed(
          f"{POSTGRES}/psql -h 127.0.0.1 -U postgres -d postgres -At -F ' ' "
          "-c \"SELECT p.id, p.resource_version, b.id, b.resource_version, p.prefix "
          "FROM surface_placements p JOIN bindings b ON b.id = p.binding_id "
          "WHERE p.name = 'primary' AND p.prefix = 'registries/fleet-containers'\""
      ).strip().split()
      assert len(registry_selector) == 5, registry_selector
      head_time = int(time.time())
      deleted_head_plan = {
          **cache_verification_plan,
          "plan_id": "7" * 32,
          "issued_at": head_time,
          "expires_at": head_time + 30,
          "placement_id": int(registry_selector[0]),
          "placement_resource_version": int(registry_selector[1]),
          "binding_id": int(registry_selector[2]),
          "binding_resource_version": int(registry_selector[3]),
          "placement_prefix": registry_selector[4],
          "operation": {
              "kind": "head",
              "path": f"oci/blobs/sha256/{publication_digest}",
          },
      }
      for attempt in range(3):
          head_time = int(time.time())
          deleted_head_plan["issued_at"] = head_time
          deleted_head_plan["expires_at"] = head_time + 30
          head_body, head_signature = sign_storage_plan(deleted_head_plan)
          try:
              deleted_head = json.loads(client.succeed(
                  f"{CURL} -fsS -X POST -H 'content-type: application/json' "
                  f"-H 'x-aos-storage-work-signature: {head_signature}' "
                  f"--data-binary {shlex.quote(head_body.decode())} "
                  "https://aos.andyl.org/_internal/storage/v1/execute",
                  timeout=60,
              ))
              break
          except Exception:
              if attempt < 2:
                  time.sleep(2)
                  continue
              print("hybrid Worker log after OCI GC:", worker.succeed(
                  "tail -n 120 /var/lib/hybrid-worker/wrangler.log"
              ))
              print("hybrid Worker kernel log after OCI GC:", worker.succeed(
                  "journalctl -k --no-pager -n 60"
              ))
              raise
      assert deleted_head["outcome"]["kind"] == "not_found", deleted_head

      invalid_plan_time = int(time.time())
      rejected_plans = [
          {
              **cache_verification_plan,
              "plan_id": "3" * 32,
              "issued_at": invalid_plan_time - 60,
              "expires_at": invalid_plan_time - 30,
          },
          {
              **cache_verification_plan,
              "plan_id": "4" * 32,
              "deployment_id": "other-hybrid-fleet",
              "issued_at": invalid_plan_time,
              "expires_at": invalid_plan_time + 30,
          },
      ]
      for rejected_plan in rejected_plans:
          rejected_body, rejected_signature = sign_storage_plan(rejected_plan)
          rejected_status = client.succeed(
              f"{CURL} -sS -o /dev/null -w '%{{http_code}}' -X POST "
              "-H 'content-type: application/json' "
              f"-H 'x-aos-storage-work-signature: {rejected_signature}' "
              f"--data-binary {shlex.quote(rejected_body.decode())} "
              "https://aos.andyl.org/_internal/storage/v1/execute",
              timeout=60,
          ).strip()
          assert rejected_status == "401", (rejected_plan, rejected_status)

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
            https://aos.andyl.org/v2/aos/blobs/uploads/missing)
          test "$code" = 503
          code=$({CURL} -sS -o /dev/null -w '%{{http_code}}' -X DELETE \\
            --data-binary 'delete-body-must-stay-at-worker' \\
            https://aos.andyl.org/v2/aos/blobs/uploads/missing)
          test "$code" = 400
      """), timeout=60)
      native.succeed("systemctl start aos-hub.service")
      client.wait_until_succeeds(
          f"{CURL} -fsS -H 'cf-connecting-ip: 192.0.2.10' https://aos.andyl.org/healthz",
          timeout=180,
      )

      native.succeed(
          f"{CHROOT} {POSTGRES}/pg_ctl -D /var/lib/hybrid-postgres "
          "-m immediate -w stop",
          timeout=60,
      )
      database_outage_status = client.succeed(textwrap.dedent(f"""
          cookie=$(cat /tmp/hybrid-cookie)
          {CURL} -sS -o /dev/null -w '%{{http_code}}' \\
            -H 'cf-connecting-ip: 192.0.2.10' -H "Cookie: $cookie" \\
            https://aos.andyl.org/-/instance
      """), timeout=60).strip()
      assert int(database_outage_status) >= 500, database_outage_status
      client.succeed(
          f"{CURL} -fsS https://aos.andyl.org/_assets/style.css > /dev/null",
          timeout=60,
      )
      native.succeed(
          f"{CHROOT} {POSTGRES}/pg_ctl -D /var/lib/hybrid-postgres "
          "-l /var/lib/hybrid-postgres/server.log -w start "
          "-o '-c config_file=/var/lib/hybrid-postgres/fleet.conf'",
          timeout=120,
      )
      client.wait_until_succeeds(
          f"{CURL} -fsS -H 'cf-connecting-ip: 192.0.2.10' "
          "-H \"Cookie: $(cat /tmp/hybrid-cookie)\" "
          "https://aos.andyl.org/-/instance | "
          f"{GREP} -q '<html'",
          timeout=180,
      )
      assert loaded_page_gate, (
          "authenticated page p95 regressed during parallel uploads",
          first_bytes[94],
          loaded_first_bytes[23],
          native_first_bytes[23],
      )
    '';
}
