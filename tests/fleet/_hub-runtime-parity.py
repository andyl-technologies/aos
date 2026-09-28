"""Publish one signed corpus through three real Hub runtime configurations.

Companion processes run after the hybrid latency and fault measurements, with
separate local SQLite, HubDb, R2, and coordination state. They use production
artifacts, ordinary reviewed administration, and the managed publication API.
SQL is read only and observes authoritative indexes after publication finishes.
"""

import base64
import json
import re
import shlex
import textwrap


def qualify_registry_runtime_parity(client, native, worker, *, tools, fixture, snapshot_assert):
    """Require identical signed package and channel indexes in all three modes."""
    native_origin = "https://aos.staging.andyl.org:8443"
    worker_origin = "https://aos.andyl.org:8443"
    native_root = "/var/lib/hub-parity-native"
    worker_root = "/var/lib/hub-parity-worker"
    source_root = "/tmp/hub-parity-source"
    password = "runtime-parity-root-password"
    email = "runtime-parity-root@example.test"
    seal_key = "2" * 64
    curl = tools["curl"]
    hub = tools["hub"]
    coreutils = tools["coreutils"]

    # Exclude the unrelated large web-upload probe. Every signed Git, channel,
    # semantic, and package object remains byte identical to the hybrid corpus.
    corpus_path = "/tmp/hub-parity-corpus.tar"
    client.succeed(
        f"{tools['tar']} -C /tmp/hybrid-publication-surface --exclude=./web "
        f"-cf {corpus_path} .",
        timeout=60,
    )
    corpus_size = int(client.succeed(f"{coreutils}/stat -c '%s' {corpus_path}").strip())
    corpus_digest = client.succeed(f"{coreutils}/sha256sum {corpus_path}").split()[0]
    assert corpus_size > 0, "empty signed parity corpus"
    trust_key = fixture["trust_key"]

    native.succeed(textwrap.dedent(f"""
        set -eu
        umask 077
        mkdir -p {native_root}
        printf '[]' > {native_root}/probe-signers.json
        {coreutils}/install -m 0600 {fixture['route_keys']} {native_root}/route-keys.json
        {hub} --root {native_root} init \\
          --root-email {email} --root-password {password}
        HUB_DNS_JSON_ENDPOINT=https://dns.google/resolve \\
        {hub} --root {native_root} serve --listen 0.0.0.0:8443 \\
          --external-url {native_origin} --reindex-interval 0 \\
          --tls-certificate-file {fixture['certificate']} \\
          --tls-private-key-file {fixture['private_key']} \\
          --domain-probe-signer-manifest-file {native_root}/probe-signers.json \\
          --route-reservation-keys-file {native_root}/route-keys.json \\
          --cloudflare-api-token parity-fixture-token \\
          --deployment-id fleet-native-parity-v1 \\
          --release-receipt-key-id staging-publication-v1 \\
          --release-receipt-key-file {fixture['release_seed']} \\
          --channel-receipt-key-id staging-channel-v1 \\
          --channel-receipt-key-file {fixture['channel_seed']} \\
          --release-publication-keys-file {fixture['publication_keys']} \\
          --qualification-keys-file {fixture['qualification_keys']} \\
          > {native_root}/server.log 2>&1 < /dev/null &
        echo $! > {native_root}/server.pid
    """), timeout=180)

    worker_config = worker_only_configuration(tools["worker_main"], worker_origin)
    evidence = {
        "schema_version": "aos.hub.release-evidence-config/v1",
        "publication_key_id": "staging-publication-v1",
        "publication_signing_seed_base64": native.succeed(f"cat {fixture['release_seed']}").strip(),
        "channel_key_id": "staging-channel-v1",
        "channel_signing_seed_base64": native.succeed(f"cat {fixture['channel_seed']}").strip(),
        "publication_keys": json.loads(native.succeed(f"cat {fixture['publication_keys']}")),
        "qualification_keys": json.loads(native.succeed(f"cat {fixture['qualification_keys']}")),
    }
    route_keys = native.succeed(f"cat {native_root}/route-keys.json").strip()
    secrets = {
        "HUB_SEAL_KEY": seal_key,
        "HUB_JWT_SECRET": "fleet-worker-parity-stable-jwt-key-with-thirty-two-bytes",
        "HUB_CLOUDFLARE_API_TOKEN": "parity-fixture-token",
        "HUB_DOMAIN_PROBE_SIGNER_MANIFEST": "[]",
        "HUB_ROUTE_RESERVATION_KEYRING": route_keys,
        "HUB_RELEASE_EVIDENCE_CONFIG": json.dumps(evidence, separators=(",", ":")),
    }
    assert all("'" not in value and "\n" not in value for value in secrets.values())
    dev_vars = "\n".join(f"{name}='{value}'" for name, value in secrets.items()) + "\n"
    worker.succeed(textwrap.dedent(f"""
        set -eu
        umask 077
        mkdir -p {worker_root}/config {worker_root}/cache
        printf '%s' {shlex.quote(worker_config)} > {worker_root}/wrangler.toml
        printf '%s' {shlex.quote(dev_vars)} > {worker_root}/.dev.vars
        cd {worker_root}
        XDG_CONFIG_HOME={worker_root}/config XDG_CACHE_HOME={worker_root}/cache \\
        WRANGLER_LOG_PATH={worker_root}/config/logs \\
        WRANGLER_REGISTRY_PATH={worker_root}/config/registry \\
        SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \\
        {tools['wrangler']} dev --local --config {worker_root}/wrangler.toml \\
          --ip 0.0.0.0 --port 8443 --local-protocol https \\
          --https-cert-path {fixture['certificate']} \\
          --https-key-path {fixture['private_key']} \\
          > {worker_root}/wrangler.log 2>&1 < /dev/null &
        echo $! > {worker_root}/wrangler.pid
    """), timeout=30)
    try:
        worker.wait_until_succeeds(f"{curl} -fsS {worker_origin}/healthz > /dev/null", timeout=180)
    except Exception:
        print("Worker-only parity startup log:", worker.succeed(
            f"tail -n 100 {worker_root}/wrangler.log 2>/dev/null || true"
        ))
        raise
    worker.succeed(
        f"{hub} worker bootstrap-root --url {worker_origin} --email {email} "
        f"--password {password} --seal-key {seal_key}",
        timeout=120,
    )
    native.wait_until_succeeds(f"{curl} -fsS {native_origin}/healthz > /dev/null", timeout=180)

    for mode, machine, origin in (
        ("native_only", native, native_origin),
        ("worker_only", worker, worker_origin),
    ):
        token = browser_session_token(machine, origin, email, password, curl)
        copy_signed_surface(client, machine, corpus_path, corpus_size, corpus_digest, source_root, tools)
        setup_and_publish_same_registry(
            machine, origin, token, trust_key, source_root, tools,
            refresh_token=lambda: browser_session_token(machine, origin, email, password, curl),
        )
        print("signed parity registry published:", mode)

    def native_query(sql):
        output = native.succeed(
            f"{tools['sqlite']} -readonly -json {native_root}/hub.db {shlex.quote(sql)}",
            timeout=60,
        )
        return [list(row.values()) for row in json.loads(output or "[]")]

    def worker_query(sql):
        body = json.dumps({"operation": "query", "sql": sql, "params": []})
        output = worker.succeed(
            f"{curl} -fsS -X POST -H 'Content-Type: application/json' "
            f"-H 'x-hub-seal: {seal_key}' --data-binary {shlex.quote(body)} "
            f"{worker_origin}/_internal/sql",
            timeout=60,
        )
        return [
            [None if value == "Null" else next(iter(value.values())) for value in row["values"]]
            for row in json.loads(output)["rows"]
        ]

    def hybrid_query(sql):
        wrapped = "SELECT COALESCE(json_agg(row_to_json(observation)), '[]') FROM (" + sql + ") observation"
        output = native.succeed(
            f"{tools['postgres']}/psql -h 127.0.0.1 -U postgres -d postgres -At "
            f"-c {shlex.quote(wrapped)}",
            timeout=60,
        )
        return [list(row.values()) for row in json.loads(output)]

    snapshot_assert({
        "hybrid": hybrid_query,
        "native_only": native_query,
        "worker_only": worker_query,
    }, "fleet/containers")

    for machine, root in ((native, native_root), (worker, worker_root)):
        pid_file = "server.pid" if machine is native else "wrangler.pid"
        machine.succeed(f"kill $(cat {root}/{pid_file})")


def browser_session_token(machine, origin, email, password, curl):
    """Use the password login and console CSRF boundary to obtain an API token."""
    headers = machine.succeed(
        f"{curl} -fsS -D - -o /dev/null -X POST -H 'cf-connecting-ip: 192.0.2.10' "
        f"--data-urlencode {shlex.quote('email=' + email)} "
        f"--data-urlencode {shlex.quote('password=' + password)} {origin}/login/password",
        timeout=120,
    )
    cookie = re.search(r"(?im)^set-cookie:\s*([^;\r\n]+)", headers)
    assert cookie is not None, headers
    cookie_header = "Cookie: " + cookie.group(1)
    html = machine.succeed(f"{curl} -fsS -H {shlex.quote(cookie_header)} {origin}/-/instance", timeout=60)
    csrf = re.search(r'name="aos-session-csrf" content="([^"]+)"', html)
    assert csrf is not None, html
    response = machine.succeed(
        f"{curl} -fsS -X POST -H {shlex.quote(cookie_header)} -H 'cf-connecting-ip: 192.0.2.10' "
        f"-H {shlex.quote('Origin: ' + origin)} -H {shlex.quote('x-aos-csrf: ' + csrf.group(1))} "
        f"-H 'x-aos-console-route: /-/instance' {origin}/-/auth/session-token",
        timeout=60,
    )
    return json.loads(response)["accessToken"]


def copy_signed_surface(client, destination, corpus_path, corpus_size, corpus_digest, source_root, tools):
    """Copy the frozen fixture in bounded agent messages and verify its hash."""
    coreutils = tools["coreutils"]
    archive = "/tmp/hub-parity-corpus-copy.tar"
    destination.succeed(f"mkdir -p {source_root}; : > {archive}")
    chunk_size = 48 * 1024
    for offset in range(0, corpus_size, chunk_size):
        encoded = client.succeed(
            f"{coreutils}/dd if={corpus_path} bs={chunk_size} skip={offset // chunk_size} count=1 status=none "
            f"| {coreutils}/base64 -w0",
            timeout=60,
        ).strip()
        assert len(base64.b64decode(encoded)) == min(chunk_size, corpus_size - offset)
        destination.succeed(
            f"printf '%s' {shlex.quote(encoded)} | {coreutils}/base64 -d >> {archive}",
            timeout=60,
        )
    observed_digest = destination.succeed(f"{coreutils}/sha256sum {archive}").split()[0]
    assert observed_digest == corpus_digest, (observed_digest, corpus_digest)
    destination.succeed(f"{tools['tar']} -C {source_root} -xf {archive}", timeout=60)


def setup_and_publish_same_registry(machine, origin, token, trust_key, source_root, tools, *, refresh_token):
    """Create the same reviewed registry and publish exact pre-authored bytes."""
    def command(subcommand, mutation=""):
        return f"{tools['aos']} --json hub {subcommand} --hub {origin} --token {shlex.quote(token)} {mutation}"

    def reviewed(label, subcommand):
        planned = json.loads(machine.succeed(command(
            subcommand, "--plan --idempotency-key " + shlex.quote(label + "-plan"),
        ), timeout=180))["data"]["plan"]
        assert planned["effects"], planned
        return json.loads(machine.succeed(command(
            subcommand,
            f"--plan-id {shlex.quote(planned['plan_id'])} "
            f"--confirm-hash {shlex.quote(planned['confirmation_hash'])} "
            f"--yes --idempotency-key {shlex.quote(label + '-apply')}",
        ), timeout=180))

    reviewed("parity-org", "org create --slug fleet --display-name 'Hybrid fleet'")
    org = json.loads(machine.succeed(command("org show fleet")))["data"]["organization"]
    reviewed("parity-binding", "binding grant instance:default --consumer-scope " + shlex.quote(org["stable_id"]))
    reviewed("parity-network", "network-policy grant instance:public --consumer-scope " + shlex.quote(org["stable_id"]))
    reviewed("parity-registry", "registry create --org fleet --name containers --visibility public --trust-key " + shlex.quote(trust_key))
    reviewed(
        "parity-placement",
        "placement add registry:fleet/containers primary --binding instance-default "
        "--prefix registries/fleet-containers --kind complete --desired-state active --read enabled",
    )
    placement = json.loads(machine.succeed(command("placement show registry:fleet/containers primary")))["data"]["placement"]
    reviewed(
        "parity-scan", "placement scan registry:fleet/containers primary --wait --timeout 2m "
        "--if-version " + shlex.quote(placement["resource_version"]),
    )
    placement = json.loads(machine.succeed(command("placement show registry:fleet/containers primary")))["data"]["placement"]
    reviewed("parity-promote", "placement promote registry:fleet/containers primary --if-version " + shlex.quote(placement["resource_version"]))

    token = refresh_token()
    publication, token = publish_signed_surface(
        machine,
        lambda authorization: (
            f"{tools['aos']} --json hub registry publish upload fleet/containers "
            f"--root {shlex.quote(source_root)} --hub {origin} "
            f"--token {shlex.quote(authorization)}"
        ),
        token,
        refresh_token,
    )
    assert publication["state"] == "ready", publication
    machine.wait_until_succeeds(
        command("registry show fleet/containers") + f" | {tools['jq']} -e '.data.registry.index_state == \"fresh\"' > /dev/null",
        timeout=240,
    )


def worker_only_configuration(main, origin):
    """Render isolated local bindings for the production Worker-only runtime."""
    config = textwrap.dedent(f"""
        name = "hub-runtime-parity-worker"
        main = "{main}"
        compatibility_date = "2024-09-23"
        [vars]
        HUB_TOPOLOGY = "worker_only"
        HUB_REQUEST_SHARDING = "on"
        HUB_EXTERNAL_URL = "{origin}"
        HUB_DEPLOYMENT_ID = "fleet-worker-parity-v1"
        HUB_DATABASE_INSTANCE = "runtime-parity"
        HUB_DNS_JSON_ENDPOINT = "https://dns.google/resolve"
        [[r2_buckets]]
        binding = "REGISTRY_BUCKET"
        bucket_name = "runtime-parity-r2"
        [[kv_namespaces]]
        binding = "SESSIONS"
        id = "11111111111111111111111111111111"
        [[queues.producers]]
        binding = "JOBS"
        queue = "runtime-parity-jobs"
        [[queues.consumers]]
        queue = "runtime-parity-jobs"
        max_batch_size = 1
        max_batch_timeout = 1
    """)
    classes = {
        "COORDINATOR": "CoordinatorObject", "HUB_DB": "HubDb",
        "HUB_CONTROL_SHARDS": "HubControlShard", "HUB_TENANT_SHARDS": "HubTenantShard",
        "HUB_REGISTRY_SHARDS": "HubRegistryShard", "HUB_CACHE_SHARDS": "HubCacheShard",
    }
    for binding, class_name in classes.items():
        config += f'\n[[durable_objects.bindings]]\nname = "{binding}"\nclass_name = "{class_name}"\n'
    legacy_classes = [name for name in classes.values() if name != "HubDb"]
    config += '\n[[migrations]]\ntag = "runtime-parity-v1"\nnew_sqlite_classes = ["HubDb"]\n'
    config += "new_classes = " + json.dumps(legacy_classes) + "\n"
    for namespace, binding, limit in ((4101, "RL_BURST5", 5), (4102, "RL_BURST10", 10), (4103, "RL_BROWSE120", 120)):
        config += f'\n[[ratelimits]]\nname = "{binding}"\nnamespace_id = "{namespace}"\n[ratelimits.simple]\nlimit = {limit}\nperiod = 60\n'
    return config
