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
import urllib.parse


def qualify_registry_runtime_parity(client, native, worker, *, tools, fixture, snapshot_assert,
                                   corpus_fixture=None, process_observer=None, process_stop=None):
    """Require identical signed package and channel indexes in all three modes."""
    if corpus_fixture is not None:
        if (set(corpus_fixture) != {"surfaceRoot", "registrySlug", "trustKey", "sourceCommit"}
                or not re.fullmatch(r"[a-z][a-z0-9-]*/[a-z][a-z0-9-]*", corpus_fixture["registrySlug"])
                or not re.fullmatch(r"[0-9a-f]{64}", corpus_fixture["sourceCommit"])
                or not corpus_fixture["surfaceRoot"].startswith("/var/lib/hybrid-client/")):
            raise ValueError("selected signed parity corpus identity differs")
    port = 8443 if corpus_fixture is None else 8453
    native_origin = f"https://aos.staging.andyl.org:{port}"
    worker_origin = f"https://aos.andyl.org:{port}"
    registry_slug = "fleet/containers" if corpus_fixture is None else corpus_fixture["registrySlug"]
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
    corpus_root = "/tmp/hybrid-publication-surface" if corpus_fixture is None else corpus_fixture["surfaceRoot"]
    client.succeed(
        f"{tools['tar']} -C {shlex.quote(corpus_root)} --exclude=./web "
        f"-cf {corpus_path} .",
        timeout=60,
    )
    corpus_size = int(client.succeed(f"{coreutils}/stat -c '%s' {corpus_path}").strip())
    corpus_digest = client.succeed(f"{coreutils}/sha256sum {corpus_path}").split()[0]
    assert corpus_size > 0, "empty signed parity corpus"
    trust_key = fixture["trust_key"] if corpus_fixture is None else corpus_fixture["trustKey"]

    process_receipts = {}

    # Native signing readers require owner-private files, including fixture seeds.
    native.succeed(textwrap.dedent(f"""
        set -eu
        umask 077
        mkdir -p {native_root}
        printf '[]' > {native_root}/probe-signers.json
        {coreutils}/install -m 0600 {fixture['route_keys']} {native_root}/route-keys.json
        {coreutils}/install -m 0600 {fixture['release_seed']} {native_root}/release-receipt.key
        {coreutils}/install -m 0600 {fixture['channel_seed']} {native_root}/channel-receipt.key
        {hub} --root {native_root} init \\
          --root-email {email} --root-password {password}
        HUB_DNS_JSON_ENDPOINT=https://dns.google/resolve \\
        {hub} --root {native_root} serve --listen 0.0.0.0:{port} \\
          --external-url {native_origin} --reindex-interval 0 \\
          --tls-certificate-file {fixture['certificate']} \\
          --tls-private-key-file {fixture['private_key']} \\
          --domain-probe-signer-manifest-file {native_root}/probe-signers.json \\
          --route-reservation-keys-file {native_root}/route-keys.json \\
          --cloudflare-api-token parity-fixture-token \\
          --deployment-id fleet-native-parity-v1 \\
          --release-receipt-key-id staging-publication-v1 \\
          --release-receipt-key-file {native_root}/release-receipt.key \\
          --channel-receipt-key-id staging-channel-v1 \\
          --channel-receipt-key-file {native_root}/channel-receipt.key \\
          --release-publication-keys-file {fixture['publication_keys']} \\
          --qualification-keys-file {fixture['qualification_keys']} \\
          > {native_root}/server.log 2>&1 < /dev/null &
        echo $! > {native_root}/server.pid
    """), timeout=180)

    if process_observer is not None:
        process_receipts["native_only"] = process_observer(native, native_root, "server.pid", hub)

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
    worker_config = worker_only_configuration(
        tools["worker_main"], worker_origin, worker_root, fixture, secrets, port=port,
    )
    worker.succeed(textwrap.dedent(f"""
        set -eu
        umask 077
        mkdir -p {worker_root}
        printf '%s' {shlex.quote(json.dumps(worker_config))} > {worker_root}/runner.json
        SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \\
        {tools['node']} {tools['worker_runner']} {tools['miniflare']} \\
          {worker_root}/runner.json \\
          > {worker_root}/worker.log 2>&1 < /dev/null &
        echo $! > {worker_root}/worker.pid
    """), timeout=30)
    if process_observer is not None:
        process_receipts["worker_only"] = process_observer(worker, worker_root, "worker.pid", tools["node"])
    try:
        worker.wait_until_succeeds(f"{curl} -fsS {worker_origin}/healthz > /dev/null", timeout=180)
    except Exception:
        print("Worker-only parity startup log:", worker.succeed(
            f"tail -n 100 {worker_root}/worker.log 2>/dev/null || true"
        ))
        raise
    worker.succeed(
        f"{hub} worker bootstrap-root --url {worker_origin} --email {email} "
        f"--password {password} --seal-key {seal_key}",
        timeout=120,
    )
    try:
        native.wait_until_succeeds(f"{curl} -fsS {native_origin}/healthz > /dev/null", timeout=180)
    except Exception:
        print("Native-only parity startup log:", native.succeed(
            f"tail -n 100 {native_root}/server.log 2>/dev/null || true"
        ))
        raise

    for mode, machine, origin in (
        ("native_only", native, native_origin),
        ("worker_only", worker, worker_origin),
    ):
        copy_signed_surface(client, machine, corpus_path, corpus_size, corpus_digest, source_root, tools)
        token = browser_session_token(machine, origin, email, password, curl)
        setup_and_publish_same_registry(
            machine, origin, token, trust_key, source_root, tools, fixture,
            refresh_token=lambda: browser_session_token(machine, origin, email, password, curl),
            provision_worker_binding=mode == "worker_only",
            registry_slug=registry_slug, include_container=corpus_fixture is None,
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
            f"{tools['postgres']}/psql -h {tools.get('postgres_host', '127.0.0.1')} "
            "-U postgres -d postgres -At "
            f"-c {shlex.quote(wrapped)}",
            timeout=60,
        )
        return [list(row.values()) for row in json.loads(output)]

    compared = snapshot_assert({
        "hybrid": hybrid_query,
        "native_only": native_query,
        "worker_only": worker_query,
    }, registry_slug, container_index_digest=fixture.get("container_index_digest"))

    for machine, root in ((native, native_root), (worker, worker_root)):
        pid_file = "server.pid" if machine is native else "worker.pid"
        if process_stop is None:
            machine.succeed(f"kill $(cat {root}/{pid_file})")
        else:
            mode = "native_only" if machine is native else "worker_only"
            process_stop(machine, process_receipts[mode])
    return {"version": 1, "corpusSha256": corpus_digest, "corpusBytes": corpus_size,
        "registrySlug": registry_slug, "sourceCommit": None if corpus_fixture is None else corpus_fixture["sourceCommit"],
        "companionPort": port, "indexes": compared, "processes": process_receipts,
        "scope": "actual same signed semantic corpus in Native-only, ordinary Worker-only emulator and External hybrid; no managed direct-upload acceptance"}


def browser_session_token(machine, origin, email, password, curl):
    """Use the password login and console CSRF boundary to obtain an API token."""
    headers_path = "/tmp/hub-parity-login.headers"
    body_path = "/tmp/hub-parity-login.body"
    status = machine.succeed(
        f"{curl} -sS -D {headers_path} -o {body_path} -w '%{{http_code}}' "
        "-X POST -H 'cf-connecting-ip: 192.0.2.10' "
        f"--data-urlencode {shlex.quote('email=' + email)} "
        f"--data-urlencode {shlex.quote('password=' + password)} {origin}/login/password",
        timeout=120,
    ).strip()
    if status != "303":
        body = machine.succeed(f"head -c 4096 {body_path}")
        print("Parity login failure body:", body)
        print("Worker-only parity runner diagnostics:", machine.succeed(
            "tail -n 100 /var/lib/hub-parity-worker/worker.log 2>/dev/null || true"
        ))
        raise AssertionError(f"parity password login returned HTTP {status}")

    headers = machine.succeed(f"cat {headers_path}")
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


def setup_and_publish_same_registry(
    machine, origin, token, trust_key, source_root, tools, fixture, *, refresh_token,
    provision_worker_binding=False,
    registry_slug="fleet/containers", include_container=True,
):
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

    # Native provisions its filesystem binding at startup. A fresh Worker uses
    # the reviewed topology API to attach its deployment-owned R2 bucket.
    if provision_worker_binding:
        reviewed(
            "parity-worker-storage",
            "binding create --name default --stable-id instance-default "
            "--kind deployment-r2 --bucket-binding REGISTRY_BUCKET",
        )

    org_slug, registry_name = registry_slug.split("/")
    reviewed("parity-org", "org create --slug " + shlex.quote(org_slug) + " --display-name 'Hybrid fleet'")
    org = json.loads(machine.succeed(command("org show " + shlex.quote(org_slug))))["data"]["organization"]
    reviewed("parity-binding", "binding grant instance:default --consumer-scope " + shlex.quote(org["stable_id"]))
    reviewed("parity-network", "network-policy grant instance:public --consumer-scope " + shlex.quote(org["stable_id"]))
    visibility = "public" if include_container else "private"
    reviewed("parity-registry", "registry create --org " + shlex.quote(org_slug)
        + " --name " + shlex.quote(registry_name) + " --visibility " + visibility + " --trust-key " + shlex.quote(trust_key))
    reviewed(
        "parity-placement",
        "placement add " + shlex.quote("registry:" + registry_slug) + " primary --binding instance-default "
        "--prefix " + shlex.quote("registries/" + registry_slug.replace("/", "-"))
        + " --kind complete --desired-state active --read enabled",
    )
    placement = json.loads(machine.succeed(command("placement show " + shlex.quote("registry:" + registry_slug) + " primary")))["data"]["placement"]
    reviewed(
        "parity-scan", "placement scan " + shlex.quote("registry:" + registry_slug) + " primary --wait --timeout 2m "
        "--if-version " + shlex.quote(placement["resource_version"]),
    )
    placement = json.loads(machine.succeed(command("placement show " + shlex.quote("registry:" + registry_slug) + " primary")))["data"]["placement"]
    reviewed("parity-promote", "placement promote " + shlex.quote("registry:" + registry_slug) + " primary --if-version " + shlex.quote(placement["resource_version"]))

    token = refresh_token()
    if include_container:
        configure_oci_parity_route(
            machine, origin, command, reviewed, org, tools, fixture,
            worker_ingress=provision_worker_binding,
        )
        stage_same_container_graph(machine, origin, tools, fixture, refresh_token=refresh_token)
    token = refresh_token()
    try:
        publication, token = publish_signed_surface(
            machine,
            lambda authorization: (
                f"{tools['aos']} --json hub registry publish upload {shlex.quote(registry_slug)} "
                f"--root {shlex.quote(source_root)} --hub {origin} "
                f"--token {shlex.quote(authorization)}"
            ),
            token,
            refresh_token,
        )
    except Exception:
        print("Worker-only parity publication diagnostics:", machine.succeed(
            "tail -n 100 /var/lib/hub-parity-worker/worker.log 2>/dev/null || true"
        ))
        raise
    assert publication["state"] == "ready", publication
    token = refresh_token()
    machine.wait_until_succeeds(
        command("registry show " + shlex.quote(registry_slug)) + f" | {tools['jq']} -e '.data.registry.index_state == \"fresh\"' > /dev/null",
        timeout=240,
    )


def configure_oci_parity_route(
    machine, origin, command, reviewed, org, tools, fixture, *, worker_ingress,
):
    """Configure and observe a public route using the ordinary reviewed APIs."""
    def reviewed_control(label, plan_command, apply_command):
        plan = json.loads(machine.succeed(command(
            plan_command, "--idempotency-key " + shlex.quote(label + "-plan"),
        ), timeout=180))["data"]["plan"]
        assert plan["effects"], plan
        return json.loads(machine.succeed(command(
            apply_command,
            f"--plan-id {shlex.quote(plan['plan_id'])} "
            f"--confirm-hash {shlex.quote(plan['confirmation_hash'])} "
            f"--yes --idempotency-key {shlex.quote(label + '-apply')}",
        ), timeout=180))

    hostname = urllib.parse.urlsplit(origin).hostname
    assert hostname, origin
    reviewed("parity-oci-domain", "domain add " + shlex.quote(hostname) + " --org fleet")
    reviewed_control(
        "parity-oci-controller", "org service-account create plan fleet parity-controller",
        "org service-account create apply",
    )
    reviewed_control(
        "parity-oci-controller-membership",
        "org member set-role plan --principal-kind service_account "
        "--principal fleet/parity-controller --scope " + shlex.quote(org["stable_id"]) +
        " --role owner --if-version absent",
        "org member set-role apply",
    )
    issued = reviewed_control(
        "parity-oci-controller-token",
        "access-token issue plan " + shlex.quote(org["stable_id"]) +
        " --owner service_account:fleet/parity-controller "
        "--permission endpoint.read --permission endpoint.manage "
        "--ttl-secs 3600 --comment 'Runtime parity endpoint controller'",
        "access-token issue apply",
    )
    controller_secret = issued["data"]["result"]["secret"]
    controller_token = json.loads(machine.succeed(
        f"{tools['curl']} -fsS -X POST -H 'Content-Type: application/x-www-form-urlencoded' "
        f"-H 'Authorization: Bearer {controller_secret}' "
        "--data-urlencode 'grant_type=urn:aos:params:oauth:grant-type:provisioning-token' "
        f"{origin}/oauth2/token",
        timeout=60,
    ))["access_token"]

    # Both ordinary runtimes supply hub ingress evidence. The Hybrid front's
    # signed layer7 evidence belongs to its separately configured routes.
    ingress = "hub"
    listener_provider = "hub-worker" if worker_ingress else "hub-native"
    listener_resource = "parity-runner" if worker_ingress else "aos-hub.service"
    reviewed(
        "parity-oci-endpoint", "endpoint add " + shlex.quote(origin) +
        " --stable-id parity-oci --org fleet --network-policy instance:public@1 "
        f"--ingress {ingress} --listener-provider {listener_provider} "
        f"--listener-resource-id {listener_resource} "
        "--tls-provider external --certificate-ref parity-fleet "
        "--probe-provider native-file --probe-signer-secret-ref fleet-probe-v1 "
        "--probe-public-key " + shlex.quote(fixture["probe_public_key"]),
    )
    endpoint = json.loads(machine.succeed(command("endpoint show parity-oci")))["data"]["endpoint"]
    generation = int(endpoint["desired_generation"])
    observation = {
        "stableId": "parity-oci",
        "expectedObservationVersion": endpoint["resource_version"],
        "controllerLeaseId": "parity-fleet-controller",
        "controllerGeneration": 1,
        "observation": {
            "observedGeneration": generation,
            "boundaryRevision": endpoint["desired"]["boundary_revision"],
            "state": "healthy", "listenerObserved": True, "tlsObserved": True,
        },
    }
    machine.succeed(
        f"{tools['curl']} -fsS -X POST -H 'Content-Type: application/json' "
        "-H 'Connect-Protocol-Version: 1' "
        f"-H 'Authorization: Bearer {controller_token}' "
        f"--data {shlex.quote(json.dumps(observation))} "
        f"{origin}/aos.hub.v1.DeliveryControllerService/ReportEndpoint",
        timeout=60,
    )
    reviewed(
        "parity-oci-route", f"route add registry:fleet/containers --stable-id parity-oci-route "
        f"--endpoint parity-oci@{generation} --base-path / --mode hub-proxy "
        "--placement primary --serves oci --access public",
    )
    route = next(row for row in json.loads(machine.succeed(command(
        "route list registry:fleet/containers",
    )))["data"]["routes"] if row["stable_id"] == "parity-oci-route")
    reviewed("parity-oci-route-enable", "route enable parity-oci-route --if-version " + shlex.quote(route["resource_version"]))
    machine.wait_until_succeeds(f"{tools['curl']} -fsS {origin}/v2/", timeout=180)


def stage_same_container_graph(machine, origin, tools, fixture, *, refresh_token):
    """Finalize and stage the exact externally signed graph on another runtime."""
    container_root = fixture["container_root"]
    authority = urllib.parse.urlsplit(origin).netloc
    # Reassemble the same public signed bundle from the shared Nix inputs and
    # exact external signature; no private signing key enters these machines.
    signature_path = "/tmp/parity-container-signature.sig"
    machine.succeed(
        f"printf '%s' {shlex.quote(fixture['container_signature'])} > {signature_path}",
        timeout=60,
    )
    finalized = json.loads(machine.succeed(
        f"{tools['aos']} --json --progress off --color never container finalize-signature "
        f"{shlex.quote(fixture['container_inputs'])} --signer {shlex.quote(fixture['trust_key'])} "
        f"--signature {signature_path} --output {shlex.quote(container_root)}",
        timeout=900,
    ))
    assert finalized["verification"] == "verified-external-sshsig", finalized
    assert finalized["index_digest"] == fixture["container_index_digest"], finalized
    upload_cache = container_root + "/upload-cache"
    machine.succeed(f"{tools['coreutils']}/install -d -m 0700 {shlex.quote(upload_cache)}")
    token = refresh_token()
    staged = json.loads(machine.succeed(
        f"XDG_CACHE_HOME={shlex.quote(upload_cache)} "
        f"{tools['aos']} --json --progress off --color never container publish aos "
        f"{shlex.quote(authority + '/aos:parity')} "
        f"--release {shlex.quote(finalized['release'])} "
        f"--release-layout {shlex.quote(finalized['layout'])} "
        f"--signature-input {shlex.quote(finalized['signature_input'])} "
        f"--registry fleet/containers --registry-origin {shlex.quote(origin)} "
        f"--registry-token {shlex.quote(token)} --idempotency-key runtime-parity-container-stage --stage-only",
        timeout=900,
    ))
    assert staged["state"] == "staged" and not staged["tag_updated"], staged
    assert staged["index_digest"] == fixture["container_index_digest"], staged


def worker_only_configuration(main, origin, root, fixture, secrets, *, port=8443):
    """Configure persistent production bindings for the direct Worker runner."""
    classes = {
        "COORDINATOR": "CoordinatorObject", "HUB_DB": "HubDb",
        "HUB_CONTROL_SHARDS": "HubControlShard", "HUB_TENANT_SHARDS": "HubTenantShard",
        "HUB_REGISTRY_SHARDS": "HubRegistryShard", "HUB_CACHE_SHARDS": "HubCacheShard",
    }
    return {
        "name": "hub-runtime-parity-worker",
        "scriptPath": main,
        "compatibilityDate": "2024-09-23",
        "host": "0.0.0.0",
        "port": port,
        "certificatePath": fixture["certificate"],
        "privateKeyPath": fixture["private_key"],
        "resourcePersistencePath": f"{root}/state",
        "r2Buckets": {"REGISTRY_BUCKET": "runtime-parity-r2"},
        "kvNamespaces": {"SESSIONS": "runtime-parity-sessions"},
        "queueProducers": {"JOBS": "runtime-parity-jobs"},
        "queueConsumers": {
            "runtime-parity-jobs": {"maxBatchSize": 1, "maxBatchTimeout": 1},
        },
        "durableObjects": {
            binding: {"className": name, "useSQLite": name == "HubDb"}
            for binding, name in classes.items()
        },
        "ratelimits": {
            binding: {"namespace_id": str(namespace), "simple": {"limit": limit, "period": 60}}
            for namespace, binding, limit in (
                (4101, "RL_BURST5", 5), (4102, "RL_BURST10", 10), (4103, "RL_BROWSE120", 120),
            )
        },
        "bindings": {
            **secrets,
            "HUB_TOPOLOGY": "worker_only",
            "HUB_REQUEST_SHARDING": "on",
            "HUB_EXTERNAL_URL": origin,
            "HUB_DEPLOYMENT_ID": "fleet-worker-parity-v1",
            "HUB_DATABASE_INSTANCE": "runtime-parity",
            "HUB_DNS_JSON_ENDPOINT": "https://dns.google/resolve",
        },
    }
