"""Exercises reviewed settings against an actual native Hub process over TCP.

Run with the AOS Python package, passing freshly built native Hub and aos
binaries. The test owns a fresh state directory and retains its log on failure.
It never writes database rows or fabricates controller observations. An
unconfigured external CDN must remain blocked and unadvertised after restart.
"""

import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        return None


class NativeHub:
    def __init__(self, binary, client):
        self.binary = str(Path(binary).resolve())
        self.client = str(Path(client).resolve())
        self.root = Path(tempfile.mkdtemp(prefix="aos-hub-settings-"))
        self.root.chmod(0o700)
        self.process = None
        self.log = None
        self.token = None
        self.checks = []
        self.cookie = None
        self.http = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirects(),
        )
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            self.port = listener.getsockname()[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self.environment = os.environ.copy()
        for key in list(self.environment):
            if key.startswith("HUB_"):
                del self.environment[key]
        for variable, filename, value in [
            ("HUB_JWT_SECRET_FILE", "jwt", "local-settings-fixture-jwt-key-32bytes"),
            ("HUB_DOMAIN_PROBE_SIGNER_MANIFEST_FILE", "signers.json", "[]"),
            (
                "HUB_ROUTE_RESERVATION_KEYS_FILE",
                "routes.json",
                json.dumps({"activeVersion": 1, "keys": [{
                    "version": 1,
                    "keyBase64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                }]}),
            ),
        ]:
            path = self.root / filename
            path.write_text(value)
            path.chmod(0o600)
            self.environment[variable] = str(path)
        self.environment["HUB_DNS_JSON_ENDPOINT"] = "https://8.8.8.8/resolve"
        config = self.root / "client-config"
        config.mkdir(mode=0o700)
        self.environment["AOS_CONFIG_HOME"] = str(config)
        profile = config / "hub-profiles.json"
        profile.write_text(json.dumps({
            "schema_version": "aos.hub.profiles/v1", "active_origin": "http://127.0.0.1:9",
            "profiles": {"http://127.0.0.1:9": {
                "access_token": "expired-fixture", "access_expires_at": 0,
                "refresh_token": "expired-fixture", "refresh_expires_at": 0,
            }},
        }))
        profile.chmod(0o600)

    def check(self, condition, description):
        if not condition:
            raise AssertionError(description)
        self.checks.append(description)
        print(f"PASS {description}", flush=True)

    def initialize(self):
        result = subprocess.run(
            [self.binary, "--root", str(self.root / "state"), "init",
             "--root-email", "operator@example.test", "--root-password-stdin"],
            input="local-settings-password\n", text=True, capture_output=True,
            env=self.environment, timeout=60,
        )
        if result.returncode:
            raise RuntimeError(f"native init failed: {result.stderr}")

    def start(self):
        self.log = (self.root / "serve.log").open("ab")
        self.process = subprocess.Popen(
            [self.binary, "--root", str(self.root / "state"), "serve",
             "--listen", f"127.0.0.1:{self.port}", "--external-url", self.url,
             "--reindex-interval", "0"],
            stdout=self.log, stderr=subprocess.STDOUT, env=self.environment,
        )
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(f"native Hub exited; inspect {self.root / 'serve.log'}")
            try:
                if self.request("/healthz")[0] == 200:
                    return
            except (urllib.error.URLError, TimeoutError, ConnectionError):
                pass
            time.sleep(0.1)
        raise TimeoutError("native Hub did not become healthy")

    def stop(self):
        if self.process is not None:
            self.process.terminate()
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
            self.process = None
        if self.log:
            self.log.close()
            self.log = None

    def request(self, path, data=None, headers=None):
        headers = dict(headers or {})
        if self.cookie:
            headers["Cookie"] = self.cookie
        request = urllib.request.Request(self.url + path, data=data, headers=headers)
        try:
            response = self.http.open(request, timeout=30)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, response.read(), response.headers

    def login(self):
        status, _, headers = self.request("/login/password", urllib.parse.urlencode({
            "email": "operator@example.test", "password": "local-settings-password",
        }).encode(), {"Content-Type": "application/x-www-form-urlencoded"})
        # Like the VM curl harness, send the secure cookie explicitly on this
        # loopback-only HTTP fixture. Production browser sessions use HTTPS.
        self.check(status == 303 and headers.get("Set-Cookie"), "native password login creates a session")
        self.cookie = headers["Set-Cookie"].split(";", 1)[0]
        status, body, _ = self.request("/-/instance")
        csrf = re.search(rb'name="aos-session-csrf" content="([^"]+)"', body)
        self.check(status == 200 and csrf is not None, "native password login and authenticated shell")
        status, body, _ = self.request("/-/auth/session-token", b"", {
            "Origin": self.url, "x-aos-csrf": csrf[1].decode(),
            "x-aos-console-route": "/-/instance",
        })
        self.check(status == 200, "browser session exchanges for scoped API bearer")
        self.token = json.loads(body)["accessToken"]

    def rpc(self, service, method, payload, expected=200):
        status, body, _ = self.request(f"/aos.hub.v1.{service}/{method}",
            json.dumps(payload).encode(), {
                "Content-Type": "application/json", "connect-protocol-version": "1",
                "Authorization": f"Bearer {self.token}",
            })
        parsed = json.loads(body)
        if status != expected:
            raise AssertionError(f"{service}/{method}: expected {expected}, got {status}: {parsed}")
        return parsed

    def reviewed(self, service, method, payload, key):
        plan = self.rpc(service, "Plan" + method, dict(payload, idempotencyKey=key + "-plan"))["plan"]
        return self.rpc(service, method, {
            "planId": plan["planId"], "confirmationHash": plan["confirmationHash"],
            "idempotencyKey": key + "-apply",
        })

    def cli(self, command, *arguments, succeeds=True, explicit_hub=True):
        origin_args = ["--hub", self.url] if explicit_hub else []
        result = subprocess.run(
            [self.client, "--json", "hub", *command.split(), *arguments,
             *origin_args, "--token", self.token],
            capture_output=True, text=True, timeout=60, env=self.environment,
        )
        if succeeds != (result.returncode == 0):
            raise AssertionError(f"{command}: {result.stdout} {result.stderr}")
        return json.loads(result.stdout)["data"] if succeeds else result.stdout + result.stderr


def exercise(hub, require_assets, serve_only=False):
    hub.initialize()
    hub.start()
    hub.login()
    if require_assets:
        _, shell, _ = hub.request("/-/instance")
        assets = re.findall(rb'(?:src|href)="([^"]*hub-console[^\"]*)"', shell)
        hub.check(bool(assets), "authenticated shell references console assets")
        for asset in assets:
            status, content, _ = hub.request(asset.decode())
            hub.check(status == 200 and b"asset is unavailable" not in content,
                      f"built console asset is served: {asset.decode().split('?')[0]}")
            if b"bootstrap" in asset:
                assets.extend(b"/_assets/" + name for name in
                              re.findall(rb"'\./(hub-console[^']+)'", content))
            elif asset.endswith(b".wasm"):
                hub.check(content[:4] == b"\0asm" and len(content) > 8,
                          "native server embeds the compiled console WebAssembly")
            elif asset.endswith(b".js"):
                hub.check(b"export function mount" in content,
                          "native server embeds the matching wasm-bindgen JavaScript")

    org = hub.reviewed("OrganizationService", "CreateOrganization", {
        "slug": "workflow-test", "displayName": "Workflow test",
    }, "organization")["organization"]
    scope = org["stableId"]
    hub.reviewed("RegistryService", "CreateRegistry", {
        "orgSlug": "workflow-test", "name": "main", "visibility": "private",
    }, "registry")
    hub.reviewed("BinaryCacheService", "CreateBinaryCache", {"desired": {
        "slug": "workflow-test/builds", "name": "builds", "ownerScopeKey": scope,
        "visibility": "private", "nixPriority": 40, "compression": "zstd",
        "wantMassQuery": False,
    }}, "cache")
    surface = {"registrySlug": "workflow-test/main"}
    hub.reviewed("BindingService", "GrantBindingScope", {
        "resourceKind": "binding", "resourceStableId": "instance-default",
        "consumerScopeKey": scope,
    }, "storage-grant")
    hub.reviewed("NetworkPolicyService", "GrantNetworkPolicyScope", {
        "resourceKind": "network_policy", "resourceStableId": "instance:public",
        "consumerScopeKey": scope,
    }, "network-grant")
    hub.reviewed("TopologyService", "CreatePlacement", {
        "surface": surface, "name": "primary", "bindingId": "instance-default",
        "prefix": "workflow-test/main", "kind": "complete", "desiredState": "active",
        "desiredReadEnabled": True, "readOrder": "0",
    }, "placement")
    hub.check(True, "organization, registry, shared storage grant and placement created through reviewed APIs")

    for path in ["/-/instance", "/-/org/workflow-test", "/workflow-test/main/-/settings",
                 "/workflow-test/main/-/settings/delivery", "/workflow-test/main/-/settings/placements",
                 "/-/org/workflow-test/caches/builds"]:
        status, body, _ = hub.request(path)
        hub.check(status == 200 and b'aos-session-csrf' in body, f"authenticated settings shell: {path}")

    if serve_only:
        return

    intent = {
        "surface": surface, "ownerScopeKey": scope, "placementName": "primary",
        "clientBasePath": "/cdn", "accessPolicy": {"public": True},
        "capabilities": {"servesCache": True}, "audiences": ["nix_cache"],
        "newEndpoint": {
            "hostname": "cdn.workflow.example.test", "networkPolicyId": "instance:public",
            "revision": {
                "boundaryRevision": "1", "ingressKind": "ENDPOINT_INGRESS_KIND_EXTERNAL",
                "listenerConfigurationRef": "listener:local-workflow-fixture",
                "tls": {"provider": "external", "certificateRef": "secret:fixture"},
                "probeConfigurationRef": json.dumps({"provider": "native_file",
                    "signerSecretRef": "fixture-probe-key",
                    "publicKey": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}, separators=(",", ":")),
            },
        },
    }
    intent_file = hub.root / "intent.json"
    intent_file.write_text(json.dumps(intent))
    plan = hub.cli("delivery plan", "--intent-file", str(intent_file), "--idempotency-key", "setup-plan")["plan"]
    hub.check(True, "explicit local credentials bypass an unrelated expired Hub profile")
    rejected = hub.cli("delivery apply", "--plan-id", plan["plan_id"], "--confirm-hash", "wrong-hash",
                       "--idempotency-key", "unreviewed-apply", "--yes", succeeds=False)
    hub.check("confirmation" in rejected.lower(), "setup rejects an incorrect review confirmation")
    apply = ("delivery apply", "--plan-id", plan["plan_id"], "--confirm-hash", plan["confirmation_hash"],
             "--idempotency-key", "setup-apply", "--yes")
    workflow = hub.cli(*apply)["workflow"]
    workflow_id = workflow["workflow_id"]
    hub.check(workflow["state"] == "blocked" and bool(workflow["blockers"]),
              "real unconfigured CDN setup stays blocked with explicit prerequisites")
    replay = hub.cli(*apply)["workflow"]
    hub.check(replay["workflow_id"] == workflow_id, "retrying apply preserves workflow identity")
    hub.check(len(hub.cli("delivery list", "--surface", "registry:workflow-test/main")["workflows"]) == 1,
              "apply replay creates no duplicate workflow")
    profile = Path(hub.environment["AOS_CONFIG_HOME"]) / "hub-profiles.json"
    store = json.loads(profile.read_text())
    expired = store["profiles"].pop(store["active_origin"])
    store["profiles"][hub.url] = expired
    store["active_origin"] = hub.url
    profile.write_text(json.dumps(store))
    hub.check(hub.cli("delivery show", workflow_id, explicit_hub=False)["workflow"]["workflow_id"] == workflow_id,
              "explicit token uses the stored origin without refreshing expired credentials")
    topology = hub.rpc("TopologyService", "GetSurfaceTopology", {"surface": surface})
    before = topology.get("routeAdvertisements", [])
    hub.check(not topology.get("routes"), "blocked gateway preparation creates no route")

    hub.stop()
    hub.start()
    recovered = hub.cli("delivery show", workflow_id)["workflow"]
    identities = ("workflow_id", "domain_id", "endpoint_id", "endpoint_generation", "gateway_id", "route_id")
    hub.check(all(recovered.get(key) == replay.get(key) for key in identities)
              and recovered["intent"] == replay["intent"],
              "real server restart preserves workflow steps and reviewed intent")
    resume = ("delivery resume", workflow_id, "--if-version", recovered["resource_version"],
              "--idempotency-key", "resume-after-restart")
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: hub.cli(*resume)["workflow"], range(2)))
    hub.check(all(item["workflow_id"] == workflow_id for item in results),
              "concurrent resume over TCP preserves one durable workflow")
    current = hub.cli("delivery show", workflow_id)["workflow"]
    failure = hub.cli("delivery activate plan", workflow_id, "--if-version", current["resource_version"],
                      "--idempotency-key", "premature-activation", succeeds=False)
    hub.check(bool(failure), "activation review rejects unverified external infrastructure")
    rejected_activation = hub.cli("delivery activate apply", "--plan-id", plan["plan_id"],
                                  "--confirm-hash", plan["confirmation_hash"],
                                  "--idempotency-key", "wrong-kind-activation", "--yes", succeeds=False)
    hub.check(bool(rejected_activation), "activation apply rejects a setup plan")
    after = hub.rpc("TopologyService", "GetSurfaceTopology", {"surface": surface})
    hub.check(after.get("routeAdvertisements", []) == before,
              "failed setup and activation leave advertised destinations unchanged")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hub-binary", required=True)
    parser.add_argument("--aos-binary", required=True)
    parser.add_argument("--require-assets", action="store_true")
    parser.add_argument("--keep-running", action="store_true",
                        help="Keep the isolated server alive for browser inspection after checks")
    parser.add_argument("--serve-only", action="store_true",
                        help="Prepare the browser fixture without running delivery CLI assertions")
    args = parser.parse_args()
    hub = NativeHub(args.hub_binary, args.aos_binary)
    print(f"Native Hub test artifacts: {hub.root}", flush=True)
    try:
        exercise(hub, args.require_assets, args.serve_only)
        if args.keep_running or args.serve_only:
            password = hub.root / "browser-password"
            password.write_text("local-settings-password")
            password.chmod(0o600)
            print(f"Browser fixture: {hub.url}, operator@example.test, password file {password}", flush=True)
            while True:
                time.sleep(1)
    finally:
        hub.stop()
        (hub.root / "checks.json").write_text(json.dumps(hub.checks, indent=2))
    print(f"PASS {len(hub.checks)} native process checks", flush=True)


if __name__ == "__main__":
    main()
