"""Checks ordinary Workers-only authentication and registry serving over HTTPS.

The fixture reuses the Native settings driver's HTTP/session/API client and the
fleet Miniflare runner. It initializes through the production seal-gated CLI,
never through a test-only Worker endpoint. All runtime state and logs are kept
in the printed private temporary directory; no hosted service is contacted.
"""

import argparse
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import secrets
import ssl
import subprocess
import time
import urllib.error
import urllib.request


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("native_settings", HERE / "hub-settings.py")
SETTINGS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SETTINGS)


def sha256_file(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def worker_configuration(dist, root, port, seal):
    """Constructs a local ordinary profile with the production execution shards."""
    classes = {
        "HUB_DB": "HubDb",
        "COORDINATOR": "CoordinatorObject",
        "HUB_CONTROL_SHARDS": "HubControlShard",
        "HUB_TENANT_SHARDS": "HubTenantShard",
        "HUB_REGISTRY_SHARDS": "HubRegistryShard",
        "HUB_CACHE_SHARDS": "HubCacheShard",
    }
    route_keys = {"activeVersion": 1, "keys": [{
        "version": 1,
        "keyBase64": base64.b64encode(secrets.token_bytes(32)).decode(),
    }]}

    return {
        "name": "worker-only-smoke",
        "scriptPath": str(dist / "shim.mjs"),
        "compatibilityDate": "2024-09-23",
        "compatibilityFlags": ["nodejs_compat"],
        "host": "127.0.0.1",
        "port": port,
        "certificatePath": str(root / "tls.crt"),
        "privateKeyPath": str(root / "tls.key"),
        "resourcePersistencePath": str(root / "worker-state"),
        "durableObjectsPersist": True,
        "kvPersist": True,
        "r2Persist": True,
        "durableObjects": {
            binding: {"className": name, "useSQLite": name == "HubDb"}
            for binding, name in classes.items()
        },
        "r2Buckets": {"REGISTRY_BUCKET": "worker-only-smoke-surfaces"},
        "kvNamespaces": {"SESSIONS": "worker-only-smoke-sessions"},
        "queueProducers": {"JOBS": "worker-only-smoke-jobs"},
        "queueConsumers": {"worker-only-smoke-jobs": {"maxBatchSize": 10}},
        "ratelimits": {
            name: {"namespace_id": str(1000 + index), "simple": {"limit": limit, "period": 60}}
            for index, (name, limit) in enumerate([
                ("RL_BURST5", 5), ("RL_BURST10", 10), ("RL_BROWSE120", 120),
            ])
        },
        "bindings": {
            "HUB_TOPOLOGY": "worker_only",
            "HUB_REQUEST_SHARDING": "on",
            "HUB_EXTERNAL_URL": f"https://localhost:{port}",
            "HUB_DEPLOYMENT_ID": "worker-only-smoke",
            "HUB_DATABASE_INSTANCE": "hub",
            "HUB_JWT_SECRET": secrets.token_hex(32),
            "HUB_SEAL_KEY": seal,
            "HUB_ROUTE_RESERVATION_KEYRING": json.dumps(route_keys),
            "HUB_DOMAIN_PROBE_SIGNER_MANIFEST": "[]",
            "HUB_DNS_JSON_ENDPOINT": "https://dns.example.test/resolve",
            # This fixture exercises no provider control-plane operation.
            "HUB_CLOUDFLARE_API_TOKEN": "local-unused-control-plane-fixture",
        },
    }


class WorkerHub(SETTINGS.NativeHub):
    """Uses the existing HTTP client against the ordinary Worker process."""

    def __init__(self, args):
        super().__init__(args.hub_binary, args.hub_binary)
        print(f"Worker smoke artifacts: {self.root}", flush=True)
        self.args = args
        self.url = f"https://localhost:{self.port}"
        self.seal = secrets.token_hex(32)
        self.configuration = self.root / "worker-options.json"
        self.runner = HERE.parent / "fleet" / "_hub-worker-runner.cjs"
        self.console = Path(args.console_dist).resolve(strict=True)
        self.dist = Path(args.worker_dist).resolve(strict=True)
        miniflare = Path(args.wrangler_root) / "lib/node_modules/wrangler/node_modules/miniflare"
        selected_inputs = {
            "hub": self.binary,
            "node": args.node_binary,
            "openssl": args.openssl_binary,
            "runner": self.runner,
            "settingsClient": HERE / "hub-settings.py",
            "workerShim": self.dist / "shim.mjs",
            "workerWasm": self.dist / "index.wasm",
            "miniflareManifest": miniflare / "package.json",
            **{name: self.console / name for name in [
                "hub-console.js", "hub-console_bg.wasm", "hub-console.css",
            ]},
        }
        self.inputs = {}
        for name, path in selected_inputs.items():
            path = Path(path).resolve(strict=True)
            if not path.is_file():
                raise ValueError(f"selected input is not a regular file: {name}")
            self.inputs[name] = {
                "path": str(path),
                "sha256": sha256_file(path),
                "bytes": path.stat().st_size,
            }

        self.create_tls()
        context = ssl.create_default_context(cafile=str(self.root / "ca.crt"))
        self.http = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), SETTINGS.NoRedirects(),
            urllib.request.HTTPSHandler(context=context),
        )
        config = worker_configuration(self.dist, self.root, self.port, self.seal)
        self.configuration.write_text(json.dumps(config))
        self.configuration.chmod(0o600)
        proxy_names = {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}
        self.environment = {
            key: value for key, value in self.environment.items()
            if not key.startswith("HUB_") and key.lower() not in proxy_names
        }
        self.environment["SSL_CERT_FILE"] = str(self.root / "ca.crt")

    def create_tls(self):
        openssl = str(Path(self.args.openssl_binary).resolve(strict=True))
        commands = [
            ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
             "-subj", "/CN=Worker smoke CA", "-addext", "basicConstraints=critical,CA:TRUE",
             "-keyout", "ca.key", "-out", "ca.crt"],
            ["req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
             "-keyout", "tls.key", "-out", "tls.csr"],
            ["x509", "-req", "-in", "tls.csr", "-CA", "ca.crt", "-CAkey", "ca.key",
             "-CAcreateserial", "-days", "2", "-extfile", "tls.extensions", "-out", "tls.crt"],
        ]
        (self.root / "tls.extensions").write_text(
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n"
        )
        with (self.root / "tls.log").open("wb") as log:
            for command in commands:
                subprocess.run([openssl, *command], cwd=self.root, stdout=log, stderr=log,
                               timeout=30, check=True)
        for name in ["ca.key", "tls.key"]:
            (self.root / name).chmod(0o600)

    def start(self):
        self.log = (self.root / "workerd.log").open("ab")
        self.process = subprocess.Popen([
            self.args.node_binary, str(self.runner), self.args.wrangler_root, str(self.configuration),
        ], stdout=self.log, stderr=subprocess.STDOUT, env=self.environment)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(f"Worker exited; inspect {self.root / 'workerd.log'}")
            try:
                status, body, _ = self.request("/.well-known/aos-deployment")
                if status == 200 and body == b"worker-only-smoke":
                    return
            except (urllib.error.URLError, TimeoutError, ConnectionError):
                pass
            time.sleep(0.1)
        raise TimeoutError("Worker did not expose the selected deployment identity")

    def initialize(self):
        env = dict(self.environment, HUB_SEAL_KEY=self.seal)
        with (self.root / "bootstrap.log").open("wb") as log:
            subprocess.run([
                self.binary, "worker", "bootstrap-root", "--url", self.url,
                "--email", "operator@example.test", "--password-stdin",
            ], input=b"local-settings-password\n", env=env, stdout=log, stderr=log,
                timeout=60, check=True)
        self.check(True, "production seal-gated CLI bootstrap succeeds over verified HTTPS")

    def anonymous_rpc(self, service, method, payload):
        cookie = self.cookie
        self.cookie = None
        try:
            return self.request(f"/aos.hub.v1.{service}/{method}", json.dumps(payload).encode(), {
                "Content-Type": "application/json", "connect-protocol-version": "1",
            })
        finally:
            self.cookie = cookie

    def request(self, path, data=None, headers=None):
        status, body, returned_headers = super().request(path, data, headers)
        self.last_response_headers = returned_headers
        return status, body, returned_headers

    def check_retained_session(self):
        status, shell, _ = self.request("/-/instance")
        csrf = re.search(rb'name="aos-session-csrf" content="([^"]+)"', shell)
        self.check(status == 200 and csrf is not None, "retained session reaches the shell after restart")
        status, body, _ = self.request("/-/auth/session-token", b"", {
            "Origin": self.url, "x-aos-csrf": csrf[1].decode(),
            "x-aos-console-route": "/-/instance",
        })
        session = json.loads(body)
        self.check(status == 200 and session.get("tokenType") == "Bearer"
                   and bool(session.get("accessToken")),
                   "persistent session exchanges for a fresh scoped bearer after restart")
        self.token = session["accessToken"]

    def check_assets(self):
        status, shell, _ = self.request("/-/instance")
        self.check(status == 200, "authenticated Worker shell is available")
        bootstrap = re.search(rb'src="(/_assets/hub-console-bootstrap-[a-f0-9]{8}\.js)"', shell)
        css = re.search(rb'href="(/_assets/hub-console-[a-f0-9]{8}\.css)"', shell)
        self.check(bootstrap is not None and css is not None, "Worker shell names versioned production assets")
        status, source, _ = self.request(bootstrap[1].decode())
        self.check(status == 200 and b"mount();" in source, "Worker console bootstrap is served")
        for pattern, local in [
            (rb"hub-console-[a-f0-9]{8}_bg\.wasm", "hub-console_bg.wasm"),
            (rb"hub-console-[a-f0-9]{8}\.js", "hub-console.js"),
        ]:
            selected = re.search(pattern, source)
            self.check(selected is not None, f"bootstrap selects {local}")
            status, content, _ = self.request("/_assets/" + selected[0].decode())
            self.check(status == 200 and content == (self.console / local).read_bytes(),
                       f"Worker serves exact selected production {local}")
        status, content, _ = self.request(css[1].decode())
        self.check(status == 200 and content == (self.console / "hub-console.css").read_bytes(),
                   "Worker serves exact selected production CSS")


def exercise(hub):
    hub.start()
    hub.initialize()
    status, _, _ = hub.anonymous_rpc("IdentityService", "WhoAmI", {})
    hub.check(status == 401, "anonymous identity API is refused")
    hub.login()
    identity = hub.rpc("IdentityService", "WhoAmI", {})
    hub.check(identity.get("email") == "operator@example.test"
              and identity.get("deploymentId") == "worker-only-smoke"
              and identity.get("transferMode") == "legacy"
              and "read" in identity.get("accessPermissions", []),
              "scoped browser bearer resolves the ordinary deployment and current operator")
    hub.check_assets()
    hub.reviewed("OrganizationService", "CreateOrganization", {
        "slug": "worker-smoke", "displayName": "Worker smoke",
    }, "worker-organization")
    created = hub.reviewed("RegistryService", "CreateRegistry", {
        "orgSlug": "worker-smoke", "name": "main", "visibility": "private",
    }, "worker-registry")["registry"]
    selected = hub.rpc("RegistryService", "GetRegistry", {"slug": "worker-smoke/main"})["registry"]
    hub.check(selected["stableId"] == created["stableId"] and selected["visibility"] == "private",
              "reviewed private registry is returned by the ordinary API")
    hub.check(hub.last_response_headers.get("x-aos-hub-shard") == "registry",
              "ordinary registry API executes in the production registry shard")
    status, _, _ = hub.anonymous_rpc("RegistryService", "GetRegistry", {"slug": "worker-smoke/main"})
    hub.check(status in (401, 403), "anonymous private registry read is refused")
    status, shell, _ = hub.request("/worker-smoke/main/-/settings")
    hub.check(status == 200 and b"aos-session-csrf" in shell, "private registry website is served")

    hub.stop()
    hub.start()
    hub.check_retained_session()
    retained = hub.rpc("RegistryService", "GetRegistry", {"slug": "worker-smoke/main"})["registry"]
    hub.check(retained["stableId"] == created["stableId"],
              "process restart preserves the private registry and retained browser session")
    hub.login()
    hub.check_assets()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["hub-binary", "worker-dist", "console-dist", "node-binary", "wrangler-root", "openssl-binary"]:
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    hub = WorkerHub(args)
    completed = False
    try:
        exercise(hub)
        completed = True
    finally:
        hub.stop()
        report = {"version": 1, "completed": completed, "scope": "local_ordinary_workers_only_smoke",
                  "inputs": hub.inputs, "configurationSha256": sha256_file(hub.configuration),
                  "checks": hub.checks}
        (hub.root / "checks.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"PASS {len(hub.checks)} ordinary Workers-only process checks", flush=True)


if __name__ == "__main__":
    main()
