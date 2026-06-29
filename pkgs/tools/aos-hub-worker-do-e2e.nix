##! aos-hub-worker-do-e2e — run the deployed Worker under the from-source workerd
##! with a **real SQLite-backed `HubDb` Durable Object** and assert the
##! managed-registry bootstrap.
##!
##! The production system of record is the `HubDb` colocated-SQLite Durable Object
##! (RFC-0004 ch.14 Phase E), reached over
##! [`SqlDoBackend`](aos_hub_worker::sqldobackend). The miniflare-based
##! `aos-hub-worker-e2e` check cannot exercise that path: its pinned miniflare
##! predates programmatic SQLite-DO support, so it drives the (now-dead) D1
##! binding instead. This check closes that gap by driving **workerd directly**
##! with a capnp config that sets `enableSql = true` on the `HubDb` namespace, so
##! the worker's create + read logic runs against the genuine DO SQLite engine.
##!
##! It POSTs the `do-e2e`-gated `/_e2e/managed-registry-bootstrap` endpoint, which
##! runs entirely over `SqlDoBackend` (no router/rate-limit/R2/KV bindings — which
##! open-source workerd does not provide): create org `andyl`, create a
##! binding-less (default-storage) managed registry `andyl/main`, then read it
##! back via `list_registries` / `registry_by_slug` and the per-registry reads the
##! list/get RPCs issue. The transcript must end with `ALL OK`.
##!
##! This is the regression guard for the bound-`NULL` corruption: DO SQLite stored
##! a bound `null` parameter as the JavaScript string `"[object Object]"`, so a
##! binding-less registry's `storage_binding_id` read back as text and 500'd every
##! `ListRegistries`/`GetRegistry`. The fix
##! ([`aos_hub_worker::placeholder::numbered_to_positional`]) inlines a bound
##! `NULL` as a SQL literal.
##!
##! ## Why a launcher (not a pure check)
##!
##! Like `aos-hub-worker-e2e`, workerd's tcmalloc reads
##! `/sys/devices/system/cpu/possible`, unavailable in the Nix build sandbox, so
##! workerd is run **outside** the sandbox: the derivation bakes the launcher and
##! the aos test harness / CI `exec`s `$out/bin/aos-hub-worker-do-e2e`.
{
  mkDerivation,
  callPackage,
  nodejs,
  workerd,
  bash,
}: let
  # The worker built with the `do-e2e` probe endpoint compiled in (never in the
  # production/default build). Built via `callPackage` with an explicit
  # `cargoFeatures` rather than `.override`, which the repo's wrapped
  # `mkDerivation` does not thread into a discovered package's function args.
  dist = callPackage ./aos-hub-worker-dist.nix {cargoFeatures = "do-e2e";};

  # The workerd config: a module worker (shim.mjs + index.wasm) with the three DO
  # classes, `enableSql = true` on the SQLite-backed `HubDb`/`TenantDb`, and the
  # secrets/vars the DO reads before the e2e endpoint returns. Open-source workerd
  # has no R2/KV/rate-limit bindings, so the e2e endpoint deliberately runs before
  # the router (which needs them). The compat date matches the workerd build.
  workerCapnp = builtins.toFile "aos-hub-do-e2e.capnp" ''
    using Workerd = import "/workerd/workerd.capnp";

    const config :Workerd.Config = (
      services = [
        (name = "main", worker = .mainWorker),
        (name = "do-disk", disk = (path = "do-storage", writable = true)),
      ],
      sockets = [
        (name = "http", address = "127.0.0.1:8799", http = (), service = "main"),
      ],
    );

    const mainWorker :Workerd.Worker = (
      modules = [
        (name = "shim.mjs", esModule = embed "shim.mjs"),
        (name = "index.wasm", wasm = embed "index.wasm"),
      ],
      compatibilityDate = "2024-09-09",
      compatibilityFlags = ["nodejs_compat"],
      durableObjectNamespaces = [
        (className = "HubDb", uniqueKey = "hubdb-key", enableSql = true),
        (className = "CoordinatorObject", uniqueKey = "coord-key"),
        (className = "TenantDb", uniqueKey = "tenant-key", enableSql = true),
      ],
      durableObjectStorage = (localDisk = "do-disk"),
      bindings = [
        (name = "HUB_DB", durableObjectNamespace = "HubDb"),
        (name = "COORDINATOR", durableObjectNamespace = "CoordinatorObject"),
        (name = "TENANT_DB", durableObjectNamespace = "TenantDb"),
        (name = "HUB_JWT_SECRET", text = "e2e-jwt-secret"),
        (name = "HUB_SEAL_KEY", text = "0000000000000000000000000000000000000000000000000000000000000000"),
        (name = "HUB_EXTERNAL_URL", text = "http://localhost"),
      ],
    );
  '';

  # The driver: wait for workerd, POST the probe, assert `ALL OK`.
  driver = builtins.toFile "aos-hub-do-e2e.mjs" ''
    const BASE = "http://127.0.0.1:8799";
    async function probe() {
      const r = await fetch(BASE + "/_e2e/managed-registry-bootstrap", { method: "POST", body: "" });
      return { status: r.status, body: await r.text() };
    }
    let last = null;
    for (let i = 0; i < 80; i++) {
      try { last = await probe(); break; } catch { await new Promise((r) => setTimeout(r, 250)); }
    }
    if (!last) { console.error("workerd never accepted a connection"); process.exit(1); }
    console.log(last.body.trimEnd());
    const ok = last.status === 200 && last.body.includes("ALL OK");
    console.log(ok ? "aos-hub-worker do-e2e: PASS" : "aos-hub-worker do-e2e: FAIL");
    process.exit(ok ? 0 : 1);
  '';
in
  mkDerivation {
    pname = "aos-hub-worker-do-e2e";
    version = "0.1.0";

    runtimeDeps = [dist nodejs workerd bash];
    nukeRefsKeep = [workerCapnp driver];

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          cat > "$out/bin/aos-hub-worker-do-e2e" <<EOF
          #!${bash}/bin/bash
          # Run the deployed Worker under the from-source workerd with a real
          # SQLite-backed HubDb DO and assert the managed-registry bootstrap. Must
          # run OUTSIDE the Nix sandbox: workerd's tcmalloc needs
          # /sys/devices/system/cpu, unavailable there.
          set -euo pipefail
          work="\$(mktemp -d)"
          trap 'kill \$WPID 2>/dev/null || true; rm -rf "\$work"' EXIT
          cp ${dist}/shim.mjs ${dist}/index.wasm "\$work/"
          cp ${workerCapnp} "\$work/worker.capnp"
          cp ${driver} "\$work/driver.mjs"
          cd "\$work"
          mkdir -p "\$work/do-storage"
          ${workerd}/bin/workerd serve worker.capnp > "\$work/workerd.log" 2>&1 &
          WPID=\$!
          if ! ${nodejs}/bin/node driver.mjs; then
            echo "=== workerd.log ==="
            cat "\$work/workerd.log" || true
            exit 1
          fi
          EOF
          chmod +x "$out/bin/aos-hub-worker-do-e2e"
        '';
      }
    ];

    meta = {
      description = "Launcher: run the deployed aos-hub-worker under workerd with a real SQLite HubDb DO and assert the managed-registry bootstrap";
      homepage = "https://github.com/andyl/andyl-os";
      license = "MIT";
    };
  }
