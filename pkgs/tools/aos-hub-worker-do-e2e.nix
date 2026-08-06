##! aos-hub-worker-do-e2e — run the deployed Worker under the from-source workerd
##! with a **real SQLite-backed `HubDb` Durable Object** and assert the
##! managed-registry and multipart-write invariants.
##!
##! The production system of record is the `HubDb` colocated-SQLite Durable Object
##! (RFC-0004 ch.14 Phase E), reached over
##! [`SqlDoBackend`](aos_hub_worker::sqldobackend). This check drives
##! **workerd directly**
##! with a capnp config that sets `enableSql = true` on the `HubDb` namespace, so
##! the worker's create + read logic runs against the genuine DO SQLite engine.
##!
##! It POSTs the `do-e2e`-gated bootstrap endpoint to install disposable
##! topology/authentication state and prove checked-batch rollback. Every
##! multipart request after that traverses the outer Worker, HubDb, Worker-to-
##! axum bridge, shared router/service, SqlDoBackend, and a feature-gated
##! SQLite-backed object-store adapter injected at the production storage-
##! provider boundary. It runs cache and registry multipart admission through
##! both flat and nested resource identities: eight simultaneous distinct
##! parts, an exact same-part retry, and a mismatched same-part rejection for
##! each identity. Finally, the driver checks the
##! live Worker body boundary at 20 MiB and 20 MiB + 1, changes the operator cap
##! through the ordinary Connect API, and proves both single and multipart
##! writes honor that lower cap. The transcript must end with `PASS`.
##!
##! Open-source workerd cannot instantiate Cloudflare R2. Production R2 remains
##! covered by focused adapter tests; the e2e adapter proves provider dispatch,
##! persistence, routing, body limits, and multipart/database concurrency.
##!
##! ## Why a launcher (not a pure check)
##!
##! Workerd's tcmalloc reads
##! `/sys/devices/system/cpu/possible`, unavailable in the Nix build sandbox, so
##! workerd is run **outside** the sandbox: the derivation bakes the launcher and
##! the aos test harness / CI `exec`s `$out/bin/aos-hub-worker-do-e2e`.
{
  mkDerivation,
  callPackage,
  aos,
  aos-system-image-e2e-fixture,
  coreutils,
  grep,
  nodejs,
  nix,
  workerd-source,
  bash,
}: let
  # The worker built with the `do-e2e` probe endpoint compiled in (never in the
  # production/default build). Built via `callPackage` with an explicit
  # `cargoFeatures` rather than `.override`, which the repo's wrapped
  # `mkDerivation` does not thread into a discovered package's function args.
  dist = callPackage ./aos-hub-worker-dist.nix {cargoFeatures = "do-e2e";};

  # The workerd config: a module worker (shim.mjs + index.wasm) with the two DO
  # classes, `enableSql = true` on the SQLite-backed `HubDb`, and the
  # secrets/vars the DO reads. Open-source workerd has no R2/KV/rate-limit
  # bindings, so the non-default build injects durable SQLite surface storage
  # and in-memory coordination at the production port boundaries. The compat
  # date matches the workerd build.
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
      ],
      durableObjectStorage = (localDisk = "do-disk"),
      bindings = [
        (name = "HUB_DB", durableObjectNamespace = "HubDb"),
        (name = "COORDINATOR", durableObjectNamespace = "CoordinatorObject"),
        (name = "HUB_JWT_SECRET", text = "e2e-jwt-secret"),
        (name = "HUB_SEAL_KEY", text = "0000000000000000000000000000000000000000000000000000000000000000"),
        (name = "HUB_EXTERNAL_URL", text = "http://127.0.0.1:8799"),
      ],
    );
  '';

  # The driver: wait for workerd, bootstrap, and assert the live HTTP matrix.
  driver = builtins.toFile "aos-hub-do-e2e.mjs" ''
    import fs from "node:fs";
    import path from "node:path";
    const BASE = "http://127.0.0.1:8799";
    const fixtureRoot = process.env.AOS_HUB_E2E_IMAGE_FIXTURE;
    if (!fixtureRoot) throw new Error("AOS_HUB_E2E_IMAGE_FIXTURE is required");
    const objects = {};
    function collect(directory, relative = "") {
      for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
        const child = path.join(directory, entry.name);
        const objectPath = relative ? `''${relative}/''${entry.name}` : entry.name;
        if (entry.isDirectory()) collect(child, objectPath);
        else if (entry.isFile()) objects[objectPath] = fs.readFileSync(child).toString("base64");
        else throw new Error(`non-file producer surface entry: ''${objectPath}`);
      }
    }
    collect(path.join(fixtureRoot, "surface"));
    const producerSurface = JSON.stringify({
      trust_key: fs.readFileSync(path.join(fixtureRoot, "trust-key"), "utf8").trim(),
      objects,
    });
    async function bootstrap() {
      const r = await fetch(BASE + "/_e2e/managed-registry-bootstrap", {
        method: "POST", headers: { "content-type": "application/json" }, body: producerSurface,
      });
      return { status: r.status, body: await r.text() };
    }
    let last = null;
    for (let i = 0; i < 80; i++) {
      try { last = await bootstrap(); break; } catch { await new Promise((r) => setTimeout(r, 250)); }
    }
    if (!last) { console.error("workerd never accepted a connection"); process.exit(1); }
    if (last.status !== 200) { console.error(last.body); process.exit(1); }
    const r2Contract = await fetch(BASE + "/_e2e/r2-js-contract", {
      method: "POST",
      body: "",
    });
    if (r2Contract.status !== 200) {
      throw new Error(`R2 JS contract: ''${r2Contract.status} ''${await r2Contract.text()}`);
    }
    const bootstrapState = JSON.parse(last.body);
    if (bootstrapState.gc_root_count !== 4) throw new Error("published images were not GC roots");
    const token = bootstrapState.token;
    const headers = { authorization: `Bearer ''${token}` };

    async function imageRpc(method, body, authenticated = false) {
      const response = await fetch(BASE + `/aos.hub.v1.ImageService/''${method}`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "connect-protocol-version": "1",
          ...(authenticated ? headers : {}),
        },
        body: JSON.stringify(body),
      });
      return { response, text: await response.text() };
    }

    const publicList = await imageRpc("ListImages", {
      slug: "failure/images-public",
      channel: "stable",
    });
    const rawBytes = new Uint8Array(fs.readFileSync(fs.readFileSync(path.join(fixtureRoot, "raw-path"), "utf8").trim()));
    const rawDigest = new Uint8Array(await crypto.subtle.digest("SHA-256", rawBytes));
    const rawSha256 = Array.from(rawDigest, byte => byte.toString(16).padStart(2, "0")).join("");
    if (publicList.response.status !== 200
        || !publicList.text.includes("raw")
        || !publicList.text.includes("qcow2")
        || !publicList.text.includes(bootstrapState.raw_key)
        || !publicList.text.includes('"releaseVerification":"verified"')
        || !publicList.text.includes('"bootVerification":"unsigned"')
        || !publicList.text.includes(rawSha256)) {
      throw new Error(`public image list: ''${publicList.response.status} ''${publicList.text}`);
    }
    const inspected = await imageRpc("GetImage", {
      slug: "failure/images-public",
      release: "2026.3.0",
      architecture: "x86_64",
      format: "raw",
      package: "aos-system",
    });
    if (inspected.response.status !== 200
        || !inspected.text.includes(bootstrapState.raw_key)
        || !inspected.text.includes("image-info.json")
        || !inspected.text.includes(rawSha256)) {
      throw new Error(`image inspect: ''${inspected.response.status} ''${inspected.text}`);
    }
    const resolved = await imageRpc("ResolveImage", {
      slug: "failure/images-public",
      channel: "stable",
      architecture: "x86_64",
      target: "qemu-kvm",
    });
    if (resolved.response.status !== 200 || !resolved.text.includes("qcow2")) {
      throw new Error(`image resolve: ''${resolved.response.status} ''${resolved.text}`);
    }

    const rawUrl = BASE + "/failure/images-public/" + bootstrapState.raw_key;
    const rawDownload = await fetch(rawUrl);
    const downloaded = new Uint8Array(await rawDownload.arrayBuffer());
    if (rawDownload.status !== 200
        || downloaded.length !== rawBytes.length
        || !downloaded.every((byte, index) => byte === rawBytes[index])
        || !rawDownload.headers.get("content-disposition")?.includes("aos-e2e.img")
        || !rawDownload.headers.get("cache-control")?.includes("immutable")
        || rawDownload.headers.get("x-aos-sha256") !== rawSha256
        || !rawDownload.headers.get("repr-digest")?.startsWith("sha-256=:")) {
      throw new Error(`public raw download contract failed: ''${rawDownload.status}`);
    }
    const rawHead = await fetch(rawUrl, { method: "HEAD" });
    if (rawHead.status !== 200
        || Number(rawHead.headers.get("content-length")) !== rawBytes.length
        || rawHead.headers.get("x-aos-sha256") !== rawSha256
        || (await rawHead.arrayBuffer()).byteLength !== 0) {
      throw new Error(`public raw HEAD contract failed: ''${rawHead.status}`);
    }
    const rawRange = await fetch(rawUrl, { headers: { range: "bytes=4-11" } });
    const ranged = new Uint8Array(await rawRange.arrayBuffer());
    if (rawRange.status !== 206
        || rawRange.headers.get("content-range") !== `bytes 4-11/''${rawBytes.length}`
        || !ranged.every((byte, index) => byte === rawBytes[index + 4])) {
      throw new Error(`public raw range contract failed: ''${rawRange.status}`);
    }
    const unsatisfiedStart = rawBytes.length;
    const unsatisfied = await fetch(rawUrl, {
      headers: { range: `bytes=''${unsatisfiedStart}-` },
    });
    if (unsatisfied.status !== 416
        || unsatisfied.headers.get("content-range") !== `bytes */''${rawBytes.length}`
        || (await unsatisfied.arrayBuffer()).byteLength !== 0) {
      throw new Error(`public raw 416 contract failed: ''${unsatisfied.status}`);
    }

    const imagesPage = await fetch(BASE + "/failure/images-public/-/images");
    const imagesHtml = await imagesPage.text();
    if (imagesPage.status !== 200
        || !imagesHtml.includes("Download")
        || !imagesHtml.includes("qcow2")
        || !imagesHtml.includes("2026.3.0")
        || !imagesHtml.includes("stable")
        || !imagesHtml.includes("x86_64")
        || !imagesHtml.includes("qemu-kvm")
        || !imagesHtml.includes(`''${(rawBytes.length / (1024 * 1024)).toFixed(1)} MiB`)
        || !imagesHtml.includes(rawSha256)
        || !imagesHtml.includes("verified")
        || !imagesHtml.includes("unsigned")
        || !imagesHtml.includes('href="/failure/images-public/-/images"')
        || !imagesHtml.includes('aria-current="page">Images')) {
      throw new Error(`Worker Images page: ''${imagesPage.status} ''${imagesHtml}`);
    }

    const privateUrl = BASE + "/failure/images-private/" + bootstrapState.qcow2_key;
    const privateAnonymous = await fetch(privateUrl);
    if (privateAnonymous.status === 200) {
      throw new Error("private image was anonymously downloadable");
    }
    const privateDownload = await fetch(privateUrl, { headers });
    const qcow2Bytes = new Uint8Array(fs.readFileSync(fs.readFileSync(path.join(fixtureRoot, "qcow2-path"), "utf8").trim()));
    const qcow2Digest = new Uint8Array(await crypto.subtle.digest("SHA-256", qcow2Bytes));
    const qcow2Sha256 = Array.from(qcow2Digest, byte => byte.toString(16).padStart(2, "0")).join("");
    const downloadedQcow2 = new Uint8Array(await privateDownload.arrayBuffer());
    if (privateDownload.status !== 200
        || downloadedQcow2.length !== qcow2Bytes.length
        || !downloadedQcow2.every((byte, index) => byte === qcow2Bytes[index])
        || !privateDownload.headers.get("content-disposition")?.includes("aos-e2e.qcow2")
        || privateDownload.headers.get("x-aos-sha256") !== qcow2Sha256
        || !privateDownload.headers.get("cache-control")?.includes("no-store")
        || privateDownload.headers.get("vary") !== "Authorization, Cookie") {
      throw new Error(`private image download contract: ''${privateDownload.status}`);
    }
    const cookieHeaders = {
      cookie: `__Host-aos_session=''${bootstrapState.session}`,
    };
    const privateImagesPage = await fetch(
      BASE + "/failure/images-private/-/images",
      { headers: cookieHeaders },
    );
    const privateImagesHtml = await privateImagesPage.text();
    if (privateImagesPage.status !== 200
        || !privateImagesHtml.includes("Download")
        || !privateImagesHtml.includes(bootstrapState.qcow2_key)) {
      throw new Error(`private cookie Images page: ''${privateImagesPage.status} ''${privateImagesHtml}`);
    }
    const cookieDownload = await fetch(privateUrl, { headers: cookieHeaders });
    const cookieBytes = new Uint8Array(await cookieDownload.arrayBuffer());
    if (cookieDownload.status !== 200
        || cookieBytes.length !== qcow2Bytes.length
        || !cookieBytes.every((byte, index) => byte === qcow2Bytes[index])
        || !cookieDownload.headers.get("cache-control")?.includes("no-store")
        || cookieDownload.headers.get("vary") !== "Authorization, Cookie") {
      throw new Error(`private cookie image download: ''${cookieDownload.status}`);
    }
    const privateAnonymousApi = await imageRpc("ListImages", {
      slug: "failure/images-private",
    });
    if (privateAnonymousApi.response.status === 200) {
      throw new Error("private image API was anonymously readable");
    }
    const privateApi = await imageRpc("ListImages", {
      slug: "failure/images-private",
      format: "qcow2",
    }, true);
    if (privateApi.response.status !== 200 || !privateApi.text.includes(bootstrapState.qcow2_key)) {
      throw new Error(`private image API: ''${privateApi.response.status} ''${privateApi.text}`);
    }

    async function multipart(slug, path) {
      const target = BASE + "/" + slug + "/" + path;
      const initiated = await fetch(target + "?uploads&size=32", { method: "POST", headers, body: "" });
      if (initiated.status !== 200) throw new Error(`initiate ''${slug}/''${path}: ''${initiated.status} ''${await initiated.text()}`);
      const upload = await initiated.json();
      const send = async (part, fill) => {
        const response = await fetch(target + `?uploadId=''${encodeURIComponent(upload.upload_id)}&partNumber=''${part}`, {
          method: "PUT", headers, body: new Uint8Array(4).fill(fill),
        });
        if (response.status !== 200) throw new Error(`part ''${part}: ''${response.status} ''${await response.text()}`);
        return await response.json();
      };
      const requests = Array.from({ length: 8 }, (_, index) => send(index + 1, index + 1));
      requests.push(send(1, 1));
      const responses = await Promise.all(requests);
      const distinct = responses.slice(0, 8);
      if (responses[8].etag !== distinct[0].etag) throw new Error("same-part retry changed etag");
      const mismatch = await fetch(target + `?uploadId=''${encodeURIComponent(upload.upload_id)}&partNumber=1`, {
        method: "PUT", headers, body: new Uint8Array(4).fill(99),
      });
      if (mismatch.status < 400) throw new Error("same-part mismatch was accepted");
      const completed = await fetch(target + `?uploadId=''${encodeURIComponent(upload.upload_id)}`, {
        method: "POST",
        headers: { ...headers, "content-type": "application/json" },
        body: JSON.stringify({ parts: distinct.map((part) => ({ part_number: part.part_number, etag: part.etag })) }),
      });
      if (completed.status !== 201 && completed.status !== 200) {
        throw new Error(`complete ''${slug}/''${path}: ''${completed.status} ''${await completed.text()}`);
      }
    }

    await multipart("flat-cache", "00000000000000000000000000000000.narinfo");
    await multipart("failure/cache", "nar/nested/path.nar");
    await multipart("flat-registry", "HEAD");
    await multipart("failure/registry", "objects/ab/nested-object");

    const atBuiltinLimit = await fetch(BASE + "/flat-cache/nar/builtin-limit.nar", {
      method: "PUT", headers, body: new Uint8Array(20 * 1024 * 1024),
    });
    if (atBuiltinLimit.status !== 201) {
      throw new Error(`built-in boundary: ''${atBuiltinLimit.status} ''${await atBuiltinLimit.text()}`);
    }
    const overLimit = await fetch(BASE + "/flat-cache/nar/too-large.nar", {
      method: "PUT", headers, body: new Uint8Array(20 * 1024 * 1024 + 1),
    });
    if (overLimit.status !== 413) {
      throw new Error(`built-in over-limit: ''${overLimit.status} ''${await overLimit.text()}`);
    }

    const getSettings = await fetch(BASE + "/aos.hub.v1.InstanceService/GetInstanceSettings", {
      method: "POST",
      headers: {
        ...headers,
        "content-type": "application/json",
        "connect-protocol-version": "1",
      },
      body: "{}",
    });
    if (getSettings.status !== 200) {
      throw new Error(`settings read API: ''${getSettings.status} ''${await getSettings.text()}`);
    }
    const settings = await getSettings.json();
    const planSettings = await fetch(BASE + "/aos.hub.v1.InstanceService/PlanSetInstanceSettings", {
      method: "POST",
      headers: {
        ...headers,
        "content-type": "application/json",
        "connect-protocol-version": "1",
      },
      body: JSON.stringify({
        values: { max_upload_bytes: "4" },
        expected_resource_version: settings.resourceVersion,
        idempotency_key: "worker-e2e-plan-settings",
      }),
    });
    if (planSettings.status !== 200) {
      throw new Error(`settings plan API: ''${planSettings.status} ''${await planSettings.text()}`);
    }
    const plannedSettings = await planSettings.json();
    const applySettings = await fetch(BASE + "/aos.hub.v1.InstanceService/SetInstanceSettings", {
      method: "POST",
      headers: {
        ...headers,
        "content-type": "application/json",
        "connect-protocol-version": "1",
      },
      body: JSON.stringify({
        plan_id: plannedSettings.plan.planId,
        confirmation_hash: plannedSettings.plan.confirmationHash,
        idempotency_key: "worker-e2e-apply-settings",
      }),
    });
    if (applySettings.status !== 200) {
      throw new Error(`configured cap API: ''${applySettings.status} ''${await applySettings.text()}`);
    }

    const cappedSingle = await fetch(BASE + "/flat-cache/nar/configured-cap.nar", {
      method: "PUT", headers, body: new Uint8Array(5),
    });
    if (cappedSingle.status !== 413) {
      throw new Error(`configured single-upload cap: ''${cappedSingle.status} ''${await cappedSingle.text()}`);
    }
    const cappedTarget = BASE + "/flat-registry/objects/ab/configured-cap";
    const cappedInitiated = await fetch(cappedTarget + "?uploads&size=5", {
      method: "POST", headers, body: "",
    });
    if (cappedInitiated.status !== 200) {
      throw new Error(`configured multipart initiate: ''${cappedInitiated.status} ''${await cappedInitiated.text()}`);
    }
    const cappedUpload = await cappedInitiated.json();
    const cappedPart = await fetch(cappedTarget + `?uploadId=''${encodeURIComponent(cappedUpload.upload_id)}&partNumber=1`, {
      method: "PUT", headers, body: new Uint8Array(5),
    });
    if (cappedPart.status !== 413) {
      throw new Error(`configured multipart cap: ''${cappedPart.status} ''${await cappedPart.text()}`);
    }

    console.log("aos-hub-worker do-e2e: PASS");
  '';
in
  mkDerivation {
    pname = "aos-hub-worker-do-e2e";
    version = "0.1.0";

    runtimeDeps = [dist aos nix nodejs workerd-source bash coreutils grep aos-system-image-e2e-fixture];
    nukeRefsKeep = [workerCapnp driver];

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          cat > "$out/bin/aos-hub-worker-do-e2e" <<EOF
          #!${bash}/bin/bash
          # Run the deployed Worker under the from-source workerd with a real
          # SQLite-backed HubDb DO and assert the API/storage/write matrix. Must
          # run OUTSIDE the Nix sandbox: workerd's tcmalloc needs
          # /sys/devices/system/cpu, unavailable there.
          set -euo pipefail
          export PATH="${nix}/bin:${aos}/bin:${coreutils}/bin:${grep}/bin:$PATH"
          work="\$(mktemp -d)"
          WPID=""
          trap 'if test -n "\$WPID"; then kill "\$WPID" 2>/dev/null || true; fi; rm -rf "\$work"' EXIT
          cp ${dist}/shim.mjs ${dist}/index.wasm "\$work/"
          cp ${workerCapnp} "\$work/worker.capnp"
          cp ${driver} "\$work/driver.mjs"
          ${aos-system-image-e2e-fixture}/bin/aos-system-image-e2e-fixture "\$work/producer"
          export AOS_HUB_E2E_IMAGE_FIXTURE="\$work/producer"
          cd "\$work"
          mkdir -p "\$work/do-storage"
          ${workerd-source}/bin/workerd serve worker.capnp > "\$work/workerd.log" 2>&1 &
          WPID=\$!
          if ! ${nodejs}/bin/node driver.mjs; then
            echo "=== workerd.log ==="
            cat "\$work/workerd.log" || true
            exit 1
          fi
          ${aos}/bin/aos --json image list \
            --hub http://127.0.0.1:8799 \
            --registry failure/images-public --channel stable \
            > "\$work/cli-images.json"
          ${grep}/bin/grep -q 'aos-e2e.img' "\$work/cli-images.json"
          ${aos}/bin/aos image download \
            --hub http://127.0.0.1:8799 \
            --registry failure/images-public --channel stable --format raw \
            --output "\$work/worker-cli.img" >/dev/null
          ${coreutils}/bin/cmp "\$work/worker-cli.img" "\$(${coreutils}/bin/cat "\$work/producer/raw-path")"
          EOF
          chmod +x "$out/bin/aos-hub-worker-do-e2e"
        '';
      }
    ];

    meta = {
      description = "Launcher: run the deployed aos-hub-worker under workerd and assert its HubDb, API, routing, and multipart matrix";
      homepage = "https://github.com/andyl/andyl-os";
      license = "MIT";
    };

    checks = {
      testing,
      self,
      ...
    }: {
      live-worker-topology = testing.mkVMTest {
        name = "aos-hub-worker-do-e2e-live";
        rootfsDeps = [self];
        memory = 2048;
        testScript = ''
          ${nix}/bin/nix-store --load-db < /aos-registration
          ${self}/bin/aos-hub-worker-do-e2e
        '';
      };
    };
  }
