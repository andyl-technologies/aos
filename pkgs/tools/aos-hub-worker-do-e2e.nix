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
##! live shared-API body boundary at 8 MiB and 8 MiB + 1, changes the operator cap
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
  diffutils,
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

  egressFixture = ./aos-hub-direct-egress-fixture.mjs;
  stateFixture = ./aos-hub-worker-state-fixture.mjs;
  removedManagementPaths = ../../crates/aos-hub/tests/fixtures/removed-management-paths-v1.json;
  removedManagementPosts = ../../crates/aos-hub/tests/fixtures/removed-management-posts-v1.json;
  ociProtocolTranscript = ../../crates/aos-hub/tests/fixtures/oci-protocol-parity-v1.json;

  # The workerd config: a module worker (shim.mjs + index.wasm) with the six DO
  # classes, `enableSql = true` on the SQLite-backed `HubDb`, the direct-Fetch
  # outbound contract fixture, and the secrets/vars the DO reads. Open-source
  # workerd has no R2/KV/rate-limit
  # bindings, so the non-default build injects durable SQLite surface storage
  # and in-memory coordination at the production port boundaries. The compat
  # date matches the workerd build.
  workerCapnp = builtins.toFile "aos-hub-do-e2e.capnp" ''
    using Workerd = import "/workerd/workerd.capnp";

    const config :Workerd.Config = (
      services = [
        (name = "main", worker = .mainWorker),
        (name = "egress-fixture", worker = .egressFixtureWorker),
        (name = "state-fixture", worker = .stateFixtureWorker),
        (name = "do-disk", disk = (path = "do-storage", writable = true)),
      ],
      sockets = [
        (name = "http", address = "127.0.0.1:8799", http = (), service = "main"),
        (name = "oci-private", address = "127.0.0.1:8800", http = (), service = "main"),
      ],
    );

    const mainWorker :Workerd.Worker = (
      modules = [
        (name = "shim.mjs", esModule = embed "shim.mjs"),
        (name = "index.wasm", wasm = embed "index.wasm"),
      ],
      compatibilityDate = "2024-09-09",
      compatibilityFlags = ["nodejs_compat"],
      globalOutbound = "egress-fixture",
      cacheApiOutbound = "state-fixture",
      durableObjectNamespaces = [
        (className = "HubDb", uniqueKey = "hubdb-key", enableSql = true),
        (className = "CoordinatorObject", uniqueKey = "coord-key"),
        (className = "HubControlShard", uniqueKey = "control-shard-key"),
        (className = "HubTenantShard", uniqueKey = "tenant-shard-key"),
        (className = "HubRegistryShard", uniqueKey = "registry-shard-key"),
        (className = "HubCacheShard", uniqueKey = "cache-shard-key"),
      ],
      durableObjectStorage = (localDisk = "do-disk"),
      bindings = [
        (name = "HUB_DB", durableObjectNamespace = "HubDb"),
        (name = "COORDINATOR", durableObjectNamespace = "CoordinatorObject"),
        (name = "HUB_CONTROL_SHARDS", durableObjectNamespace = "HubControlShard"),
        (name = "HUB_TENANT_SHARDS", durableObjectNamespace = "HubTenantShard"),
        (name = "HUB_REGISTRY_SHARDS", durableObjectNamespace = "HubRegistryShard"),
        (name = "HUB_CACHE_SHARDS", durableObjectNamespace = "HubCacheShard"),
        (name = "SESSIONS", kvNamespace = "state-fixture"),
        (name = "HUB_JWT_SECRET", text = "e2e-jwt-secret"),
        (name = "HUB_SEAL_KEY", text = "0000000000000000000000000000000000000000000000000000000000000000"),
        (name = "HUB_EXTERNAL_URL", text = "http://127.0.0.1:8799"),
        (name = "HUB_DEPLOYMENT_ID", text = "workerd-e2e-deployment"),
        (name = "HUB_OCI_PULL_ENABLED", text = "true"),
        (name = "HUB_OCI_PUSH_ENABLED", text = "true"),
        (name = "HUB_OCI_VERIFIED_PUBLICATION_ENABLED", text = "true"),
        (name = "HUB_OCI_ADMINISTRATION_ENABLED", text = "true"),
        (name = "HUB_OCI_GC_ENABLED", text = "true"),
      ],
    );

    const egressFixtureWorker :Workerd.Worker = (
      modules = [
        (name = "fixture.mjs", esModule = embed "fixture.mjs"),
      ],
      compatibilityDate = "2024-09-09",
    );

    const stateFixtureWorker :Workerd.Worker = (
      modules = [
        (name = "state-fixture.mjs", esModule = embed "state-fixture.mjs"),
      ],
      compatibilityDate = "2024-09-09",
    );
  '';

  # The driver: wait for workerd, bootstrap, and assert the live HTTP matrix.
  driver = builtins.toFile "aos-hub-do-e2e.mjs" ''
    import fs from "node:fs";
    import path from "node:path";
    const BASE = "http://127.0.0.1:8799";
    const PRIVATE_OCI_BASE = "http://127.0.0.1:8800";

    function humanSize(bytes) {
      const units = ["B", "KiB", "MiB", "GiB", "TiB"];
      let value = bytes;
      let unit = 0;
      while (value >= 1024 && unit < units.length - 1) {
        value /= 1024;
        unit += 1;
      }
      return unit === 0 ? `''${bytes} B` : `''${value.toFixed(1)} ''${units[unit]}`;
    }
    const fixtureRoot = process.env.AOS_HUB_E2E_IMAGE_FIXTURE;
    if (!fixtureRoot) throw new Error("AOS_HUB_E2E_IMAGE_FIXTURE is required");
    const objects = {};
    function collect(directory, relative = "") {
      // Current system-image delivery is store-backed: the signed registry
      // graph names immutable store identities and this cache surface carries
      // their NARs. The DO adapter chunks each object below SQLite's value
      // bound, including the small qualification closure is safe.
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
    const deploymentIdentity = await fetch(BASE + "/.well-known/aos-deployment");
    if (deploymentIdentity.status !== 200
        || await deploymentIdentity.text() !== "workerd-e2e-deployment"
        || deploymentIdentity.headers.get("x-aos-deployment-id") !== "workerd-e2e-deployment"
        || !deploymentIdentity.headers.get("cache-control")?.includes("no-store")) {
      throw new Error("deployment identity contract failed");
    }
    const deploymentHead = await fetch(BASE + "/.well-known/aos-deployment", { method: "HEAD" });
    if (deploymentHead.status !== 200
        || await deploymentHead.text() !== ""
        || deploymentHead.headers.get("x-aos-deployment-id") !== "workerd-e2e-deployment") {
      throw new Error("deployment identity HEAD contract failed");
    }
    const directEgress = await fetch(BASE + "/_e2e/direct-egress", { method: "POST" });
    const directEgressBody = await directEgress.text();
    if (directEgress.status !== 200 || directEgressBody !== "ok") {
      throw new Error(`Worker-direct egress: ''${directEgress.status} ''${directEgressBody}`);
    }
    const r2Contract = await fetch(BASE + "/_e2e/r2-js-contract", {
      method: "POST",
      body: "",
    });
    if (r2Contract.status !== 200) {
      throw new Error(`R2 JS contract: ''${r2Contract.status} ''${await r2Contract.text()}`);
    }
    const bootstrapState = JSON.parse(last.body);
    if (bootstrapState.gc_root_count !== 0) {
      throw new Error("store-backed images entered the direct-object GC root set");
    }
    const token = bootstrapState.token;
    const headers = { authorization: `Bearer ''${token}` };
    // Store-backed system images are delivered by an advertised binary cache,
    // not by an untracked read from their source registry placement. Admit the
    // exact producer closure through the ordinary cache upload surface so this
    // qualification covers catalog identity, quota accounting, and presence.
    for (const objectPath of Object.keys(objects)
      .filter((path) => path.endsWith(".narinfo") || path.startsWith("nar/"))
      .sort()) {
      const bytes = Buffer.from(objects[objectPath], "base64");
      const uploadUrl = await createSingleUpload("flat-cache", objectPath, bytes.length);
      const uploaded = await fetch(uploadUrl, { method: "PUT", headers, body: bytes });
      if (uploaded.status !== 201) {
        throw new Error(
          `producer cache upload ''${objectPath}: ''${uploaded.status} ''${await uploaded.text()}`,
        );
      }
    }
    const imageInventory = await fetch(BASE + "/_e2e/rescan-image-cache", {
      method: "POST",
    });
    if (imageInventory.status !== 200) {
      throw new Error(
        `producer cache inventory: ''${imageInventory.status} ''${await imageInventory.text()}`,
      );
    }
    const protocolTranscript = JSON.parse(
      fs.readFileSync("${ociProtocolTranscript}", "utf8"),
    );
    if (protocolTranscript.version !== 1 || !Array.isArray(protocolTranscript.cases)) {
      throw new Error("OCI protocol transcript fixture has an unsupported shape");
    }
    const expectedTranscript = new Map(
      protocolTranscript.cases.map((entry) => [entry.id, entry.status]),
    );
    const observedTranscript = new Set();
    function transcriptStatus(id, response, detail = "") {
      const expected = expectedTranscript.get(id);
      if (expected === undefined) throw new Error("undeclared OCI transcript case: " + id);
      if (response.status !== expected) {
        throw new Error(
          "OCI transcript " + id + ": expected " + expected + ", got "
            + response.status + " " + detail,
        );
      }
      observedTranscript.add(id);
    }
    async function sha256(bytes) {
      const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
      return "sha256:" + Array.from(digest, (byte) =>
        byte.toString(16).padStart(2, "0")).join("");
    }
    async function exchangeOciToken(base, authorization, scope) {
      const authority = new URL(base).host;
      const query = new URLSearchParams({ service: authority, scope });
      const response = await fetch(base + "/v2/token?" + query, {
        headers: { authorization },
      });
      const text = await response.text();
      return { response, text, value: text ? JSON.parse(text) : null };
    }
    async function beginBlob(base, ociToken, caseId = null) {
      const response = await fetch(base + "/v2/aos/blobs/uploads/", {
        method: "POST",
        headers: { authorization: "Bearer " + ociToken },
      });
      const text = await response.text();
      if (caseId) transcriptStatus(caseId, response, text);
      else if (response.status !== 202) throw new Error("private upload begin: " + response.status + " " + text);
      const location = response.headers.get("location");
      if (!location) throw new Error("OCI upload begin omitted Location");
      return new URL(location, base);
    }
    async function completeBlob(base, ociToken, bytes, beginCase = null, completeCase = null) {
      const location = await beginBlob(base, ociToken, beginCase);
      const digest = await sha256(bytes);
      location.searchParams.set("digest", digest);
      const response = await fetch(location, {
        method: "PUT",
        headers: {
          authorization: "Bearer " + ociToken,
          "content-type": "application/octet-stream",
        },
        body: bytes,
      });
      const text = await response.text();
      if (completeCase) transcriptStatus(completeCase, response, text);
      else if (response.status !== 201) throw new Error("private upload complete: " + response.status + " " + text);
      return digest;
    }
    async function putOciManifest(base, ociToken, reference, document, caseId = null) {
      const bytes = new TextEncoder().encode(JSON.stringify(document));
      const digest = await sha256(bytes);
      const response = await fetch(base + "/v2/aos/manifests/" + encodeURIComponent(reference), {
        method: "PUT",
        headers: {
          authorization: "Bearer " + ociToken,
          "content-type": "application/vnd.oci.image.manifest.v1+json",
        },
        body: bytes,
      });
      const text = await response.text();
      if (caseId) transcriptStatus(caseId, response, text);
      else if (response.status !== 201) throw new Error("private manifest put: " + response.status + " " + text);
      return { digest, bytes };
    }
    async function containerRpc(method, request) {
      const response = await fetch(BASE + "/aos.hub.v1.ContainerService/" + method, {
        method: "POST",
        headers: {
          ...headers,
          "content-type": "application/json",
          "connect-protocol-version": "1",
        },
        body: JSON.stringify(request),
      });
      const text = await response.text();
      return { response, text, value: text ? JSON.parse(text) : null };
    }

    const publicDiscovery = await fetch(BASE + "/v2/");
    transcriptStatus("distribution.public.discovery", publicDiscovery, await publicDiscovery.text());
    if (publicDiscovery.headers.get("docker-distribution-api-version") !== "registry/2.0") {
      throw new Error("public discovery omitted the Distribution version");
    }
    const publicTokenResponse = await exchangeOciToken(
      BASE,
      "Bearer " + token,
      "repository:aos:pull,push",
    );
    transcriptStatus(
      "distribution.public.token",
      publicTokenResponse.response,
      publicTokenResponse.text,
    );
    const publicOciToken = publicTokenResponse.value?.token;
    if (!publicOciToken || publicTokenResponse.value?.access_token !== publicOciToken) {
      throw new Error("public OCI token response omitted aliases");
    }

    const layerBytes = new TextEncoder().encode("aos protocol parity layer\n");
    const layerDigest = await sha256(layerBytes);
    const configDocument = {
      created: "1970-01-01T00:00:01Z",
      architecture: "amd64",
      os: "linux",
      config: { Entrypoint: ["/bin/sh"], Cmd: ["-c", "echo aos-protocol-parity"] },
      rootfs: { type: "layers", diff_ids: [layerDigest] },
      history: [{ created_by: "aos protocol parity transcript" }],
    };
    const configBytes = new TextEncoder().encode(JSON.stringify(configDocument));
    const configDigest = await sha256(configBytes);
    await completeBlob(
      BASE,
      publicOciToken,
      configBytes,
      "distribution.public.upload-config-begin",
      "distribution.public.upload-config-complete",
    );
    await completeBlob(
      BASE,
      publicOciToken,
      layerBytes,
      "distribution.public.upload-layer-begin",
      "distribution.public.upload-layer-complete",
    );
    const manifestDocument = {
      schemaVersion: 2,
      mediaType: "application/vnd.oci.image.manifest.v1+json",
      config: {
        mediaType: "application/vnd.oci.image.config.v1+json",
        digest: configDigest,
        size: configBytes.length,
      },
      layers: [{
        mediaType: "application/vnd.oci.image.layer.v1.tar",
        digest: layerDigest,
        size: layerBytes.length,
      }],
    };
    const publicManifest = await putOciManifest(
      BASE,
      publicOciToken,
      "latest",
      manifestDocument,
      "distribution.public.manifest-put",
    );
    const publicManifestByTag = await fetch(BASE + "/v2/aos/manifests/latest");
    transcriptStatus(
      "distribution.public.manifest-tag-get",
      publicManifestByTag,
      await publicManifestByTag.text(),
    );
    if (publicManifestByTag.headers.get("docker-content-digest") !== publicManifest.digest) {
      throw new Error("public manifest tag resolved to the wrong digest");
    }
    const publicManifestHead = await fetch(
      BASE + "/v2/aos/manifests/" + publicManifest.digest,
      { method: "HEAD" },
    );
    transcriptStatus(
      "distribution.public.manifest-digest-head",
      publicManifestHead,
      await publicManifestHead.text(),
    );
    const publicBlob = await fetch(BASE + "/v2/aos/blobs/" + layerDigest);
    const publicBlobBytes = new Uint8Array(await publicBlob.arrayBuffer());
    transcriptStatus("distribution.public.blob-get", publicBlob);
    if (publicBlobBytes.length !== layerBytes.length
        || !publicBlobBytes.every((byte, index) => byte === layerBytes[index])) {
      throw new Error("public blob response changed bytes");
    }
    const publicTags = await fetch(BASE + "/v2/aos/tags/list");
    const publicTagsText = await publicTags.text();
    transcriptStatus("distribution.public.tags-list", publicTags, publicTagsText);
    if (!JSON.parse(publicTagsText).tags?.includes("latest")) {
      throw new Error("public tags response omitted latest");
    }
    const emptyBytes = new TextEncoder().encode("{}");
    const emptyDigest = await completeBlob(BASE, publicOciToken, emptyBytes);
    const sbomBytes = new TextEncoder().encode('{"spdxVersion":"SPDX-2.3"}');
    const sbomDigest = await completeBlob(BASE, publicOciToken, sbomBytes);
    const referrerDocument = {
      schemaVersion: 2,
      mediaType: "application/vnd.oci.image.manifest.v1+json",
      artifactType: "application/spdx+json",
      config: {
        mediaType: "application/vnd.oci.empty.v1+json",
        digest: emptyDigest,
        size: emptyBytes.length,
      },
      layers: [{
        mediaType: "application/spdx+json",
        digest: sbomDigest,
        size: sbomBytes.length,
      }],
      subject: {
        mediaType: "application/vnd.oci.image.manifest.v1+json",
        digest: publicManifest.digest,
        size: publicManifest.bytes.length,
      },
    };
    const referrer = await putOciManifest(
      BASE,
      publicOciToken,
      "sbom",
      referrerDocument,
      "distribution.public.referrer-put",
    );
    const referrers = await fetch(BASE + "/v2/aos/referrers/" + publicManifest.digest);
    const referrersText = await referrers.text();
    transcriptStatus("distribution.public.referrers-list", referrers, referrersText);
    if (!referrersText.includes(referrer.digest)) {
      throw new Error("public referrers response omitted the artifact digest");
    }

    const privateDiscovery = await fetch(PRIVATE_OCI_BASE + "/v2/");
    transcriptStatus("distribution.private.discovery", privateDiscovery, await privateDiscovery.text());
    const privateAnonymous = await fetch(PRIVATE_OCI_BASE + "/v2/aos/manifests/latest");
    transcriptStatus(
      "distribution.private.manifest-anonymous",
      privateAnonymous,
      await privateAnonymous.text(),
    );
    if (!privateAnonymous.headers.get("www-authenticate")?.includes("127.0.0.1:8800/v2/token")) {
      throw new Error("private challenge was not bound to its authority");
    }
    const basic = Buffer.from(
      bootstrapState.docker_username + ":" + bootstrapState.docker_password,
      "utf8",
    ).toString("base64");
    const privateTokenResponse = await exchangeOciToken(
      PRIVATE_OCI_BASE,
      "Basic " + basic,
      "repository:aos:pull,push",
    );
    transcriptStatus(
      "distribution.private.token-basic",
      privateTokenResponse.response,
      privateTokenResponse.text,
    );
    const privateOciToken = privateTokenResponse.value?.token;
    if (!privateOciToken) throw new Error("private token exchange omitted token");
    await completeBlob(PRIVATE_OCI_BASE, privateOciToken, configBytes);
    await completeBlob(PRIVATE_OCI_BASE, privateOciToken, layerBytes);
    await putOciManifest(
      PRIVATE_OCI_BASE,
      privateOciToken,
      "latest",
      manifestDocument,
    );
    const privateManifest = await fetch(PRIVATE_OCI_BASE + "/v2/aos/manifests/latest", {
      headers: { authorization: "Bearer " + privateOciToken },
    });
    const privateManifestText = await privateManifest.text();
    transcriptStatus(
      "distribution.private.manifest-authenticated",
      privateManifest,
      privateManifestText,
    );
    if (privateManifest.headers.get("cache-control") !== "private, no-store") {
      throw new Error("private manifest response was cacheable");
    }

    const repositories = await containerRpc("ListContainerRepositories", {
      registry: bootstrapState.oci_public_registry,
      pageSize: 20,
    });
    transcriptStatus("container.repositories-list", repositories.response, repositories.text);
    if (!repositories.value?.repositories?.some((repository) => repository.repository === "aos")) {
      throw new Error("ContainerService repository list omitted pushed repository");
    }
    const resolvedTag = await containerRpc("ResolveContainerTag", {
      registry: bootstrapState.oci_public_registry,
      repository: "aos",
      tag: "latest",
      operatingSystem: "linux",
      architecture: "amd64",
    });
    transcriptStatus("container.tag-resolve", resolvedTag.response, resolvedTag.text);
    if (resolvedTag.value?.tag?.digest !== publicManifest.digest) {
      throw new Error("ContainerService resolved a different manifest digest");
    }
    const manifestRead = await containerRpc("GetContainerManifest", {
      registry: bootstrapState.oci_public_registry,
      repository: "aos",
      digest: publicManifest.digest,
    });
    transcriptStatus("container.manifest-get", manifestRead.response, manifestRead.text);
    if (manifestRead.value?.manifest?.digest !== publicManifest.digest) {
      throw new Error("ContainerService manifest projection changed digest");
    }
    const referrerRead = await containerRpc("ListContainerReferrers", {
      registry: bootstrapState.oci_public_registry,
      repository: "aos",
      subjectDigest: publicManifest.digest,
      pageSize: 20,
    });
    transcriptStatus("container.referrers-list", referrerRead.response, referrerRead.text);
    if (!referrerRead.value?.referrers?.some((entry) => entry.digest === referrer.digest)) {
      throw new Error("ContainerService referrer projection omitted artifact");
    }
    const publications = await containerRpc("ListContainerPublications", {
      registry: bootstrapState.oci_public_registry,
      repository: "aos",
      pageSize: 20,
    });
    transcriptStatus("container.publications-list", publications.response, publications.text);
    const invalidPublication = await containerRpc("BeginContainerPublication", {
      registry: bootstrapState.oci_public_registry,
      repository: "aos",
      containerReleaseJson: Buffer.from("{}").toString("base64"),
      targetTag: "invalid-release",
      idempotencyKey: "worker-parity-invalid-publication",
      targetKind: "release",
    });
    transcriptStatus(
      "container.publication-invalid-release",
      invalidPublication.response,
      invalidPublication.text,
    );
    const tagPlan = await containerRpc("PlanSetContainerTag", {
      registry: bootstrapState.oci_public_registry,
      repository: "aos",
      tag: "promoted",
      targetDigest: publicManifest.digest,
      idempotencyKey: "worker-parity-tag-plan",
    });
    transcriptStatus("container.tag-plan", tagPlan.response, tagPlan.text);
    const reviewedTagPlan = tagPlan.value?.plan;
    if (!reviewedTagPlan?.planId || !reviewedTagPlan?.confirmationHash) {
      throw new Error("ContainerService tag plan omitted review identity");
    }
    const tagApply = await containerRpc("SetContainerTag", {
      planId: reviewedTagPlan.planId,
      idempotencyKey: "worker-parity-tag-apply",
      confirmationHash: reviewedTagPlan.confirmationHash,
    });
    transcriptStatus("container.tag-apply", tagApply.response, tagApply.text);
    if (tagApply.value?.tag?.tag !== "promoted"
        || tagApply.value?.tag?.digest !== publicManifest.digest) {
      throw new Error("ContainerService tag apply returned the wrong pointer");
    }
    const retention = await containerRpc("GetContainerRetentionPolicy", {
      registry: bootstrapState.oci_public_registry,
    });
    transcriptStatus("container.retention-get", retention.response, retention.text);
    const policyVersion = retention.value?.policy?.resourceVersion ?? "0";
    const gcPlan = await containerRpc("PlanRunContainerGc", {
      registry: bootstrapState.oci_public_registry,
      expectedResourceVersion: policyVersion,
      idempotencyKey: "worker-parity-gc-plan",
    });
    transcriptStatus("container.gc-plan", gcPlan.response, gcPlan.text);
    const gcRunId = gcPlan.value?.run?.runId;
    if (!gcRunId || gcPlan.value?.run?.state !== "failed"
        || !Array.isArray(gcPlan.value?.blockers)
        || gcPlan.value.blockers.length === 0) {
      throw new Error("injected-provider GC plan did not fail closed with blockers");
    }
    const gcStatus = await containerRpc("GetContainerGcRun", {
      registry: bootstrapState.oci_public_registry,
      runId: gcRunId,
    });
    transcriptStatus("container.gc-status", gcStatus.response, gcStatus.text);
    if (gcStatus.value?.run?.runId !== gcRunId) {
      throw new Error("ContainerService GC status lost durable run identity");
    }
    const gcBlockers = await containerRpc("ListContainerGcBlockers", {
      registry: bootstrapState.oci_public_registry,
      runId: gcRunId,
    });
    transcriptStatus("container.gc-blockers", gcBlockers.response, gcBlockers.text);
    if (!Array.isArray(gcBlockers.value?.blockers) || gcBlockers.value.blockers.length === 0) {
      throw new Error("ContainerService GC blocker list was empty");
    }
    const missingTranscript = [...expectedTranscript.keys()].filter(
      (id) => !observedTranscript.has(id),
    );
    if (missingTranscript.length !== 0) {
      throw new Error("unobserved OCI transcript cases: " + missingTranscript.join(", "));
    }
    console.log(
      "aos-hub-worker OCI protocol transcript v1: PASS ("
        + observedTranscript.size + " cases; injected SQLite provider, no R2 physical GC apply)",
    );
    const removedManagementPaths = JSON.parse(
      fs.readFileSync("${removedManagementPaths}", "utf8"),
    );
    for (const removedPath of removedManagementPaths) {
      for (const method of ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]) {
        const removed = await fetch(BASE + removedPath, { method, headers });
        const expected = method === "GET" || method === "HEAD"
          ? removed.status === 404
          : removed.status === 404 || removed.status === 405;
        if (!expected) {
          throw new Error(`removed management path remained mounted: ''${method} ''${removedPath} (''${removed.status})`);
        }
      }
    }
    const removedManagementPosts = JSON.parse(
      fs.readFileSync("${removedManagementPosts}", "utf8"),
    );
    for (const removedPath of removedManagementPosts) {
      const removed = await fetch(BASE + removedPath, {
        method: "POST",
        headers,
      });
      if (removed.status !== 404 && removed.status !== 405) {
        throw new Error(`removed management POST remained mounted: ''${removedPath} (''${removed.status})`);
      }
    }

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
      const text = await response.text();
      return { response, text, value: text ? JSON.parse(text) : null };
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
        || publicList.text.includes('"downloadUrl"')
        || publicList.text.includes('"objectKey"')
        || !publicList.text.includes('"cacheUrls":["http://127.0.0.1:8799/flat-cache"]')
        || !publicList.text.includes('"releaseVerification":"verified"')
        || !publicList.text.includes('"bootVerification":"signed-unverified"')
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
        || inspected.text.includes('"downloadUrl"')
        || inspected.text.includes('"objectKey"')
        || !inspected.text.includes('"storePath":"/nix/store/')
        || !inspected.text.includes('"narHash":"sha256:')
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

    const imagesPage = await fetch(BASE + "/failure/images-public/-/images");
    const imagesHtml = await imagesPage.text();
    if (imagesPage.status !== 200
        || !imagesHtml.includes("CDN / CLI")
        || !imagesHtml.includes("Delivered from the registry cache with aos image download")
        || !imagesHtml.includes("qcow2")
        || !imagesHtml.includes("2026.3.0")
        || !imagesHtml.includes("stable")
        || !imagesHtml.includes("x86_64")
        || !imagesHtml.includes("QEMU/KVM")
        || !imagesHtml.includes(humanSize(rawBytes.length))
        || !imagesHtml.includes(rawSha256)
        || !imagesHtml.includes("verified")
        || !imagesHtml.includes("signed, unverified")
        || !imagesHtml.includes('href="/failure/images-public/-/images"')
        || !imagesHtml.includes('aria-current="page">Images')) {
      throw new Error(`Worker Images page: ''${imagesPage.status} ''${imagesHtml}`);
    }

    const qcow2Bytes = new Uint8Array(fs.readFileSync(fs.readFileSync(path.join(fixtureRoot, "qcow2-path"), "utf8").trim()));
    const qcow2Digest = new Uint8Array(await crypto.subtle.digest("SHA-256", qcow2Bytes));
    const qcow2Sha256 = Array.from(qcow2Digest, byte => byte.toString(16).padStart(2, "0")).join("");
    const cookieHeaders = {
      cookie: `__Host-aos_session=''${bootstrapState.session}`,
    };
    const managementShell = await fetch(BASE + "/-/instance", { headers: cookieHeaders });
    const managementHtml = await managementShell.text();
    const bootstrapPath = managementHtml.match(/src="(\/_assets\/hub-console-bootstrap-[a-f0-9]{8}\.js)"/)?.[1];
    const stylesheetPath = managementHtml.match(/href="(\/_assets\/hub-console-[a-f0-9]{8}\.css)"/)?.[1];
    if (managementShell.status !== 200 || !bootstrapPath || !stylesheetPath) {
      throw new Error(`management shell omitted content-addressed assets: ''${managementShell.status}`);
    }
    const bootstrapAsset = await fetch(BASE + bootstrapPath);
    const bootstrapSource = await bootstrapAsset.text();
    const wasmName = bootstrapSource.match(/hub-console-[a-f0-9]{8}_bg\.wasm/)?.[0];
    const moduleName = bootstrapSource.match(/hub-console-[a-f0-9]{8}\.js/)?.[0];
    const stylesheetAsset = await fetch(BASE + stylesheetPath);
    if (bootstrapAsset.status !== 200
        || !bootstrapAsset.headers.get("cache-control")?.includes("immutable")
        || stylesheetAsset.status !== 200
        || !wasmName
        || !moduleName
        || !bootstrapSource.includes("import init, { mount }")
        || !bootstrapSource.includes("init({ module_or_path:")
        || !bootstrapSource.includes("mount();")) {
      throw new Error("management console bootstrap/CSS assets failed");
    }
    const [wasmAsset, moduleAsset] = await Promise.all([
      fetch(BASE + "/_assets/" + wasmName),
      fetch(BASE + "/_assets/" + moduleName),
    ]);
    const wasmBytes = new Uint8Array(await wasmAsset.arrayBuffer());
    if (wasmAsset.status !== 200
        || moduleAsset.status !== 200
        || wasmBytes.length < 4
        || wasmBytes[0] !== 0x00
        || wasmBytes[1] !== 0x61
        || wasmBytes[2] !== 0x73
        || wasmBytes[3] !== 0x6d) {
      throw new Error("management console JavaScript/WASM artifact failed");
    }
    const csrf = managementHtml.match(/name="aos-session-csrf" content="([^"]+)"/)?.[1];
    if (!csrf) throw new Error("management shell omitted the browser CSRF proof");
    const sessionResponse = await fetch(BASE + "/-/auth/session-token", {
      method: "POST",
      headers: {
        ...cookieHeaders,
        origin: BASE,
        "x-aos-csrf": csrf,
        "x-aos-console-route": "/-/orgs",
      },
    });
    const browserSession = await sessionResponse.json();
    if (sessionResponse.status !== 200
        || browserSession.tokenType !== "Bearer"
        || !browserSession.routePermissions?.includes("read")) {
      throw new Error(`browser session exchange failed: ''${sessionResponse.status}`);
    }
    const browserHeaders = {
      authorization: `Bearer ''${browserSession.accessToken}`,
      "connect-protocol-version": "1",
      "content-type": "application/json",
      accept: "application/json",
    };
    async function browserRpc(method, request) {
      const response = await fetch(BASE + `/aos.hub.v1.OrganizationService/''${method}`, {
        method: "POST",
        headers: browserHeaders,
        body: JSON.stringify(request),
      });
      const text = await response.text();
      return { response, text, value: text ? JSON.parse(text) : null };
    }
    const browserRead = await browserRpc("ListOrganizations", { pageSize: 100 });
    if (browserRead.response.status !== 200 || !Array.isArray(browserRead.value.organizations)) {
      throw new Error(`browser API read failed: ''${browserRead.response.status} ''${browserRead.text}`);
    }
    const browserIdempotencyKey = "worker-browser-organization-create";
    const browserPlan = await browserRpc("PlanCreateOrganization", {
      slug: "browser-e2e",
      displayName: "Browser E2E",
      idempotencyKey: browserIdempotencyKey,
    });
    const plan = browserPlan.value?.plan;
    if (browserPlan.response.status !== 200 || !plan?.planId || !plan?.confirmationHash) {
      throw new Error(`browser API plan failed: ''${browserPlan.response.status} ''${browserPlan.text}`);
    }
    const browserApply = await browserRpc("CreateOrganization", {
      planId: plan.planId,
      confirmationHash: plan.confirmationHash,
      idempotencyKey: browserIdempotencyKey,
    });
    if (browserApply.response.status !== 200
        || browserApply.value?.organization?.slug !== "browser-e2e") {
      throw new Error(`browser API apply failed: ''${browserApply.response.status} ''${browserApply.text}`);
    }
    for (const legacyAsset of [
      "/_assets/hub-console.js",
      "/_assets/hub-console-bootstrap.js",
      "/_assets/hub-console_bg.wasm",
      "/_assets/hub-console.css",
    ]) {
      if ((await fetch(BASE + legacyAsset)).status !== 404) {
        throw new Error(`legacy console asset remained deployed: ''${legacyAsset}`);
      }
    }
    const privateImagesPage = await fetch(
      BASE + "/failure/images-private/-/images",
      { headers: cookieHeaders },
    );
    const privateImagesHtml = await privateImagesPage.text();
    if (privateImagesPage.status !== 200
        || !privateImagesHtml.includes("CDN / CLI")
        || !privateImagesHtml.includes(qcow2Sha256)) {
      throw new Error(`private cookie Images page: ''${privateImagesPage.status} ''${privateImagesHtml}`);
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
    if (privateApi.response.status !== 200
        || !privateApi.text.includes(qcow2Sha256)
        || privateApi.text.includes('"downloadUrl"')
        || privateApi.text.includes('"objectKey"')
        || !privateApi.text.includes('"storePath":"/nix/store/')
        || privateApi.text.includes('"cacheUrls"')) {
      throw new Error(`private image API: ''${privateApi.response.status} ''${privateApi.text}`);
    }
    const privateUrl = privateApi.value?.images?.[0]?.downloadUrl;
    if (privateUrl !== undefined) {
      throw new Error(`private store-backed image exposed a direct download URL: ''${privateUrl}`);
    }

    async function cacheRpc(method, body) {
      const response = await fetch(BASE + `/aos.hub.v1.BinaryCacheService/''${method}`, {
        method: "POST",
        headers: {
          ...headers,
          "content-type": "application/json",
          "connect-protocol-version": "1",
        },
        body: JSON.stringify(body),
      });
      const text = await response.text();
      return { response, text, value: text ? JSON.parse(text) : null };
    }

    async function multipart(cacheId, path, byteSize = 32) {
      const initiated = await cacheRpc("BeginCacheMultipartUpload", {
        delivery_url: BASE + "/" + cacheId,
        path,
        byte_size: byteSize,
      });
      if (initiated.response.status !== 200) {
        throw new Error(`initiate ''${cacheId}/''${path}: ''${initiated.response.status} ''${initiated.text}`);
      }
      const upload = initiated.value;
      const send = async (part, fill) => {
        const response = await fetch(
          BASE + `/aos.hub.v1.BinaryCacheService/UploadPart/''${encodeURIComponent(upload.uploadId)}/''${part}`,
          {
          method: "PUT", headers, body: new Uint8Array(4).fill(fill),
          },
        );
        if (response.status !== 200) throw new Error(`part ''${part}: ''${response.status} ''${await response.text()}`);
        return await response.json();
      };
      const requests = Array.from({ length: 8 }, (_, index) => send(index + 1, index + 1));
      requests.push(send(1, 1));
      const responses = await Promise.all(requests);
      const distinct = responses.slice(0, 8);
      if (responses[8].etag !== distinct[0].etag) throw new Error("same-part retry changed etag");
      const mismatch = await fetch(BASE + `/aos.hub.v1.BinaryCacheService/UploadPart/''${encodeURIComponent(upload.uploadId)}/1`, {
        method: "PUT", headers, body: new Uint8Array(4).fill(99),
      });
      if (mismatch.status < 400) throw new Error("same-part mismatch was accepted");
      const completed = await cacheRpc("CompleteCacheMultipartUpload", {
        upload_id: upload.uploadId,
        parts: distinct.map((part) => ({ part_number: part.partNumber, etag: part.etag })),
      });
      if (completed.response.status !== 200 || completed.value.state !== "completed") {
        throw new Error(`complete ''${cacheId}/''${path}: ''${completed.response.status} ''${completed.text}`);
      }
    }

    await multipart("flat-cache", "nar/flat-path.nar");
    await multipart("failure/cache", "nar/nested/path.nar");

    async function createSingleUpload(cacheId, path, size) {
      const created = await cacheRpc("CreateCacheObjectUploads", {
        delivery_url: BASE + "/" + cacheId,
        path,
        size,
      });
      if (created.response.status !== 200 || !created.value.uploadUrl) {
        throw new Error(`single upload admission: ''${created.response.status} ''${created.text}`);
      }
      return created.value.uploadUrl;
    }

    const builtinBytes = 8 * 1024 * 1024;
    const atBuiltinUrl = await createSingleUpload("flat-cache", "nar/builtin-limit.nar", builtinBytes);
    const atBuiltinLimit = await fetch(atBuiltinUrl, {
      method: "PUT", headers, body: new Uint8Array(builtinBytes),
    });
    if (atBuiltinLimit.status !== 201) {
      throw new Error(`built-in boundary: ''${atBuiltinLimit.status} ''${await atBuiltinLimit.text()}`);
    }
    const overLimitUrl = await createSingleUpload("flat-cache", "nar/too-large.nar", builtinBytes);
    const overLimit = await fetch(overLimitUrl, {
      method: "PUT", headers, body: new Uint8Array(builtinBytes + 1),
    });
    if (overLimit.status !== 413) {
      throw new Error(`built-in over-limit: ''${overLimit.status} ''${await overLimit.text()}`);
    }
    const configuredSingleUrl = await createSingleUpload("flat-cache", "nar/configured-cap.nar", 5);

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

    const cappedSingle = await fetch(configuredSingleUrl, {
      method: "PUT", headers, body: new Uint8Array(5),
    });
    if (cappedSingle.status !== 429) {
      throw new Error(`configured single-upload cap: ''${cappedSingle.status} ''${await cappedSingle.text()}`);
    }
    const cappedInitiated = await cacheRpc("BeginCacheMultipartUpload", {
      delivery_url: BASE + "/flat-cache",
      path: "nar/configured-multipart-cap.nar",
      byte_size: 5,
    });
    if (cappedInitiated.response.status !== 200) {
      throw new Error(`configured multipart initiate: ''${cappedInitiated.response.status} ''${cappedInitiated.text}`);
    }
    const cappedUpload = cappedInitiated.value;
    const cappedPart = await fetch(BASE + `/aos.hub.v1.BinaryCacheService/UploadPart/''${encodeURIComponent(cappedUpload.uploadId)}/1`, {
      method: "PUT", headers, body: new Uint8Array(5),
    });
    if (cappedPart.status !== 429) {
      throw new Error(`configured multipart cap: ''${cappedPart.status} ''${await cappedPart.text()}`);
    }

    console.log("aos-hub-worker do-e2e: PASS");
  '';
in
  mkDerivation {
    pname = "aos-hub-worker-do-e2e";
    version = "0.1.0";

    runtimeDeps = [dist aos nix nodejs workerd-source bash coreutils diffutils grep aos-system-image-e2e-fixture];
    nukeRefsKeep = [workerCapnp driver egressFixture stateFixture];

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
          cleanup() {
            if test -n "\$WPID"; then
              kill -KILL "\$WPID" 2>/dev/null || true
              wait "\$WPID" 2>/dev/null || true
            fi
            rm -rf "\$work"
          }
          trap cleanup EXIT
          cp ${dist}/shim.mjs ${dist}/index.wasm "\$work/"
          cp ${egressFixture} "\$work/fixture.mjs"
          cp ${stateFixture} "\$work/state-fixture.mjs"
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
          ${grep}/bin/grep -q 'aos-e2e.img.zst' "\$work/cli-images.json"
          ${aos}/bin/aos image download \
            --hub http://127.0.0.1:8799 \
            --registry failure/images-public --channel stable --format raw \
            --output "\$work/worker-cli.img" >/dev/null
          ${diffutils}/bin/cmp "\$work/worker-cli.img" "\$(${coreutils}/bin/cat "\$work/producer/raw-path")"
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
          export NIX_REMOTE=""
          ${self}/bin/aos-hub-worker-do-e2e
        '';
      };
    };
  }
