# Operate AOS Hub

AOS Hub hosts AOS package registries and binary caches. It provides a web
console for people, an HTTP API for automation, and the Git- and Nix-compatible
surfaces consumed by AOS tools.

The same application is available in two forms:

| Deployment | State | Storage | Best fit |
| --- | --- | --- | --- |
| [Native server](native.md) | Local SQLite | Local filesystem or S3-compatible storage | AOS systems, private infrastructure, and deployments where you operate the host |
| [Cloudflare Worker](cloudflare.md) | SQLite in a Durable Object | R2, with KV as a session/hot-state cache | Cloudflare-operated deployment with edge-cached assets and public facade reads |

Both forms serve the web interface, HTTP API, registry facade, and managed
publish path, and both are administered through the console, the API, and the
remote `aos hub` client. The local `aos-hub` command initializes and recovers a
native deployment and, through `aos-hub worker`, deploys the Worker.

The Worker does not make every Hub request edge-local. Static assets and
cacheable public registry reads can be served at the edge; every other request
is answered from one authoritative database. The
[Hub engineering documentation](../../engineering/hub/README.md) describes that
execution model.

## Start here

Follow these in order for a first deployment:

1. [Run a local Hub](quickstart.md) creates a signed demo registry and gets a
   working server on localhost.
2. [Trust an internal AOS Hub deployment](trust.md) defines signing authority,
   client bootstrap, hosted-key tradeoffs, access boundaries, and recovery.
   Read it before choosing where keys and credentials live.
3. Deploy one form: [Deploy the native server](native.md) covers
   initialization, service configuration, TLS, and storage;
   [Deploy to Cloudflare](cloudflare.md) covers the packaged installer,
   resources, secrets, updates, domains, email, and observability.
4. [Operate AOS Hub in production](production.md) covers topology, TLS,
   identity, backup and recovery, storage retention, monitoring, upgrades, and
   incidents.
5. [Operate an AOS package registry](../registry/) covers producer keys,
   releases, uploads, channels, and incident response.

Use these as reference once the Hub is running:

- [Use the web interface](web.md) covers browsing, sign-in, and the console.
- [Choose the right CLI](cli.md) distinguishes the local `aos-hub` command
  from the remote `aos hub` client.
- [Use the API](api.md) covers transport, authentication, and stable endpoint
  patterns.
- [Set up a delivery destination](delivery.md) connects existing CDN and storage
  infrastructure through reviewed setup, verification, and activation.
- [Serve OCI containers](oci-containers.md) covers rollout gates and pull and
  push behavior; the [OCI GC runbook](oci-gc.md) covers container
  administration and garbage collection.
- [Hub engineering documentation](../../engineering/hub/README.md) explains
  the runtime, tenancy, topology, delivery, and retention model.

## Native runtime ability documents

A runtime ability document is the generated reference for a package's module
options and operations, or a desired package transaction; see
[runtime abilities](../aos/runtime-abilities.md).

The [runtime ability viewer](web.md#inspect-native-runtime-ability-documents)
browses generated module references and deferred transactions, including package
relationships and desired execution paths. Imported artifacts use the
stateless viewer. Published native references also appear in authenticated
release search and package pages with exact release and document-digest pins.
See the [documentation API](api.md#read-native-release-documentation) and
[CLI examples](cli.md#read-published-native-documentation).
