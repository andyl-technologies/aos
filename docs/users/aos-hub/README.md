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
publish path. Native deployments also expose direct database
administration through `aos-hub`. Worker deployments are administered through
the web/API surface and the `aos-hub worker` deployment commands.

The Worker does not make every Hub request edge-local. Static assets and
cacheable public facade reads can be served at the edge; console, API, browse,
and write traffic is serialized through one `HubDb` Durable Object. Account for
that control-plane latency and capacity when choosing a deployment.

## Start here

- [Run a local Hub](quickstart.md) creates a signed demo registry and gets a
  working server on localhost.
- [Use the web interface](web.md) covers browsing, sign-in, and the management
  console.
- [Use the API](api.md) covers transport, authentication, and stable endpoint
  patterns.
- [Choose the right CLI](cli.md) distinguishes local operator commands from
  the remote API client.
- [Operate an AOS package registry](../registry/) covers producer keys,
  releases, uploads, channels, and incident response.
- [Deploy the native server](native.md) covers initialization, service
  configuration, storage, backup, and monitoring.
- [Deploy to Cloudflare](cloudflare.md) covers the packaged installer,
  resources, secrets, updates, domains, email, and observability.
