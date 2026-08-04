# aos-hub-worker

This crate is the Cloudflare Worker runtime for AOS Hub. It mounts the shared
Hub web, API, registry, cache, authentication, and publishing surface in a
Worker, backed by:

- SQLite in the `HubDb` Durable Object for relational state;
- R2 for registry and binary-cache surfaces;
- KV as a read-through cache for sessions and frequently read point state;
- Durable Object and edge rate-limit bindings for coordination and request
  budgets;
- a scheduled trigger for indexing and maintenance.

The Worker and native `aos-hub` server share the application core but not their
operator interface. Native administration can act directly on local SQLite.
Worker administration goes through the web/API surface, while deployment and
root bootstrap use `aos-hub worker`.

## Build and deploy

Use the repository packages so the Worker, provider tooling, and installer are
built together:

```sh
nix build .#pkg-aos-hub-cloudflare
```

The canonical user guide is [Deploy AOS Hub to
Cloudflare](../../docs/users/aos-hub/cloudflare.md). It covers the supported
installer, provider resources, secrets, domains, updates, email, and
observability.

This crate's checked-in `wrangler.toml` is an implementation fixture. The
packaged installer generates deployment configuration from the current command
options and bundled Worker artifact; it is the supported operational path.
