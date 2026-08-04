# Choose the right AOS Hub CLI

The repository ships two Hub command surfaces with different trust boundaries.

| Command | Talks to | Use it for |
| --- | --- | --- |
| `aos-hub` | A native Hub's local SQLite database, local storage, or the deployment provider | Starting and initializing a native server, trusted local administration, indexing, validation, and Worker deployment |
| `aos hub` | A running Hub's public HTTP API | Public reads, token-authorized workflows, integrations, and JSON output |

## Local operator command: `aos-hub`

Build it with:

```sh
nix build .#pkg-aos-hub
```

Most native administration starts with the state root:

```sh
./result/bin/aos-hub --root /var/lib/aos-hub registry list
./result/bin/aos-hub --root /var/lib/aos-hub org list
```

The command groups cover registries, organizations, projects, storage
bindings, caches, indexing, tokens, members, identity providers, domains,
hosted keys, channels, webhooks, validation, mirrors, and instance settings.
Run `aos-hub --help` and `aos-hub <group> --help` for the exact command surface
in your build.

These commands are trusted, out-of-band operations: they act directly on local
state rather than going through HTTP authorization. They do not open a Worker's
Durable Object database. Use the web console, API, or `aos hub` for remote
administration of a Worker deployment.

The `aos-hub worker` group is the exception: it authenticates to Cloudflare and
installs or updates the Worker application. See the
[Cloudflare deployment guide](cloudflare.md).

## Remote client: `aos hub`

Build the repository CLI with:

```sh
nix build .#pkg-aos
```

Public reads work without a token:

```sh
./result/bin/aos hub registry list --hub https://hub.example.com
./result/bin/aos hub registry get acme/cdn --hub https://hub.example.com
```

Exchange a provisioning token for a one-hour access token:

```sh
./result/bin/aos hub login \
  --hub https://hub.example.com \
  --provisioning-token '<aos_...>'
```

Then pass the printed token to authenticated commands:

```sh
./result/bin/aos hub org list \
  --hub https://hub.example.com \
  --token '<access-token>'
```

Use the global `--json` flag for scripts:

```sh
./result/bin/aos --json hub org list \
  --hub https://hub.example.com \
  --token '<access-token>'
```

The remote client includes registry, cache, organization, project, binding,
webhook, instance, audit, changeset, and upload operations. Authorization is
checked by the server for every request. The shipped token-minting flow is
currently aimed at read and publish automation; use the web console or native
operator CLI to bootstrap administrative work rather than assuming an owner JWT
is available.
