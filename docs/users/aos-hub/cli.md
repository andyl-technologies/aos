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

Sign in interactively:

```sh
./result/bin/aos hub login \
  --hub https://hub.example.com
```

The CLI prints a browser URL and short approval code. After approval it stores
an access token and rotating refresh credential in
`$XDG_CONFIG_HOME/aos/hub-profiles.json` (or
`$HOME/.config/aos/hub-profiles.json`) with user-only permissions. The selected
Hub becomes the active profile, so authenticated commands need no repeated
connection flags:

```sh
./result/bin/aos hub whoami
./result/bin/aos hub org list
```

`whoami` reports the principal reference, current live role grants, and the
scope, permissions, and expiry carried by the access token. This makes a
server-side role and a deliberately narrower token easy to distinguish.

The access token lasts one hour. The CLI refreshes it automatically before
expiry and rotates the stored refresh credential. Sign out and revoke the
complete refresh-token family with `aos hub logout`; pass `--hub` to remove a
specific stored origin instead of the active one.

Explicit `--hub` and `--token` values take precedence over `AOS_HUB` and
`AOS_TOKEN`, which take precedence over the active profile. Public reads may
still select a Hub explicitly and run without a token.

For non-interactive bootstrap automation, exchange an administrator-issued
provisioning secret explicitly. This prints a one-hour access token but does
not persist a profile:

```sh
./result/bin/aos hub login \
  --hub https://hub.example.com \
  --provisioning-token '<aos_...>'
```

Use the global `--json` flag for scripts:

```sh
./result/bin/aos --json hub org list \
  --hub https://hub.example.com
```

The remote client includes registry, cache, organization, project, binding,
webhook, instance, audit, changeset, and upload operations. Authorization is
checked against current server-side grants for every request; approval never
preserves authority the approving user could not grant.
