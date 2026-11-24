# Choose the right AOS Hub CLI

The repository ships two Hub command surfaces with different trust boundaries.

| Command | Talks to | Use it for |
| --- | --- | --- |
| `aos-hub` | A native Hub's local SQLite database, or the deployment provider | Starting and initializing a native server, root-account recovery, on-demand indexing, and Worker deployment |
| `aos hub` | A running Hub's public HTTP API | All resource administration on either deployment, public reads, integrations, and JSON output |

## Local operator command: `aos-hub`

Build it with:

```sh
nix build .#pkg-aos-hub
```

The command surface is deliberately small. Every command except `worker`
acts on the state root named by `--root`:

| Command | Purpose |
| --- | --- |
| `serve` | Run the Hub server |
| `init` | Create or migrate the database and optionally bootstrap the root administrator |
| `reset-root` | Reset or create a root administrator's password |
| `index [slug]` | Re-index one registry, or every registry, now |
| `schema dump` | Print the migration statements as a JSON array |
| `worker` | Deploy and manage the Cloudflare Worker |

```sh
./result/bin/aos-hub --root /var/lib/aos-hub index
```

Run `aos-hub --help` and `aos-hub <command> --help` for the exact flags in
your build.

The state-root commands are trusted, out-of-band operations: they act directly
on local state rather than going through HTTP authorization. They do not open a
Worker's Durable Object database.

`aos-hub` has no commands for organizations, registries, bindings, caches,
tokens, members, or instance settings. Administer those through the console,
the API, or `aos hub` on both native and Worker deployments.

The `aos-hub worker` group is the exception: it authenticates to Cloudflare and
installs or updates the Worker application. See the
[Cloudflare deployment guide](cloudflare.md).

## Remote client: `aos hub`

Most changes follow one reviewed plan/apply flow. A planning command prints the
effects together with a plan ID and confirmation hash; a second command applies
that exact plan. Depending on the command group, planning is either a `plan`
subcommand or a `--plan` flag, and applying is either an `apply` subcommand or
the same command with `--plan-id`, `--confirm-hash`, and `--yes`. Reuse an
`--idempotency-key` when retrying a request whose response was lost.

### Build and sign in

Build the repository CLI with:

```sh
nix build .#pkg-aos
```

Public reads work without a token:

```sh
./result/bin/aos hub registry list --hub https://hub.example.com
./result/bin/aos hub registry show acme/cdn --hub https://hub.example.com
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

### Access tokens

Bearer credentials are scoped access tokens. Copy a canonical scope from
`aos hub whoami`, then grant permission verbs such as `read` and `publish`:

```sh
aos hub access-token list 'registry:0123456789abcdef0123456789abcdef'
aos hub access-token issue plan \
  'registry:0123456789abcdef0123456789abcdef' \
  --owner 'service_account:acme/publisher' \
  --permission read \
  --permission publish \
  --comment 'release publisher' \
  --idempotency-key 'plan-release-publisher'
```

Issuance and retirement use the reviewed plan/apply flow. The secret is
printed only by a successful first apply. Tokens default to 30 days and may
not exceed 90 days; the server rechecks the owner's current role authority when
applying the plan.

### Service accounts

Service accounts belong to one organization:

```sh
aos hub org service-account list acme
aos hub org service-account show acme publisher
aos hub org service-account create plan acme publisher \
  --idempotency-key 'plan-create-publisher'
```

`update plan` renames an account while retaining its stable principal identity,
memberships, and token ownership. `delete plan` removes its direct memberships
atomically and immediately deadens its owned credentials. Both require the
`resource_version` returned by list or show.

### Invitations

Manage invitations beneath their owning organization:

```sh
aos hub org invitation list acme
aos hub org invitation create plan acme new.member@example.com \
  --scope 'org:0123456789abcdef0123456789abcdef' \
  --role developer \
  --idempotency-key 'invite-new-member'
aos hub org invitation accept acme --secret "$AOS_INVITATION_SECRET"
```

Apply the create plan to receive the acceptance secret. An interrupted client
may retry with the exact same plan and apply idempotency key to recover the same
secret; another key is rejected. The administrator
delivers that secret to the exact invited email. `cancel plan` requires the
invitation `resource_version` returned by list or show. Accepting creates the
membership atomically; creating an invitation never creates a user or grants
authority. Use global `--json` for stable machine-readable output.

### Organization SSO

Organization SSO has two resources, an identity provider and its email
domains:

```sh
aos hub org identity-provider show acme
AOS_OIDC_CLIENT_SECRET='<secret>' \
  aos hub org identity-provider set plan acme \
    --issuer https://idp.example.com \
    --authorization-endpoint https://idp.example.com/authorize \
    --token-endpoint https://idp.example.com/token \
    --jwks-uri https://idp.example.com/jwks \
    --client-id aos-hub \
    --if-version absent \
    --idempotency-key plan-acme-idp

aos hub org domain claim plan acme login.example.com \
  --if-version absent \
  --idempotency-key plan-acme-domain
```

A resource that does not exist yet requires `--if-version absent`; later
changes use the `resource_version` returned by the previous read or apply.

Apply the domain claim, publish the returned `txt_challenge`, then run
`org domain verify plan` with the returned `resource_version`. Applying the
verification plan resolves DNS and commits only an exact TXT match. Use
`identity-provider set plan --clear-client-secret` to convert an existing
confidential client to a public client; omitting both the environment variable
and that flag preserves the existing sealed credential. Every set, remove,
claim, verify, and release operation uses the same explicit `plan` then `apply`
flow.

### Storage bindings

A binding is a named storage location that registries and caches refer to, so
provider credentials are never embedded in a registry or cache. A Worker
deployment can refer directly to one of its R2 bindings; no S3 endpoint or R2
API token is needed for that provider kind:

```sh
aos hub binding create \
  --org acme \
  --name worker-objects \
  --kind deployment-r2 \
  --bucket-binding STORAGE \
  --plan \
  --idempotency-key plan-worker-objects
```

Review the returned effects and apply the exact plan with `--plan-id`,
`--confirm-hash`, and `--yes`. Use `--kind s3` or `--kind r2` with `--bucket`,
`--endpoint`, `--region`, and `--access` when the Hub reaches storage through
an HTTP object API, or `--kind local-fs` with an absolute `--root` on a native
Hub. Credentials are separate purpose-scoped secret-version
references and can be rotated or validated without replacing the binding.

### Delivery resources

For coordinated CDN setup, prefer the [delivery workflow](delivery.md). Its
`plan`, `apply`, `show`, `list`, `resume`, and `activate` commands preserve
reviewed intent and expose durable progress across interrupted sessions. The
commands below edit the same resources individually.

Delivery resources also use reviewed plans. Creation commands generate an
opaque stable identity and print it in the plan; pass `--stable-id` when an
external controller needs to choose that identity. A network policy seals a
complete initial revision at creation time, including its transport policy and
the controller location that will verify it:

```sh
aos hub network-policy add packages-edge \
  --kind trusted-ingress \
  --org acme \
  --provider cloudflare \
  --provider-account production \
  --listener-id packages-worker \
  --protected-transport required \
  --probe-location cloudflare-worker \
  --idempotency-key plan-packages-boundary \
  --plan
```

HTTPS endpoints require an explicit record of where TLS terminates:

```sh
aos hub endpoint add https://packages.example.com \
  --org acme \
  --network-policy instance:public@1 \
  --ingress hub \
  --listener-provider hub-worker \
  --listener-resource-id packages-edge \
  --tls-provider external \
  --certificate-ref edge-certificate:packages.example.com \
  --probe-provider worker-secret \
  --probe-signer-secret-ref packages-endpoint-v1 \
  --probe-public-key '<base64url-no-padding Ed25519 public key>' \
  --idempotency-key plan-packages-endpoint
```

Use `--tls-provider hub-managed` when the Hub owns certificate issuance.
Cleartext endpoints require `--acknowledge-cleartext` and reject TLS options.
The probe identity pins the responder key for this immutable endpoint
generation; its matching private seed stays in the named runtime secret
provider and rotates only through a new generation.

Verify a delivery domain by hostname or stable identity after its endpoint and
probe signer are configured:

```sh
aos hub domain verify packages.example.com \
  --if-version <domain-resource-version> \
  --idempotency-key verify-packages-example \
  --plan
```

The probe response is signed over the request nonce, hostname, endpoint
identity, and exact endpoint generation. Applying successful evidence advances
the domain observation and promotes that endpoint generation to healthy in one
transaction. Enabled routes that previously failed while the endpoint was not
ready are queued for a fresh probe automatically; they do not need to be
recreated. A concurrently revised endpoint causes the entire reconciliation to
fail closed without advancing either resource.

Routes are created disabled. Enabling a route queues its current configuration
probe, and the route remains ineligible for traffic until that probe succeeds.
Use `aos hub route explain` with
`--access-class web`, `git`, or `nix_cache` to inspect the selected access
policy, publication, and placement before enabling a route. Route advertisement
selection is explicit and independent for the `web`, `git`, and `nix_cache`
audiences, and includes the typed surface so one route identity cannot be
selected for the wrong registry or cache. Deployment settings never synthesize
routes or advertisements:

```sh
aos hub route canonical registry:acme/packages route:packages-public \
  --audience nix_cache \
  --plan
```

The remote client includes registry, cache, organization, project, binding,
webhook, instance, audit, changeset, and upload operations. Authorization is
checked against current server-side grants for every request; approval never
preserves authority the approving user could not grant.

### Topology and placements

Inspect the physical topology without internal storage identifiers:

```sh
aos hub surface explain cache:acme/builds \
  --url https://cache.example/nar/object.nar.zst \
  --path /nar/object.nar.zst \
  --access-class nix_cache
aos hub placement presence cache:acme/builds nar/object.nar.zst
```

Cache placement eviction is distinct from logical GC and always uses the
stable surface-local placement name and reviewed plan:

```sh
aos hub placement eviction plan cache:acme/builds primary \
  --if-version <version> --idempotency-key <key>
aos hub placement eviction run --plan-id <id> --confirm-hash <hash> \
  --idempotency-key <key> --yes
```

Package and registry producer commands use the same cache upload admission and
multipart API as the console; direct storage capabilities never receive a
Hub bearer.

## Inspect native ability artifacts locally

Use the same native reader as the Hub viewer without contacting a server:

```sh
aos docs runtime options.json
aos docs runtime transaction.json --format html --output execution.html
```

This inspects exported artifacts through the same native reader used by
installed-package documentation, release search, and package pages. See
[runtime abilities](../aos/runtime-abilities.md) for code examples and
[the viewer](web.md#inspect-native-runtime-ability-documents) for imported documents.

## Read published native documentation

Use `aos hub docs` with the registry's normal read credentials:

```sh
aos hub docs search enable --registry acme/packages --kind option
aos hub docs package sample --registry acme/packages --version 1.0 --platform x86_64-linux
aos hub docs option sample --registry acme/packages --version 1.0 --platform x86_64-linux --prefix aos.sample
aos hub docs fetch sample --registry acme/packages --version 1.0 --platform x86_64-linux --output options.json
aos hub docs open sample --registry acme/packages --version 1.0 --platform x86_64-linux
aos hub docs compare sample --registry acme/packages --from 1.0 --to 2.0 --platform x86_64-linux
```

Search kinds are `package`, `option`, and `operation`. Results retain release,
registry commit, and document digest alongside package/version/platform.
`fetch` verifies exact bytes before writing them; `open` prints a browser URL
pinned to the selected release and digest. Omitting version/platform requests
Hub's deterministic default selection. The CLI package commands do not expose
a release selector; use the documentation RPC when an explicit release pin is
required.

`package` renders the same native reference as the browser, including complete
recursive input/result contracts and each operation's declaring, handling, and
consuming owners. When declared, it also shows independent ability contract
versions and requester-qualified module requirements. These requirements are
source declarations, not a solver result. `option` lists typed native declarations,
with optional owner, prefix, portable type JSON, and extensibility filters. Comparisons cover option
types and mutability/extension policy, operation inputs/results, handler
availability, configured instances, interface release versions/owners, and module
requirements. They exclude prose and do not report live runtime state.


## Inspect release operations and report a deployment

```sh
aos hub docs abilities --registry acme/packages --release 1.0.0 --platform x86_64-linux
aos ability inspect transaction.json --format html
aos ability compare before.json after.json
aos ability removal-preview transaction.json --effect '<exact-effect-identity>'
aos ability diagnostic /var/lib/apm/profiles/default 3
aos ability journal activation.journal --format json
```

`abilities` verifies the exact native references in the selected completed
release. Local inspection accepts native documentation and desired transactions;
transaction comparison tracks semantic effect revisions. Removal preview bounds
a traversal of desired dependencies. Diagnostic output separates a committed
profile's desired graph from retained output values and does not verify live
state. Its default audience redacts protected details. `journal` reads a
bounded native activation journal through the checked replay reader, showing
recorded pending dispatch identities, completed transactions, and retained
outputs without repairing or executing anything. The public journal command can
observe a checked prefix while the manager runs; see the runtime guide's
[journal inspection semantics](../aos/runtime-abilities.md#journal-inspection).

An already enrolled reporter can submit a checked desired transaction and
optional named result assertions:

```sh
aos hub docs report --registry acme/packages --release 1.0.0 \
  --package sample --version 1.0 --platform x86_64-linux \
  --transaction transaction.json --outputs results.json \
  --deployment sample-production --sequence 8 --reporter-resource-version 2
```

The next sequence must exceed the slot's current sequence. The report lifetime
is at most 300 seconds. Hub checks the reference, native graph, and reported
result types; receiving a report does not establish that its desired effects
are running or its result assertions remain true.
