# Static CDN domain proof responder

The Hub verifies the TLS terminator with a signed, single-use random challenge.
A direct R2 custom domain cannot generate that response. This Worker serves only
`/.well-known/aos-domain-probe`; the registry's Git, NAR, and image objects retain
their direct R2 delivery.

Configure an exact hostname and immutable endpoint generation with these Worker
variables:

- `PROBE_HOSTNAME`
- `PROBE_ENDPOINT_ID`
- `PROBE_ENDPOINT_GENERATION`
Declare `PROBE_CHALLENGES` as a SQLite Durable Object namespace using
`ProbeChallengeGuard`. Its Ed25519 key is generated and retained inside the
provider's encrypted object storage. No private key is uploaded or returned.
Read the public key from the exact CDN proof path with `?public_key=1`, review
and pin it in the endpoint generation through the Hub API, and set the endpoint
probe provider to `external`. The responder needs no Hub login, storage
credentials, or maintenance key. Keep the object namespace identity stable
across deployments; replacing it requires a new reviewed endpoint key pin.

Attach a Worker route for the exact hostname and
`/.well-known/aos-domain-probe*`. Retain the R2 custom-domain attachment and avoid
a catch-all route. Register and activate delivery through the supported Hub
delivery workflow after its observations are ready. Direct route observation
also requires the controller's signed publication manifest for the exact route
generation and current publication. Remove both `HUB_ROUTE_PUBLICATION_MANIFEST` and
`HUB_ROUTE_PUBLICATION_PUBLIC_KEY` after observation rather than leaving an expired manifest in runtime startup
configuration; prepare a fresh one when the publication or route changes.

For registry setup instructions, configure `HUB_REGISTRY_CACHE_PUBLIC_KEYS` on
the Hub Worker as a JSON object mapping registry slugs to lists of Nix public
keys (`name:base64-of-raw-32-byte-Ed25519-key`). These public keys must match the
`Sig` identifiers and signing keys in the uploaded narinfos. Registry SSH trust
keys remain separate and are used only in the APM and module instructions.
