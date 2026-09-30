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
- `PROBE_PUBLIC_KEY_SHA256`, the hexadecimal SHA-256 digest of the raw Ed25519
  public key pinned in the endpoint revision

Supply `PROBE_SIGNING_PKCS8` as a Worker secret containing the base64-encoded
PKCS#8 Ed25519 private key. Verify the private key matches the endpoint's public
key before deployment. Declare `PROBE_CHALLENGES` as a SQLite Durable Object
namespace using `ProbeChallengeGuard`. Set the endpoint's probe provider to
`external` and its secret reference to the operator's dedicated responder key
identity. Each deployment uses its own key; the responder needs no Hub login,
storage credentials, or maintenance key.

Attach a Worker route for the exact hostname and
`/.well-known/aos-domain-probe*`. Retain the R2 custom-domain attachment and avoid
a catch-all route. Register and activate delivery through the supported Hub
delivery workflow after its observations are ready. Direct route observation
also requires the controller's signed publication manifest for the exact route
generation and current publication. Remove that temporary controller manifest
after observation rather than leaving an expired manifest in runtime startup
configuration; prepare a fresh one when the publication or route changes.
