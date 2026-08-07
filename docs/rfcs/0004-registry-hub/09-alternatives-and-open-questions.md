## Alternatives considered

- **Extend `aos-server` instead of a new crate.** `aos-server` is a
  build + ephemeral-cache server (views, TTLs, `nix-store --realise`)
  with a tokio/axum/process-spawning core that cannot target Workers.
  The hub's job — tenancy, indexing, static-surface facade — is
  disjoint; what they share (token model, upload endpoints, protos) is
  shared through `aos-proto` and protocol compatibility, not code
  colocation.
- **A JS/TS frontend with a Rust API.** Rejected by requirement (the
  WebUI is Rust→WASM) and by preference: one language across
  `surface/`, `domain/`, and `ui/` lets the browser reuse the exact
  verification and parsing code the server uses, and Leptos SSR gives
  the no-JS baseline a JS framework cannot.
- **The hub as the registry's source of truth** (database-first, à la
  crates.io). Rejected: it would break the property that consumption
  needs no server, put the hub in the trust path, and turn the SQL
  database into a single point of failure. The git surface already *is*
  a database with signatures; the hub indexes it.
- **Password authentication.** Rejected outright: a credential-stuffing
  surface, an awkward memory-hard-KDF story under Workers CPU limits,
  and reset flows that duplicate the magic-link path which must exist
  anyway for recovery.
- **SAML SSO.** No credible Rust/wasm implementation path
  (XML-DSIG); orgs bridge via OIDC. Permanently out of scope.
- **Single-file SPA (base64-inlined WASM in `index.html`).** Rejected:
  ~33% payload inflation, loses streaming instantiation, and saves
  nothing — the static-upload pipeline already handles file sets, and
  the hash-named multi-file layout is what makes SPA upgrades atomic.
- **Dedicated bucket per registry by default.** Rejected on the
  Workers target: R2 bindings are deploy-time static, so dynamic
  buckets forgo the zero-egress path; prefix sharing is sound because
  the data plane never lists. Dedicated buckets remain an opt-in.
- **An ORM / sea-orm for the three-dialect story.** Rejected: the
  schema is small, the D1 driver would still need hand-writing, and
  dialect divergence is better handled by keeping the SQL in sight.
- **gRPC-web or REST-only instead of ConnectRPC.** The repo already
  standardized on ConnectRPC (`aos-proto`, `aos-remote`); Connect's
  JSON mapping doubles as the pragmatic REST surface for third parties.

## Open questions

1. **Provider-custodied signing keys in v1?** Without them the channel console is
   read-only and web config editing is change-request-only; with them
   the hub enters the TCB. Current position: BYO-key first, minimal
   change requests promoted to phase 3 as the mitigation, with immutable
   secret-provider custody an explicit org-level opt-in in phase 4.
2. **How much of `aos-package`'s registry code is wasm-clean today?**
   `types.rs` and `registry/parse.rs` look pure; `registry/git.rs`
   shells out to git. The factoring (direct reuse vs a shared no-IO
   module) needs a spike before phase 1.
3. **Leptos vs Dioxus, and CSR bundle size.** Leptos is the working
   assumption (SSR-first for the no-JS ethos); the phase-1 spike must
   also validate the CSR build for the on-CDN web surface — target
   well under ~500 KB compressed wasm — and the ergonomics of one
   codebase with SSR + CSR profiles.
4. **Range requests through the Workers facade.** R2 supports native
   ranged GETs; the facade should always redirect/proxy ranges to R2
   rather than slicing — verify this covers `apm`'s delta-fetch access
   patterns.
5. ~~**JWT minting on Workers.** `jsonwebtoken` historically depends on
   ring; confirm a RustCrypto path or hand-roll HS256 (`hmac` + `sha2`)
   / EdDSA via `ed25519-dalek`.~~ **Resolved (RFC-0004 Phase 5, console-dedup
   stage F).** The hub's session/bearer HS256 JWTs are minted/verified with
   pure-Rust `hmac` + `sha2` (`core::auth::jwt`), and the OIDC id_token RS256
   verification uses `jwt-rustcrypto` over the RustCrypto `rsa` crate — no ring,
   no C — so `core` (and the Worker) build to `wasm32-unknown-unknown` with no C
   toolchain. (`ring`/`jsonwebtoken` *can* be made to compile to wasm by giving
   AOS clang the WebAssembly target, but the pure-Rust path makes that
   unnecessary for the registry.) `getrandom`'s js feature + the
   `getrandom_backend="wasm_js"` rustflag are wired in `crates/.cargo/config.toml`.
   `openidconnect` was not adopted; the OIDC flow is the hand-written PKCE +
   `jwt-rustcrypto` verifier in `core::auth::oidc`.
6. **The in-house passkey verifier spike.** Attestation-`none` RP
   verification is ~500–800 lines on RustCrypto crates with W3C test
   vectors; if it overruns, magic links carry phase 2 alone and
   passkeys slip a phase (or `webauthn-rs` lands its OpenSSL removal
   and slots in behind the same trait).
7. **Exact `[cache_stack]` schema and rollout.** The flattened
   `[[caches]]` compatibility layer is settled; the committed
   expression encoding (inline TOML tables vs a parallel section) and
   the `apm` stack-resolution semantics need a short design pass with
   the `apm` miss-fallthrough change.
8. **R2 dynamic bindings and temp credentials.** Workers R2 bindings
   are deploy-time static today, which shapes the shared-bucket
   default — re-verify (dispatch namespaces et al.) before phase 2
   locks the provisioning model. Likewise, R2 temporary-credential
   prefix scoping (load-bearing for shared-bucket direct upload) is
   documented but should be validated in practice in the same spike.
9. **SSO timing for the first deployment.** Magic links + passkeys are
   sufficient for the bootstrap team; if Andyl needs org SSO sooner
   than phase 3, OIDC moves up.
10. **"Full IPAM."** This RFC reads the requirement as full **IAM**
    (identity and access management). If IP/host management for fleet
    operators (host inventory, per-host partition buckets) is also
    intended, that is a separate consumer-side design.
11. **Hermetic workerd.** `workerd` builds with Bazel and the repo
    already builds Bazel from source, so a hermetic workerd AOS
    package is plausible — but it drags in a V8 build, a heavy chain.
    Decide its priority relative to the in-tree-fakes + staging-deploy
    tiers of the testing story.
