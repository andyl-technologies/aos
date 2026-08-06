### Sequencing

References to *v1* elsewhere in this document mean the end of
phase 2 — the first generally usable release.

1. **Read-only hub** (highest value, lowest risk): `surface/` reader +
   indexer, public browse UI, nix-cache/dumb-HTTP facade,
   **consistency validation** (read-only by nature) and frontend
   freshness probes. Deploy on Cloudflare against the existing
   `cdn.aos.andyl.org` bucket in registration-only mode. Since
   tenancy arrives in phase 2, phase-1 registries are **instance-level
   records** — created by instance config or CLI, owned by no org,
   served at a flat configured slug — and are adopted into an org
   (acquiring the canonical `{org}/{proj…}/{registry}` URL, with a
   redirect from the flat slug) when tenancy lands. In parallel
   (phase 1): `apr web generate` and the phase-major upload fix.
2. **Tenancy + tokens + upload facade**: orgs/projects/IAM, magic
   links + the passkey verifier spike, device-flow login, storage
   bindings + registry creation (hub-managed R2 + BYO), the AOS-mode
   upload endpoints so `apr release` targets the hub; private
   registries.
3. **Producer console**: publish pipeline view, channel console, key
   rotation wizard, configuration change-sets + minimal change
   requests, per-org OIDC SSO, hub-driven mirror jobs + pull-through
   frontends, cache stacks (with the `apm` miss-fallthrough change),
   audit.
4. **Provider-custodied signing generations, derived registries, fuller change-request review,
   webhooks/notifications**; postgres/mysql drivers hardened; AOS
   package + module for self-hosting; `[registry.upstream]` and
   `[[origins]]` if demand materializes.
