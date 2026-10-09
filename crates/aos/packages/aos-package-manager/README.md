# aos-package-manager

AOS package installation and runtime policy for the `apm` application. This
crate resolves requested packages, maintains user and system generations,
coordinates image transitions, and enforces container admission before effects
begin. It also applies those admission rules before the `apr` application
dispatches registry authoring commands.

Shared responsibilities have separate owners:

- `aos-registry-format` defines portable registry documents and identities.
- `aos-registry-client` reads and verifies registries, acquires their metadata,
  and owns consumer configuration and trust.
- `aos-registry-authoring` writes registry workspaces and publishes artifacts.
- `aos-deployment-format` defines portable deployment, admission, resolution,
  evaluation-input, and installed-inventory documents.
- `aos-deployment` evaluates immutable inputs and executes retained, journaled
  deployment transactions independently of package-manager state.

Package selection, profile publication, credentials, package attestation, and
system-image rollout policy remain here. `update` orchestrates configured
registry refreshes, consumer state persistence, aggregate errors, and the
`apm update` presentation. Consumers that only need a registry
document or deployment operation should depend on its owning library directly.
