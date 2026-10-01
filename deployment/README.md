# Local AOS Hub hybrid delivery

Build, test and deploy the Hub from a trusted local AOS environment. GitHub
Actions and CI are not part of the delivery or qualification procedure. Use the
[hybrid deployment runbook](../docs/maintainers/aos-hub-hybrid-deployment.md) for
the Worker-fronted Native service and the
[manual Worker deployment runbook](../docs/maintainers/aos-hub-deployment.md) for
Workers-only serving.

`application-project.nix` remains the application-owned Native deployment
intent. Runtime identities, PostgreSQL and protected credential files must be
selected and provisioned separately. The declaration does not create resources,
initialize state or establish a successful serving revision.

## Local build and qualification

Pin one exact source commit and retain the actual image, source and qualification
receipts. The existing local targets remain available:

```sh
nix-build -A containerImages.aos-hub.ociIndex --no-out-link
nix-build -A containerImages.aos-hub.evidence --no-out-link
nix-build -A containerImages.aos-hub.checks.reproducibility --no-out-link
nix-build -A checks.fleet.hub-native-container --no-out-link
nix-build -A checks.fleet.hub-hybrid --no-out-link
```

Run targeted Native process, Worker runtime and fleet checks using matching
source-built AOS tools and artifacts. Preserve failures and pending gates;
successful image construction or TCP readiness alone does not qualify the
Worker/Native pair or its provider paths.

The local artifact inventory/scanning sources and `pkgs.grype`/`pkgs.syft`
packages remain available. Use an independently fetched, SHA-256-pinned
vulnerability database and retain its integrity, schema and age checks. Empty
package recognition or zero findings does not establish complete coverage or
runtime qualification.

## Deployment and publisher status

Follow the operator runbooks to install protected configuration and match the
Worker's deployment identity, storage attachment, Native origin and shared
ingress/storage keys. Qualify the actual installed source and unchanged runtime
before enabling independently accepted provider work.

The former Actions-specific `aos-delivery` transport is retired from the
delivery procedure. Its source remains for the separate local publisher
implementation; it currently requires an Actions identity proof and is not a
working manual publisher. Do not fabricate workflow environment values or
bypass its source/authentication checks. A local replacement must preserve
exact source/artifact commitments and the independently authorized deployment
protocol. No automated release submission is claimed here.
