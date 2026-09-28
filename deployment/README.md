# Signed AOS Hub hybrid staging delivery

`application-project.nix` is application intent. The public hostname is the
Worker; the separately reviewed origin reaches the Native service. The Native
service owns PostgreSQL and ordinary application APIs. Infrastructure selects
the external runtime identity, Cloud SQL, TCP readiness and eleven pinned
private credential files. No provider coordinates or credentials belong here.

The new `delivery-hub-staging.yml` runs only for a same-repository push to
`dplecki/hub-hybrid-topology`, using the exact registered workflow identity.
It reconciles the base graph, builds and qualifies the actual image, catalogs
the image, scans both that catalog and the AOS closure SPDX, uploads one
immutable v2 artifact through the dedicated intake audience, then submits the
anchored signed release graph through the staging audience. Infrastructure
owns graph expansion, signatures, Cloud Deploy and runtime continuations.

## Required live registration

Before the workflow can succeed, reviewed infra registration for
`aos-hub-hybrid` must be published from protected master, independently
qualified and selected by the signed staging engine channel. A local grant or
provider apply does not install application source admission. Keep the two
protected GitHub environments separate:

| Environment | Role | WIF audience |
| --- | --- | --- |
| `aos-hub-hybrid-staging-artifact` | Artifact intake only | `https://github.com/andyl-technologies/aos/delivery/staging/artifact` |
| `aos-hub-hybrid-staging` | Registered staging reconciliation | `https://github.com/andyl-technologies/aos/delivery/staging/staging` |

Each environment receives its own emitted `DELIVERY_WORKLOAD_IDENTITY_PROVIDER`,
`DELIVERY_SERVICE_ACCOUNT`, `DELIVERY_WIF_AUDIENCE`, and `DELIVERY_ENDPOINT`.
They are API-only identities. No service-account key, provider permission,
signing key, registry credential or direct infrastructure workflow belongs in
the application workflow. These protections and CODEOWNERS must be configured
with actual repository reviewers before accepting production authority.

Actual applied identities, archive recipients, signing/trust/evidence outputs,
eleven enabled secret versions and initialized PostgreSQL are prerequisites.
The service artifact neither creates those resources nor initializes state on
every rollout. See the existing Hub hybrid deployment maintainer runbook.

## Evidence and scanning

The build gate runs actual container reproducibility, the Native container
fleet check and hybrid fleet check. It uses AOS-built Python, Git, Grype and
Syft, with no nixpkgs tools. The database is an independently fetched,
SHA-256-pinned official archive exposed by
`pkgs.grype.passthru.databaseArchive`; automatic updates are disabled. Integrity,
schema and a 120-hour build-age bound are enforced. Refresh the reviewed pin
when it expires; do not disable the age check.

The bundle retains actual image catalog, closure SPDX and original AOS build
provenance, along with actual Grype reports and exact Git source/configuration
digests. Normalizing the component source tag changes only the OCI index tag;
the wrapper records both original and normalized index digests. Static Rust
inventory is augmented from the compiler-artifact messages present in the final
Hub image, using actual crates.io package IDs and excluding proc-macro, build
script, test and executable records. These are conservative compiled-library
candidates; some build-only libraries may remain. The evidence retains the
metadata source hash and the selection rules. Static Rust and Nix package
recognition must be audited from real artifact evidence before
claiming full vulnerability coverage. Empty package recognition cannot pass
the catalog gate. Zero findings alone do not establish qualification.

Unit scanner fixtures test bytes and rejection behavior only. They never
supply workflow evidence, a signed receipt or a real qualification claim.
The release workflow fails closed when registration or evidence is missing.

Before submitting the signed Native rollout, deploy and configure the
independently named Worker at `hub-hybrid.staging.andyl.com`. Its R2 attachment,
deployment ID, Native origin setting and shared ingress/storage keys must match
the reviewed pair. Provision its Cloudflare hostname/route and actual secrets
through the existing operator runbook. The signed storage capability endpoint
and versioned console assets are served locally by the Worker and must work
while the Native origin is unavailable. Native checks both before opening its
listener, so the Worker must already be reachable.

Then submit the signed Native rollout and its single policy/backend
continuation. Once Native is listening and the rollout settles, qualify the
HTTPS origin and public Worker/Native pair, and run hosted fleet/browser checks
before accepting the public hub. Cloud Run TCP readiness alone does not
establish successful hybrid operation. This workflow does not claim that those
hosted checks or pairing have already succeeded.

## Resuming observation

The client prints and writes the operation name immediately after submission.
If an observation deadline expires, inspect that existing operation through
the registered API instead of creating another release. In the same exact
workflow/source context, `aos-delivery watch --endpoint URL --source-sha SHA
--declaration FILE --phase application --operation operations/NAME` observes
a base graph without resubmitting. Release observation selects `--phase
release-graph` and requires the original `--artifact-coordinate FILE` and
`--generation-anchor operations/NAME`. The client fences the full public source,
registered target, retained artifact and engine anchor before observation.
The caller must still have the appropriate current API and GitHub proofs.
