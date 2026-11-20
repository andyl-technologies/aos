# Canonical release coordinator

Each registry carries its own channels. `andyl/main` carries `edge`,
`candidate`, and `stable`. `andyl/experimental`, and each `andyl/experimental-vN` epoch,
carries `edge` only. Main requires strict build and publication provenance for
every channel; the experimental registry isolates the experimental pipeline and its keys. The experimental registry
releases never become main releases by changing a channel or copying signed
artifacts.

Disk images and OCI containers must configure APM for their exact publishing
registry. The shared `aos.release` profile supplies the registry URL
(`<registryOrigin>/<registry>/`, by default
`https://cdn.aos.andyl.org/<registry>/`), the default Hub (`hubUrl`), trust
alias, root epoch, channel, and experimental notice. Planning, building, and image
finalization check this profile from the clean source commit frozen in the
plan, on every selected platform. An experimental profile fails a main plan and vice
versa. Every image's baked `hubUrl` must equal the origin of the Hub surface
consumers will install from: the production surface when the plan has any
production destination (the same signed bytes reach production, and staging
exercises them with an explicit cache override), or the staging surface for a
staging-only plan. Build the `aos-experimental-staging` variant for staging-only
plans on the canonical staging Hub, as described in
[the Hub deployment guide](aos-hub-deployment.md#build-artifacts-for-the-staging-destination).
A static surface has no Hub origin to bind. Package
transactions, manifests, evidence, and channel receipts bind the same registry;
packages inherit their client's configured registry when installed. Inspect the
destinations and their obligations with
`aos maintain release step contract --registry andyl/experimental` or
`--registry andyl/main` before starting a release.

Start with the [release checklist](release-checklist.md) for the order of
operations and the conditions for proceeding. This page introduces the
coordinator and links its command reference pages;
the [qualification specification](qualification.md) defines destinations,
profiles, fitness attestations, and the evidence. New plans embed the
source-controlled contract in `aos.release.plan/v1`.

Canonical AOS releases are driven by one reviewed plan. The plan freezes the
source revision, registry base, complete package and image matrices, signer
roles, both publication surfaces, every destination with its profile digest,
gates, soak, and rollout rings, the change scope, any accepted profile
override, and the retention policy before a build or signing effect occurs.

The role boundaries and compromise implications behind this procedure are
defined in [Maintain the AOS trust model](trust-model.md).

The command surface has two layers:

- **Porcelain.** `aos maintain release new`, `advance`, `publish`, `status`, `explain`, `review`,
  and `fitness` operate a release from the
  [maintainer configuration](release-maintainer-machine.md#maintainer-configuration) and a
  [work directory](release-commands.md#work-directory-layout). They are the normal interface.
- **Steps.** `aos maintain release step ...` exposes each fail-closed operation with
  explicit inputs. The porcelain calls the same functions in process; it never
  spawns itself. Use steps directly for recovery, audit, qualification
  snapshots, and inspection of captured evidence.

Every operation is fail-closed. A surface may be an AOS Hub deployment or a
[static origin](release-static-surfaces.md#static-surfaces); no command requires a Hub unless the plan
names one.

Supported publication to `andyl/main` remains forbidden until its remaining
launch gates are complete. The experimental `andyl/experimental` registry
may be published to its production surface only under
[`registry-experimental.md`](registry-experimental.md); that does not satisfy or bypass
any main-registry launch gate.

The canonical release image profile enables external Secure Boot, distinct
module and PCR-policy roles, lockdown, measured boot, encrypted state,
dm-verity, signed recovery, audit, firewalling, and the hardened runtime
preset. It deliberately reports SELinux as excluded: the current immutable
root is not pre-labeled, so enabling the existing policy would overstate the
MAC boundary. SELinux may enter the production profile only with labeled-root
construction and an enforcing boot qualification gate.

## Pages

| Page | Contents |
| --- | --- |
| [Release commands](release-commands.md) | The `aos maintain release` porcelain: `new`, `advance`, `publish`, `status`, `explain`, `review`, and `fitness`, emergency overrides, and the work directory layout |
| [Release maintainer machine and configuration](release-maintainer-machine.md) | The coordinator services, the release tooling closure, the maintainer configuration file, and Hub credentials |
| [Release step commands](release-step-commands.md) | Every `aos maintain release step` operation with its inputs, outputs, and checks |
| [Static release surfaces](release-static-surfaces.md) | Origin schemes, supported surface pairs, surface identity, layout, channels, and receipts without a Hub |

## Exercise the complete Hub transition in a fleet

Native Hub deployments terminate TLS in `aos-hub` itself. Configure
`aos.registry-hub.listen` for the public listener, set an HTTPS `externalUrl`,
and supply the `tlsCertificate` and `tlsPrivateKey` credential names. The
listener rejects missing or unexpected SNI and injects HTTPS route evidence
only after a successful rustls handshake; the Hub does not infer security from
forgeable forwarding headers. Keep the private key in the deployment secret
provider and rotate it by replacing the systemd credential followed by a
service restart.

`checks.fleet.native-hub-release-pipeline` is the production-shaped acceptance
test for the online half of this runbook. It boots separate native staging and
production Hub machines with distinct deployment identities, publication keys,
and channel keys using native TLS at the canonical hostnames. The Hub system module
loads every private signing seed and trust map through systemd credentials; a
partial release-evidence configuration fails evaluation.

The publisher is the only machine with `hostStoreMount = true`. It mounts the
host Nix store read-only through the fleet 9p device, binds and registers only
four small prebuilt fixture closures, and exports one NAR for each package cell:
`x86_64-linux`, `aarch64-linux`, `x86_64-darwin`, and `aarch64-darwin`. Those
payloads are not rebuilt into any guest image. Darwin participates only in the
package and qualification matrix; no Darwin image cell is created.

The test initializes both empty native Hubs and creates the public
`andyl/main` delivery topology through reviewed `aos hub` operations, without
any publication. The release is therefore the registry's first: the publisher
approves a real `aos hub login` device ceremony for staging and configures
production with `token_credential`, shows that `new` refuses the
unbootstrapped staging surface without `--first-release` and refuses a dirty
authoring clone, and derives the request with
`new --first-release --source-registry --request-only` from the single-commit
clone `apr create` wrote. The fixture then stands in for the Nix-evaluated
`step plan` leaf, which needs an AOS source checkout the fleet does not carry:
it freezes the request's base, generation, surfaces, and destinations into a
plan around the four prebuilt package cells. Threshold-signed intents install
that base with `step bootstrap` on staging (through the login profile) and
then production, a second bootstrap and a second first-release plan are
refused, and the real step commands perform offline verification, staging
publication, four-platform public-byte qualification, production
publication with qualification admission, channel compare-and-swap, and
rollout completion. It verifies the final journal state and anonymous
production channel object. The deterministic authorities and TLS
key used by this test are confined to explicit test fixtures and the
`pkgs.aos.testSupport` output; no test authority is installed in a shipped CLI
output.

Run the focused evaluation and fleet gate with:

```sh
nix-build -A checks.registry-hub --no-out-link
nix-build -A checks.fleet.native-hub-release-pipeline --no-out-link
```

This gate proves exact-byte publication and all four matrix branches. Native
functional qualification on each architecture remains the responsibility of
the platform-specific executors supplied to a real release; the fleet fixture
does not pretend that one x86 VM executes Darwin or Arm binaries.

## Operational boundary

Do not bypass the isolated registry transaction, closed bundle finalizer,
role-separated signing, exact-byte publication receipts, public read-back, or
compare-and-swap channel updates with ad hoc publishes or manual object copies,
on a Hub or a static origin. `andyl/main` remains fail-closed until its
remaining launch gates are complete and its fitness attestations are current. An
experimental publication on a production surface remains explicitly experimental
and cannot be moved across registries.

The release model, signer roles, and enforcement code are described in
[canonical release publishing](../engineering/release-publishing/README.md).
