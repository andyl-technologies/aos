# Run campaign operator and dogfood flights

This runbook turns
[RFC-0020 section 14](../../rfcs/0020-crucible-campaigns/14-manual-validation-and-dogfooding.md)
into public commands and retained evidence. It prepares two distinct sessions:
an operator acceptance flight lasting four to eight hours, and a dogfood flight
lasting at least 24 hours, or at least 72 hours for a release candidate.

The feature author may observe, but the driver must not have implemented the
feature under test. A separate reviewer challenges the result. Dogfood also
includes an operator handoff. One person's actions or one shortened session
cannot satisfy both layers.

The checked worked-network generator has an offline, artifact-free form and a
materialized AOS Envoy form. Use the latter for the release fixture: three VMs
run AOS-built Envoy and the Crucible guest integration, an nginx endpoint
serves responses, and a Python endpoint sends sequenced traffic through the
modeled network. The immutable `crucible-envoy-network-guest` root image and
AOS Linux kernel identify the guest build; every branch uses a private disk
overlay. The automated five-VM gate is a prerequisite, while an independent
operator must still run and sign the full flight below.

## Acceptance boundary

Record the following before reserving the flight window:

- the independent driver, reviewer, handoff investigator, and campaign model,
  QEMU boundary, storage, guest API, and operations owners;
- the exact source commit and tree, Nix derivations, QEMU and plugin identities,
  product image identities, scenario, policy, seed, and starting store state;
- a constrained host and every advertised QEMU fork capability profile;
- the campaign host used for sustained parallelism;
- allowed failure injections and the separate destructive-recovery contract;
  and
- duration, attempt scale, hot-child count, template depth, pressure, restart,
  hibernation, and handoff targets.

Treat the flight as blocked if any public command below is absent from the
pinned build, if the product fixture is unavailable, or if the independent
roles are unfilled. Automated and toy-fixture results are prerequisites and
cannot sign a manual gate.

Run the destructive-recovery gate as its own four-to-eight-hour session using
the checked
[injection catalog and evidence contract](../../rfcs/0020-crucible-campaigns/fixtures/campaign-destructive-recovery-contract.toml).
Do not silently omit an entry whose `implementation_state` or `recovery_gap`
blocks execution. Record it as blocked and fail the destructive gate until the
named public surface exists.

At minimum, retain successful results for these build gates from the exact
source tree:

~~~sh
nix-build -A checks.crucible.phase2.gates.typedChoiceProductCheckpoint
nix-build -A checks.crucible.phase4.packagedCampaignVm
nix-build -A checks.crucible.phase4.packagedCampaignChoiceVm
nix-build -A checks.crucible.phase4.packagedCampaignEnvoyNetworkVm
nix-build -A checks.crucible.phase7.qemuHotForkAtomicWorldVm
nix-build -A checks.crucible.phase2.gates.abiConformance
nix-build -A checks.crucible.phase5.gates.campaignStoreComposition
nix-build -A checks.crucible.phase5.gates.campaignStoreEquivalence
nix-build -A checks.crucible.phase1.gates.licenseBoundary
~~~

The packaged-campaign result must include the real-QEMU
hibernate/report/restart/resume selector. Preserve its Nix result path, test log,
and CAMPAIGN-HIBERNATE-EVIDENCE-V1 records. Run it serially from other native
QEMU pressure or atomic-world tests.

## Prepare private evidence

Run from a clean checkout of the pinned revision. Build public binaries and
enter the dev shell so the recorder uses AOS-built tools:

~~~sh
nix build .#pkg-crucible -o result-crucible
nix build .#pkg-jq -o result-jq
nix build .#pkg-openssl -o result-openssl
nix build .#pkg-linux -o result-linux
nix build .#crucible-envoy-network-guest -o result-envoy-guest
nix build .#crucible-envoy-network-smoke -o result-envoy-smoke
nix develop

CRUCIBLE=./result-crucible/bin/crucible
JQ=./result-jq/bin/jq
RECORDER=docs/rfcs/0020-crucible-campaigns/fixtures/campaign-manual-flight-recorder.sh
set -eu
set -- ./result-linux/boot/vmlinuz-*
test "$#" -eq 1
CRUCIBLE_KERNEL=$(readlink -f "$1")
CRUCIBLE_ROOT_IMAGE=$(readlink -f ./result-envoy-guest/root.ext4)
BUILD_INFO=./result-crucible/nix-support/crucible-build-info
CRUCIBLE_QEMU=$(sed -n 's/^qemu_path=//p' "$BUILD_INFO")
CRUCIBLE_PLUGIN=$(sed -n 's/^plugin_path=//p' "$BUILD_INFO")
test -f "$CRUCIBLE_KERNEL"
test -f "$CRUCIBLE_ROOT_IMAGE"
test -x "$CRUCIBLE_QEMU"
test -f "$CRUCIBLE_PLUGIN"
~~~

The Envoy smoke result checks the real AOS-built proxy chain on loopback. The
packaged five-VM gate checks it under QEMU and the modeled fabric. Record both
result paths and the kernel, root-image, Envoy, nginx, Python, guest-integration,
QEMU, and plugin build identities in the flight provenance. Pin the executor's
`CRUCIBLE_KERNEL`, `CRUCIBLE_ROOT_IMAGE`, `CRUCIBLE_QEMU`, and
`CRUCIBLE_PLUGIN` to these exact files. The fixture authenticates the QEMU and
plugin build markers when it writes the lineage. The QEMU lifecycle verifies
the kernel and root-image content against the scenario before boot.

Create a JSON object following RFC-0020 sections 14.4 and 14.14. Include the
actual values; do not copy placeholders into accepted evidence. This example
is a starting shape, not another gate schema:

~~~json
{
  "schema": "crucible.campaign-manual-flight-manifest.v1",
  "gate": "gate:campaign-operator-acceptance",
  "acceptance_state": "in-progress",
  "flight_id": "campaign-operator-YYYYMMDD-01",
  "runbook": "campaign-manual-flights-v1",
  "layer": "operator-acceptance",
  "intended_claims": ["CMAN-1..14", "CMAN-19..22"],
  "planned_duration_hours": 6,
  "participants": {
    "driver": {"name": "REPLACE", "implemented_feature": false},
    "independent-reviewer": {"name": "REPLACE", "can_challenge": true},
    "observers": []
  },
  "provenance": {
    "build-id": "REPLACE",
    "source-revision": "REPLACE_WITH_40_HEX",
    "source-tree": "REPLACE_WITH_40_HEX",
    "qemu-identity": "REPLACE",
    "plugin-identity": "REPLACE",
    "product-artifact-identities": ["REPLACE"],
    "host-profile": "REPLACE_WITH_CAPTURED_ARTIFACT",
    "store-profile": "REPLACE_WITH_CAPTURED_ARTIFACT"
  },
  "scenario": "REPLACE_WITH_CONTENT_ID",
  "policy": "REPLACE_WITH_CONTENT_ID",
  "seed": "REPLACE",
  "budget": {"attempts": 1000000, "concurrency": 32},
  "starting_store_state": "REPLACE_WITH_GENERATION_AND_DIGEST",
  "authorized_fault_actions": ["planned daemon restart", "planned host reboot"],
  "required_artifacts": [
    "runbook", "campaign-snapshots", "exact-reproduction", "thin-reproduction",
    "operational-telemetry", "resource-audit", "automated-gate-results", "final-result"
  ],
  "required_result_fields": [
    "observed-result", "operator-task-checklist", "claim-checklist",
    "automated-gate-results", "defects", "documentation-changes", "resource-audit"
  ],
  "sign_offs": {
    "required_roles": [
      "driver", "independent-reviewer", "campaign-model-owner",
      "qemu-boundary-owner", "storage-owner", "guest-api-owner", "operations-owner"
    ],
    "authorized_public_keys": {
      "driver": "sha256:REPLACE_WITH_64_HEX",
      "independent-reviewer": "sha256:REPLACE_WITH_DISTINCT_64_HEX",
      "campaign-model-owner": "sha256:REPLACE_WITH_DISTINCT_64_HEX",
      "qemu-boundary-owner": "sha256:REPLACE_WITH_DISTINCT_64_HEX",
      "storage-owner": "sha256:REPLACE_WITH_DISTINCT_64_HEX",
      "guest-api-owner": "sha256:REPLACE_WITH_DISTINCT_64_HEX",
      "operations-owner": "sha256:REPLACE_WITH_DISTINCT_64_HEX"
    },
    "unsigned_result": "blocked"
  }
}
~~~

For a dogfood manifest, also provide nonempty `handoff-operator` and
`release-owner` participant objects with a `name` field. These operating
participants are separate from the seven roles that sign the final evidence.

Compute each authorized public-key digest with `sha256sum` before initializing
the flight. The seven digests must be distinct. The recorder rejects missing or
additional provenance keys, roles, artifacts, and result fields.

Place declared secret literals, one per nonempty line, in an owner-only file
outside the evidence root. The recorder rejects and replaces a capture that
contains one. It records argv, stdout, stderr, exit status, UTC timestamps,
elapsed seconds, and SHA-256 digests.

~~~sh
export CAMPAIGN_FLIGHT_REDACTIONS=/private/campaign-flight-redactions
chmod 600 "$CAMPAIGN_FLIGHT_REDACTIONS"

EVIDENCE=/private/campaign-operator-YYYYMMDD-01
"$CONFIG_SHELL" "$RECORDER" init "$EVIDENCE" ./flight-manifest.json

record() {
  step=$1
  expected=$2
  shift 2
  "$CONFIG_SHELL" "$RECORDER" record \
    "$EVIDENCE" "$step" "$expected" -- "$@"
}
~~~

Use the recorder's capture action for redacted host facts, service units,
product manifests, store deployment, and automated result paths. Structured
command output is authoritative; video and screenshots are supplemental.

~~~sh
"$CONFIG_SHELL" "$RECORDER" capture \
  "$EVIDENCE" host-profile ./host-profile-public.json
"$CONFIG_SHELL" "$RECORDER" capture \
  "$EVIDENCE" store-profile ./store-profile-public.json
~~~

## Author and validate

First materialize the supported Envoy guest into the canonical worked-network
topology. The output contains `import.toml`, `lineage.bin`, and `policy.bin` for
the campaign run below. Separately prove that a fresh operator can act on a
public validation error without source or daemon logs. The invalid and
corrected authoring examples should differ only by the declared bad guest
domain and its documented correction:

~~~sh
record 008-guest-artifact-digests zero \
  sha256sum "$CRUCIBLE_KERNEL" "$CRUCIBLE_ROOT_IMAGE" \
  "$CRUCIBLE_QEMU" "$CRUCIBLE_PLUGIN"
record 009-worked-network-envoy zero \
  "$CRUCIBLE" --format json campaign fixture worked-network \
  --output ./envoy-network-fixture \
  --kernel "$CRUCIBLE_KERNEL" --root-image "$CRUCIBLE_ROOT_IMAGE" \
  --qemu "$CRUCIBLE_QEMU" --plugin "$CRUCIBLE_PLUGIN"
record 010-invalid-scenario nonzero \
  "$CRUCIBLE" --format json campaign scenario compile \
  ./product-network-invalid.toml --output ./invalid-bundle
record 011-compile-scenario zero \
  "$CRUCIBLE" --format json campaign scenario compile \
  ./product-network.toml --output ./product-bundle
record 012-compile-lineage zero \
  "$CRUCIBLE" --format json campaign lineage compile \
  ./product-lineage.toml --output ./product-lineage.bin
record 013-compile-policy zero \
  "$CRUCIBLE" --format json campaign policy compile \
  ./product-policy.toml --scenario ./product-network.toml \
  --output ./product-policy.bin
record 014-validate-policy zero \
  "$CRUCIBLE" --format json campaign validate --policy ./product-policy.bin
record 015-validate-import zero \
  "$CRUCIBLE" --format json campaign validate-import \
  ./envoy-network-fixture/import.toml \
  ./product-bundle/import.toml ./product-generators/import.toml
~~~

The reviewer checks that the diagnostic identifies the invalid declaration and
constraint. The corrected result must expose units, defaults, domains,
objectives, stop boundaries, retention, resource bounds, and the distinction
between search and statistical claims.

Start the pinned production deployment through its documented service manager.
Capture the public unit definition. It must bind the recorded state, peer
policy, component authority, packaged executor, composed store, product import
manifests, production QEMU, and plugin without putting secrets in argv:

~~~sh
record 020-service-unit zero systemctl cat crucible-campaign.service
record 021-start-owner zero systemctl start crucible-campaign.service

CAMPAIGN_SOCKET=/run/crucible/campaign.sock
CAMPAIGN_NAME=network-recovery-operator
record 022-owner-ready zero \
  "$CRUCIBLE" --format json campaign --socket "$CAMPAIGN_SOCKET" \
  --principal operator list --limit 32 --pages 8
~~~

## Create, run, and inspect

Create without immediate start so each accepted transition is visible. Use a
fresh 64-hex command ID for every new intent and reuse it only for an exact
retry:

~~~sh
record 030-create zero \
  "$CRUCIBLE" --format json campaign --socket "$CAMPAIGN_SOCKET" \
  --principal operator create "$CAMPAIGN_NAME" \
  --lineage ./envoy-network-fixture/lineage.bin \
  --policy ./envoy-network-fixture/policy.bin
CREATED=$("$JQ" -er .snapshot "$EVIDENCE/commands/030-create/stdout")

PRODUCT_EXECUTOR_UNIT=REPLACE_WITH_SUPPORTED_UNIT
EXECUTOR_SOCKET=REPLACE_WITH_SUPPORTED_SOCKET
record 030-executor-unit zero \
  systemctl cat "$PRODUCT_EXECUTOR_UNIT"
record 030-attach-executor zero \
  "$CRUCIBLE" --format json campaign --socket "$CAMPAIGN_SOCKET" \
  --principal operator attach "$CAMPAIGN_NAME" \
  --executor-socket "$EXECUTOR_SOCKET"

BUDGET_COMMAND=REPLACE_WITH_64_HEX
record 031-budget zero \
  "$CRUCIBLE" --format json campaign --socket "$CAMPAIGN_SOCKET" \
  --principal operator budget "$CAMPAIGN_NAME" \
  --expected "$CREATED" --command "$BUDGET_COMMAND" \
  add 500 --proposals 2000
BUDGETED=$("$JQ" -er .new_snapshot "$EVIDENCE/commands/031-budget/stdout")

START_COMMAND=REPLACE_WITH_64_HEX
record 032-start zero \
  "$CRUCIBLE" --format json campaign --socket "$CAMPAIGN_SOCKET" \
  --principal operator start "$CAMPAIGN_NAME" \
  --expected "$BUDGETED" --command "$START_COMMAND"
record 033-status-running zero \
  "$CRUCIBLE" --format json campaign --socket "$CAMPAIGN_SOCKET" \
  --principal operator status "$CAMPAIGN_NAME"
RUNNING=$("$JQ" -er .snapshot "$EVIDENCE/commands/033-status-running/stdout")
~~~

Run this bounded campaign once through a coordinator with a direct executor
client and once through the supported same-host executor transport. Use
identical artifacts, seed, budget, and execution settings, then compare
snapshot, attempt, observation, finding, and explanation identities from the
public reports. Repeat the bounded sequence under separately initialized direct
and transport evidence roots. The transport sequence uses the two
`030-executor` steps; omit them from the direct sequence.

The current `attach` command consumes an existing authenticated endpoint; it
does not start or supervise an independent executor. If the pinned product has
no documented public service or API runner that owns that endpoint, record the
component-equivalence step as blocked.

Record snapshot-bound views with bounded pagination:

~~~sh
record 034-report-running zero \
  "$CRUCIBLE" --format json campaign --socket "$CAMPAIGN_SOCKET" \
  --principal operator report "$CAMPAIGN_NAME" \
  --snapshot "$RUNNING" --limit 64 --pages 64
record 035-graph-running zero \
  "$CRUCIBLE" --format json campaign --socket "$CAMPAIGN_SOCKET" \
  --principal operator graph "$CAMPAIGN_NAME" \
  --snapshot "$RUNNING" --limit 64 --pages 64
record 036-choices-running zero \
  "$CRUCIBLE" --format json campaign --socket "$CAMPAIGN_SOCKET" \
  --principal operator choices "$CAMPAIGN_NAME" \
  --snapshot "$RUNNING" --limit 64 --pages 64
record 037-frontier-running zero \
  "$CRUCIBLE" --format json campaign --socket "$CAMPAIGN_SOCKET" \
  --principal operator frontier "$CAMPAIGN_NAME" \
  --snapshot "$RUNNING" --limit 64 --pages 64
record 038-findings-running zero \
  "$CRUCIBLE" --format json campaign --socket "$CAMPAIGN_SOCKET" \
  --principal operator findings "$CAMPAIGN_NAME" \
  --snapshot "$RUNNING" --limit 64 --pages 64
~~~

Select and retain IDs for one exploitative and one widening or novelty planner
decision, their attempts, one opportunity and domain, generated request, large
integral branch point and parent, finding, suspicious configuration, and Pareto
survivor. Inspect the corresponding choice-object, frontier-object, explain,
explain-attempt, explain-finding, and rankings output. For example:

~~~sh
OPPORTUNITY=REPLACE
REQUEST=REPLACE
ATTEMPT_EXPLOIT=REPLACE
ATTEMPT_NOVELTY=REPLACE
PLANNER_STEP=REPLACE
BRANCH_POINT=REPLACE
FINDING=REPLACE
record 040-choice-declaration zero \
  "$CRUCIBLE" --format json campaign --socket "$CAMPAIGN_SOCKET" \
  --principal operator choice-object "$CAMPAIGN_NAME" \
  --snapshot "$RUNNING" --opportunity "$OPPORTUNITY" --kind declaration
record 041-choice-domain zero \
  "$CRUCIBLE" --format json campaign --socket "$CAMPAIGN_SOCKET" \
  --principal operator choice-object "$CAMPAIGN_NAME" \
  --snapshot "$RUNNING" --opportunity "$OPPORTUNITY" --kind domain
record 042-frontier-object zero \
  "$CRUCIBLE" --format json campaign --socket "$CAMPAIGN_SOCKET" \
  --principal operator frontier-object "$CAMPAIGN_NAME" \
  --snapshot "$RUNNING" --request "$REQUEST"
record 043-explain-choice zero \
  "$CRUCIBLE" --format json campaign --socket "$CAMPAIGN_SOCKET" \
  --principal operator explain "$CAMPAIGN_NAME" \
  --snapshot "$RUNNING" --opportunity "$OPPORTUNITY" --request "$REQUEST"
record 044-explain-exploit zero \
  "$CRUCIBLE" --format json campaign --socket "$CAMPAIGN_SOCKET" \
  --principal operator explain-attempt "$CAMPAIGN_NAME" \
  --snapshot "$RUNNING" --attempt "$ATTEMPT_EXPLOIT"
record 045-explain-novelty zero \
  "$CRUCIBLE" --format json campaign --socket "$CAMPAIGN_SOCKET" \
  --principal operator explain-attempt "$CAMPAIGN_NAME" \
  --snapshot "$RUNNING" --attempt "$ATTEMPT_NOVELTY"
record 046-rankings zero \
  "$CRUCIBLE" --format json campaign --socket "$CAMPAIGN_SOCKET" \
  --principal operator rankings "$CAMPAIGN_NAME" \
  --snapshot "$RUNNING" --step "$PLANNER_STEP" \
  --pages 64 --branch-point "$BRANCH_POINT" --top 40
record 047-explain-finding zero \
  "$CRUCIBLE" --format json campaign --socket "$CAMPAIGN_SOCKET" \
  --principal operator explain-finding "$CAMPAIGN_NAME" \
  --snapshot "$RUNNING" --finding "$FINDING"
~~~

The reviewer independently reconstructs both planner scores from displayed
fixed-point terms and retains the calculation and disposition.

## Pause, restart, and resume

Issue checkpoint pause while status shows active children. Poll with separately
numbered status captures until state is paused and active-world counts are zero:

~~~sh
PAUSE_BASIS=$RUNNING
PAUSE_COMMAND=REPLACE_WITH_64_HEX
record 050-pause-active zero \
  "$CRUCIBLE" --format json campaign --socket "$CAMPAIGN_SOCKET" \
  --principal operator pause "$CAMPAIGN_NAME" \
  --expected "$PAUSE_BASIS" --command "$PAUSE_COMMAND" --active checkpoint
record 051-status-paused zero \
  "$CRUCIBLE" --format json campaign --socket "$CAMPAIGN_SOCKET" \
  --principal operator status "$CAMPAIGN_NAME"
PAUSED=$("$JQ" -er .snapshot "$EVIDENCE/commands/051-status-paused/stdout")
record 052-report-paused zero \
  "$CRUCIBLE" --format json campaign --socket "$CAMPAIGN_SOCKET" \
  --principal operator report "$CAMPAIGN_NAME" \
  --snapshot "$PAUSED" --limit 64 --pages 64

record 053-stop-owner zero systemctl stop crucible-campaign.service
record 054-start-owner zero systemctl start crucible-campaign.service
record 055-report-restarted zero \
  "$CRUCIBLE" --format json campaign --socket "$CAMPAIGN_SOCKET" \
  --principal operator report "$CAMPAIGN_NAME" \
  --snapshot "$PAUSED" --limit 64 --pages 64
record 056-compare-paused-report zero \
  cmp "$EVIDENCE/commands/052-report-paused/stdout" \
  "$EVIDENCE/commands/055-report-restarted/stdout"
record 057-retry-pause zero \
  "$CRUCIBLE" --format json campaign --socket "$CAMPAIGN_SOCKET" \
  --principal operator pause "$CAMPAIGN_NAME" \
  --expected "$PAUSE_BASIS" --command "$PAUSE_COMMAND" --active checkpoint

RESUME_COMMAND=REPLACE_WITH_64_HEX
record 058-resume zero \
  "$CRUCIBLE" --format json campaign --socket "$CAMPAIGN_SOCKET" \
  --principal operator resume "$CAMPAIGN_NAME" \
  --expected "$PAUSED" --command "$RESUME_COMMAND"
~~~

The retry must return its original transition with replay indicated. After
resume, show unchanged facts and accounting and continued lazy feedback.

## Branch, steer, pin, and derive

Refresh the current snapshot before every mutation. Use values authenticated by
the selected large integral opportunity:

~~~sh
HEAD=REPLACE_WITH_CURRENT_SNAPSHOT
FINITE_COMMAND=REPLACE_WITH_64_HEX
PARENT=REPLACE
DOMAIN=REPLACE
record 060-finite-branch zero \
  "$CRUCIBLE" --format json campaign --socket "$CAMPAIGN_SOCKET" \
  --principal operator branch "$CAMPAIGN_NAME" \
  --expected "$HEAD" --command "$FINITE_COMMAND" \
  --branch-point "$BRANCH_POINT" --parent "$PARENT" \
  --opportunity "$OPPORTUNITY" --domain "$DOMAIN" \
  --value i64:-10 --value i64:0 --value i64:10 \
  --attempts 3 --stop next-choice

HEAD=REPLACE_WITH_CURRENT_SNAPSHOT
GENERATOR=REPLACE
GENERATED_COMMAND=REPLACE_WITH_64_HEX
record 061-generated-branch zero \
  "$CRUCIBLE" --format json campaign --socket "$CAMPAIGN_SOCKET" \
  --principal operator branch "$CAMPAIGN_NAME" \
  --expected "$HEAD" --command "$GENERATED_COMMAND" \
  --branch-point "$BRANCH_POINT" --parent "$PARENT" \
  --opportunity "$OPPORTUNITY" --domain "$DOMAIN" \
  --generator "$GENERATOR" --proposals 1000 --attempts 100 \
  --stop next-choice

HEAD=REPLACE_WITH_CURRENT_SNAPSHOT
record 062-reject-huge-all nonzero \
  "$CRUCIBLE" --format json campaign --socket "$CAMPAIGN_SOCKET" \
  --principal operator branch "$CAMPAIGN_NAME" \
  --expected "$HEAD" --branch-point "$BRANCH_POINT" --parent "$PARENT" \
  --opportunity "$OPPORTUNITY" --domain "$DOMAIN" --all

SUSPICIOUS_CONFIGURATION=REPLACE
HEAD=REPLACE_WITH_CURRENT_SNAPSHOT
PIN_COMMAND=REPLACE_WITH_64_HEX
record 063-pin-suspicious zero \
  "$CRUCIBLE" --format json campaign --socket "$CAMPAIGN_SOCKET" \
  --principal operator pin "$CAMPAIGN_NAME" "$SUSPICIOUS_CONFIGURATION" \
  --expected "$HEAD" --command "$PIN_COMMAND" --tier exact \
  --reason "operator flight finding"

HEAD=REPLACE_WITH_CURRENT_SNAPSHOT
ADDITIONAL_BUDGET_COMMAND=REPLACE_WITH_64_HEX
record 064-add-budget zero \
  "$CRUCIBLE" --format json campaign --socket "$CAMPAIGN_SOCKET" \
  --principal operator budget "$CAMPAIGN_NAME" \
  --expected "$HEAD" --command "$ADDITIONAL_BUDGET_COMMAND" \
  add 1000 --proposals 4000

HEAD=REPLACE_WITH_CURRENT_SNAPSHOT
STEER_COMMAND=REPLACE_WITH_64_HEX
REVISED_POLICY=REPLACE_WITH_IMPORTED_POLICY_ID
record 065-steer zero \
  "$CRUCIBLE" --format json campaign --socket "$CAMPAIGN_SOCKET" \
  --principal operator steer "$CAMPAIGN_NAME" \
  --expected "$HEAD" --command "$STEER_COMMAND" --policy "$REVISED_POLICY"
~~~

Record graph, frontier, explanations, rankings with --policy-groups, and reports
before and after. Prove lazy admission, independent finite/generated sources,
one edge and reward for the duplicate value, unchanged old planner reasons,
correct statistical intervention labeling, and later work under the new policy.

Derive hot-fork-enabled and disabled campaigns from one snapshot and compare
edges and results. Derivation must share objects without adding a source edge;
QEMU hot fork remains an execution realization:

~~~sh
DERIVE_BASIS=REPLACE
record 066-derive-hot zero \
  "$CRUCIBLE" --format json campaign --socket "$CAMPAIGN_SOCKET" \
  --principal operator derive "$CAMPAIGN_NAME" \
  --snapshot "$DERIVE_BASIS" network-recovery-hot --policy ./hot-policy.bin
record 067-derive-cold zero \
  "$CRUCIBLE" --format json campaign --socket "$CAMPAIGN_SOCKET" \
  --principal operator derive "$CAMPAIGN_NAME" \
  --snapshot "$DERIVE_BASIS" network-recovery-cold --policy ./cold-policy.bin
~~~

## Hibernate, terminate, and resume

Hibernate while hot templates and active lazy continuations are visible. The
durability argument names a configured logical policy:

~~~sh
record 070-hibernate zero \
  "$CRUCIBLE" --format json campaign --socket "$CAMPAIGN_SOCKET" \
  --principal operator hibernate "$CAMPAIGN_NAME" \
  --durability archive --timeout-ms 300000
HIBERNATED=$("$JQ" -er .paused_snapshot "$EVIDENCE/commands/070-hibernate/stdout")
ARCHIVE_MANIFEST=$("$JQ" -er .archive_manifest "$EVIDENCE/commands/070-hibernate/stdout")

record 071-authenticate-hibernate-manifest zero \
  "$CRUCIBLE" --format json store ensure "$ARCHIVE_MANIFEST" \
  --in ./campaign-store.toml
record 072-hibernate-retry zero \
  "$CRUCIBLE" --format json campaign --socket "$CAMPAIGN_SOCKET" \
  --principal operator hibernate "$CAMPAIGN_NAME" \
  --durability archive --timeout-ms 300000
record 073-status-hibernated zero \
  "$CRUCIBLE" --format json campaign --socket "$CAMPAIGN_SOCKET" \
  --principal operator status "$CAMPAIGN_NAME"
record 074-report-hibernated zero \
  "$CRUCIBLE" --format json campaign --socket "$CAMPAIGN_SOCKET" \
  --principal operator report "$CAMPAIGN_NAME" \
  --snapshot "$HIBERNATED" --limit 64 --pages 64
~~~

The V1 receipt must set safe_to_terminate true, name the exact pause and final
paused snapshots, authenticate its archive manifest, satisfy durable placement
policy, and show retained roots backed by materialized checkpoints. The status
capture must show the final paused snapshot with no active worlds. The retry
must preserve command, snapshots, manifest, durability, and inventory evidence
with replay indicated.

Stop the service and prove every daemon, QEMU, executor, cgroup, shared-memory
object, overlay, and descriptor has left live inventory. Reboot for release
acceptance; an earlier operator flight may use a reviewed cache purge. Never
delete state, ledgers, refs, or durable objects:

~~~sh
record 075-stop-for-hibernate zero systemctl stop crucible-campaign.service
record 076-resource-audit-stopped zero ./capture-campaign-resource-audit
~~~

After reboot, restore only shell variables, start the pinned deployment, and
compare the same snapshot-bound report before resume:

~~~sh
record 077-start-after-reboot zero systemctl start crucible-campaign.service
record 078-report-after-reboot zero \
  "$CRUCIBLE" --format json campaign --socket "$CAMPAIGN_SOCKET" \
  --principal operator report "$CAMPAIGN_NAME" \
  --snapshot "$HIBERNATED" --limit 64 --pages 64
record 079-compare-hibernated-report zero \
  cmp "$EVIDENCE/commands/074-report-hibernated/stdout" \
  "$EVIDENCE/commands/078-report-after-reboot/stdout"

RESUME_HIBERNATED_COMMAND=REPLACE_WITH_64_HEX
record 080-resume-hibernated zero \
  "$CRUCIBLE" --format json campaign --socket "$CAMPAIGN_SOCKET" \
  --principal operator resume "$CAMPAIGN_NAME" \
  --expected "$HIBERNATED" --command "$RESUME_HIBERNATED_COMMAND"
~~~

Continue until descendant feedback reopens an ancestor and capture status,
graph, frontier, report, and explanation evidence.

## Transfer and collect

Stop both owners. Preserve the source until destination validation completes:

~~~sh
TRANSFER_SNAPSHOT=REPLACE_WITH_CURRENT_SNAPSHOT
record 090-stop-for-transfer zero systemctl stop crucible-campaign.service
record 091-transfer-executable zero \
  "$CRUCIBLE" --format json campaign archive transfer \
  --source-state ./campaign-state \
  --source-policy ./campaign-peers.toml \
  --source-store ./campaign-store.toml \
  --source-campaign "$CAMPAIGN_NAME" --snapshot "$TRANSFER_SNAPSHOT" \
  --mode executable \
  --destination-state ./maintenance-state \
  --destination-policy ./maintenance-peers.toml \
  --destination-store ./maintenance-store.toml \
  --archive operator-maintenance --campaign maintenance-copy \
  --minimum-durable-placements 1 \
  --maximum-checkpoint-bytes 1073741824
record 092-inspect-archive zero \
  "$CRUCIBLE" --format json campaign archive inspect \
  --state ./maintenance-state --policy ./maintenance-peers.toml \
  --store ./maintenance-store.toml --archive operator-maintenance
record 093-verify-destination zero \
  "$CRUCIBLE" --format json store verify ./maintenance-store.toml
~~~

Repeat into a destination containing the sibling base and compare copied and
existing bytes with logical closure size. Start the compatible maintenance
campaign, compare its authenticated configuration, and attempt deliberately
incompatible provenance. It must fail before guest resume while the source
still verifies.

GC is a stopped-owner operation with its journal outside every store leaf:

~~~sh
record 094-store-status zero \
  "$CRUCIBLE" --format json store status ./campaign-store.toml
record 095-store-verify zero \
  "$CRUCIBLE" --format json store verify ./campaign-store.toml
record 096-gc-plan zero \
  "$CRUCIBLE" --format json store gc \
  --state ./campaign-state --policy ./campaign-peers.toml \
  --store ./campaign-store.toml --journal ./campaign-gc-journal plan
record 097-gc-apply zero \
  "$CRUCIBLE" --format json store gc \
  --state ./campaign-state --policy ./campaign-peers.toml \
  --store ./campaign-store.toml --journal ./campaign-gc-journal apply
record 098-store-verify-after-gc zero \
  "$CRUCIBLE" --format json store verify ./campaign-store.toml
~~~

Inspect and retain the plan identity before apply. Then use store ensure for
known roots, restart the owner, check the exact head, and replay every retained
finding.

## Finding handoff and blocking surfaces

Retain campaign findings, explain-finding, minimized triage report, thin
reproducer, exact midpoint, and debugger transcript. The standalone public
forms are:

~~~sh
record 100-triage-finding zero \
  "$CRUCIBLE" --format json --store ./triage-store \
  --artifact-dir ./triage-artifacts \
  triage ./signed-findings-ledger --policy default \
  --minimize representative --report ./triage-report \
  --recompute-signatures
record 101-replay-thin zero \
  "$CRUCIBLE" --format json --backend qemu \
  replay ./minimized-reproduction --check ./original-event-log
record 102-debug-midpoint zero \
  "$CRUCIBLE" --format json --backend qemu \
  debug ./minimized-reproduction \
  --at-checkpoint "$EXACT_MIDPOINT" --read-only
~~~

Before acceptance, verify a documented public path from a campaign finding or
findings archive to those standalone files. Also verify commands for compatible
restore/import, incompatible restore rejection, canonical debug selection
override, and explicit non-canonical debugger fork. Missing bridges block the
step; copying repository objects or editing refs invalidates the flight.

The handoff investigator receives only the exported bundle and documentation.
They must reproduce the signature, reach the midpoint, inspect register,
memory, event, signal, selection, and metric state through read-only surfaces,
and explain the selected fault and guest response.

The store surface provides status, ensure, verify, stopped-owner physical-copy
repair, GC plan/cancel/apply, and generation-bound repack plan/apply. Physical
repair requires an authenticated source node, a distinct target storage
identity, and the campaign owner lock; it reauthenticates the target before
returning success.
The full retention flight also needs documented flows for archive plans across
all modes, transfer protection roots, loss-of-acceleration impact warning, plan
cancellation, repacking with concurrent readers, and stale-plan rejection after
a pin and generation change. Missing commands block CMAN-19.

## Dogfood schedule

Use a separate evidence root and set planned duration to at least 24 hours, or
72 for a release candidate. Repeat lifecycle, inspection, branching, steering,
finding, hibernation, transfer, and GC at reviewed scale. Targets are at least
10,000 created and retired hot children, three promoted template generations,
one million lightweight attempts or a preapproved equivalent, and repeated
useful-concurrency intervals.

Capture status, report, frontier, findings, and sampled explanations at least
every 15 minutes, including early, middle, and late policy epochs:

~~~sh
SAMPLES=96
INTERVAL_SECONDS=900
sample=1
while test "$sample" -le "$SAMPLES"; do
  suffix=$(printf '%03d' "$sample")
  record "soak-$suffix-status" zero \
    "$CRUCIBLE" --format json campaign --socket "$CAMPAIGN_SOCKET" \
    --principal operator status "$CAMPAIGN_NAME"
  HEAD=$("$JQ" -er .snapshot "$EVIDENCE/commands/soak-$suffix-status/stdout")
  record "soak-$suffix-report" zero \
    "$CRUCIBLE" --format json campaign --socket "$CAMPAIGN_SOCKET" \
    --principal operator report "$CAMPAIGN_NAME" \
    --snapshot "$HEAD" --limit 64 --pages 64
  record "soak-$suffix-frontier" zero \
    "$CRUCIBLE" --format json campaign --socket "$CAMPAIGN_SOCKET" \
    --principal operator frontier "$CAMPAIGN_NAME" \
    --snapshot "$HEAD" --limit 64 --pages 64
  sleep "$INTERVAL_SECONDS"
  sample=$((sample + 1))
done
~~~

Use 288 samples for 72 hours and record actual start/end timestamps. Schedule
separate CPU, RAM/dirty-page, descriptor, and store-throughput pressure windows
within limits. Preserve service-manager changes and telemetry. Cross one planned
restart, operator handoff, and hibernate/reboot/resume. Produce an expected
finding, useful Pareto survivors, progressive feedback, dormant ancestors,
minimization, and a second fault path.

The operator must explain backpressure, fallback, idle capacity, admission,
retention, and store growth from public views. The final audit accounts for
processes, threads, descriptors, shared memory, overlays, cgroups, staging
uploads, pins, exact roots, and physical growth. Unexplained resources or
workaround-only recovery fail the flight.

## Stop, seal, and review

Gracefully stop and seal the campaign, then capture its final report:

~~~sh
HEAD=REPLACE_WITH_CURRENT_SNAPSHOT
STOP_COMMAND=REPLACE_WITH_64_HEX
record 110-stop-and-seal zero \
  "$CRUCIBLE" --format json campaign --socket "$CAMPAIGN_SOCKET" \
  --principal operator stop "$CAMPAIGN_NAME" \
  --expected "$HEAD" --command "$STOP_COMMAND" --seal
SEALED=$("$JQ" -er .new_snapshot "$EVIDENCE/commands/110-stop-and-seal/stdout")
record 111-final-report zero \
  "$CRUCIBLE" --format json campaign --socket "$CAMPAIGN_SOCKET" \
  --principal operator report "$CAMPAIGN_NAME" \
  --snapshot "$SEALED" --limit 64 --pages 64
record 112-stop-owner-final zero systemctl stop crucible-campaign.service
record 113-final-resource-audit zero ./capture-campaign-resource-audit
~~~

Add outcomes, defects, documentation changes, regression dispositions,
resource audit, independent calculations, and handoff result to the evidence
root. Every gating task is pass, fail, or blocked; observations have an explicit
disposition. A blocked safety or recovery task prevents acceptance. Capture the
eight manifest-required artifacts, including a `final-result` JSON object with
schema `crucible.campaign-manual-flight-result.v1`, an observed result, nonempty
operator and claim checklists, automated-gate results, defect dispositions,
documentation changes, a complete resource audit, and
`"sign-off-status":"pending"`. Seal the reviewed content before collecting
detached signatures:

~~~sh
"$CONFIG_SHELL" "$RECORDER" seal "$EVIDENCE"
export CAMPAIGN_FLIGHT_OPENSSL=./result-openssl/bin/openssl

# Repeat for every exact role in sign_offs.required_roles, using its authorized
# distinct key. The generated canonical statement binds the bundle, result,
# role, signer, and public-key identity before it is signed.
"$CONFIG_SHELL" "$RECORDER" statement "$EVIDENCE" driver \
  "DRIVER_NAME" ./driver-public.pem ./driver.statement.json
"$CAMPAIGN_FLIGHT_OPENSSL" pkeyutl -sign -inkey ./driver-private.pem -rawin \
  -in ./driver.statement.json -out ./driver.signature
"$CONFIG_SHELL" "$RECORDER" attest "$EVIDENCE" driver \
  "DRIVER_NAME" ./driver-public.pem ./driver.statement.json ./driver.signature
"$CONFIG_SHELL" "$RECORDER" verify "$EVIDENCE"
cat "$EVIDENCE/BUNDLE-ID"
~~~

`attest` verifies Ed25519 over the canonical statement and stores that exact
statement, key, and signature. `verify` requires all seven authorized distinct
keys and distinct signatures, reconstructs every statement, rechecks every
signature, and rejects content, result, signer, role, key, or file-inventory
drift. Publish through the approved evidence path and record the bundle identity
beside the exact campaign snapshot. Any content change creates a new identity
and requires new statements and signatures. Cryptographic verification only
checks evidence integrity; manual review still decides acceptance.

## Requirement-to-evidence map

| Requirements | Required evidence |
| --- | --- |
| CMAN-1..4 | Independent roles, layer and duration, pinned provenance, claims, inputs, and allowed actions |
| CMAN-5..6 | Three-router/two-endpoint product workload on every profile, constrained fallback, and declared injections |
| CMAN-7..8 | Commands, snapshots, artifacts, telemetry, defects, signatures, secret scan, checksum manifest, and bundle identity |
| CMAN-9..10 | Public lifecycle, restart, steering, report, and two reconstructed planner decisions |
| CMAN-11..12 | Finding, minimization, thin replay, exact debug, branch labels, and bundle-only handoff |
| RFC 14.7, CMAN-13..14 | Direct/transport equivalence, hibernate durability, process/cache loss, resume, sibling reuse, transfer, and incompatible rejection |
| CMAN-15..16 | Separate destructive-recovery contract and drill, with no internal repair or unexplained resource |
| CMAN-17..18 | 24/72-hour timing, concurrency, child/template/attempt scale, pressure, restart, handoff, hibernate, explanations, and resource audit |
| CMAN-19 | Multi-root retention, transfer protection, stale plans, repack/read concurrency, post-GC verification, and replay |
| CMAN-20 | Independent checklist, defect disposition, documentation changes, and five owner approvals |
| CMAN-21..22 | Finite/generated deduplication, lazy admission, huge-domain rejection, statistical labeling, derive sharing, realization equivalence, and debug mutation |
