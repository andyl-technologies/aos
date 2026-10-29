# Managed mirror pack inspection acceptance

Git pack/index inspection has its own reviewer purpose,
`managed_r2_pack_inspection_v1`, and Ed25519 signing domain,
`aos.hub.accepted-managed-mirror-pack-inspection.v1` followed by a NUL byte.
Existing none/Zstandard publication approval cannot authorize this parser.
The authorized mirror reviewer role and installed
`HUB_MIRROR_QUALIFICATION_PUBLIC_KEY` are reused; no provider token or additional
permanent key is required.

The closed `MirrorPackAcceptanceArtifact` binds the complete **signed** ordinary
mirror artifact's SHA-256, actual compiled source, deployed script and complete
release pack. That prerequisite already binds the exact deployment, full managed
profile, private policy and direct acceptance evidence. Replacing any prerequisite
pin, report or signature requires a new pack review. Both immutable review
cutoffs are rechecked after capacity waits, together with the direct producer
cutoff. A read inspection constructs no guessed copy original or encoded SHA.

The artifact is installed in the existing `HUB_MIRROR_ACCEPTANCE` store at the
key returned by `mirror_pack_acceptance_key(deployment, source, script)`.
The Worker accepts at most 64 KiB for this separate document. Missing, foreign,
expired or controlled evidence refuses pack inspection without disabling
already qualified none/Zstandard workflows. Controlled source-built experiments
use their separate raw authority and reserved namespace; even a valid reviewer
signature on their evidence cannot grant hosted admission.

## Fixed measured geometry

| Allocation or result | Bound |
| --- | ---: |
| Complete encoded pack, streamed | 8 MiB |
| Retained index | 4 MiB |
| Simultaneous decoded graph, including delta results | 12 MiB |
| One decoded Git object | 4 MiB |
| Complete pair entries | 65,536 |
| Strictly ordered selected OIDs | 8 |
| Total selected decoded content across all ranges | 128 KiB |
| Native input feed | 64 KiB |
| Shared bulk buffered producers | 1 |
| Independently reserved metadata producers | 2 |

Inspection shares the bulk buffer admission and must hold it through complete
pair validation and bounded selection. Each positive report records whole
encoded pack and index SHA-256/size, the distinct pack payload trailer checksum,
actual decoded graph high-water, largest decoded object, strict selected OIDs
and the canonical selected-result digest. The exact query/result transcript is
retained separately; encoded pack and index bodies never cross Native.

## Required raw observations

The reviewer checks the raw reports committed by `reportSha256`, rather than
treating a configured bound or a signature as evidence that a test ran.
At least three positive base/offset-delta/reference-delta observations are
required. Positive boundary examples must exercise an actual 8 MiB encoded
pack, 12 MiB decoded graph and 4 MiB object. Valid indexes remain subject to
the entry-count bound as well as the 4 MiB input ceiling.

Ten closed cases are required, with actual sample counts and zero observed
violations:

1. Base-object selection.
2. Offset-delta selection.
3. Reference-delta selection.
4. Whole encoded checksum refusal.
5. Index CRC/offset refusal.
6. Selected decoded OID refusal.
7. Encoded input limit refusal.
8. Decoded object, entry count or graph limit refusal.
9. Expired read-plan refusal with zero actual provider dispatches.
10. Both metadata producers completing while bulk inspection is active.

Each case commits its exact canonical signed query and bounded semantic result
or refusal transcript. Dispatch counts come from actual provider invocation
observation, not configured concurrency. Positive pair commitments and selected
ranges come from the same production parser used for inspection.

Whole-worker memory samples must include Wasm graph/index allocations, JavaScript
and SDK buffers and the overlapping metadata producers. The peak must remain
below 128 MiB; the Wasm high-water must cover the observed graph and index bytes.
Nominal graph size or VM memory allocation alone does not establish this limit.
CPU and wall measurements cover the complete inspector invocation; the CPU
ceiling must match the installed limit in the prerequisite release report.
Actual provider concurrency stays within that independently accepted profile,
and Native bulk bytes remain zero. The exact release pack is the one measured
and installed, including its script, Wasm and startup observations.

Contract tests use explicitly synthetic reports to verify purpose, binding and
refusal rules. They do not establish provider execution or hosted qualification.
