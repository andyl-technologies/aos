> Informative implementation plan. This preserves the initial QEMU-oriented
> work packages; it does not enable a capability. Normative release requirements
> remain in [chapter 11](../../rfcs/0021-crucible-paged-ram/11-implementation-plan.md).
> Read with the [profile roadmap](profile-roadmap.md). gem5 and KVM are specified
> future profiles, with no delivered implementation claimed here.

# Initial QEMU-SIM implementation sequence

## 1 Delivery model

This document records the initial QEMU-SIM implementation sequence. Acceptance
alone does not enable swap or advertise a new executor capability. Implementation proceeds
in reviewable work packages with explicit evidence. Staging phases are not a
backward-compatibility program: old and new incompatible contracts are never
accepted together by the deployed runtime. The final cutover is coordinated.

### Current host integration (informative)

The host implementation retains the actual Main's Source admission and node
supervisor before Source birth in both resident and controller-managed launches.
The same owner funds the fixed descriptor window and metadata overlap. Controller
endpoints, spill resources and workspace remain conditional; their absence does
not create another bank, clock or resident-only timing roster.

The current transport source contracts are:

| Surface | Current contract |
| --- | --- |
| Plugin control | Version 8; noncurrent peers are refused. |
| Shared region | ABI 33; each node slot is 768 bytes. Ordinary action return remains at offset 264; parent-Park return has a separate journal at offset 512. Constructor and clone reset paths clear both journals. The checked-in C header is emitted from the actual Rust layout. |
| Selected pre-exec Setup | Edition 6, selector `QEMU_CRUCIBLE_PREEXEC_SETUP=6`, tag `0x16`, 125-byte frame. |
| Setup descriptor roster | Eight mandatory roles: shared region, wake event, sealed plan, read-only standing publication, standing cancellation event, publisher region and distinct producer/receiver events. An optional device workspace precedes the publisher trio, making nine roles. |
| Sealed plan | `CRUCSUP9`, schema 9, retaining the `CRUCPUR8` process purpose of 2520 bytes and adding the exact 224-byte publisher purpose. |
| Native receiver declaration | The selected complete ELF contains one 40-byte `CRUCRCV1` record. Source activation and checkpoint ingress have separate edition fields. Startup checks Source activation independently; zero and unspecified positive activation editions refuse. The complete declaration and ELF digest remain bound to the installed Source. A declaration grants no execution authority. |
| Standing publication | Schema 4 with producer-retention edition 1 at byte 196 in a 1504-byte shared file: one 8-byte sequence followed by a 1496-byte observation, accessed as atomic big-endian 64-bit words. The observation binds each action's kind, cohort, and parent-Park correlation where applicable. The host alone holds the writable mapping; the transmitted file role is read-only. |
| Sealed standing corroboration | The purpose's 1520-byte tail binds the retained publication file identity/extent and its initial 1496-byte observation. Copied fields issue no authority. |
| Standing cancellation | A separate nonblocking eventfd, with kernel event identity encoded as raw ID plus one. It is distinct from the wake event and Setup amendment event. |
| Operational durations | One exact-nanosecond roster under RAM schema 11; Host operational frames use schema 4. Configured values are positive and checked; observed expiry may be zero. |

Source publication preserves the same cap, original monotonic origin and nominal
Source subject across policy revisions. Publication commits through odd/even
atomic sequence transitions; terminal invalidation cannot be replaced by a later
live sequence. Ordinary policy changes publish new revisions without signaling
terminal cancellation. Completing Setup retains these physical owners for the
Source lifetime. Only actual child wait/reap and proven physical cleanup permit
retirement; kill, copied process identifiers and local uniqueness do not.

Execution still reserves full guest RAM and evicts at paused boundaries. The
configured Main/Source ownership path and native Root observation bodies exist,
but plugin registration still ends at explicit callback-activation refusal.
Native groups remain inactive, registry binding refuses and command-receive
custody supplies neither a live publisher/action parent nor genuine peer return.
The support declaration retains activation and ingress edition zero. Actual
activation and CPU-use issuance, complete diagnostic payload funding and native
physical-return qualification remain open. Smaller initial and steady physical
peaks and CPU/elapsed-time parity remain unproved.

The latest checkpoints are summarized here; their detailed source scopes and
failed attempts appear in the dated entries below.

| Surface | Latest checkpoint | Remaining qualification |
| --- | --- | --- |
| Publisher transport | `e9784079c4` creates the once-owned physical session under the actual Source payer and installing Original, exports exact roles and sends Setup6 with plan nine. Six physical controls, five alias controls, seven startup controls, setup completion and hygiene pass. | Mandatory application compilation passes with all 5,279 committed Rust/TOML files matching the frozen source. Genuine launched transfer, command publication, peer acquisition and terminal consumption remain unqualified. |
| Host alias custody | `90f00965fa` journals each standing descriptor before the next guarded duplication. Five real-socket controls, 73 focused policy checks and five hygiene checks pass. | Mandatory application compilation passes at `yyiy0g0z5lfdkx3x563k0sgnf1i20d1c`; all 5,272 committed Rust/TOML files match its immutable source. All 211 exact supervision cases pass at `dy2jldwf5dizmsmj0icwwxnlfpf8k45a`. |
| Installing plan reads | `54caaed474` guards every plan read and retry with the same installing Source and preserves the first validation cause on failed ACK. All 24 focused setup tests, 73 policy controls and five hygiene controls pass. | Mandatory application compilation passes with all 5,274 Rust/TOML files matching the immutable source. The corrected setup gate `edb742a73f` passes 39 tests; all 218 exact supervision cases pass at `7iwxg7vg1r0gxwv39ajixz95n45jg9b4`. Genuine Native admission remains unexecuted. |
| Native integration | Signed atomic `7b817c94ba`, conventional `060716ff3d`, tree `b26b7645` verifies the eleven function exports and two immutable layout objects using their genuine recorded attributes. Independent review verifies all 36 correction payloads, 78,470 Git/disk/archive paths and four byte-exact generated outputs; all 359 pure controls pass. | The earlier genuine-provider companion passes its complete build and all nineteen ordinary/unissued-state TAP cases. Earlier legacy configuration and thirteen read-only Ninja queries pass; later target attempts retain generator, interpreter and unavailable-process refusals. The latest original invocation refuses during configure because a disappeared wrapper lacks original exit-observation custody; its complete signed result and diagnosis pass independent review. Actual object transformation, final provider-binding proof and its 187-case TAP run remain unqualified. Complete paid profile issuance, activation, external physical reap, lower residency and performance parity remain unfinished. |
| Prior native build | `b69de00f81` retains signed `3376c0ee90`; all twelve independently bounded custody components pass, including final failure-evidence replay at `wxxp873qw0khc3zykvlfhgi2f6x9ff63`. | Its five fixture regressions are corrected in `83ecde0031`. Its passing component evidence does not qualify actual installed Source authority. |
| Policy and release | All 90 testing-standard controls pass, including the broad operational-wait gate and unchanged causal mutations. All five engineering-hygiene controls pass. | The license-boundary gate remains blocked at strict controller Clippy; the latest direct check reports 674 host-library errors and 723 host-test errors. Its boundary assertions have no passing result for the current source. Earlier attempts remain recorded below. Lower residency, physical return, fork rearm and performance parity remain unqualified. |
| Rust publisher receiver | `c37c5a1808` borrows exact Setup6 roles, requires plan nine and retains the canonical Native service field inside the prepaid pinned Runtime. Component return follows group and workspace return. All 1,150 plugin unit tests and six new view/retention controls pass. | Mandatory application compilation passes at `7g4cs18mj0a4yhwwmdw7na1j53flhxaw`, with all 5,277 committed Rust/TOML inputs matching the frozen source. The setup gate passes 45 tests; genuine launched transfer and physical cleanup remain unexecuted. |
| Requirements | 556 bindings: 537 component and nineteen native, across 243 requirements. | 148 requirements remain uncovered and none fully qualified. |

#### Isolated patched-libc build support

The shared hermetic libc builder now applies an ordered list of explicit source
patches before configuration and retains every patch beside the upstream source
in its corresponding-source evidence. The current libc tier accepts a separate
derivation name and defaults to its unchanged production name and empty patch
list. This permits a matching specialized loader/header/runtime build without
replacing the production toolchain.

Independent before/after evaluation confirms the production libc and compiler
output identities are unchanged. Focused evaluation checks patch order, retained
patch evidence and distinct variant identity; formatting and diff checks pass.
Core evaluation passes at `p0dcd4r7i1xmwbd0byjs53q3kybpd8s2`.
This infrastructure does not yet import or qualify the bounded pthread provider,
change QEMU's loader, or admit a selected stack profile. The actual provider's
release reentry correction and immutable source handoff remain separate work.

#### Packaged physical stack/member qualification

The `d1c072e984` import reconstructs successfully at
`qavz36q8skncd70rapajwrrhihwlxckk`; its complete license ledger passes at
`c37zb150np9khn2zja51r4dkawb4amjf`. The hermetic Native custody gate passes
at `1mwdpdp466h28zxva03cwdysn20lz47f`, including all 36 separately bounded
components and its embedded 187 actual Source tests. This closes the preceding
extracted cleanup bridge's genuine-provider link failure without weakening its
bounds. The separately registered Source gate passes all 187 tests at
`j6mj9gz7m0s0kzm0xd482imd73dgrpn7`. Full packaged ordinary fixture delivery
fails at `rwgq0y6r0l23mz5ghcxd9a9r4m2v99m6`: twenty of 26 fixtures pass.
`control-deferred`, `stopped-control-rearm` and `template-control-drain`
refuse the outdated identity of `accel/tcg/tcg-accel-ops-rr.c`;
`ram-worker-inventory` and `settle-prepark` extract functions without the real
`native_quantum_rr` canonical declaration. `dirty-iterator` refuses missing
genuine launched Source/Root ownership, read/post/rearm/ACK and physical-return
coverage. This last refusal is a substantive lifecycle gap, not an obsolete
fixture dependency. The full package remains unqualified; all failures are
retained. Its explicit provider Ninja invocation honors the requested
`NIX_BUILD_CORES` instead of Ninja's unrestricted default.

ABI conformance passes at `5bmw67dp0dxp493520gi2az5hrkf428l`. Engineering
hygiene passes at `zcvijji792yblcv5r97p578pnwrl3izi`. The canonical
license-boundary gate still fails on 908 Host-library and 962 Host-test Clippy
errors; its boundary assertions did not run. These passing physical component
checks do not qualify Module/Core semantic issuance, a populated matched
execution, lower residency, bounded application closure or stack admission.

#### Isolated bounded-thread libc package

`pkgs.glibc-crucible` imports the exact signed glibc implementation
`dae19eda3e0ca54dc8198ef83e8ba1a6c187441e`, including the correction that
serializes physical arena release with allocation and retains reentry debt.
It builds matching libc, loader, headers and thread-debug outputs; the private
TCB change requires those matching components. The production libc and public
compiler output identities remain unchanged after adding the optional build
hooks. The complete upstream source and exact patch remain corresponding-source
evidence, with a ledger covering all 33 changed upstream paths.

Independent review verifies both signed implementation commits, all 169 sealed
artifacts and all 19,481 signed source/archive entries, including the one literal
source link. All 19,473 upstream baseline entries match the pinned glibc source.
Applying the two-commit patch in an isolated index produces the exact signed
tree `54b4ee8cfae3fd4241985304b0edc70e0150e992`. The complete bundle verifies;
19,136 actual build files and twenty literal output links match their sealed
inventory without differences. The source proof is
`6aa38955b85c90becc730fd48d1d3e12fa30f0fca45ef02dc800f683340683b8`;
the independent output/patch proof is
`05ee7061177f17819205a3e663c1dd111e73fe557b95705b1de52c68b7bda811`.

The sealed implementation's full build, bounded-thread controls and eleven
ordinary regression targets pass. Its ABI invocation remains an overall
failure: nineteen checks pass and the libc check reports the prefix-dependent
`_nl_default_dirname` data-size difference. No ABI waiver is introduced.
The hermetic package passes at
`hzmrki4bk0j2s3rymskfx5v2qs5px8j4-glibc-crucible-2.39`. All twelve actual
bounded/ordinary targets pass with original exit status zero using its built
loader/libc and an explicit source-built unwinder. The package requires each
runner's original exit status and PASS result because the upstream single-test
make target can return zero after a failure. Each process is limited to two GiB
of address space. Independent installed-result and exported-symbol review is
`cf7b82aa95187a0e66011718b0d5f7ed86baa19c8d84ebbd17c08b1a9e5dcbde`.

`pkgs.crucible-cc` supplies an isolated C/C++ wrapper for that runtime. GCC's
embedded specs otherwise select the construction libc before user library
paths: the actual external consumer first failed to link the new API. The
wrapper retargets those specs to the matching headers, static libraries and
runtime before applying the existing compiler wrapper. Its first package build
failed because copied store metadata was read-only; making only the new output
writable fixes package finalization. Production compiler and libc identities
remain unchanged.

The installed compiler package passes at
`wzqnn5nz40d9yvyc2bq81bzlyclxjnfn-crucible-cc-16.2.0`. Its build compiles and
executes an external public-header consumer, checks the embedded loader and
actual libc resolution without environment overrides, and checks the C++17
header ABI. The consumer exercises actual unused-arena return, absent
registration and rejection of the prior incarnation after reuse. Its first
manual run incorrectly expected `ESTALE` after removal; the actual registry
returns `ESRCH` until reuse, when the old incarnation returns `ESTALE`. The
failure is retained and the control is corrected. The independent external
consumer proof is
`58ade586db97cea2abfd340b535dce61f51f983e39a8b287541d99d2d21ca9f8`.
The installed consumer now also creates a real joinable thread on a supplied
one-MiB stack through the exported bounded API. A deliberate live-worker
terminal cut returns `EBUSY` and retains stack/backing debt. After releasing
the worker, the public try-only terminal API completes within one fixed
ten-second test bound and reports actual entry, exit cleanup, kernel exit,
join, list/TLS removal and stack/backing return. The returned worker value is
checked independently. Its first run incorrectly expected successful return
to clear `first_error`; the implementation preserves the earlier `EBUSY`,
which the corrected control now requires alongside successful `retire_status`.
No provider implementation changed. Core evaluation passes at
`p0dcd4r7i1xmwbd0byjs53q3kybpd8s2`.
The independent installed-worker package review, including equality with the
derivation's immutable C source, is
`d27c884827aecc96f4f2087d5306a48b50f925f971ce82ec6c19c7834691ed2b`.

No QEMU loader change, caller application closure, nonwaiting
creation/TLS/callback claim or stack profile admission follows from these
packages. The ordinary public-ABI worker is distinct from QEMU's still-missing
application and thread-lifetime closure.

#### Canonical stack debt and caller-backed wrapper storage

The current signed atomic patch selects
`996393eb0e950647b7caf9d57b55d9ace836db38`, conventional source
`f5220fe98053a2b504d88f4b236c079afb2bd471`, tree
`303b8b33bfdbec44035ec3255374de6ee5486e78`. It adds canonical same-parent
Main/RR stack-debit journals and caller-backed prebirth thread wrapper storage.
The actual wrapper, arguments, copied name and hot-fork registry node are
retained together; preparation and unstarted return authenticate real retained
membership and exclude active metadata and borrower spans. These operations
create no pthread, application lender or selected runtime profile. Main
retirement now requires the actual independent return-post completion rather
than accepting an untouched zero status.

The physical source stage passes 64 storage/native/Source/layout steps,
including eighteen exact fixed-control omissions. All 27 genuine owning getter
translation units compile; 31 direct getters resolve through 38 compiled
bodies. The measured Source is 255,424 bytes and getters contribute 44,782,
giving a 300,206-byte floor. Preexec is 215,760 bytes, including its embedded
600-byte grant and 16-byte effect. The separate preexec inventory passes all
403 steps and 99 literal omission controls within its original 600-second
bound. Twenty stack-debt variants include one healthy baseline and nineteen
intended assertion failures. These are physical and predicate observations.

The same production bytes are retained in the final fixture composition.
The following runtime measurements belong to the preceding physical and fixture
stages; the final extractor correction changes only nine SHA-256 literals in
six Python files and introduces no new owning execution.
Five ordinary fixture dependency repairs and six exact CLI omission controls
pass. Delivery and stopped-control fixtures now honor the actual nominated
build directory, retaining and rechecking its canonical path, device and inode
before native-provider lookup. The first source stage's normal entry failed in
0.435 seconds because its helper ignored the nominated directory. That failure
remains separate from the corrected source's single passing normal entry:
57.075220144 seconds within the unchanged 60-second bound, two compiler workers,
CORE zero and six-GiB per-process and sampled process-tree address-space limits.
Fresh genuine provider preparation passes separately in 51.585 seconds.

Independent verification matches all 78,240 signed source entries, including
72 literal links, nineteen sealed artifacts and both complete evidence
archives: 10,117 regular files plus six links for the earlier physical source
and 9,162 regular files plus six links for the final fixture source. Every
production identity agrees between those stages. The conventional review is
`897a331fff5c79df6d17d58d2d34b347ac7238a852ea82d99a0db488a6a5856a`;
the separate signed atomic review is
`48ca44036aa43eee11191afce736bf9c8780b2c813a60b719dddbe1d99ea2bd1`.
The initial atomic candidate used current commit dates and was withheld; its
replacement preserves the tree and sole upstream parent with both required
fixed dates. Five new explicitly GPL-compatible files bring the created-file
ledger to 433, with no deletions.

Packaged validation exposed three separate failures before the final correction.
The first Source build stopped at target 896 of 909 when its extractor rejected
a stale stopped-control fixture fingerprint. The first atomic reconstruction
rejected a full bundle without the required pinned-base prerequisite; the next
rejected a patch whose diffstat disagreed with canonical `--no-stat` regeneration.
The corrected handoff contains a single-prerequisite delivery bundle and the
byte-exact canonical patch. All 120 final-source extraction invocations pass,
with zero compiler processes. Independent verification matches all nineteen
payloads, 78,240 source identities and 72 literal links, both signatures, fixed
raw dates, tree equivalence, canonical patch and bundle. Its proof is
`f53d965b03500ba28602f0cc964aa23b46fe48350a9b43b55bb8e10e3e843aa5`.

The packaged Native harness now includes the genuine stack-bank component as
its 37th component. It authenticates the actual Source owning compile command
and preserves every flag while canonicalizing its source operand for the
component's compile-database lookup. The original and derived commands remain
in evidence. Its original 180-second component and six-GiB process-tree bounds
remain unchanged. Fresh packaged Source qualification passes all 187 tests.
Canonical atomic reconstruction, the 433-file license ledger, engineering hygiene and ABI
conformance pass. The packaged Native attempt passes the Source suite and
eleven components, then fails compiling the publisher-member-return positive
control because its extracted pending-constructor closure omitted the actual
`stack_bank_borrowers_closed` dependency. The stack-bank component was not
reached. The original compiler failure remains retained; a later source stage
adds the genuine dependency and emits captured compiler diagnostics. Its direct
positive and all 25 exact omission controls pass, without changing assertions.
The subsequent complete packaged Native rerun is recorded below. The strict
license-boundary attempt fails during host Clippy compilation with 908 errors;
the boundary gate therefore remains unqualified. The earlier full-package six-failure result is retained;
direct fixture repairs do not establish a new full-package pass. The substantive
dirty-iterator launched lifecycle refusal remains. Genuine matched Module/Core/Source construction,
post-Main terminal ownership, application and stack grants, worker last use,
external reap, physical debit return and profile admission remain unqualified.

#### Native fixture closure correction

The signed atomic patch now selects `2564b502e49f7d164d07fcd64fdd4ec2bfad9545`,
conventional source `e2803b5320ec454d6d50e719e758a69ab50701d0`, tree
`a5bf76c20ff8ac6d08704cfe5a792503ede92555`. Eight Python files change;
production C and headers remain identical to the installed consumer below.
The pending-constructor fixture now emits its captured compiler diagnostic,
and both it and the RR-parent fixture extract the actual stack-bank closure
helper before its callers. Authentic transitive fingerprints are refreshed.
The original complete Native refusal and the separate diagnostic-only attempt
remain retained; the latter identifies the missing helper declaration.

Independent review verifies all 24 sealed payloads, 78,240 tracked source
entries and 72 literal links, 1,078 evidence files, signed stage identities,
fixed atomic dates, canonical patch and single-prerequisite delivery bundle.
Its proof is `25dc1a15c1f8711af91596db2a0185b6fad6ef864ef40b202e1918b75487ead9`.
The exact corrected source passes the constructor positive and 54 intended
assertions in 27.405 seconds, RR-parent positive and 29 classified omissions
in 16.698 seconds, and stack-bank positive and 19 intended omissions in
9.098 seconds. One sequential compiler retains the original 600-second suite,
180-second compile, 30-second run, CORE zero and six-GiB process and sampled
process-tree limits. Another 120 source extractions pass in 9.594 seconds
without compilation. The focused checks use authenticated recovered configured
inputs and no support archive. The 37-fixture source inventory alone is an audit.
The fresh complete packaged Native check now passes all 37 real-body components,
including the formerly failing constructor and the RR-parent and stack-bank
components. The genuine Source unit suite also passes all 187 tests. All
components return zero within the original 180-second and six-GiB aggregate
limits; the slowest takes 71.234 seconds and their cumulative runtime is
712.625 seconds. The independent result review is
`addba3d24f60c135bd4c78431628d4fad02cc9971f31cd5e6bc05311b8aa994b`.
This qualification covers standalone real-body components; it does not establish
launched Source authority or a full QEMU-package pass. Canonical atomic
reconstruction, engineering hygiene, core evaluation and the unchanged 433-file
license ledger pass.

#### Dormant Cleanup protocol observations

The permissive process-protocol crate now independently implements the proposed
384-byte dormant capability, 128-byte termination request and 1,024-byte actual
entry report. The capability retains future duration and unit limits without
an origin, start or endpoint: reserving Cleanup does not start its clock during
Work. Six positive, overflow-checked funding constituents must sum to the exact
physical child extent. Request and entry correlation preserve the original
reservation, recipient, command and ticket incarnations.

Entry facts retain negative born outputs, interrupted factory-return capture,
captured output without a known interval, and dirty Cleanup/Preparation cohorts.
None authenticates no-entry, grants Current or permits retrying an uncertain
entry. Nine new controls pass, the complete protocol suite passes 209 tests,
strict protocol Clippy passes, and all host, plugin and protocol targets compile.
Protocol documentation checks pass. The separately proposed Setup 9, plan 12,
service 7 and publisher schema 3 constants do not enable negotiation. Genuine
delegated local entry authority, complete same-parent physical funding,
installation and end-to-end entry/return remain required. The current entered
schema-two Cleanup row cannot substitute for this dormant capability.

The separate 128-byte physical-return codec now preserves independent entered
owner, reservation and funding histories. Known consumption survives interrupted
return capture or a negative post; absent request/entry fields for parent returns
do not prove no-entry. Thirteen Cleanup controls and all 213 protocol unit tests
pass, with strict protocol Clippy. The independent implementation accepts or
refuses all 99 public syntax vectors as specified and re-encodes all 24 accepted
records byte-for-byte; this does not establish executed C interoperability.
The ABI gate now requires the exact thirteen-test group and a canonical named
consumption case before running it, preventing a zero-test filter from passing.

The independently implemented 736-byte schema-three purpose now correlates the
physical session with a sealed future-entry delegation. It preserves the
assigned Source, authenticated carrier, clock domain, outer entry right,
dedicated resource parent, recipient, concrete profile and exact child extent.
An explicit absent endpoint differs from an immutable finite outer endpoint;
neither starts Cleanup time. Capability comparison requires exact parents,
profile and extent and limits future duration and canonical required units.
Sixteen Cleanup controls and all 216 protocol tests pass. The ABI gate requires
the exact sixteen-test group. These bytes cannot select a carrier or issue any
of the retained nominal owners; actual host issuance and native construction
remain required before installing the proposed profile.

The purpose implementation also matches all 169 independently generated public
vectors, including 22 byte-exact accepted round trips. The actual C decoder and
process-purpose owning units compile, link and pass the same vectors, including
unchanged-output negative controls. All 902 configured inputs and 311 unique
compiler dependencies match their recorded hashes. This is executed wire
compatibility, not issuer or runtime admission. The independent review proof is
`e90b422547725fff192c363175f239ad6e932043e653e1ce56d26446703947e5`.

The actual host budget owner now retains a once-only local Cleanup issuer.
Delegation occurs during genuine Setup or Preparation, creates no operation
record or Cleanup interval, and saves born output before the independent post.
Reservation requires the exact same supervisor allocation; equal capability
bytes and shared outer ancestry do not authorize another budget owner. Four
new controls cover allocation-free delegation, Setup return before reservation,
foreign owners, permanent once-only refusal and a negative independent post.
All 215 resource-crate tests pass; the private measurement feature passes 290
with one existing ignored test. The preceding sixteen-codec ABI gate passes.
The strict license gate reproduces the actual 908 host Clippy failures and
remains failed.

Initial Source admission now prepays an inline canonical issuer slot as part
of its actual retained state. The real startup Setup delegates into that slot
only after exact node-supervisor and Source-custody checks. A negative post
keeps the born issuer with the same admission after startup refuses. No native
resource child, selected carrier or wire capability is issued by this local
holder; the authenticated cross-process installation remains required.

The proposed plan-twelve carrier now encodes and decodes its exact 48-byte
header and 736-byte purpose without changing the active carrier. It preserves
the existing body order and aggregate cap, refuses every other edition, and
correlates the delegated Source issuer and local process resource parent with
the fixed family assignment. Four carrier controls and one overflow/cap control
pass; the complete protocol suite passes all 221 tests and strict protocol
Clippy passes. The ABI gate requires
both exact test groups before executing them. This is transport syntax and
correspondence, not authenticated installation or native entry authority.

The separate Setup-nine encoder/decoder now preserves the exact 125-byte
frame, incarnation-bearing footer, and optional workspace position. Its Unix
sender accepts exactly eight or nine borrowed descriptors and refuses malformed
or mixed editions before sending. Four framing controls and two real SCM_RIGHTS
controls pass; all 227 protocol tests and strict protocol Clippy pass. The ABI
gate requires those exact groups independently of the existing codec controls.
These byte and physical-alias checks do not issue a delegation or activate
Setup nine; the genuine retained-parent installer and complete runtime profile
remain required.

The distinct Setup-ten/plan-thirteen syntax now carries the immutable runtime
pair as an exact 192-byte record and two appended borrowed descriptor roles.
Its x86-64 file identities, nonwrapping generations and Source assignment must
correspond to the same containing purpose. Plan thirteen retains the unchanged
aggregate cap and existing body order; every other selected edition refuses it.
Twelve new controls cover exact records, all 272 public vectors with two exact
accepted round trips, malformed/mixed frames, foreign parents, optional workspace,
aggregate overflow, and real ten/eleven-alias SCM_RIGHTS delivery. All 239
protocol tests and strict protocol Clippy pass. Independent C-vector execution,
actual prebirth artifact retention, loaded-image/TLS funding and the real
retained-parent installer remain required before activating this edition.

The corrected Setup-nine ABI gate passes at
`4vg3xzidzz40k0fp3zm6g3c6ckrhk575`. Its first run correctly refused an
overlapping libtest filter: the root codec group also selected a nested plan
test. The corrected invocation excludes the separately counted plan module;
all original expected counts remain enforced. Mandatory application compilation
passes at `8ggrxi1dqbhi1ficwxf7vrran22yxbmk` with all 5,343 committed
Rust/TOML inputs matching its immutable source. Core evaluation also passes.

For the subsequent runtime-pair revision, all 5,348 committed Rust/TOML inputs
match the mandatory application's immutable source, and the separately checked
public vector fixture matches SHA-256
`cf11e957a8e305a8de6f3725156c8335c854ec3bb1f084a717832b9f0d58012a`.
Mandatory application compilation passes at
`clw18mqc3ap1f82jnn5hxi3qv458vn8k`. ABI conformance passes at
`1hhxmh0pa82f61j7397lgg7c35q2wwxh`; core evaluation also passes.
The requirement inventory now binds these 23 exact executed framing, carrier,
vector and alias controls to PLAN-2. Its fresh inventory passes at
`6nlclw3mmfljgba60y1wlr0qpwrjwir2`, with 467 total bindings across 243
requirements. All 148 uncovered requirements remain uncovered and none is
marked fully qualified; these component cases enable no capability.

Separate signed native source `4ad28c785d4dd60762c7df9ddda9abf21a365479`
passes its independent C reader component on the identical shared vector file:
272 cases, two exact round trips and 270 refusals. The finite twelve-step batch
also reads and hashes actual sealed libc/loader files, parses their ELF records,
retains real closed-descriptor EBADF, and rejects missing seals and wrong
digests. Both literal omission controls fail at their intended assertions.
Independent review matches all 452 sealed payloads and the complete reader
source in proof
`7362fc8189064ccc6373e7e91307eb123fc437c11b117a3de17fd7f09a95ad14`.
This separately staged native source is not the currently imported atomic QEMU
patch. Owning Source/preexec compilation, loaded-map/TLS association, physical
union payment and actual Setup-ten landing remain required.

#### Application allocator component qualification

Public libc source `39425b83aec13492400eccc0ea96d920f236099c`, tree
`ba222464fc63818a2d43be830119f0e39226e81f`, passes a fresh complete sequential
build and installation, application and bounded-pthread controls, eleven
ordinary regressions, and the real configured GLib/hidden-formatting component.
The actual installed loader, libc and public headers are retained together.
The earlier static-link collision and the first missing `libgcc_eh` test-link
failure remain recorded; the successful test uses the configured compiler's
actual unwinder archive through the standard static-test override.

The ABI check reports nineteen passes and one failure: the private install
prefix changes `_nl_default_dirname` from 18 to 64 bytes. It remains a failed
check. The measured application registry is 6,208 bytes aligned to 64, pthread
control is 552 bytes, and the separate shared metadata registry is 1,056 bytes.
The current public application-only process extent cannot pay that shared
registry. A complete canonical process owner, same-parent payment and complete
runtime profile remain prerequisites; libc custody return does not release
quarantined virtual addresses or permit child reuse. All 179 sealed payloads
match independent review proof
`a73f9728cd6028dcfdc9c1cabd75fa155f16f2197b147ff836a3e12c1fbb5d33`.

The additive complete-process API in signed source
`fe88ebc237bad3b3880a52ab7f2c29082ce6e3f2`, tree
`a2876d353f8b886f016ddbf93a1e515da1959c87`, passes a fresh full build,
installation, actual process/application and bounded-pthread controls, eleven
ordinary regressions and the configured GLib/hidden-formatting component.
Its canonical Current reports 7,300 bytes: 6,208 application, 1,088 complete
shared-pthread container including padding, and four readonly identity bytes.
Actual ELF symbols, mapped addresses and LOAD permissions corroborate all three
objects. The two new public symbols and installed headers match that source.
The complete installed archive's 1,434 file/link identities and all 184 sealed
payloads match independent review. The ABI check remains failed: nineteen
passes and the private locale-prefix size change from 18 to 62 bytes. Whole
ELF/page/TLS ownership, one same-parent union payment and complete runtime
profile admission remain required; the object inventory supplies none of them.

The package now imports the complete verified seven-commit source range through
that complete-process revision, with all 46 changed paths in its license ledger.
It derives the real static test unwinder from the configured compiler, runs the
application control as well as the existing pthread and ordinary controls, and
retains the original complete ABI log and status. A separate
`checks.crucible.phase7.glibcBoundedAbi` refuses any nonzero ABI result.
The installed compiler consumer also queries the canonical complete-process
inventory through the public header and matching runtime.

The earlier prefix-sensitive ABI failure is an exported
`_nl_default_dirname@@GLIBC_2.2.5` array, not a private-symbol exception. The
package configures the canonical `/usr/share/locale` runtime message path and
stages `locale.alias` under its output using installation-only `inst_localedir`;
it preserves all normal locale/charmap source installation. This leaves the
compiled runtime path unchanged during installation. Deployment must provide
that canonical message path or explicit domain bindings.

The fresh hermetic build of this complete-process revision now passes all
thirteen bounded/application and ordinary runtime controls, each with the
original runner's literal PASS and zero exit status. The complete original
`check-abi` returns zero, and its independent gate passes at
`cljibydqkm1v2lhzd27fr7vc6ndp69v0`. The installed public
`_nl_default_dirname@@GLIBC_2.2.5` object is exactly eighteen bytes; neither
the expected ABI list nor the source declaration was changed. The matching
compiler package passes at `zpmhwdlxhmxbhq7dids0fxbss4pd5ill`: its actual C
consumer queries the canonical process inventory, creates and physically
returns the supplied-stack thread, refuses stale reuse, and checks the exact
installed loader and libc. Its C++ public-header check also passes. Independent
review retains all thirteen original results and hashes the installed pair and
headers in proof
`c38afd5c5f448572b25400746b38d25ca5fc4e788abd171bce5fcd30c1a7b555`.
These results qualify this package component, not the subsequent fail-stop
provider revision, whole-image/TLS payment or launched runtime profile.

#### Prebirth containing-process transfer description

An independent Rust reader now describes the proposed 1,472-byte native subloan
material separately from RuntimePair192. It uses the public contract clarified
at signed `2dd6a79aeaa86d8db86ff903e2eda657ff5b006a`, tree
`733732b88065db12c710425f910af2a409470802`. Independent review verifies all seven
contract payloads against manifest
`ad4748312e373e2e7edc0d792bd36397782c426571e3402ab381ff0f4236de08`.
The earlier signed proposal remains separately retained, including its missing
artifact-count and page-edition bounds; it is not attributed the clarification.

The reader preserves ten ordered process-reap liabilities, disjoint native and
outside memory, compulsory fixed-floor/progress/physical-terminal rows and
positive outside creator history. It accepts only the proposed 4-KiB page
edition and two-to-32-artifact syntax bound, checks every arithmetic sum and
corroborates the exact runtime encoding and process/account/Source coordinates.
Nine adversarial/component cases pass in the full 248-test protocol suite;
strict all-target protocol Clippy also passes after replacing dynamic chunk
iteration with the compiler's fixed-array views. The initial Clippy refusal is
retained. Counted ABI registration and exact component bindings are added;
the hermetic ABI gate passes at `k8q7cjm0v2sz5fg52lsmdxgskn1n8x2g`. All
5,350 committed Rust/TOML inputs match that checkpoint's final application-test
source. Its mandatory application unit/integration target compilation now passes
at `9b61z4xrwvyy541fi0wlq8cd0a7bhz9a`; the exact source-comparison record has
SHA256 `209d6bc048f867e30ab262bf2705da3687bea9643eb89ab3d27692cbe640a852`.
Later manifest, plan-fourteen and probe additions require their own fresh
hermetic gates.

The borrowed complete manifest reader additionally checks the public clarification
at signed `86ed25302e7778b2ca24fe18f705645371d54cec`, tree
`f28d6ca445bf3a36e84362ccc2e0ed14e9a8092c`. Independent review verifies all seven
payloads against manifest
`41ec2c5070f82dcf406e32d94c537d1bb2e23e2c9e7aa5fb86e016690e51586c`.
It borrows at most 23,808 bytes, checks the consecutive artifact roster and its
unique child identities, all sixteen ordered producer rows, canonical unselected
rows, required finite request dimensions and exact launch strings. Argument and
environment totals include their four-byte length prefixes; environment names
are unique, while argument bytes may be non-UTF-8. Repeated descriptive producer
coordinates remain representable and confer no shared-custody or payment proof.
Complete manifest SHA256 and actual libc/loader identity correlation remain
separate from syntax. Eight additional focused cases pass, including every
truncation and independently valid foreign correlations; strict all-target
protocol Clippy passes. Counted ABI registration and component bindings cover
these cases separately from the nine transfer cases.

Independent C transfer/manifest vectors, negotiated resource phase, real prebirth
issuer and launcher, retained borrower adoption and matching
kernel reap remain incomplete. Setup ten and plan thirteen cannot consume this
material. A distinct plan-fourteen codec now adds an eight-byte header extension
and exact 1,472-byte transfer after RuntimePair192, under the unchanged aggregate
cap. It checks the same Source/process/account coordinates and full runtime digest;
mutually consistent foreign records cannot bypass the original Source purpose.
Four adversarial/component cases cover every truncation, changed header, foreign
parent and optional workspace; the independent extent case checks the aggregate
limit and overflow. Earlier selected decoders refuse the new framing. Counted
ABI registration separates these cases from the original transfer reader.
Parsing grants no resources or execution/cleanup permission; no negotiated
resource phase, extra descriptor role or profile is activated by these codecs.

The separate borrowed 3,584-byte paid-probe report reader follows signed
`6e7e4bc1d74f58e15de3a7dacfb632cad51cf957`, tree
`ed98000b05c4658751350b80f548259c3f5a58d5`. Independent review verifies all four
clarification payloads against manifest
`1b389e660f6da1d878267691bc40ab1ec5fa3ff4e89e63c8612edb42ad3e26c7`.
It preserves known no-birth, unknown birth, independent witnesses and matching
reap descriptions after lost launch-return observations. Impossible flag/witness
combinations refuse; nonzero errno or raw wait status remain valid negative
reports. Completed normal-exit-zero syntax is a separate predicate and grants
no birth/reap authority or outside-owner closure. Exact profile/report/runtime
digests and selected compiled producer contracts are correlated, while actual
probe-child identities may differ from future recipient children. Seven cases
and strict all-target protocol Clippy pass; counted ABI registration and exact
component bindings are added. Real paid probe issuance and launch remain absent.

Independent public NativeTransfer1 vectors are now shared under their explicit
MIT data license, without importing GPL implementation code. Signed source
`6ad9e2910c043d2fce01ccd616d143f6ab744294`, tree
`dc377e6e52839b134d5aa2b6f5cac4064c0d7b2e`, supplies 1,750 cases including every
truncation and nine accepted descriptive forms. Independent review verifies all
fifteen source-packet payloads against manifest
`6b1729939cfd94299dcebcc29f4d896dab46e6238f776dcc2a5264920698415b`.
The Rust decoder agrees with every case and reproduces all nine accepted byte
strings exactly; the TSV SHA256 is pinned separately. The full 269-test protocol
suite and strict all-target Clippy pass after replacing the test's randomized
name set with an ordered set. The initial Clippy refusal remains retained.
This adds a tenth root-transfer case to the counted ABI group. The complete
ABI conformance gate passes at `kxzxdxkfjr7mgwiaqq0ynax6si920zpl`, including
all 269 protocol tests, guest round trips and the host/guest API compilation
matrix. C compilation and execution remain unqualified at this source checkpoint.

The refreshed inventory at `9c6xv6gc2b9skkwd163y3jiaaka0ra30` verifies 497
bindings: 465 model, thirteen format and nineteen native, across 243 requirements.
It leaves 148 requirements uncovered and grants no execution qualification.
The mandatory application build for `5579c1d09b` passes at
`7n9c89am1ijypminch0q44p6klmkyd14`; independent comparison matches all 5,356
committed Rust/TOML files to immutable source
`l4dh43sfyz2vmqbbpjxcd6yk9y8n6vg5`, with zero mismatches. Its comparison record
has SHA256 `479a7d43a32a3d466271d065a08aad941ae2bf570fa2260011a83dc411097428`.

#### Complete native-profile plan component

Plan fifteen now independently frames the containing transfer, complete manifest
and paid-probe report under the existing 37,748,764-byte aggregate cap. Its exact
80-byte header and tail order follow signed public contract
`cbce456dee06e2008834d2f8e117b54493f4d176`, tree
`3fd1ceb0093012a13a74c981ed393b72b7403001`; all four contract payloads and the
signed-tree document were independently verified. Earlier plan decoders retain
their exact editions. Complete manifest/probe bytes are borrowed from the input,
including negative wait/errno and reap observations without a launch return.

Seven framing/correlation cases and one extent case join the counted ABI groups
and requirement bindings. The complete 277-test protocol suite and strict
all-target Clippy pass. Mutually consistent foreign tails still refuse the
original containing Source identity. Refreshed inventory
`c42yjzg3319bsgwgwym8j0lc13si6smv` verifies 505 canonical bindings: 473 model,
thirteen format and nineteen native, with 148 uncovered requirements and none
fully qualified. The fresh hermetic ABI gate passes at
`407pgc4zibhjkv5sqhj5vh7b33gmc89x`, including all 277 protocol cases and
the host/guest compilation matrix. Core evaluation passes at
`p0dcd4r7i1xmwbd0byjs53q3kybpd8s2`. Mandatory application compilation passes
at `asnmgd8pwrrb8jsfdmaydyflfvlsg4rd`.
All 5,358 committed Rust/TOML inputs match the latter's immutable source
`6dzf80a82r1894dj4pdfbx2mhs5sh5xg`; comparison record SHA256 is
`c965bfe66696331a34445f7e2f228324d1747158fb9bd0e112b60270639541d6`. This codec issues no paid landing,
receiving alias, containing loan, producer qualification or reap authority;
Setup-twelve receiver admission and full process admission remain unavailable.

The separate Setup-twelve sender now transfers the original eight/nine roles
followed by libc, loader, transfer, complete manifest and probe: thirteen or
fourteen actual Unix aliases. Its frame intentionally matches Setup ten;
selector `12` must be negotiated separately. The exact roster count distinguishes
transport, and malformed frames, earlier counts, extra roles and every negative
descriptor refuse before a socket byte is sent. Two real ancillary-transport
cases join the counted ABI and requirement bindings. All twelve transport cases,
the full 279-test protocol suite and strict all-target Clippy pass. This sender
does not authenticate sealed artifact contents, issue receiving custody or
activate the unavailable profile. Refreshed inventory
`l9dnzq26773nq6pkihy0xh1givxdcvhm` verifies 507 canonical bindings: 475 model,
thirteen format and nineteen native, with 148 uncovered requirements and no
execution qualification. The fresh ABI gate passes at
`l69dislqbcw37zq46mjmbwkw33a2ma0p`, including all 279 protocol cases and the
host/guest compilation matrix. Mandatory application compilation passes at
`022yvm54w1yf97jhp3xqn8l2zh3wwjfi`. All 5,359 committed Rust/TOML inputs
match immutable application-build source `ffjn61mkg8gknydx6r6p0r7k7v4nbr7z`;
comparison record SHA256 is
`89e513acc82e4c181b0aec4ce7e359cefb04c0556a80954d8685634fd9a5735d`.

The later signed clarification `77f7f203899996ee65739ea8c7b6cde8aeffaa32`,
tree `9eed56538d8c5522304d5b497bb1441609de5fe7`, broadens descriptive negative
reports. All seven payloads and the signed document match manifest
`90e44a08349a385eee282d3bd388564a92238e7337a2e9422e60549f8eed1833`.
Known birth can coexist with missing kernel/PID captures or sticky birth
uncertainty; retained local custody can precede a birth attempt. The reader now
preserves those facts without inventing witnesses. Completion still requires
all four positive coordinates, all completion flags, no birth uncertainty,
zero errno and zero wait status. Two additional cases and expanded plan-fifteen
round trips verify that partial reports never become completed results. All
281 protocol tests and strict all-target Clippy pass. Refreshed inventory
`1ka443fkc0ifwagp2pwqwrf8aidhy99r` verifies 509 canonical bindings: 477 model,
thirteen format and nineteen native; 148 requirements remain uncovered, with
no execution qualification. Its ABI gate passes at
`fnm4bxrwcsk9ziz289c03dzmwf2jw3kp`, and mandatory application compilation
passes at `35598whrilm72sd6f3pbzgzzmwxglxdw`. All 5,359 committed Rust/TOML
inputs and both then-existing fixture/license files match that build source.
Real paid probe issuance remains unavailable.

Independent manifest/probe public data now follows signed
`4c436f5b9557df0af17c831642e05f55c6715f1b` and compact-data revision
`e5d7f1fdfcde0018bc37d8b2d47a6a2e3b7e4820`. Independent review verifies all
fifty source-packet payloads and thirteen compact-packet payloads, both detached
signatures and both signed commits. The explicit MIT data license permits the
byte examples and bounded recipes; no GPL generator or decoder is imported.
The independently transformed 958,244-byte TSV reconstructs all 8,678 original
vectors exactly, checks every full-wire SHA256, and pins its own SHA256
`ac90eed8eb97dd424aa462d994b9f09f6e1756113a350f523783b5f34ae77f78`.
All 4,461 manifest vectors agree with Rust syntax, including eight accepted
descriptions. All 4,217 probe vectors agree independently on syntax and
completion: twenty-three accepted reports include six completed descriptions.
Every accepted report preserves its original bytes, including partial facts.
The complete 283-test protocol suite and strict all-target Clippy pass; the
initial test-helper Clippy refusal remains preserved. Both cases join counted
ABI groups and requirement bindings. Inventory
`61b28h5yxkvcib8zifyh4kjq2mgf7yzv` verifies 511 canonical bindings: 479 model,
thirteen format and nineteen native, with 148 requirements uncovered and no
execution qualification. Independent C execution, actual receiving custody and
paid probe issuance remain unavailable.

Complete-description examples now follow signed
`ae72e557a4f4e83feac04a5186b9783f7d786f90`. Independent review verifies all
twenty-eight packet payloads, the detached signature and signed commit. Only
explicitly MIT-licensed wire data is imported. A separate 113,418-byte compact
TSV reconstructs all 236 original four-record rows exactly and checks every
complete record SHA256; its own SHA256 is
`de013fc5ce061357a0715b3cc31ccfa4c79391d3a95b980cdda4d91f6cac60ad`.
All examples agree with the actual Rust runtime/transfer/manifest/probe
correlation: seven correlate, including six partial reports and one completed
description. Probe launcher/child facts stay distinct, and producer request
epochs remain distinct from transaction sequences. All 284 protocol tests and
strict all-target Clippy pass. The case joins a counted ABI group and the
requirement inventory. Inventory `j08b7v8yxvgknh9ankd19qfk2vigf1fj` verifies
512 canonical bindings: 480 model, thirteen format and nineteen native, with
148 requirements uncovered and no execution qualification. This data does not
qualify the unexecuted C reader, immutable receiving custody, a paid probe or
an actual resource issuer.

The partial-probe correction also passes its hermetic ABI gate at
`fnm4bxrwcsk9ziz289c03dzmwf2jw3kp`. The following independent-vector revision's
application inputs match all 5,360 committed Rust/TOML files and all four
existing public fixture/license files. Its hermetic ABI gate passes at
`8h4g3gnil4q1hr6fbck7ar3sxnyqsn8f`; its application build remains pending.
The complete-description revision's application inputs also match all 5,361
committed Rust/TOML files and all six public fixture/license files. Its
application build remains pending; its hermetic ABI gate passes at
`15al4s7ac4df59wynxd4m9d2k54nxl31`.

The Setup-twelve sender now refuses repeated descriptor handles before socket
identity checks or transmission. All 169 pair substitutions across the thirteen
and fourteen-role rosters return a malformed-roster error and leave the actual
peer socket empty. Distinct numeric handles still need actual physical alias
authentication by their retained owners. All thirteen transport tests, the
complete 285-test protocol suite and strict all-target Clippy pass. The counted
ABI group and requirement binding include the new case. Inventory
`2f8hj9dyd2vf1q2p9pngy4v94sl1vjvx` verifies 513 canonical bindings: 481 model,
thirteen format and nineteen native. The same 148 requirements remain uncovered
and none fully qualified; no selected receiver or paid landing is admitted.

The fresh engineering-hygiene evaluation first refused the stale source-review
digest for `host_supervision.rs`. Review against the previously approved source
confirms that the change adds the once-only Cleanup issuer latch to its existing
budget owner and initializes it only for a genuine new supervisor or budget
owner. Delegation and reservation remain in the focused child. The corrected
content-bound review passes at `zcvijji792yblcv5r97p578pnwrl3izi`; no source
behavior, size threshold or lint allowance changes.

The Setup-twelve descriptor correction passes its hermetic ABI gate at
`1ax53270s22xv8swmfi8jqj91jcgc7pp`. Its required application inputs match all
5,361 committed Rust/TOML files and all six fixture/license files; compilation
remains pending. The earlier Plan-fifteen revision's mandatory application
compilation passes at `asnmgd8pwrrb8jsfdmaydyflfvlsg4rd`, with all 5,358
committed Rust/TOML files matching its immutable source.

Target cleanup retry scheduling now uses a focused host-supervision cadence
instead of reading the host clock directly in the dispatcher. Actual per-job
next-attempt facts survive quarantine, unrelated readiness cannot accelerate a
retry, and zero or unrepresentable intervals refuse without erasing the prior
schedule. Typed cadence failures stay separate from physical control and
independent operation failures. Existing Cleanup checks still surround actual
physical passes; scheduling eligibility supplies no operation authority. All
three cadence controls, twelve real dispatcher component tests, strict
all-target resource-crate Clippy and engineering hygiene pass. The existing
quarantine control now waits out its actual retry interval instead of replacing
a timestamp. Inventory `dil0nl9vx77fri7frchmccc7z9h606g8` verifies 516 canonical
bindings: 484 model, thirteen format and nineteen native. The same 148
requirements remain uncovered and none fully qualified. All 5,362 committed
Rust/TOML inputs and six fixture/license files match the fresh required
application build; compilation remains pending. The private-feature Host Clippy
run reports no disallowed clock method, but still fails on 988 other findings,
including retained error sizes. This is not a passing license-boundary gate.
Five direct refusal adapters now pass their existing functions without
redundant closures, and the fixed-length parent-park identity reader uses
array chunks after its exact-length check. These changes retain the same
errors, custody and parser acceptance. All fifteen existing parent-park receipt
tests pass. The fresh mandatory application-target build has all 5,362
committed Rust/TOML inputs and six fixture/license files verified; compilation
remains pending. The remaining strict findings remain unresolved.

All 399 counted supervision cases pass at
`by431cc4vnwvazylwxbdx6jlv76jd0pk`, including the three retry-cadence cases.
The fresh canonical license-boundary attempt still fails in its Host dependency
with 908 Clippy findings; no suppression or error-custody weakening is applied.

The existing missing-helper-owner regression now expects the concrete
`HelperCustodyUnavailable` refusal instead of an obsolete constructed I/O
wrapper. Its actual negative run passes and still removes the image before
launch to prove that unavailable custody refuses before path revalidation.
This corrects one stale assertion from the earlier full-library failure report;
it creates no Source owner and does not qualify the separate helper execution
cases that need genuine retained Main/Source custody. Mandatory application
compilation for this test correction is running.

The actual hot-fork worker-disposition quarantine regression also passes on
recheck with its original timeout and resource bounds. This is one exact case,
not a new full-library qualification.

Native pool, Source, dispatcher, World and node-window issuers now prepay their
private refusal carrier from the same actual Main before child publication or
kernel effects. A failed cut moves its genuine owner into that existing
allocation. First, independent post, delivery and receiving-stage causes remain
separate; later diagnostic recording allocates nothing. The unique carrier
exposes no shared or weak aliases and closes its allocation before destroying
its retained owner and original paired charges. Clean postcut and actual
unassigned-World refusal share an explicit state representation; a negative
postcut cannot acquire the unassigned classification. The complete report fits
below the fixed 128-byte inline threshold, removing five prior large-error
exceptions without suppressing a lint. All 222 host-resource unit controls and
strict all-target resource Clippy pass. Allocation controls observe all three
real allocator requests and both original charges immediately before and after
the carrier's actual free. These component checks issue no authenticated Main
or Source and do not qualify complete error-payload funding or native launch.
Inventory `1ydgg9pg14zh56wqz9ih748ay50mlfk8` verifies 521 canonical bindings:
489 model, thirteen format and nineteen native; 148 requirements remain
uncovered and none fully qualified. The required application-target compilation
remains in progress. The same private-feature strict Host-library lint command
now reports 734 findings, down from the earlier 988; remaining large enclosing
errors and other findings still prevent a passing host/license gate.
Engineering hygiene passes after review and correction of the preceding spawn
adapter/test source digests; no threshold or waiver changes.

Cleanup and publication branches now use ordered let chains, preserving the
same physical effects, original observations and first-failure retention while
removing all seventeen nested-branch lint findings and one redundant return
binding. The existing focused dispatcher, hot-fork, shutdown, Source-stop and
publication checks pass all 59 cases. The same strict private-feature Host
Clippy command now reports 716 remaining findings; enclosing error custody and
other required gate work remain incomplete. Engineering hygiene passes with
the two containing-source reviews refreshed; no lint policy changes.

The descriptor-alias revision's mandatory application-target build passes at
`wm62a08l5ap5d1dgkdqxvwzrraxklg4s`, and the four-record public-vector revision
passes at `6gns9hv88l4pa6kn3b67sbxh30dy9755`. Their previously recorded complete
committed-input and fixture/license correspondence remains exact. These
compilation results do not qualify a launched native profile.

The actual shared launch-cleanup record now frees its allocation before its
extracted payload retires custody. Every observer uses the same private
`Arc::into_inner` destruction route; no weak or raw shared alias escapes.
The original Source control loan is the payload's last field, so other
physical owners close before that loan returns. Admission also covers the
construction/extraction overlap and owner handle. Three causal controls first
failed on the old implementation: both paired charges had already returned
when the actual allocation was freed, and the recipe omitted the extracted
frame. All thirteen cleanup controls pass after the fix, including eight
concurrent final observers and observed funding immediately before and after
the actual free. The fixture provides mechanism funding without issuing Main,
Source or native retirement authority. Inventory
`3vjnw0zv535q2z8zk6bqbmh9s40bklsj` verifies 524 bindings; 148 requirements
remain uncovered and none qualified. Engineering hygiene passes. Strict Host
linting still reports 716 findings; application-target compilation and the
fresh counted supervision check remain in progress.

The cleanup fix's final application derivation matches all 5,364 committed
Rust/TOML inputs and six protocol fixture/license files. The source comparison
record has SHA-256
`93b72cbc59d15025bdb0f9668707cbd3a0913a564e768de7c36e8f1f2537fed6`;
compilation subsequently passes at `k1mppn1nli00s2zf4v4kjfpnyxb5s0cp`.
Preexec preparation now borrows its existing
source record and a focused plan/descriptor material record instead of twelve
independent arguments. Validation, descriptor effects and failure custody keep
their original order. All five existing preexec controls pass; focused
formatting passes and the strict Host command reports 715 remaining findings.
The mandatory application build for this grouping subsequently passes at
`ls8pcqg6hbn7v3z1afzlqyq51f6av1lc`.

The remaining simple control-flow findings now use the same final original
check, ordered action-loan iteration and direct fresh-node error propagation.
All 27 existing native-account and action controls pass, focused formatting and
engineering hygiene pass, and strict Host findings are down to 712. There are
no new lint exceptions; retained error sizes and other required gate failures
remain unresolved. Mandatory application compilation subsequently passes at
`6q2k9al836mksfjz8vcxxc7cbizficin`.

The missing-helper-cause correction passes application-target compilation at
`bcikwrhnzsr5in369zllhill83qwv1qf`; the refusal adapters pass at
`4v0145697ak7llgcbfbwhiizy1360vbg`; the cleanup retry cadence passes at
`6xk8qyq86jir9q6vsv6r85x149zh1xmi`; and the prepaid refusal carrier passes at
`hjjw1p5mdgwlcffmw5d2whylx16nvd9i`. Their previously verified committed
Rust/TOML inputs and fixture/license correspondence remain exact. These are
compilation results, not a native launch or complete RFC qualification.

The preceding refusal-carrier revision passes all 404 counted supervision
cases at `ki9kfmxkqzv7n56wmyx46zj3fxqdsw4j`. This is component evidence,
not qualification of the missing native Source issuer or complete RFC.

The cleanup allocation fix subsequently passes all 407 counted supervision
cases at `0yfhg3pzw37rnl26a7fmqmz3m64n6id2`, including its three new
allocation controls. Initial Source admission now uses the existing funded
storage owner: the actual original loan remains external to its shared value
through allocation free, and the reservation covers both shared allocations,
their funding constructor, the Source value and its holder. Subject, original
Main, artifact, receiver and supervisor checks remain unchanged. No Source
issuer is supplied by these mechanism changes.

A separate causal constructor-refusal control first fails with the old
argument destruction order: the value closes after its original charges have
returned. The corrected refusal destroys the value before releasing the same
charges, with no allocation. All 223 host-resource unit controls and strict
all-target resource linting pass; engineering hygiene passes. The strict Host
run reports 711 remaining findings after removing the former eight-argument
admission constructor. Inventory `l5fm3sidhm682fx9k9rlv310ncq1rcaw` verifies
525 bindings: 493 model, thirteen format and nineteen native. The same 148
requirements remain uncovered and none qualified. All 408 counted supervision
cases subsequently pass at
`aj5wl3sj39bqbilagff5mh40vahdcbdi`, including the constructor-refusal control.
Fresh application-target compilation subsequently passes at
`j9xs7v7vhx231h1pam4p85w6hfd141pj`.

The ordered cleanup/publication revision also passes mandatory application-target
compilation at `c95k373n7dr23iq2k8rdgks1z9awcxj6`. Its previously recorded
5,362 committed Rust/TOML inputs and six fixture/license files remain exact;
this does not qualify the later revisions or a native launch.

The fork Target geometry now names each checked envelope limit instead of
returning a five-value tuple. Generation reservation, descriptor accounting,
credential identity and failure custody retain their existing order and values.
All 26 focused envelope, construction and missing-Source controls pass; focused
formatting and engineering hygiene also pass. Strict Host linting reports
696 errors and fourteen warnings, with the geometry type-complexity finding
removed. Mandatory application-target compilation subsequently passes at
`7y3zsm8pxgqpaw0pjb4llvjgd3zl2d77`. The exact 5,364 committed Rust/TOML
inputs and six fixture/license files remain verified for each of these five
application revisions; these compilations do not supply the missing native issuer.

The installed image preparation and issued-record consumer now use named input
records. Artifact, original, contract, generation, Source publication and endpoint
checks retain their existing order and values; the records add no heap allocation.
All fifteen focused process-purpose and preexec controls pass, as does the actual
source-shape integration check against refreshed hashes and responsibilities.
Focused formatting passes for the three edited implementation files; the roster's
unrelated existing whole-file formatting differences remain preserved. The Nix
engineering-hygiene gate also passes. Strict default-feature Host linting remains
failed (624 library and 697 test diagnostics); the two former process-purpose
argument-count findings are absent. The feature-matched strict run reports 694 library errors and fourteen warnings,
with 765 test errors and five warnings; no compiler type error or interface
visibility warning remains. Mandatory application-target compilation passes at
`8n0g45iar92qafd7pc6fdbbxj6k54v77` against commit `a44d65bee6`; all 5,364
Rust/TOML inputs and six fixture/license files match its immutable build source.
These checks do not qualify native
issuance or physical return.

The remaining guarded child-birth and concurrent fork-worker argument groups
now use named borrowed inputs. The launch record retains the existing contract,
run directory, cleanup alias, preexec selection and child-return reservation;
the worker records distinguish retained rows from row operations. Neither
record allocates or issues authority. Validation, descriptor/resource effects,
worker joining, panic custody and child publication retain their prior order.
All eighteen existing focused worker, preexec and Target-construction cases
pass. Focused formatting, the actual source-shape integration check and Nix
engineering hygiene pass with the three containing-source reviews refreshed.
The strict default-feature all-target Host command with `-D warnings` still
fails with 639 library and 701 test diagnostics, including warnings promoted
by that flag; both former argument-count findings are absent. The matching
private-feature lint comparison reports 692 library errors and fourteen warnings,
with 763 test errors and five warnings, two fewer errors in each target than
the preceding comparison. Mandatory application-target compilation passes at
`60h25h1jjilx241ym9047f4q3hmg3iv7` against commit `a2aa1d11bb`; all 5,364 Rust/TOML inputs and six fixture/license
files match its immutable build source. These changes do not qualify
native birth, issued Cleanup, paid profiles or physical retirement.

The shutdown and startup component fixtures now return named records instead
of anonymous four- and five-field tuples, preserving field and destruction
order. Cleanup's test registrar uses a direct block for its preparation result.
All thirty existing causal controls pass: nine shutdown, eight startup and
thirteen cleanup cases. Focused formatting and engineering hygiene pass. The matching strict Host
lint command retains 692 library errors and fourteen warnings; test findings
fall from 763 to 759 with five warnings. All three tuple-complexity findings
and the immediate closure-call finding are removed without lint exemptions.
Mandatory application-target compilation passes at
`a9ka61gsqlkzn6jjyvfqpi21kawkiwjh` against commit `4cee718eda`; all 5,364
Rust/TOML inputs and six fixture/license files match its immutable build source.

The Target dispatcher now retains its actual unresolved native join owner when
the facade is abandoned. A single-publication slot lives in the containing
state allocated before worker birth; its exact layout is included in the
existing control peak. Abandonment moves the unique record into that slot
before retaining the state and payer, without allocation, joining or a new
wait. A native-zero result still clears the active owner before independent
Cleanup postchecks. All thirteen dispatcher component tests pass, including a
real blocked worker whose unchanged identity and unqueried native handle
survive transfer and subsequently observe actual return. The source-shape
integration check and Nix engineering hygiene pass. The matching strict Host
lint command reports 690 library errors and fourteen warnings, with 757 test
errors and five warnings; both previous non-Drop ownership diagnostics are
removed without exemptions. Mandatory application-target compilation passes at
`073mk0sg2vj3zx04d92c31hrang5c3mz` against commit `30ab2c5cc4`; all 5,364
Rust/TOML inputs and six fixture/license files match its immutable build source. These component results do not issue Main custody
or qualify complete native retirement.

Source-service abandonment now retains its unique native join owner in the
existing outcome allocation, alongside its actual containing join obligation,
recorded cancellation/return history and independent birth observations. The
single-publication slot is outside the worker-result mutex, so abandonment
neither waits for delivery nor allocates a new recipient. Its full actual layout
is included in the existing startup metadata admission before worker birth.
The same existing outcome alias keeps the task, controls and original service
loan charged until containing process exit; a returned Rust body or completed
TLS destructor cannot replace the missing native join.

All twenty-eight Source controls pass. The new causal control keeps no extra
worker, outcome alias or service lease and holds the actual Source worker in
TLS destruction after its Rust body and delivery alias close. The same account
refuses another byte during and after that teardown, and facade destruction
performs zero allocations or reallocations. Omitting only the retention
transfer makes the test fail at the budget-refusal assertion; restoring it
passes, including the complete recorded-history recipient. The existing real
success and unwind controls still prove allocation-header closure before
refund after an explicit native join. Engineering hygiene passes. The matching
strict Host library lint result remains 690 errors and fourteen warnings; no
new library finding is introduced. Mandatory application-target compilation
passes at `9wakr6dqpbmnyyfix390d43xff61s1mz` against commit `6473eeaadd`; all
5,364 Rust/TOML inputs and six fixture and license files match its immutable
build source. These are component custody
checks, not authenticated Main issuance or a complete paid native-profile result.

The broader Host suite passes 1,348 cases with ten failures and four ignored
cases. Eight failures involve unavailable helper custody. The selectable idle
case expires during Setup in the parallel suite and passes independently. The
remaining cleanup fixture expected abandoned capacity to return after Rust
completion without a native join; that expectation is corrected. Its real
worker now reports TLS teardown, after which both original capacity and the
containing launch remain retained, with neither retirement nor a quarantine
callback. Omitting only the actual containing-join transfer makes this control
observe an erroneous quarantine callback; restoring it passes. All thirteen
cleanup controls pass, including the independent normal join/discharge case.
Mandatory application-target compilation passes at
`8jkrh6iryn7c84j60pmpxkm95lkg7r30` against commit `bac7b40048`; all 5,364
Rust/TOML inputs and six fixture/license files match its immutable build source.
No missing helper issuer or Main authority is synthesized.

Pre-exec abandonment now retains its complete handover history in a linear
recipient inside the containing cleanup allocation. The recipient is claimed
before control reservation or descriptor effects; its full actual layout is
included in existing admission, with construction overlap included in the
pre-exec peak. On uncertain cleanup, Drop moves the frame, actual completed-write
receipt, every attempted alias close, concrete first cause, independent original
post-observation and original control loan into that already allocated record.
It retains a real strong owner without allocating, waiting or joining. The
unreaped-child fallback now runs this owner destruction instead of forgetting
an inline record. Closing the parent's aliases cannot close the child's imported
aliases. Proven cleanup closes the local owners normally, with the pre-exec
control loan destroyed after its failure and local observer handles.

All nine pre-exec, thirteen cleanup and twenty-eight Source controls pass, as
do both stopped-child polling controls.
The new controls use real descriptor queue writes, alias closes and child reap,
paired component funding and allocation observation. They establish neither
Main nor Source issuance. Omitting only history publication makes the new
causal control fail while the containing allocation remains retained; restoring
it passes. Abandonment, unqueued close and proven receiver-close/reap paths
perform zero allocations or reallocations during owner destruction. Both normal
controls refund the complete paired loan. Nix engineering hygiene and the Rust
source-shape integration check pass. The
matching strict Host lint result remains 690 library errors and fourteen warnings,
with 757 test errors and five warnings; no exemption is added. Mandatory
application-target compilation passes at `02x255pmhxjikap5zjyjac9niqjjc55j`
against commit `c2747bbf05`; all 5,364 Rust/TOML inputs and six fixture/license
files match its immutable build source.

The unreaped-child fallback now retains the complete live RAM Source facade
in another single-publication slot inside its original outcome allocation.
This preserves the actual wake and startup sockets, immutable backing,
unqueried native owner, birth and stop history, journals and original service
loan. The transfer neither cancels page service nor joins, polls or allocates.
The full allocation and overlapping construction/retention frames are admitted
before preparation and worker birth. The separate ordinary-abandonment recipient
continues to preserve a canceled worker's unresolved native join debt.

All thirty Source controls pass. Two new controls retain an actual prepared
service before worker birth and an actual running service that subsequently
serves a real authenticated page request. The native identity remains unchanged
and unqueried; Rust delivery and closing the diagnostic alias do not refund the
same account. Both transfers allocate and reallocate zero times. Omitting only
whole-facade publication makes the live-worker control fail at its retained-owner
assertion; restoring it passes, along with thirteen cleanup and nine pre-exec
controls. The existing abandoned-worker TLS fixture now installs its destructor
on the actual serving worker during a real request and holds that callback
through facade destruction. It no longer assumes that the final shared backing
destructor runs on the worker. These component checks do not establish Main or
Source issuance, complete unreaped-child retention, or native-profile activation.
All four child-exit and two stopped-child controls also pass. The source-shape
integration check and Nix engineering hygiene pass. The matching strict Host
lint result remains 690 library errors and fourteen warnings, with 757 test
errors and five warnings; no exemption is added. Mandatory application-target
compilation passes at `2hjzicxx5ml1951rp38xhzk7kv9zn9vc` against commit
`c17fc21248`; all 5,364 Rust/TOML inputs and six fixture/license files match its
immutable build source.

The containing cleanup record now also reserves a sole child-return recipient
before actual process birth. Both successful enrollment and refused enrollment
install that same linear recipient. If bounded final cleanup cannot observe
reap, Drop transfers the actual wait owner, pending RAM input, original startup
and checkpoint owners, and independent kill/wait observations into its funded
record. The same transfer retains the live Source facade and pre-exec history.
It creates neither a substitute wait authority nor a reap receipt. Final wait
polling preserves the original kernel error without allocating diagnostic text.
The complete recipient layout and construction overlap are admitted before birth.

Three actual-child component controls pass, alongside thirty Source, thirteen
cleanup, nine pre-exec, four child-exit and two stopped-child controls. They
check a single prebirth claim, unchanged actual wait identity and pending
backing, zero transfer allocations/reallocations, conservative paired-credit
retention, and complete refund after an actual reap closes an unused recipient.
A real externally reaped child supplies the raw ECHILD allocation control.
Omitting only child publication fails the real-process retention assertion;
restoring the exact source passes all affected controls. These component checks
supply no Main/Source issuance or native-profile activation. The source-shape
integration check and Nix engineering hygiene pass. Strict Host lint findings
remain 690 library errors
and fourteen warnings, with 757 test errors and five warnings; no exemption is
added. Mandatory application-target compilation remains required for this change.

Pre-exec refusals now use a small owning error handle into a separate recipient
inside that same prepaid cleanup allocation. The first cause and independent
postcut stay immutable; public source inspection borrows the actual stored cause.
The unique prepared owner publishes at most one refusal. Error destruction takes
its local owner under a private mutex and closes aliases outside that lock,
without allocating a late box. Uncertain handover history keeps the same record
and original pre-exec control loan. Normal final cleanup destroys diagnostics
and that loan before registrar retirement refunds the containing allocation.
Both physical record storage and overlapping construction remain prepaid.

All ten pre-exec controls pass, including real kernel refusal, exact source-chain
identity, zero error-creation/destruction allocations and reallocations, actual
socket EOF after local alias closure, and complete paired refund after diagnostics
close. The EOF check uses a bounded socket timeout so a concurrently forked
fixture can finish its real exec and close inherited CLOEXEC aliases. Omitting
local-owner destruction makes that control fail; restoring the exact source
passes all ten controls, thirteen cleanup, three child-retention, four child-exit,
thirty Source, two stopped-child and eight startup controls. Source shape and
Nix engineering hygiene pass. Strict lint findings fall to 678 library errors
and fourteen warnings, with 744 test errors and five warnings; no exemption is
added. Other large retained errors remain, and the strict gate still fails.
These component controls issue no Main, Source or native-profile authority.
Mandatory application-target compilation remains required for this change.

Cleanup fixture validation now polls the same retained native owners a finite
number of times and checks their actual successful return status, without
reading host clocks. The cleanup allocation fixtures report explicit setup and
refund failures; the Source-health fixture propagates missing local custody.
All thirteen dispatcher, fourteen worker-failure, thirteen cleanup and three
Source-health controls pass, along with the source-shape check. Strict Host lint
still fails at 678 library errors and fourteen warnings, with test-target errors
falling from 744 to 731 and five warnings; no lint exemption is added. These are
fixture changes and establish no additional native authority or RFC capability.
Mandatory application-target compilation remains required for this change.

The fixture changes also pass Nix engineering hygiene at
`zcvijji792yblcv5r97p578pnwrl3izi`.

The subsequent ordering-only cleanup moves complete existing production blocks
before their test modules, with byte-exact block contents preserved. All four
attempt-owner and two process-stage controls pass, along with source shape.
Strict Host lint remains at 678 library errors and fourteen warnings; test-target
errors fall to 729 with five warnings. The remaining diagnostics concern large
error carriers. Mandatory application-target compilation remains required.

Source stop receipts now borrow immutable records in a finite journal admitted
under the same service loan before worker birth. The journal covers all monotone
birth, cancellation, Original-boundary, worker, panic and native-status changes;
repeated observations share the existing record. Even a receipt containing only
an Original refusal retains the journal and original charge after the Source
body closes. The last receipt frees the actual shared header before destroying
its records and returning the loan. Publication and cloning allocate nothing.
Scheduler conversion borrows those immutable records and shares the same worker
cause. No Main/Source issuer or native-return authority is added.

All thirty-one Source, three Source-health and nine node-error controls pass.
The actual allocation observer verifies zero receipt-publication and clone
allocations, immutable earlier observations, continued charge after body removal,
and original credit retained across actual shared-header deallocation. Omitting
only header-before-record destruction fails that real credit assertion; restoring
the exact source passes all affected controls. The source-shape check and Nix
engineering hygiene pass. Strict Host lint still fails, with findings falling to
674 library errors and fourteen warnings, and 723 test errors and five warnings;
no exemption is added. Mandatory application-target compilation remains required.

The complete Host suite against `c169861aa6` passes 1,361 tests, with four
ignored and eight failures at the existing unissued helper-custody boundaries.
No additional failure appears from the stop-history change. All 5,368 committed
Rust/TOML inputs and six protocol fixture/license files match the mandatory
application build's immutable source; compilation remains in progress.

The journal admission controls now include the stop journal among the other
funded controls in the existing single-worker-journal refusal. A separate
one-byte-short complete-peak control refuses before allocating or consuming the
actual Source socket and backing. It preserves their identities and leaves the
whole original component allowance available. Omitting only the stop-journal
charge defeats that actual admission refusal; the exact production source is
restored afterward. All thirty-two Source controls pass; these checks provide
no Main or Source issuance.

Both existing cleanup source-contract controls pass with the exact owning
snapshot publication. Their causal mutations reject a return to inline history
copies while retaining the actual native-return, saved-Cleanup and independent
post-observation obligations. The source-shape check also passes.

The broader source-contract suite initially passes 51 controls and fails 23.
Its Target-dispatcher witness now binds the actual retained-worker cell,
fallible host cadence polling and cadence-failure retention, while preserving
actual native return and saved-Cleanup observations. Mutating either cadence
poll to immediate readiness is rejected. The focused dispatcher control passes;
the complete suite now passes 52 controls and fails 22. These remaining source
classification failures still prevent a complete testing-standards pass.

The shared World and Node witnesses now require the actual prepaid refusal
carrier, reservation before World assignment, typed independent postcut and
closed shared-header destruction before credit return. The helper witness keeps
the same installed recipient after the error-conversion simplification. The
child witness additionally requires the original preborn abandonment recipient,
actual wait-authority transfer and ECHILD after transfer; causal controls reject
foreign owners and invented reap observations.

Dispatcher component checks require the real fallible cadence, independent
physical-empty observation, finite native-join allowance and same retained
worker. Wait and recovery contracts independently inspect the unchanged source
before combining masks, so neither erases the other's ownership evidence. All
74 focused controls pass; the remaining broad gate reports 25 findings across
24 paths. These are open classification failures, not a complete standards pass.
The final formatted source-shape check passes after reviewing the same recovery
module and refreshing its content-bound digest and unchanged-threshold count.
The original stale-record refusal remains recorded; no size limit is relaxed.

Mandatory application-target compilation for unreaped-child retention commit
`16927f3a5a` passes, producing `b6437jdpvrgi1nwm0dbvrjrq7ix51zdn`.
The previously recorded immutable source and protocol-fixture correspondence
binds that result. Three subsequent application builds also pass with their
previously verified complete immutable source and fixture correspondence:
`bc49492cf4` produces `jyckv3mdvmlkzb058xbzqkrgdwlfhc4p`, `29bdfa8a89`
produces `5nlic3q5nrk05i7c4rj6ly0b77nf45kj`, and `3e090c3243` produces
`rgagh52sxn61plpzppbgpkfsl5rjyrmw`. The stop-journal application build at `c169861aa6` passes at
`9cfd0mjhsplmk3wxpzx9n6k2qh1j8xwh`; its source-contract successor
`51e05754c3` passes at `k75bfxilxagaxpv720bdghn653bl6qpz`; and dispatcher
contract commit `7aae80bc53` passes at `q96h3q0j3kcya4p3p93qfw5hk00jg87i`.
All 5,368 committed Rust/TOML files and six fixtures were independently matched
to each build's complete immutable source. The retained-custody contract build
at `32cb19e316` also passes at `vw6alzv06iz8zr74fz3ssvmlvblvfwzc`, with the
same complete source and fixture correspondence. The cancellation-cause
application build for `7277cfa58c` now passes at
`y74i0wid9zab019d4s6acn905yd4l727`, with all 5,369 committed Rust/TOML files
and six fixtures independently matched to its immutable source.

Source cancellation failure publication now uses a separate immutable cause
body allocated under the stop journal's original loan before worker birth.
The complete journal peak includes its shared header, body, construction storage
and owner handle. The first returned I/O error fills its private once-only cell;
receipt publication and cloning share that existing allocation. An erased cause
observer retains the same original loan independently of the stop journal, and
the last observer frees its shared header before dropping the error and loan.
The original I/O error remains reachable through the standard error chain.

All 33 Source controls pass, including zero-allocation cause publication,
first-error identity preservation, complete-peak admission refusal and physical
shared-header credit observations. No Main/Source issuance or native-return
authority is added. Replacing the shared cause's actual header-before-payload
closure with ordinary destruction defeats the physical-credit control; exact
restoration passes all 33 Source controls again. Both cleanup witnesses and
both new component-observation contracts pass. Those contracts bind the complete
actual journal and worker observations, prebirth funding and finite poll bounds;
controls reject foreign owners, invented return receipts and additional waits.

Source shape passes. The complete testing-standard suite passes 76 controls;
its remaining broad operational-wait failure reports 22 findings in 22 other
paths. Strict host Clippy remains blocked by the unchanged 674 library and 723
test-target errors, with 14 and five warnings respectively. Mandatory packaged
application-target compilation for this increment remains pending.

The resource-free component launcher's cleanup adapter now has an exact
classification covering its test-only guards, absent native post-body, delegated
finish and production launch/replay refusals. Removing a guard, introducing a
native effect or adding another retry defeats the classification. Both mutation
controls pass while preserving the actual source's token boundaries. This
component adapter supplies no World, Service, Source or physical-return proof.
Source shape passes. Testing standards pass 88 controls and retain one broad
failure over eleven other daemon paths. Mandatory application-target compilation
for this increment remains pending.

Three earlier mandatory application-target builds now pass: shutdown error
storage at `r08n6856z7ngm39mvncvzwx1fdp5gdvz`, compact Source receipts at
`a1cwykmshg5190i6zkdi7s98s6z5vvzk`, and retry cadence at
`97x3idhz1bh0m82k27kmicv3phfq8f6a`. Each frozen source had all committed
Rust/TOML inputs and six required fixtures independently matched before later
source edits.

Source installation cleanup reports now borrow fixed status text and move both
actual cleanup and independent stage-observation refusals into inline typed
storage. Repeated factory reports retain the original constructor cause in the
same owning factory until terminal history handoff. They no longer render or
copy that cause after effects. The existing independently observed Complete gate
and physical custody rules remain unchanged.

All three new component controls pass: repeated reporting allocates nothing,
the original constructor retains its exact string storage, and both returned
refusals retain their actual typed causes and string identities. Restoring the
old diagnostic rendering defeats the allocation control; exact restoration
passes it. The controls issue no native Main, Source or physical-return grant.
Source shape passes, and all 88 focused/source-policy controls pass apart from
the existing broad operational-wait finding across eleven daemon paths. The
unrestricted full daemon run has 1,657 passes, 114 failures and 43 ignored tests;
its failures include quota-bound SQLite setup and out-of-memory refusals. The
serial rerun passes all 1,771 daemon tests with 43 ignored, including the unchanged
512-MiB packed-volume control. No fixture capacity or assertion was relaxed.
Mandatory application-target compilation for this increment is also pending.

Two more mandatory application-target builds pass: four retained refusal paths
at `zr2039jhxnlx7722s45pgf0d9vl912cs` and publisher refusals at
`jz3vyywv1sk1mgwm4yzskg7z1hldyrnn`. All committed Rust/TOML inputs and six
required fixtures independently matched each build's complete immutable source
before subsequent edits.



The debugger-candidate runtime and shutdown callers now share the existing exact
handback, terminal custody and containing-history contracts. Classification
requires the same retained candidate, propagated cleanup refusal, completed
history transfer and whole-shutdown gates. Discarding a refusal, dropping history
before transfer or returning the launcher while candidate cleanup is refused is
rejected. All 89 focused/source-policy controls pass; the remaining broad retry
finding covers nine other daemon paths. The unchanged generic mutation controls
continue to reject extra attempts and foreign receivers. This is source evidence,
not native execution qualification.

The earlier compact controller-receipt application-target build passes at
`6zh9wnycc2hz2hbdhs21vqpjic84v8gq`. Its 5,379 committed Rust/TOML inputs and six
required fixtures independently matched the immutable build source before later
edits.


The native Flight and ordinary/exact-resume factory adapters now classify only
their exact retained-owner calls. They share the existing Source publication,
Main retirement, original receipt and native-body producer contracts. Flight
continues to borrow its same factory; resume cleanup continues through the saved
installation owner. All 89 focused/source-policy controls and source shape pass,
including the unchanged generic foreign-owner, omitted-obligation and additional-
attempt mutations. The remaining broad retry-policy finding covers six daemon
paths. Mandatory application-target compilation for this increment is pending.

Independent read-only review of the sealed legacy provider-isolation design
`0113b3c9ab4826cd4f971ffea3bb8cd1a2c9d07efd7f911f45765d77f5146f37`
checks all 69 payloads and their signature, all 4,865 pure controls and all
4,050,630 proposed relocation rows. The original build and reconstruction
baselines remain unchanged. The proposed namespace selects 87 private objects
and 2,854 names while keeping actual production providers unmodified. This is
source/design evidence; object transformation, actual archive/version winners,
final linking and the 187-case legacy fixture remain unqualified.

Replay, native paging-test scopes and completed reproduction now classify only
their exact saved Service retirement calls. Their source contracts require
native-body closure, Original completion, alias destruction before receiver
acknowledgment, and actual pending or terminal custody with independent raw
refusals. They share the existing Main, receiver and native producer obligations.
All 89 focused/source-policy controls and source shape pass, including the
unchanged generic omitted-obligation, foreign-owner and extra-attempt mutations.
The remaining broad retry-policy finding covers three daemon paths. This source
evidence issues no native authority. Application-target compilation is pending.

Two earlier application-target builds pass: lifecycle classification at
`7c2bjza8mvv01bzjigkbyjswq9vql96w` and component launcher adapters at
`k4dx610p2vmz21nz8v19wbyjqr4vwwaj`. Each build's complete immutable source
independently matched all committed Rust/TOML inputs and six required fixtures
before subsequent edits.

The remaining executor and construction-carrier cleanup paths now bind their
actual saved owners. Component executor shutdown closes workers, materializer,
hot-fork owners and the canonical cleanup queue before dispatcher return. Main
panic handback continues through its saved completion header and body. Partial,
complete, shared Source, rearm-refusal and preparation phases propagate actual
refusals before publishing physical closure. Node destruction precedes external
lease return, and a refused generation lease stays in the same carrier.

The component controls preserve their original negative launchers, pointer and
cause identities, call/drop counts, real file leaves and canonical queued
destruction assertions. All 90 testing-standard controls now pass, including the
broad operational-wait gate and unchanged causal mutations. Source shape passes.
These source contracts grant no Main, Source or execution capability. Mandatory
application-target compilation for this increment is pending.

Independent read-only review of sealed legacy source manifest
`b4fcc11b43b5b143475bb23cca99871ff297ac5a4cacd7520340095f75a2270e`
verifies all 66 payloads, its detached signature, both signed commits and exact
incremental trees/diffs, and all 78,470 Git/disk/archive paths, including 72 literal
symlinks. All 236 pure controls pass. The six guards reverse byte-exact after ten
digest substitutions, and independent extraction reproduces all three outputs
with 179 roots and 1,299 functions unchanged. Meson AST parsing is source evidence;
configuration, object transformations, actual link ownership, the 187-case legacy
fixture and native execution remain unqualified.

The reviewed legacy namespace source is now imported through signed cumulative
atomic commit `cf897fddea21e1dafdeec4ec87b3e4517ad92305`, exact tree
`d81308a943d3e1cae29b55e730b1f1ab3ec85515`. Its additive metadata packet
`b6541f9ca8d60d08fd01f06868f640d19911c196eba4d025982a2b2c31aab913`
preserves the original source packet and corrects both atomic dates to the
existing deterministic convention. All eleven payloads, its signature, exact
patch, sole bundle prerequisite and unchanged raw commit message were verified.
A separately signed two-payload erratum
`000fb628fe8be6d0366bd3439143995d5dfa1eaf1e2057be62a5c660bf39476e`
distinguishes the pretty-printed message's extra trailing newline from the exact
795-byte raw commit message; neither original artifact was rewritten.

Hermetic signed-tree reconstruction and patch regeneration pass at
`wa8ac5k7qxwnv2friivj7jgjafnph9b6`. The complete 663-created-file license
ledger passes at `3b7agqxfxsprqfzi5dn8bc1r5rw3iyds`, including all six new
GPL files and the JSON's explicit license field. All five engineering-hygiene
controls also pass for the cleanup source contracts. These source and provenance
results do not qualify object transformation, final link ownership or native
execution.

Independent review of configured-graph plan
`922b45e0c529db3a6c9aaf723f6376d13ba6220932553f333157730680bb838e`
verifies all 53 payloads, its signature, 177 external inputs, ten reconstruction
inputs, 71 complete tool roots, the 16-path signed source overlay and all 90 pure
controls. The original 6,583-path build and 86,111-path reconstruction baselines
match completely. Its one bounded invocation returns failure after genuine
configuration succeeds in 33.266 seconds: the first fixture-command
correspondence check refuses the workspace variant. No graph query, target
build, transformation, link or TAP run follows that refusal. The initiating
failure is preserved. Actual configure, exception and final independent cleanup
report no remaining children and ECHILD, with no signal, wait, adoption or
cleanup error. Final evidence completes inside the original 900-second bound
at 150.794 seconds. Exact ordered command differences still need independent
review; configuration success does not qualify the rejected graph or legacy test.

The original failed result is retained separately as
`d9c9f6e7100de359ab0901f8a7269999c87649ada9972ca3752172ddfce15fbf`.
Independent review verifies all 42 payloads and their signature, all 2,918
execution and 86,117 reconstruction disk/archive paths, both unchanged original
baselines, the reparsed raw graph and all three empty cleanup observations. The
separate signed diagnosis
`1babea2743af49b4f407710e2704eb358f90370fea718936478f01b3e9bd8962`
retains complete ordered commands for all three variants: each adds exactly one
adjacent `-fPIE` at token 76. Every other ordered token matches after the sealed
coordinate substitutions. Review authenticates all eighteen payloads and eight
actual producer files. The pinned Meson option-selection method independently
confirms that the manual target flag requests PIE and is then appended after
Meson has already emitted its own PIE flag. Removing that redundant authored
flag remains a source correction to validate; the strict classifier is unchanged.

The subsequent source correction is imported as signed atomic
`de079e19836c67483cb082eea7257b569b9142cd`, tree
`134ade121be2a24d4a24d8c9422d81d337b79e8d`, from sealed source manifest
`edecaec901b5492e17894c10b4db2f7dffc784eb363e639ee7bca8930af9a36b`.
Independent review verifies all 45 payloads, both signed commits, deterministic
atomic dates, the sole upstream prerequisite, exact raw message/patch/bundle and
all 78,470 Git/disk/archive identities. The only functional edit deletes the
manual fixture PIE argument. Eight digest tokens across six extractors account
for the other changes; reversing them recovers every prior byte. All 236
isolation controls and fifteen actual pinned-Meson owner controls pass. Actual
extraction reproduces the same three outputs with 179 roots and 1,299 functions.
Hermetic reconstruction passes at `a3971r7r21m3f7x3dc160bzk9pckmjh6`; the
unchanged 663-file license ledger passes at `3b7agqxfxsprqfzi5dn8bc1r5rw3iyds`.
The strict command classifier remains unchanged. The fresh configured-graph plan
is separate; no target transformation, link or legacy TAP result is claimed.

That fresh configure returns zero in 31.125 seconds. Its original worker stops
at the literal export-flag check and returns one; final evidence completes in
150.905 seconds, with no Ninja query or target effect. All three cleanup cuts
observe empty children and ECHILD. Independent review verifies all 51 signed
result payloads, 2,921 execution and 86,117 reconstruction disk/archive paths,
and both immutable baselines. The metadata-only signing failure is preserved
separately; no original worker was replayed. The sealed result is
`528f60ec834bd9f5074b863b0ec4224b95e824d59974546059c08162504f9f46`.

The actual declaration contains `-Wl,-export-dynamic`, while the frozen worker
requires the substring `--export-dynamic`. Independent review of the pinned
Meson producer and selected GNU linker manual confirms the emitted spelling;
ten negative declaration controls reject absent, disabled, duplicate and foreign
arguments. Fixture compilation, private staging, production rows, registration
and absence of target outputs independently pass. A separate final-verifier
defect remains: two of the thirteen required exports are recorded data objects,
while its current predicate requires functions for all thirteen. The actual
specification and retained symbol index agree on eleven functions and two
32-byte layout objects. Review reproduces that pure metadata refusal without
linking or loading an ELF. The signed diagnosis is
`0db1ea10a03e97a215dde6e2731b55aa6d036b06bf628cb8ee342bc69157cd54`;
all 67 payloads, five signatures and actual producer identities match. These
findings do not qualify the future transformed objects, link map or legacy TAP.
ABI conformance passes at `0b10yln9nglnv559myr2c20nm03njxsy`.

The export-verifier correction is imported as signed atomic
`7b817c94baa67cd2537d4ca01643c604be4caf86`, tree
`b26b7645af433ea531a7f341fa10baf072ccdf63`. Its sealed source manifest is
`bcebc6e59a1c015f6dae0bb7fd8cb47ef6d3cb4594d55139261e468957e22986`.
Independent review verifies all 36 payloads, both signed commits, all 78,470
Git/disk/archive identities, deterministic atomic dates and exact raw message.
Only the verifier and its pure controls change. Each export uses its unique
recorded kind, strong binding and default visibility. Both data exports must
retain 32 bytes in allocated, read-only, non-executable PROGBITS storage, within
their recorded section bounds. Missing, undefined, duplicate, weak, hidden,
protected, swapped or changed-extent exports refuse. Private namespace checks
remain intact. All 359 pure controls pass; actual extraction reproduces all four
prior outputs, including the separate literal preexec-purpose unit. No guard,
fixture, provider, registration, timeout or license path changes. Fresh graph
discovery separately checks the exact pinned-Meson forwarding declaration and
its negative controls; actual transformed ELF, provider binding and TAP remain
unqualified.

Hermetic reconstruction of this exact atomic source passes at
`6m9s4h1j952w1pmd9pif32mzsqxvbmys`; its unchanged 663-file license ledger passes
at `3b7agqxfxsprqfzi5dn8bc1r5rw3iyds`.

The subsequent fresh configured-graph plan
`e9e7093aec0d9a634dd405a006156dbac3f56ec82cc9945e7fa620e00474f654`
passes all 122 pure controls. Its actual configured link declaration has exactly
one pinned-Meson `-Wl,-export-dynamic` argument; aliases, duplicates, disabling
arguments and foreign owners refuse. The original graph classifier is unchanged.
Genuine configure returns zero in 32.874 seconds and all thirteen read-only Ninja
queries return zero. The whole invocation completes in 200.269 seconds, within
its original 900-second bound. All fifteen independent cleanup cuts observe
empty children and ECHILD, without signals, waits, adoptions or cleanup errors.

Independent review of original result
`66e1c9ae4eeecdfff703a3f392df053d3c4f0474f332ebe64e072ee6501c9673`
verifies all 53 signed payloads, 3,031 execution and 86,117 reconstruction
paths against their complete archives, and both 6,583/86,111-path original
baselines. All 2,029 input leaves match their actual content; 790 aggregate and
2,011 self-resource samples remain within the sealed limit. Replaying the
original strict predicates against the retained actual graphs succeeds. This
run performs no target compilation, transformation, archive, link, ELF load or
TAP execution.

The separately reviewed complete target-build plan
`3b9ec60d9d86f578ccfe2f8a487d778a7933174a687b9938e1ff1262d3037a50`
passes 14,682 plan controls and 359 production verifier controls. Its original
execution refuses after 189 successful subprocess operations and 174 accepted
scheduled edges. The first fixture compilation succeeds in 16.620 seconds, but
its genuine Ninja log also records a repeated `qemu-version.h` generator. The
strict one-effect predicate rejects that extra effect. No transformation,
archive, final link, ELF load or TAP follows.

Independent review of the original signed result
`c263d843526f06c4e934b8cf090412bf7997d3772bd0d55ff447345a7f17f0d9`
verifies all 48 payloads, 6,447 execution and 86,117 reconstruction paths against
their complete archives, all four original baselines, the actual schedule prefix
and the partial fixture ELF. All 191 cleanup cuts observe empty children and
ECHILD without signals, waits, adoptions or errors. Aggregate and self-resource
samples remain within the original six-GiB bound. The 282.985-second invocation
is a preserved refusal, not target qualification.

The separate signed diagnosis
`b54d2ae56d7f5596b6ea257c729bc684a9f95d98512c54dc4a287bd2d3b30463`
passes independent review of 54 payloads, 32 input identities and 1,988 pure
controls. The pinned source declares the version generator always stale; the
selected Meson and Ninja execute and record it even when output bytes remain
unchanged. The graph predicts 1,625 repeated invocations beyond its own scheduled
edge across a complete build. Only two version invocations were actually
observed before refusal. A successor must authenticate each genuine repeated
producer and enforce its independent live deadline. Read-only preparation also
finds unqualified shell interpreters outside the accepted tool roots; explicit
source preparation and tool provenance remain prerequisites. No accepting
successor execution has occurred.

The separate source-only shell proposal
`154d08721641a41a3b6368b0c790836957ec9733b412c88003594327aeab40ce`
passes independent review of all 72 signed payloads, 44 actual input identities
and 9,080 pure controls. The actual registered Ninja producer substitutes its
command shell explicitly; the pinned upstream bytes, exact two substitutions
and actual binary literal agree. Its complete runtime closure adds one Bash
root to the accepted tools; all 4,521 directory, file and literal-link entries
across the three runtime roots match. The proposed version-script change replaces
only its first-line interpreter with the already accepted Bash. Canonical source
is unchanged. The pure deadline model arms no timer and qualifies no process
cleanup; complete live guard wiring and a fresh sealed plan remain unexecuted.


The subsequent unexecuted plan
`e6d216d548381778ea9f44368eb4d03238c760adce4a5e2b45296360ecff5610`
is preserved after source review identifies a live timer gap: compiler entry
could restore the outer evidence deadline rather than the original request cap.
No worker runs under that plan. The separately sealed successor
`566ecf1a46db0ad1446c01fd7574be955d4370f84ad937c4f765b7cece8f36b4`
passes independent authentication of 239 payloads, 3,838 external and ten
reconstruction identities, 72 complete tool roots and six immutable baselines.
All 16,445 plan controls and 359 unchanged production controls pass. Independent review
first rejects incorrect diff-header and result-writer assumptions in its own
verifier; both refusals are retained before the corrected full review passes.

The successor binds each request to the earlier of its original launch-before
plus 180/30 seconds and the outer evidence deadline. Its generator prefix stays
within 30 seconds; compiler entry preserves the same original request deadline.
Actual signal expiry and late return refuse in every phase. Cleanup receives
only its distinct original absolute reserve and cannot grant another request.
Independent direct return, cleanup, descriptor readiness and final close remain
separate observations. One original bounded compile/transform/link invocation
was authorized under this exact manifest. Its original worker returns 1 after
188 actual operations return 0: configure, thirteen graph queries and 174
accepted scheduled edges. Guard setup refuses the generated Meson launcher's
unowned `/bin/sh` before edge 176 is launched. There is no partial fixture
object, transform, archive or final executable. The complete invocation and
final evidence take 327.349 seconds within the original 5,400-second limit.

The signed original result
`9bdb27d28914a5994f082e6015bda0ac9bee7a30840b27f51f93b34566247083`
passes independent authentication of all 46 payloads, full 6,991-path execution
and 86,117-path reconstruction archives, 72 tool roots and six unchanged
baselines. All 190 actual cleanup cuts report empty children and ECHILD without
signals, waits, adoptions or errors. All 1,681 aggregate and 2,806 self samples
stay within the original six-GiB bound. The verifier first retains its own
obsolete canonical-source expectation; the corrected complete review checks the
previously approved, exact prepared version-script shebang delta and passes.
The failed invocation is preserved; no replacement invocation is authorized.

The source-only generated-interpreter diagnosis
`80b734b2856831a52f8d27839f62e21496dc8eab70fbcb178822ddcdf55a77e5`
passes independent review of all 103 payloads, 269 actual inputs, 68 genuine
producer/template controls, 1,625 complete diagnostic role rows and 1,926 graph
field occurrences. Both pinned distlib producers generate a shell trampoline
for the 167-byte venv Python coordinate. All fifteen generated entry scripts
match their complete registered templates and definitions. Fourteen of the
fifteen original nominated interpreters authenticate; `/bin/sh` and its resolved
host Bash do not. The existing guard also omits the subsequent same-PID exec
into Python. Source and retained configure output distinguish the installed
Meson 1.11.1 entry metadata from the selected 1.12.0 module. The verifier's first
attempt assumes every retained input has a separate copy; its corrected review
also authenticates the original archived process samples. No launcher rewrite,
replacement owner, additional native run, TAP, ELF loading, profile activation
or native issuance is established by this diagnosis.

The first source-only launcher preparation proposal is preserved at
`819bac01a19aac0aef6c70d62f1c0ad5007c84f6b90bff6400048e34058f5742`
after independent review authenticates its 118 payloads and 82 inputs but
refuses its actual adapter: the RECORD loop replaces the original RECORD cut
with script bytes. Its isolated transformer controls had missed that defect.
No configure or replacement target invocation follows this refusal.

The separately sealed correction
`eb07e862884605351c4d35e39379f0c7ae595589f8013fca859514cfa061b7ba`
passes independent review of 215 payloads, 127 input identities and all 118
unchanged prior payloads. All 92 complete-adapter controls execute only in
automatically removed temporary scratch; all 76 full raw cuts match. They
reproduce the original adapter refusal, validate real multi-entry distribution
records and idempotent second preparation, preserve failed write debt and refuse
a sixth barrier without mutation. The selected source path bounds five creator
continuations with paired ATTEMPTED/RETURNED history, replacing the earlier
unvalidated raw-line counter. The reviewer's initial check-order assumption is
retained before the corrected comparison of the same 92 controls passes.
The separately sealed readable successor
`826dccefb407db67b5d2ec080fe8aeac4cc3c1761f0c5ecad52e61e9e688334e`
passes independent review of all 454 readonly payloads and 223 retained actual
inputs. Its complete helper AST is unchanged; mkvenv and guard bytes remain
exact. All 557 controls replay independently: the prior 236 pure and 92 actual
adapter controls, plus 229 staged controls. Genuine creator arrivals grow the
script inventory through 3, 4, 5, 8 and 15 entries, preserving all five paired
histories and refusing a sixth without mutation. All 179 raw-cut emissions
match, normalizing only the staged scratch coordinate; scratch is removed.
The reviewer's first source-line assertion is retained before its corrected
complete review passes. Complete execution-ready reconstruction, ownership,
graph and role review remain required. No new target run, runtime root or
native authority is issued.

The execution-ready successor plan
`384a060c59933dfc2f1704cb6e43f66707ee3151c20511c2fff5ea4d25a87304`
passes independent review of all 452 signed readonly payloads, 5,130 external
and ten reconstruction inputs, 72 full tool roots and six complete baselines.
All 17,259 plan controls and 359 production controls replay independently. Its
worker authenticates the actual generated editable `.pth` and `direct_url.json`
bytes and their exact RECORD hashes, in addition to all 115 launcher/history
artifacts. Approved launcher preparation and all critical graph, ownership,
process and cleanup predicates remain intact. The intermediate unexecuted plan
is preserved. The one original build attempt returns failure in 419.920 seconds,
with all 222 completed operations returning zero and 208 scheduled edges accepted.
The next C edge refuses `PID/start reuse in original request` after the selected
compiler's previously authenticated stat, executable and argv cuts become
unavailable. Its direct child returns zero and Ninja records both the repeated
version header and lexer object; these physical outputs do not accept the edge.

Independent review of signed result
`e695451ec840afb01b11e5deb1869070a1efa90a8a6474edc683729f4f346f2f`
verifies all 54 payloads, complete 8,028-path execution and 86,118-path
reconstruction archives, all six unchanged baselines and 72 complete tool roots.
It replays every accepted edge's actual repeated/requested effect proof and
checks all 35 partial ELF inventories. All 224 independent cleanup cuts observe
empty children and ECHILD; the separate exception path records one successful
signal and four ESRCH signal attempts. All 2,155 raw aggregate and 3,755 worker
samples remain below the original six-GiB limit. The reviewer's obsolete result
key, unprefixed command expectation and assumption that a refused edge produced
no output are preserved before the corrected complete review passes.

The independently reviewed diagnosis
`9470f4d8c760958ed54d90083262fa5a48393ef41e4719eebe88b7047ad25daf`
authenticates all 28 payloads and 23 input identities. Its actual eight samples
show no contradictory available start times: the final numeric directory cuts
return ENOENT. The genuinely bound descriptor's recorded polls are all nonready,
so the failed invocation gains no retrospective exit permission.

A separate source-only proposal
`0f0ce108358389ad3d20aff1b82a96aad27ec020f9b2160e6be54cfb2a8287b4`
passes independent authentication of all 25 payloads and 25 actual inputs,
all 81 actual-adapter controls, and four additional worker-accounting refusals.
It preserves raw missing coordinates and requires new positive kernel exit
evidence from the original authenticated descriptor, or its genuinely closed
ready history, before omitting that old liability's unavailable metrics. Partial,
contradictory, unknown, first-seen and unowned cuts refuse. No timer is extended;
raw aggregate defaults explicitly grant no accounting permission. Original
ownership, poll parsing, physical return and cleanup methods remain unchanged.
A complete sealed successor plan remains required before another native run.
The complete successor plan
`369ad59dd02ce610023b5580ed29e7da6aee0b69b72404618f848069ee2e356d`
passes independent review of all 514 readonly payloads, 5,697 external and ten
reconstruction inputs, 72 full tool roots and all six complete baselines. All
17,463 plan controls and 359 production controls replay independently. The
reviewed proposal's five runtime modules are byte-exact; original executable,
input ownership, graph, driver, ELF and cleanup predicates are unchanged. The
raw and qualified resource evidence remain separate. The one original invocation
returns one during configure: a previously selected compiler wrapper loses all
four process observations without a genuinely retained descriptor exit proof.
No read-only query or scheduled target edge runs. Configure's direct child is
separately reaped with status minus nine; final actual children are empty and
ECHILD is observed. The original 5,400-second bound remains unchanged.

Independent review of signed result
`7ad13a477ff9f77d725b94c17194c0d9f2fe5e58fc97aff5765426f760eb3f5b`
authenticates all sixty payloads, complete 1,863-path execution and 86,116-path
reconstruction disk/archive inventories, all original inputs, 72 full roots and
six baselines. All 181 qualified accounting events replay against their actual
raw samples; the final 182nd raw capture reproduces the original refusal and
receives no accounting permission. The one partial ELF inventory, 2,095 worker
samples and 39 actual compiler-driver records are independently checked.
The reviewer's initial all-readonly mode assumption fails on executable plan
helpers; the corrected full review checks each sealed mode and passes.

The independently authenticated diagnosis
`00313bd87d5419d315f888dc11ac64e37e8ac8cce51fcd54b20f2772a4635c52`
checks all 42 payloads, thirty actual inputs and 200 pure causal predicates.
Configure supplies aggregate observation without a repeated-target guard, so
no original process descriptor was bound. The selected PID has one preceding
available identity and one wholly unavailable cut; no contradictory available
start time establishes reuse. Its compiler child's successful return and later
cleanup ESRCH do not prove the wrapper's original exit. A separate source-only
ownership proposal is in progress; no replacement run is authorized by this
component evidence. No successful target build, runtime, TAP, installation,
profile or activation is claimed.

The service-client ownership contracts pass mandatory application-target
compilation at `wx20fkrpphs9zk5lrwlg7kx10d84x8b9`. Before later edits, all
5,389 committed Rust/TOML inputs and six required fixtures independently matched
its complete immutable source `rpwqwy2pqc42m6azss40qfs2lx7qjrma`.

The typed Source cleanup-status increment also passes mandatory application
target compilation at `k6xqwqda0r9pa1kalk2yll311lfbwl6w`. Its complete immutable
source matched all 5,382 committed Rust/TOML files and six required fixtures
before later edits.

The prepaid shutdown-report increment passes mandatory application-target
compilation at `y586j0zmrxb1qnbwlph7bkhypgcnqsj8`; the debug-caller contracts
pass at `v3dr8v5gsglh1brcgl31zafy2ycdyfyc`. Each frozen source independently
matches all 5,387 Rust/TOML files and its six required fixtures. These results
cover their respective committed inputs before later changes.

The Source-caller contract increment passes mandatory application-target
compilation at `v4sf66zhav7aqw1jpwj4pmibp8yb1dxi`, with all 5,388 committed
Rust/TOML files and six fixtures matching its frozen source before later edits.

The final executor and construction-cleanup contracts pass mandatory
application-target compilation at `cima4dd6mj4ci8z03zqcv5632ry1alia`. All
5,392 committed Rust/TOML files and six required fixtures independently matched
its frozen source `7nf08m8dmc9fqpj1nxiwf3q87fcbsyi6` before the parser change.

Closed JSON decoding now reserves and constructs a private diagnostic-credit
holder before entering Serde. Retaining the actual error moves that existing
holder without allocating; text, classification and source coordinates remain
unchanged. The holder exposes no strong or weak aliases. Its final observer
extracts the credit record after freeing the reference-count header, then returns
the diagnostic loan and original custody in order. The complete reservation
includes control storage and construction/extraction overlap. `PaidJsonError`
occupies two machine words without exposing the raw Serde error.

The engine test binary now installs its existing allocation observer as its
actual global allocator; the previous controls had no installed observer. All
sixteen focused controls pass with real observations. Restoring ordinary Arc
drop causes both actual-control lifetime checks to fail because their original
credit returns before physical control deallocation; exact restoration passes
all eleven diagnostic-filter controls. Retaining a genuine prepared error
allocates nothing. All 686 engine tests, ninety testing-standard controls and
five hygiene controls pass. The host suite retains 1,385 passes, the same eight
unissued helper-custody failures and four ignored controls. Strict Clippy retains
674 library and 723 test-target errors, with fourteen and five warnings.
Mandatory application-target compilation passes at
`9pynb96pmckzck7y09wf17ww1ch9abb7`. All 5,392 committed Rust/TOML files and
six required fixtures independently match the frozen source
`1isy3prc6jr847mj0plqaqzd7wha1sxm` before later account changes.
These parser controls grant no native issuance or execution authority.

Four exact parser-credit controls are now bound into `gate:ram-supervision`.
The hermetic gate passes all 412 exact cases at
`5hr2qg3ws7qa5hlw71pkjph6lrpxswl6`. The inventory passes at
`256dsc60864h4khhnr7lbh4h4v2c7v7d`, retaining 529 case bindings across 243
requirements, 148 uncovered requirements and zero fully qualified requirements.
Each new binding explicitly describes its component scope.

Fixed live decode-account refusals now use a separate diagnostic holder reserved
before either holder or account allocation. Poisoning, exhaustion and the scratch
accounting invariant return the original typed fixed cause without allocating.
Separate accounts retain distinct cause identities; sticky errors retain the
holder without retaining the account or forming a cycle. The holder frees its
shared header before returning its original loan. Its complete peak includes
storage, construction/extraction overlap and returned handles. Constructor,
layout-overflow and external-authority errors retain their existing paths and
are not claimed as fully funded by this increment.

All six new exact controls pass in the hermetic storage-transfer gate, along
with its 21 existing cases, at `21rj3c3and8gawhh3r3482d8y6y94g9l`.
The actual allocation observer verifies zero allocations for fixed refusals,
credit-before-birth refusal and credit retention through physical control free.
Restoring ordinary Arc drop makes both actual-free controls fail; exact source
restoration passes both. The original broad store run reproduces an obsolete
zero-credit assertion while two diagnostic aliases remain alive. That run was
explicitly cancelled; the corrected assertion requires credit to remain through
the first alias drop and return only after the final alias. The revised inventory
passes at `y67fbiz56y4fl5hv2iapccdc45fdvcrz`: 535 bindings, 243 requirements,
148 uncovered and zero fully qualified. The revised store suite passes all 689
executed tests, with the three costly 512 MiB cases explicitly excluded. The first engine run exposes seven fixtures that no longer admit the larger
initial control extent and four assertions that release diagnostic credit too
early; all 686 engine tests pass after correcting these fixtures. Finite output
fixtures still admit less than their 1,024-byte output. Borrowed selector checks
seal all further credit after admitting the initial controls. The first host run
has 1,384 passes, one obsolete absolute reservation-count assertion and the
same eight unissued helper-custody failures; four controls remain ignored. The
parser assertion now counts its own two reservations relative to the account's
actual initial count. Engineering hygiene initially refuses the stale reviewed
record-test digest; reviewing and updating both changed content-bound test
records restores all five hygiene checks. The first strict Clippy check retains
674 library and 723 test-target errors, with fourteen and five warnings. The corrected full host rerun restores 1,385 passes with those same eight genuine
helper-custody failures and four ignored controls. All ninety testing-standard
and five hygiene controls pass; strict Clippy retains the same error and warning
counts. Only the changed selector fixture is mechanically formatted; its tokens
match the passing run, and final source hygiene passes after refreshing its
content-bound review. Hermetic supervision passes all 412 exact cases at
`fb4dg9hwy228x7m6jnhpb9l7p24dcvf4`. Mandatory application-target compilation
passes for the account storage at `rjrwiksgm3k21av1l3ybidnaig1nyrxi` and
fixture corrections at `yvrx2pjlgxyi633frf6zhq6s5x493s57`. All 5,393 committed
Rust/TOML inputs and six required fixtures independently match each frozen
source, respectively `ns0kcgm2k1nbn2yq0bci93wmzif438lc` and
`99c1mk19bky213fcgyk7jizddl6asmnw`, before subsequent implementation edits.


Array, scratch-array and scoped vector size overflow now use the same preborn,
account-specific diagnostic holder. The enlarged complete holder peak is reserved
before account birth. Reporting overflow allocates nothing and requests no new
payload credit; original typed causes, message text and non-poisoning behavior
remain unchanged. Scoped vector errors retain the innermost installed account's
holder, independently of other accounts. Unscoped component vectors retain their
existing error path and gain no funded-account claim.

All fourteen focused account controls pass. Replacing the three overflow paths
with their former allocating implementation makes both new actual-allocation
controls fail; restoring the exact source passes both. The controls also verify
unchanged vector contents, account-specific identities and retention of original
credit through the final error alias. The inventory passes at
`cxdgysmbgmaqrx3wy84ip3w7i1pqjh6h`: 537 bindings across 243 requirements,
148 uncovered and zero fully qualified. The hermetic store-transfer gate passes
all 29 exact cases at `w6vzv4qfnpgaai19siaabnrhcmkmnv0w`. The full store
suite passes 691 tests with three costly 512 MiB cases explicitly excluded; all
686 engine tests pass. The host retains 1,385 passes, the same eight genuine
helper-custody failures and four ignored tests. All ninety testing-standard and
five hygiene controls pass. Strict Clippy retains 674 library and 723 test-target
errors, with fourteen and five warnings. Mandatory application-target compilation passes at
`dmmqpbh4b8dja1ydw4li6kqdz5svkd7q`. All 5,393 committed Rust/TOML files and
six required fixtures independently match frozen source
`04kxhcg9fvckr1r95zs4gqmb6amvr9x7` before later changes. These component
diagnostics issue no Main, Source or native authority.


B-tree multiplication and node-overlap overflow now use the explicit admitting
account's preborn diagnostic storage. An independently installed codec scope
cannot redirect that credit. Standalone geometry queries retain their existing
unscoped error path; typed layout and conversion errors also retain their
existing behavior. The original first sticky failure, message text and typed
accounting cause remain intact. The enlarged holder is reserved before birth;
errors retain its original credit independently of the closed account.

All fifteen focused account controls pass with the actual allocator installed.
Restoring the two former allocating arithmetic-error paths makes exactly two
controls fail; exact restoration passes all fifteen. The node control constructs
no huge value: it measures valid type layouts whose doubled overlap overflows,
under a foreign thread scope, and observes no allocations or credit growth.
Both controls verify the final error's retained loan. The inventory passes at
`qlm83f0w5107na7x181hsa3yar76jlg5`: 539 bindings, 243 requirements,
148 uncovered and zero fully qualified. The hermetic storage-transfer gate
passes all 31 exact cases at `rrwc61q59ds95apig67bkmf0rwpqk4sj`. The full store suite passes 692
tests, with three costly 512 MiB cases explicitly excluded. The first engine
run has 685 passes and one finite formatting fixture that cannot admit scratch
space after paying for the enlarged bank. Its finite allowance is increased to
768 bytes, and its refusal control still fills the complete remaining allowance
before calling the formatter. All 686 tests pass in the corrected complete
engine run. The host retains 1,385 passes, the same eight genuine helper-custody failures
and four ignored tests. All ninety testing-standard and five hygiene controls
pass. Strict Clippy retains 674 library and 723 test-target errors, with fourteen
and five warnings. Mandatory application-target compilation passes at
`bn7z6w0djjyd1im0qf1w1a98lh65z3q0`; all 5,393 committed Rust/TOML files
and six required fixtures independently match its frozen source before later
implementation changes. This component increment supplies no Main, Source or
native issuance.

Typed B-tree layout errors now preserve the actual standard-library cause inline
in the already charged error handle. Retaining the separate diagnostic holder
keeps its original loan alive without allocating another shared source wrapper.
The complete prebirth peak still derives from the concrete error-handle and
storage layouts. Explicit account routing, original Debug/Display/source types,
first sticky failure and distinct account identities remain intact. Unscoped
geometry queries and integer conversion errors retain their existing paths.

All seventeen focused account controls pass. Separate actual key and value
layout overflows construct no huge values, run under a foreign codec scope,
observe zero allocations or extra credit requests, preserve the typed layout
cause and keep original credit through the final error alias. Restoring the
three former allocating layout-error paths makes both new allocation controls
fail; exact source restoration passes all seventeen focused controls. The
inventory passes at `k9qygrqwm5bka8vi1wpfkk6jbv6bdznz`: 541 bindings,
243 requirements, 148 uncovered and zero fully qualified. Hermetic storage
passes all 33 exact cases at `95h5ha0ipyqap6sgjfnbwgvda34wmsrz`; every
individual result is independently checked. The full store suite passes 694
tests with three costly 512 MiB cases explicitly excluded, and all 686 engine
tests pass. The host retains 1,385 passes, the exact same eight helper-custody
failures and four ignored tests. All ninety testing-standard and five hygiene
controls pass. Strict Clippy retains 674 library and 723 test-target errors,
with fourteen and five warnings. Mandatory application-target compilation passes
at `xa38mvq259j29q7gx3mrpspwvfqxv9f8` for `dd72fff4ee`; all 5,393 committed
Rust/TOML files and six required fixtures independently match frozen source
`qzrpvfwx9si6dhyh3mrwxhmdk3l8ljn8` before further implementation changes.
This increment issues no native authority.

Typed vector-allocation refusals now retain their actual standard-library cause
inside the charged error handle. Receipt-vector failures use the explicit
account's independent holder; codec vectors retain the admitting account before
calling its authority and preserve that same holder on failure. Neither path
allocates another error wrapper. Complete prebirth credit derives from the
enlarged concrete error layout. The original typed source, Debug and Display,
receipt failure's sticky precedence and component fallback remain intact.

All nineteen focused account controls pass. The new actual Vec capacity-refusal
control consumes a finite roster of preborn component loans, admits logical
bytes and rejects an unrepresentable backing capacity before allocator entry.
It observes zero allocations or reallocations while preserving the exact typed
cause, empty vector and original credit through final diagnostic alias close.
The independent unscoped control preserves its actual cause without inferring
production authority. Restoring the former allocating wrapper makes exactly
the allocation control fail; exact restoration passes all nineteen controls.
The full store suite passes 696 tests, with three costly 512 MiB cases explicitly
excluded. The inventory passes at `mzr1axfpl1biq2sxcwnxd9y4vndrayw2`;
543 bindings cover 243 requirements, with 148 uncovered and zero fully qualified.
Hermetic storage passes all 35 exact cases at `qa3bm2ysl8k4flkb4p38dmpcfpz2nps0`;
all case logs, including nested child results, are independently checked. The
complete engine suite passes all 686 tests. All five final hygiene controls
pass. The host retains 1,385 passes, the exact same eight genuine helper-custody
failures and four ignored tests. All ninety testing-standard and five hygiene
controls pass. Strict Clippy retains 674 library and 723 test-target errors,
with fourteen and five warnings. Mandatory application compilation passes at
`3i70012xzfwhb0y3dnn14zg26v9lkh54` for `df060fe997`; all 5,393 committed
Rust/TOML files and six required fixtures independently match frozen source
`rfykbsjd3cj1l366xkridk6f573p9h7h` before further implementation changes. Actual receipt-vector allocator failure is not
injected by the capacity control. No Main, Source or native authority is issued.

The vector-refusal fixture now independently prepays each provider-owned loan's
control storage in addition to its requested payload. Its finite initial sum
covers all four preborn loans, and the final diagnostic aliases retain both the
original diagnostic payload and that loan's control charge until final close.
This corrects component accounting without changing production allocation or
claiming native physical funding. All nineteen focused controls pass; restoring
the allocating wrapper makes exactly the allocation control fail, and exact
production-source restoration passes all nineteen controls again. Hermetic
storage passes all 35 exact cases at `j35lp0j3rgxbq7jjqcbqi4bywy072hq0`;
all 47 successful summaries, including nested child results, are independently
checked. Mandatory application compilation passes for `ceb341b17f` at
`h5q25c7y4javns9zh2cgzfxxz7dhphwh`; all 5,393 committed Rust/TOML files
and six required fixtures independently match frozen source
`433kw667wm3yj9sayv8wdj00g8iyc1sk` before later edits.

A scoped exact-layout test injection now reaches actual receipt-vector
allocation failure. It returns null for one selected fallible allocation before
System owns any storage; it changes neither normal allocations nor production
builds without test support. The actual standard-library allocation error stays
inline in the charged handle, becomes the account's first sticky failure, and
survives final account close without another allocation. The unused receipt's
payload and separate loan control refund immediately; final error aliases retain
the original diagnostic payload and loan control until final close.

All twenty focused decode controls and nineteen allocator-observer controls
pass. Restoring the former allocating receipt-error wrapper makes exactly the
new zero-allocation control fail; exact production-source restoration passes all
twenty decode controls. Exact-layout, once-only, thread isolation, nested refusal
and unwind controls verify the injection's scope. The first thread-isolation
fixture accidentally armed before thread construction, whose infallible 64-byte
allocation reached the selected refusal and aborted that test binary. That
failure is retained; creating the thread before arming and exchanging only fixed
atomic observations passes. This injection proves a reached controlled failure,
not physical OOM or native memory funding. The inventory passes at
`6j2y9k2fxwk8n1i3x19w6c52f98d2y5b`: 544 bindings, 243 requirements,
148 uncovered and zero fully qualified. The complete store regression suite
passes 697 tests, with the three costly 512 MiB cases separately bounded. All
686 engine tests, ninety testing-standard controls and five hygiene controls
pass. Host retains 1,385 passes, the same eight actual helper-custody failures
and four ignored cases. Strict Clippy retains 674 library and 723 test-target
errors, with fourteen and five warnings. Hermetic storage passes all 36 exact
cases at `j4nbb0i8d527709gfvkcr1gz384rkarh`; all 48 successful summaries,
including nested child results, are independently checked. Mandatory application
compilation is running for `e501b58d92`; all 5,394 committed Rust/TOML files
and six required fixtures independently match frozen source
`2ksfppd4azphg6aiklk524jmbj79mzly` before the lazy-page changes.

The previously excluded 512 MiB packed traversal/repack cost case passes at
`df060fe997`, under a fixed 3,600-second wall/CPU limit, 2 GiB address-space
limit and disabled core dumps. It returns in 318.80 seconds; the supervisor
reaps the test, observes ECHILD and removes only its own disk-backed scratch.
Both warm reads authenticate zero manifests, rows or manifest bytes. Repacking
reduces packs from 1,537 to 628 and retained metadata from 39,164,872 to
29,029,832 bytes, but increases traversal pack switches from 11,775 to 391,776.
The result verifies this storage component workload and preserves that locality
cost; it does not establish native execution or performance qualification.

A lazy page now crosses the actual backend facade as one single-use bounded
request. Its Packed implementation borrows one pinned placement view and one
paid active manifest across the complete binary path. The selected physical
service can reuse its authenticated shared rows between independent requests;
Graph admission still precedes every selected object lookup, and complete
canonical/EOF, tree geometry, page digest and membership proof checks remain.
Reader, active metadata and all view pins close before the same final original
and physical acceptance observations. Other backends retain their existing
checked byte reads. The request's concrete control/overlap extent is reserved
before dispatch; returned page bytes and proof retain their separate credit.

All five real Packed lazy-page controls pass. Eight-page fixtures observe only
four catalog reads and one selected page read; the cold request authenticates
one manifest and the next request authenticates none. Controls refuse graph-
excluded pages before lookup, mutated actual pack bytes after cache reuse,
final cancellation after actual pin closure, and physical custody loss at that
same terminal cut. Final response/error close and explicit cache reclaim return
the unchanged finite component bank to its original usage. These controls issue
no process-wide memory or native authority and establish no performance parity.
Replacing the Packed dispatch with ordinary checked reads makes the actual
manifest-reuse control fail. Removing only the final acceptance observation
makes both terminal-refusal controls fail. Exact source restoration passes all
five controls. The full storage regression passes 702 tests, with the three
512 MiB cases separately bounded; all 686 engine tests pass. Hermetic storage
passes all 41 exact cases at `y5xlj7d724xsl8dqfdv0hi2nra9b2bdc`, with all
53 successful summaries independently checked. Inventory
`dnpzhz3z656bpqvwni56829f3gngq97f` validates 549 bindings across 243 requirements,
148 uncovered and zero fully qualified. Host retains 1,385 passes, the same
eight helper-custody failures and four ignored cases. All ninety testing-standard
and five hygiene controls pass. Store Clippy passes all targets. Strict Host
Clippy retains the same 674 library and 723 test-target errors, with fourteen
and five warnings; no lint is waived or error payload discarded. Signed commit
`84583ceb34` is pushed. Mandatory application-target compilation is running;
all 5,396 committed Rust/TOML files and six required fixtures independently
match frozen source `zma80nh74vzi5sn9zl7kq3vvv34yxcvz` before later edits.

The separately bounded incompressible 512 MiB capture/archive/restore/repack
case at `ceb341b17f` passes in 2,340.20 seconds under its unchanged 3,600-second
wall/CPU and 2 GiB address-space limits. Actual final cleanup observes ECHILD
before removing its own disk-backed scratch. The separate shared-volume case
also passes, in 909.55 seconds under its own unchanged bounds, with actual ECHILD
and scratch removal. These frozen preceding-source results
are storage component evidence and qualify neither the later lazy path nor
native execution or performance parity.

Lazy page sibling storage, region-name storage and proof encoding now allocate
fallibly under their existing complete proof reservation. Portable encoding
preserves the same canonical bytes and capacity. Its new fallible API returns
the actual allocator refusal; the response owner saves that source in the same
prepaid diagnostic bank and closes decoded page storage before refunding proof
scratch. This adds neither an allocation allowance nor another diagnostic loan.
The first failure remains sticky, including when an earlier cause already exists.

All five focused controls pass: minimum/maximum encoding bounds, actual sibling
and region allocation failures on the lazy path, actual encoding failure with
zero replacement diagnostic allocations, and earlier-cause precedence. Each
uses unchanged finite component resources and exact-layout refusal, without
claiming physical OOM or native funding. Replacing the prepaid diagnostic with
an allocating wrapper fails exactly one control; removing sticky publication
fails three. Exact production restoration passes all five. The initial fixture
compile missed a digest import; that failure is retained before the corrected
fixture passes. Inventory `72zm95l2rgixpjn2y9p5qvgjjzmyrab8` validates 554 bindings,
243 requirements, 148 uncovered and zero fully qualified. The full storage
regression passes 707 tests, with three 512 MiB cases separately bounded. All
25 logical RAM unit/integration tests pass, including the frozen canonical
format vectors. All 686 engine tests pass. Hermetic storage passes all 46 exact
cases at `7q2al0rac82fizfxgi7h8vlkvws8zvri`; all 58 successful summaries,
including nested results, are independently checked. Host retains 1,385 passes,
the same eight helper-custody failures and four ignored cases. All ninety testing
standard and five hygiene controls pass, and Store Clippy passes all targets.
Strict Host Clippy retains 674 library and 723 test-target errors with fourteen
and five warnings. ABI conformance passes at
`dfs5vwdn7wf62fq1vx925w3jf7ifx6ih`. The complete license-boundary gate remains
in progress; neither the ABI result nor passing storage controls replaces it.
Signed commit `e9321233eb` is pushed. Mandatory application-target compilation
is running. All 5,397 committed Rust/TOML files and six required fixtures match
frozen source `a66wk4sbxqch8zj5hpmz0gcbns2a15rj` before later edits.

The configure aggregate-observation proposal is independently reviewed as
source-only under manifest
`017e11de88d5b842bff101d4a3ee1f5fd24cff762f4ea05ac3bf8b27a408999e`.
All eighty signed payloads and 110 actual inputs authenticate. The actual
read-only replay passes 1,325 named controls; all 72 complete tool roots and
six immutable baselines independently match. The complete actual diff is
checked, and every preexisting descriptor-method AST remains identical. The
initial reviewer used a wrong reference-directory alias; that failure is
preserved before the corrected complete review passes. Configure observation
uses original descriptor binding and positive exit readiness, preserves
absent liabilities, and selects its explicit finite 1,024-identity history
before ownership; live capacity 32 and target history 256 remain unchanged.
Four actual historical executable/argument transitions remain refused
limitations. No old failure is requalified, historical readiness supplied,
native invocation performed or replacement run authorized by this review.
Concrete unexecuted plan-r7 arrives under manifest
`096b5022e8b9ae3ecc25c592a889b53fb990cfa86e7d9f79795b6bd47563d3f6`.
Its 632 payloads, 6,440 external plus ten reconstruction inputs, all 72 complete
tool roots and six full baselines authenticate. Independent review then refuses
its current-correspondence claims: eight current Python hashes and three current
runtime-module hashes retain preceding values. The immutable plan and first
refusal are preserved. A corrected complete successor and an audit of all
inherited current-coordinate claims are requested. No native invocation or
replacement run is authorized. Remaining read-only review independently passes
all 18,844 actual plan controls and 359 unchanged production controls, complete
source/preparation and runtime bindings, environment/driver relocation and
original bounds. That success does not repair the current-hash refusal.

RAM publication staging now retains actual pending-array allocation refusal in
its original prepaid diagnostic bank. Flush input-vector allocation is fallible
under the existing complete scratch reservation. Refusal precedes backend
publication, closes staged sources before their refundable credit and prevents
replacement admission through the original sticky first cause. No allocation
allowance is added. Both exact-layout controls pass under unchanged finite
component resources. Restoring the allocating pending diagnostic fails one;
omitting the flush refusal's sticky publication fails the other. Exact source
restoration passes both. Inventory `cnn6znjkayga83rrilb6cp3zqrsr2kmz` validates
556 bindings across 243 requirements, 148 uncovered and zero qualified.
The full storage regression passes 709 tests, with three separately bounded
512 MiB controls. All 686 engine tests pass. All ninety testing-standard and
five hygiene controls pass; Store Clippy passes all targets. Hermetic storage
passes all 48 exact cases at `gk4lm4ld77jxvb85z0a73m54g4f8iyfd`; all sixty
successful summaries, including nested results, are independently checked.
These controls qualify neither physical OOM nor native resource custody.

Shutdown report storage is now reserved as part of the original complete Source
control peak before launch. The canonical child continuation takes that launch's
journal exactly once before any target effect. Four attempt cells and six error
cells retain the actual returned outputs; immutable selection masks keep earlier
reports unchanged as later independent observations arrive. Reports and typed
refusals share the prepaid allocation without copying owned diagnostics. Missing
or already-claimed storage fails closed before a command, wait or reap.

The final observer extracts the journal only after freeing its reference-count
header, then drops the actual errors before the original financial loan. The
complete peak covers the header, construction/extraction overlap and output
frames. The allocation observer checks all five prebirth allocations. The actual
last-header control fails when ordinary Arc drop is restored and passes after
exact restoration. All six new journal controls pass, including the actual
shutdown ladder, original error-string identities, frozen receipts and a refused
second claim with zero target effects or allocations.

The full host suite passes 1,385 tests with the same eight existing unissued
helper-custody failures and four ignored controls. Source shape passes. Testing
standards pass 89 controls and retain the same broad retry-policy failure across
eleven daemon paths; all eight new ownership mutations are rejected. Strict host
Clippy retains 674 library and 723 test-target errors, with 14 and five warnings.
Mandatory application-target compilation for this increment remains pending.
These component controls do not establish Main/Source issuance or native return.

The earlier prepaid controller storage application-target build passes at
`k6wsvl3qa16xih2n1l5biqm7kv2g4y13`. All 5,378 committed Rust/TOML inputs and
six required fixtures independently matched its complete immutable source before
subsequent edits.

Shutdown now retains raw native OS errors in the target error's inline typed
cause, including the original `std::io::Error` exposed through the standard
error chain. Clones preserve the complete raw code without allocating. QMP
writes, owned-child waits, natural-exit polls and signal failures use this path;
out-of-range PID conversion uses borrowed static text before any syscall.
Authored non-OS diagnostics still require their existing separate admission.

The control Quit writer now borrows `CONTROL_QUIT_FRAME` from the permissive
protocol crate instead of allocating an encoded vector. Its bytes match the
frozen protocol-v8 Quit vector, and the existing owned encoder returns the same
bytes. Both a successful fixed-buffer write and actual closed Unix-socket
control/QMP refusals make zero allocations. All 47 shutdown controls, all eight
hot-fork return source contracts and source shape pass. The target error still
fits its existing 64-byte extent. Restoring the old QMP formatting bridge causes
the actual socket allocation control to fail; restoring the exact implementation
passes all 47 controls. ABI conformance passes at
`jmsykag70va3ypv1ib8r7ykvhaiqx42x`.

Strict host Clippy retains the same 674 library and 723 test-target errors, with
14 and five warnings. The complete testing-standards suite passes 76 controls
and retains the same broad failure over 22 unclassified retry paths. An initial
complete host run passes 1,369 controls and exposes one stale formatted-message
assertion alongside the eight existing unissued helper-custody failures. That
assertion now checks the actual typed ECHILD and zero public-poll allocations.
The complete rerun passes 1,370 controls with only the same eight helper-custody
failures and four ignored controls. All eighteen license-boundary controls pass;
the complete license gate then fails on 639 host Clippy errors. Mandatory
application-target compilation remains in progress. Controller-return causes and heap-backed public
shutdown-report collections still need complete prebirth funding; these changes
do not qualify Main/Source issuance or native return.

Source stop receipts now encode their bounded journal slot as a nonzero,
one-based index. On 64-bit hosts an optional receipt occupies the same sixteen
bytes as a present receipt, instead of adding an eight-byte discriminant. The
storage and original loan stay in the existing prepaid journal; no heap object
or authority is added. Actual component controls exercise every one of the
sixteen slots, repeated immutable observations and zero publication allocations.
All 35 Source controls, both exact Source observation contracts and source shape
pass. Restoring the old zero-based `usize` representation makes the optional
extent assertion fail at 24 versus 16 bytes; exact restoration passes all 35
Source controls. Complete application-target compilation remains pending.

The scheduling-only `HostRetryCadence` helper and its public re-export now have
exact source-policy contracts. They bind the complete finite owner and methods,
the actual monotonic clock and all three component controls. A changed schedule,
renewal, quarantine reset, weakened observation, foreign clock or added retry
remains visible to the flaky-test scanner. The contracts issue no operation or
effect authority; each caller still needs its own saved-original checks. All
three actual cadence controls, both classification controls and source shape
pass. The complete testing-standards suite now passes 78 controls and retains
one broad failure over twenty other unclassified retry paths. Mandatory
application-target compilation remains pending.


The plan-read and callback-diagnostic refusal controls now have exact component
source-policy contracts. They bind the actual retained-original pre/post read
path and the first-refusal diagnostic writer with its unconditional shutdown.
The driver finish-refusal and bounded slot/report observations also bind their
actual typed causes, same pending request and terminal-post handling. Changes
to those owners or their assertions, and additional retries outside the reviewed
blocks, remain visible. These classifications establish no native Source,
operation payer, physical-return receipt or descriptor deadline.

All six plan-read controls, three diagnostic controls, eleven actual driver
supervision controls and four bounded quantum-observation controls pass. All
four new classification controls and source shape pass. The complete
testing-standards suite passes 82 controls and retains one broad failure over
sixteen other unclassified retry paths. Mandatory application-target compilation
for this increment remains pending.

Publisher refusal classifications now bind the exact retained mapping return,
command preflight/publication journal, and sticky native-current/transfer paths.
The component controls retain actual kernel roles and mapped bytes, or borrowed
ABI views; they issue no native Source or physical-return authority. Changing a
physical disposition, reusing failed command birth, erasing the first native
refusal, or adding another retry defeats the corresponding classification.
All 22 host publisher controls, seven plugin publisher controls, both new
classification controls and source shape pass. The complete testing-standards
suite passes 84 controls and retains one broad failure over thirteen daemon
paths. Mandatory application-target compilation remains pending.

Controller-return progress now takes the launch's prepaid first-error storage
before publication inspection or provider entry. Construction admits the root,
cause and independent accounting finalizer together. Every shared owner closes
its allocation before the payload can release its original control loan. An
erased provider error keeps that finalizer alive after the launch closes; taking
the cause out of the root also prevents a cycle when the actual error retains
the launch. The exact original target and registrar identity reject foreign
controllers, and each launch permits one canonical progress claim.

The component controls retain the first typed provider error without publication
or repeat allocations, preserve paired-account credit through all three actual
control frees, and close an error that itself retains the launch. These component
accounts do not issue Main, native Source, operation or physical-return authority.
The full host suite passes 1,377 tests with the same eight unissued helper-launch
failures and four ignored tests. All 121 hot-fork and 42 retirement-filtered
controls pass. Replacing the finalizer's closed shared owner with ordinary Arc
destruction makes the actual deallocation control fail: both accounts have
already refunded all 6,336 admitted bytes when the header is freed. Exact source
restoration passes. The complete testing-standards suite retains its same
84 passing controls and thirteen-path daemon classification failure. Strict
Clippy retains the existing 674 library and 723 test errors after correcting
the new fixture layout helper. Source shape passes with updated review records. Controller history
remains inline; compact prepaid receipt storage, public shutdown collections and
the complete native issuer path remain unfinished.

Controller-return histories now borrow immutable records from a separate
prelaunch journal. Optional and present receipts both occupy sixteen bytes on
64-bit hosts; the two controller slots occupy 32 bytes. Eight bounded slots cover
all monotonic first-error, precheck, postcheck and uncertainty changes. The root
transfers both journal and cause storage to its one canonical progress owner
before any publication observation or provider entry. Records retain the
independent finalizer rather than the root, so an actual error retaining its
launch cannot create a custody cycle.

All 44 retirement-filtered controls pass, including every storage slot, repeated
zero-allocation publication, receipts surviving their launch and actual journal
header deallocation under paired component funding. The complete host suite
passes 1,379 tests with the same eight helper-launch failures and four ignored
tests. Ordinary Arc destruction makes the journal-header control fail after
prematurely refunding both 7,640-byte charges; exact restoration passes. Source
shape passes. Testing standards retain 84 passing controls and the same thirteen
unclassified daemon paths; strict Clippy retains 674 library and 723 test errors.
These component receipts grant no Main, Source, operation or physical-return
authority. Other large shutdown variants and public report collections still
need work. Mandatory application-target compilation remains pending.

Lifecycle failure classification now binds its complete pure status projection
and actual typed-cause controls to the retained protected first-error and
quarantine owners. Missing or foreign projections remain terminal; later cleanup
cannot authorize another initiating attempt. Exact companion contracts reject
changes to the protected projection, quarantine observation, original cause or
status assertions. The classification schedules no work and issues no Main,
Source, cleanup or physical-return authority.

All ten daemon failure-classification controls, both new classification controls
and source shape pass. The complete testing-standards suite passes 86 controls
and retains one broad failure over twelve other daemon paths. Mandatory
application-target compilation for this increment remains pending.

#### Cumulative construction and request ownership source

Signed atomic `e82bb4c78da7af3351ef6473935a2be2feb01a2d` imports conventional
`ce726d4a9b2fc37b6559c2cb39070b509678f318`, tree
`3b3b318164d5092261bd2374744d72e4e8298910`. The conventional history retains
the prior canonical stack consumer, complete construction and installed
Original ownership, and independently reviewed request and returned-recipient
history bodies. The two former missing request Work providers and the separate
preexec history-post provider now have actual definitions. Prospective and live
requests retain four distinct raw recipient observations; positive histories
cannot be reset or reused. Callback return history has a distinct pending
recipient selector and does not query ended Work authority.

Independent correspondence checks verify all eighty sealed artifacts, both
signed trees, every one of 78,447 tracked paths, 78,375 regular files totaling
699,493,911 bytes, and 72 literal symlinks against signed Git blob identities
and the complete source archive. The comparison record has SHA-256
`5581f880cfd63c29230fbd8882b53869ec6231c1aa40af48f250305b2c3a57fd`.
The cumulative license ledger contains 640 created files. Of its 207 added
rows, 201 have explicit GPL-2.0-or-later notices and six retain QEMU's default
GPL-2.0-or-later terms. The license-ledger check passes at
`imz4xbxj2isks9slfbh9np4jy11iymcm`; core evaluation and focused Nix formatting
also pass. Hermetic patch-and-bundle reconstruction reproduces the exact atomic
tree at `5gr390s5cr4q8cf6d81yxch7a3zmskaf`. Engineering hygiene passes at
`zcvijji792yblcv5r97p578pnwrl3izi`.

The actual literal Source extraction passes with 175 roots and 1,227 functions;
the literal preexec extraction passes. These source checks are separate from
C compilation, linking and runtime qualification. A fresh genuine configuration,
owning-translation-unit and complete getter measurement remains pending for
this exact tree; the earlier 409,334-byte observation is not a price for this
new source. Complete successful postbody resource custody, funded profile
issuance, activation, external physical reap and the remaining RFC requirements
remain unfinished. ABI conformance subsequently passes at
`agbbmbj61fpji8g23c8sqzaicrmxhhzq`. The subsequent canonical license-boundary
attempt fails in the strict controller dependency with 660 Host-library Clippy
errors; its boundary assertions do not execute. The original failed derivation
is `49j1qzy5x56n31l1fw0zxm8r77ljkk1v`. The fresh genuine configure returns
zero in 42.290 seconds, then
the complete source-effect assertion refuses an additional empty test scratch
directory before any owning-object, passive or getter compilation. No original
source row changes or disappears. Both the original failure and the ordinary
configure-time enumeration producer are preserved; a fresh run must authenticate
that precise directory and the Meson lock without excluding either effect.
The independently registered Source unit subsequently fails its real compile:
the extracted caller type appears after its uses and request predicates refer
to two nonexistent Source fields. No Source unit test executes. The failed check
is retained while declaration ordering and genuine owning coordinates are
corrected; adding fictional fields would not repair these predicates.

#### Source declaration and constructor-coordinate correction

Signed atomic `b01e82be2e8f9c98f7e3ba6380860b5b2a12a1db` corresponds to conventional
`7fdf8c13aab63dceddc4ea01947a0ad643ec6515`, the sole child of the preceding
`ce726d4a9b2fc37b6559c2cb39070b509678f318`. Both corrected commits have tree
`d2ca3f4f7b335e7abf5bd75560ab335f67a5ff77`. The actual unchanged caller
implementation moves into a GPL private fragment before its first owning use.
The wrapper and Original predicates replace nonexistent receiver/lender fields
with the constructor's saved recipient serial, the known canonical lender's
birth journal and checked Runtime holder/serial coordinates. Existing process,
thread, factory, Main/CONTROL and no-return/no-consumption checks remain.

Independent review authenticates all 46 sealed payloads, both signed trees,
78,448 tracked paths, 78,376 regular files totaling 699,496,748 bytes and 72
literal symlinks against actual Git blob identities and the complete archive.
It also checks that the conventional delta consists of exactly the twelve
reviewed source paths. The correspondence record has SHA-256
`f0a6ca8402c42639dbc59498b0626cd70ee8d176a611ea397932ea34c09cddad`.
The new private helper has explicit GPL-2.0-or-later terms; all 641 created files
pass the license-ledger check at `c6hqqb06qnym5pl69jd1zf15aji8nbj9`.
Hermetic patch-and-bundle reconstruction reproduces the exact signed atomic tree
at `0yrqgpk43saqdqz4r7z1nqirjblwill3`. Focused Nix formatting passes.
ABI conformance subsequently passes at
`jicli6dlf913ld357p64giqc2vs1v2wm`.

Literal Source extraction still passes with 175 roots and 1,227 functions;
literal preexec extraction and all 468 Source/46 preexec Meson input identities
pass. These are source checks. A separately authenticated fresh configure,
35-object-variant owning cohort, two passive translation units and 39-getter
measurement first completes source reconstruction in 68.729 seconds and genuine
configure in 48.182 seconds, then refuses the source-effect comparison before
owning-object or getter compilation. Independent complete comparison finds
86,090 rows on both sides with no added, removed or changed per-path facts;
the failure compares globally sorted expectations with depth-first enumeration.
The actual arrays and sealed first failure remain intact.

The comparator-only successor rejects duplicate actual paths, unequal row counts,
unequal path sets and changed full rows before comparing a separate sorted view.
It leaves the recorded enumeration untouched and retains the precise Meson-lock
and empty-scratch effects. All 73 payloads and 123 actual input identities are
authenticated; 31 source-effect, seven sampler and ten evaluator controls pass.
The correspondence record has SHA-256
`5b619e16e028fbd9f66c0e7f8c72dd00df00b50ee97cbd5849f37d5ef118528f`.
The fresh run uses the same exact source and original 600-second whole-cohort,
180-second compiler/archive and six-GiB process/tree ceilings with one sequential
worker. Configure returns zero in 44.305 seconds; the complete source-effect
comparison and genuine dependency closure pass. Owning variants zero through
28 compile successfully. Variant 29, the actual native-invocation object, fails
in 0.627 seconds: the construction and Original headers use the genuine
`QemuCrucibleCoreQuantumReturnResult` by value before its canonical definition
is included in the user-mode Native chain. The runner stops and is reaped with
exit one. The remaining five variants, both passive units and all getter
readbacks do not execute.
The original failure is preserved; no complete owning or layout result is claimed.

The separately registered Source unit now compiles its owning object but fails
at final linking with eighteen unresolved actual Core, preexec, Outcome, TCG
and plugin API providers. The failed derivation is
`r54l1m86vam0pq755vpg1sgm7g8nm3aj`; no TAP case runs. The prior declaration
failure and this distinct linkage failure are both preserved. Genuine provider
linkage remains required; substitute implementations cannot qualify ownership.
Later postbody, successful resource retirement and recipient-journal drafts
remain separate. There is no native runtime, paid-profile or successful
physical-return qualification for this tree.

#### Self-contained construction result types

Signed atomic `c55af78276f2b0913acedc72c1c09e9fc2f31b86` imports conventional
`ee8eebc886fc9fe1ada9ad3301ddd99d30d149bb`, the sole child of `7fdf8c13aa`.
Both commits have tree `d66b723cd8645446aae14fc1737fcf10cc5b82dc`. The
construction header now includes the canonical Core quantum header before its
existing by-value return records. Six dependent literal source guards bind the
corrected header. No type, field, layout or user/system conditional changes.
Independent inspection follows all fifteen quoted Core headers and seventeen
include edges without finding a return cycle or implementation dependency.

Independent complete correspondence authenticates all 42 sealed payloads,
78,448 tracked paths, 78,376 regular files totaling 699,496,790 bytes and 72
literal symlinks against both signed Git trees and the source archive. The
correspondence record has SHA-256
`7106671a768f4cac775ce812a5d09c2d2133e54e54f0cd772ef634f16329b4fa`.
Hermetic patch/bundle reconstruction passes at
`iklsrqyaniq8jvfwzxj2idply5zj6cbg`; the unchanged 641-file license ledger,
core evaluation and focused Nix formatting pass. ABI conformance passes at
`k51wd6d4ldmmjhvrzx0c6vjdj809gi15`.

Independent review rejects the first fresh owning-compile plan before execution
because one nested reconstruction inventory digest is stale. Its sealed bytes
remain intact. The corrected successor authenticates all 102 payloads, 128
actual inputs and ten nested reconstruction inputs; its eleven execution
scripts and owning roster are byte-identical to the preceding genuine run.
All 31 source-effect, seven sampler and ten evaluator controls pass. The
review record has SHA-256
`1c94a9e2527f3ff79f727c4d2e4a1287689f4d306211979eb6c011d430f2bec7`.
The exact bounded single-worker run returns zero. Genuine configure completes
in 36.498 seconds; all 35 owning variants compile, including the previously
failing user-mode variant in 0.775 seconds. Both passive units and all 39 direct
getter readbacks pass. Independent review authenticates all 29 sealed payloads,
4,319 execution archive paths, 35 owning objects and 1,600 dependency hashes.
All 118 original child returns are zero, with direct identities observed and
no forced stop, kill or lingering child. A separate disassembly and evaluator
readback reproduces all 46 compiled bodies and both passive binary layouts.
The independent result record has SHA-256
`8e4bb7896b8efbfb60e78c750b64f9df8d19c1fb6bdee3d885ae7a3f81f81379`.
The exact Source root occupies 398,664 bytes; the 39 getters add 79,630 bytes,
for a fixed passive floor of 478,294 bytes. These values apply only to the
exact `ee8eebc886` source and selected `cff34ac416` libc tuple. They do not
price dynamic resources, later postbody drafts or complete paid profiles.
The earlier genuine native-invocation compile failure and
the registered Source unit's eighteen unresolved providers remain preserved.
The current owning compile result supersedes that object's earlier compile
failure; the distinct unit linkage failure remains unresolved. Runtime, paid
profiles and physical return remain required.

The separate no-Target Outcome draft's original audit packet omits actual
script inputs. Its evidence-only successor preserves all 91 production rows
and freezes 88 additional historical inputs, six unchanged audit/parser scripts
and the runtime identities used for replay. Complete independent correspondence
verifies 106 artifacts and 185 archive members. Seventy added inputs equal the
canonical source; eighteen differ and remain historical evidence, never join
overlays. Isolated peer replay reproduces the original partial counts of
486 parsed functions and 208 reachable static names, and the complete cohort's
491 functions and 215 names. Both retain 120 roots and pass 142 expression,
six ordering and 112-field controls. The correspondence record has SHA-256
`6fe2632700c2ff2ed5c9ca7f97e43294a366468da728dbdd160ae3bc20658c28`.
These source audits qualify neither the coherent canonical closure nor C,
layout, runtime, paid-profile or successful physical return.

#### Composed postbody and returned-recipient ownership

Signed atomic `b62dc6074984e9976572cceca6d971e8105735a7` imports conventional
`b34f6e70973ed3cf31ac9c5ef25c3e21d8e33530`, the sole child of `ee8eebc886`.
Both have tree `4c95a54a92e688d81ded1a500f6b6515540ea9aa`. The composition
retains the reviewed physical Core postbody observations, resource disposal,
raw returned-recipient journals, Source constructor retirement and installed
Outcome transfer. Whole returned results cross the actual C return before
postbody observation; independent failure history and unresolved debt remain.
The canonical Core include is preserved. Eight missing production-purpose
prerequisite edges now name the actual guarded inputs; all six literal guards
bind the final source without changing their other bytes or formatting.
Source, Core and Outcome focused reviews pass.

Independent complete correspondence verifies all 342 sealed payloads, 78,461
tracked paths, 78,389 regular files totaling 699,703,282 bytes and 72 literal
symlinks against both signed Git trees and the complete source archive. The
record has SHA-256
`e485f274a5abaf3e996ae0c6a81edf4c9bd91beec448bf1ad9be87a87dc137e8`.
The thirteen new files retain explicit GPL-2.0-or-later identifiers; the
cumulative license ledger has 654 created-file rows and passes at
`x51jpd55ax7v5bvs6lhq1722fj0hgp6g`. Hermetic patch/bundle reconstruction
passes at `0bdmfig1b41xya91ysvvpsgvm52kid2v`; core evaluation passes. ABI
conformance for this postbody tuple passes at `idw170y5d6bm6rnzx3qw92mq8fd9s7qp`. Fresh owning
compilation, getter readback and geometry for this larger tree remain required;
the preceding header tuple's measured floor is not reused. The separate
system-link alias and no-Target successor remain excluded from this import.
No native runtime, paid-profile or successful physical-return qualification is
claimed.

#### Coherent no-Target successor

Signed atomic `e07752457bbafc69359ac7cc5cbaa3bd950e1c77` imports conventional
`66d8bdaf015b7676f4b9a144cc3dcb1a24dfbcd0`, the sole child of `b34f6e7097`.
Both have tree `e5c162ba94a949808f0a87cd98a78d488ec41cf9`. The actual reviewed
R61-to-R62 production delta is applied to the current composition: thirteen
owning paths are byte-identical to the reviewed draft, the newer execution
header receives the genuine loan-pristine declaration, and the current unit
dependency union gains the new fragment. Six literal guards retain their
other bytes and previous keys. No historical audit-input overlays are used.
The no-Target path requires complete never-issued Target/Outcome history,
actual Runtime registration and Target enrollment, and strict raw return
observations after the actual C return. Partial, touched, repeated, negative
or unknown histories preserve their existing debt; parent Source, Main,
Original, Module, Control and resource obligations remain independent.

Independent review authenticates the coherent cohort's 636 payloads, all 503
current Git source identities and 509 archive rows. Source, Core and Outcome
composition reviews pass. Isolated peer replays report 491 parsed functions,
120 locked roots and 217 reachable direct statics, with no reachable `getpid`;
142 expression, six ordering and 112-field controls pass. The two additional
statics over the historical 215 are the already-canonical Native matched-Advance
closed and untouched helpers. Literal extraction reports 179 roots and 1,299
functions, with all four outputs reproduced. These are source-parser results,
not complete indirect-call or runtime qualification. The independent coherent
review record has SHA-256
`8110c921d363289111f6f0ff197740c298e770adcfafcbf08e4546662ec251bc`.

Complete signed correspondence independently verifies all 697 sealed payloads,
78,462 tracked paths, 78,390 regular files totaling 699,751,286 bytes and 72
literal symlinks against both signed Git trees and the full source archive.
The record has SHA-256
`814c4e25b6f84e5da80b0156ec95d4a46cea63ebdeaff716689f295c42b43157`.
The new fragment retains its explicit GPL-2.0-or-later identifier and brings
the cumulative created-file ledger to 655 rows. The ledger passes at
`7if63n9kpjqcskrypc75k3zqa567zjc3`; hermetic patch/bundle reconstruction passes
at `256xqjvx3r6z34j8prqd4kbgkmg90f11`. Fresh owning compilation and
geometry for this exact combined tree remain required. No native runtime,
paid-profile, activation or successful physical-return result is claimed.

#### Opaque frame acquire correction

The exact no-Target owning build reaches genuine configure successfully in
34.777 seconds and compiles owners zero through seventeen. Owner eighteen,
`plugins/crucible-startup-source.c`, fails at the acquire load of the opaque
Core frame pointer: qualifier inference in `qatomic_load_acquire` evaluates
pointer arithmetic requiring the unavailable pointee definition. The run stops
at that first failure, reaps its children and releases its compiler lane.
Independent review verifies all 28 signed outcome payloads, all 3,673 original
execution archive paths and both complete 86,104-row configured-source
inventories. No later owning, passive or getter result is claimed. The original
failure remains unchanged; its independent record has SHA-256
`782b1aa8b5ef027dc7032eaf0f3bb3a441b30e3ee82dff32dd4899feff6a1f65`.

Signed conventional `ce0d15fb5d0125dd011dc452bba91032b841d57e` and atomic
`4edc47cba642b59e1af833cb2ffb0eb9c84ae3d9` share tree
`10c75e16bd02c87e57dc25e9657840003c88820d`. The sole owning change uses an
explicitly typed pointer result, QEMU's unchanged pointer-size assertion and
the same generic atomic load with acquire ordering. The frame remains opaque;
the null gate, once claim, exact identities and physical proofs are unchanged.
Six guards change only seven authentic digest tokens. Core and Source reviews
pass, including nine new atomic controls and the existing source audits.
Independent review verifies all 672 sealed payloads and every tracked source
path against both signed trees and the complete archive, including all 72 raw
symlink targets. Its record has SHA-256
`861dd9c81d1dda0021809c146e24070777cf7bd10f967663978b8b65a40d96bd`.
Hermetic patch and bundle reconstruction passes at
`jnbcjmzl52sknvz3mlb3hin43316gjqd`; the unchanged 655-file license ledger passes
at `7if63n9kpjqcskrypc75k3zqa567zjc3`. ABI conformance for this atomic tuple
passes at `fpi9p5xz5n4a33qflcc75dg5n3cjcfvv`.

The correction now passes its original bounded configure and layout cohort.
Genuine configure returns zero in 34.861 seconds; all 35 owning variants, both
passive units and all 118 child commands return zero. Independent review verifies
all 29 signed payloads, all 4,319 execution archive paths, 35 actual object hashes,
1,622 dependency hashes and both complete 86,104-row configured-source inventories.
It independently disassembles and evaluates the 46 compiled bodies reached by
39 direct getters and reads back both passive layout binaries. The actual Source
root is 475,728 bytes and the direct getter extents total 82,102 bytes, giving a
557,830-byte fixed declaration floor. The separate preexec root is 230,856 bytes.
These measurements apply to this exact tree and selected libc; earlier floors
are not reused. The independent result record has SHA-256
`6e3ee2ffa0a92c25144517211fe6a5aac1dafb8be93e20362a189a58f075837d`.
No application link, runtime, paid-profile, activation or physical-return result
is inferred from compilation and passive geometry.

The subsequent canonical license-boundary attempt stops before its boundary
assertions: strict controller compilation reports 653 Host-library errors. This
packaged result has a different feature selection from the standalone Host lint
command recorded above; their finding counts are not interchangeable.

#### Genuine full-system provider linkage

The current signed QEMU tuple also passes one original bounded build of its
existing `qemu-system-x86_64` target. The preceding attempt stopped after
configure because its raw header identity still used a different install
prefix; it executed no target edges. Its signed original failure remains
unchanged. The corrected plan derives exactly twelve install-prefix macros and
ten unselected compile-database object coordinates, preserving the complete
graph and database without broad normalization.

The original corrected invocation returns zero in 1,479.088 seconds. Genuine
configure takes 36.649 seconds; the 1,953-edge graph produces all 1,621 C objects,
and final link returns zero in 2.190 seconds. The sealed result manifest has
SHA-256 `acdd834fe0be0410ae734058150b6fc953d053f7cd363604f979e27a11d592a7`.
Independent review verifies its signature, all 34 payloads, all 30,022 original
execution archive entries, four complete filesystem inventories, all 3,301
compile-database rows, every actual object, and 622,048 dependency observations
across 4,423 literal paths. All 1,956 monitored operations return zero. The
21,599 process samples peak at 528,400,384 resident bytes, 650,178,560 virtual
bytes and five processes; these are sampled observations, not unsampled maxima.

Independent bounded AOS `nm` and `readelf` readbacks exactly reproduce the
original logs. The final 105,802,048-byte ELF has SHA-256
`c3539b7aadb1f48ae7c4988e21d689f3c08664397634798727a045538f962c00`,
the selected interpreter, and all eighteen genuine provider definitions. The
independent review record has SHA-256
`c89b3cf2dae1df7e2c7c16fbc7b00036fa63ec23b7045b592826e0457d946fee`.
Cleanup observes empty actual child inventories and ECHILD; it exercises no
adopted-child signaling or reaping branch. This result qualifies compilation,
linkage and static ELF identity only. It executes no registered unit, TAP,
emulator runtime, native profile, activation or installation. The registered
Source unit's earlier eighteen-provider link failure remains unresolved.

#### Genuine-provider companion source preparation

A separate, not yet imported signed source increment `0262209aa1`, tree
`7696c63e50a58f04eea0f559c4098202bfd0ead7`, adds a nineteen-case GLib/TAP
companion. It selects the genuine configured system-target object/dependency
closure, actual executable-only preexec source and actual `system/main.c`
with only that companion object's entrypoint renamed. It changes no provider
body, canonical state, legacy fixture or scenario. Six source guards receive
ten exact digest substitutions for the two Meson additions; both new files have
explicit GPL-2.0-or-later notices.

Independent source review authenticates all 971 sealed payloads, all 78,464
signed Git/disk paths, all 946 review-archive members and copies, and eighteen
prior-input references. The whole tree contains 78,392 regular files totaling
699,772,291 bytes and 72 literal symlinks. The source review record has SHA-256
`eeeb1aeb58c7da87581dc0f10085214e232a072155fe76d0a074f7cd9ba47baa`.
The 946-member review archive is not a complete corresponding-source artifact.

The cases query ordinary unissued state and retain genuine raw first/post and
access-cursor negatives. Real ELF/preinit constructors, allocations, module
registration, the detached RCU worker and plugin exit callback remain present;
the harness initializes no VM or guest and resets no production journal.
Source reasoning establishes no executed case or worker-retirement result.
Fresh configuration/graph discovery remains unexecuted. Review found that the
initial declarative proposal reused compiler wrappers with the previous run's
baked journal directory; a separate frozen executable plan must correct those
paths before execution. No companion pass, legacy-unit repair, accepting
lifecycle, profile, activation or installation is claimed.

The imported companion uses corrected conventional `fb922ae3f8`, atomic
`bbac33ec36`, tree `9f3afa755ffd0bbbf21da889dc84969b413609d8`. The first
executable discovery attempt failed in genuine Meson with unsupported dictionary
`.length()`, before any graph or target compilation. Its sealed failure
`0363f7ae627b88fe5bf8981e89cecd137a589f400c65d56e4fd28aa78684b8eb`
retains all 2,227 execution and 86,111 reconstruction disk/archive paths,
298 driver records and independent actual empty-child/ECHILD cleanup cuts.
Its complete invocation, including final inventories, took 100.865 seconds.

The separate correction changes only the guard to `has_key('objects')` and
eight digest tokens across six source guards. All provider bodies, nineteen
cases and the legacy fixture remain unchanged. Independent review authenticates
all 54 corrected payloads and all 78,464 signed Git/disk/archive paths, including
699,772,296 regular-file bytes and 72 literal symlinks. Nine actual Meson
implementation files support the expression review. Canonical email-patch
regeneration from the authenticated signed commit corrects the handoff's plain
diff packaging; exact source-tree reconstruction and the 657-file license ledger
pass without weakening either gate.

A separately frozen discovery plan passes genuine configure and four read-only
Ninja queries. Its actual graph contains 1,954 edges, 3,304 compilation-database
variants, 1,622 selected C rows and 1,544 leaves. Configure takes 33.656 seconds;
final invocation inventories finish within 151.564 seconds of the original
900-second bound. All five actual cleanup cuts observe empty kernel children
and ECHILD; no adoption, signaling or reap branch is exercised. The successful
packet `f83165f37d11ea59646a471f051816596f96238d9f331f4e6682b254217f4886`
records configuration and discovery only. Independent review verifies all 37
payloads, all 2,948 execution and 86,111 reconstruction disk/archive paths, both
raw graphs and every selected input. The genuine full-system closure retains
its unchanged target objects and exactly one separately renamed main object.
All 701 actual process samples include the monitor worker and remain below the
six-GiB aggregate bound. Canonical atomic patch reconstruction passes at
`qlh9wdmgax3gyx41fflg7yxjxk9rrqkz`; engineering hygiene passes at
`zcvijji792yblcv5r97p578pnwrl3izi`. Target compilation, final provider symbol
resolution and TAP execution remain unexecuted. ABI conformance also passes at
`nflj0wrhq0r255sjrvrrbb9np6sxddmg`.

The separately sealed build plan
`43ced7e66fea3da017b5089a674ddfed47ef69ff9f228628920ff6ef1aa03f36`
authenticates all 71 payloads, 163 external inputs, ten reconstruction inputs
and 70 complete tool/runtime roots. Independent graph translation checks every
edge, database variant, leaf and the 1,952-effect schedule; the actual pinned
Meson implementation independently derives all ten changed object coordinates.
Its original invocation starts with a 5,400-second inclusive bound, one worker,
180-second configure/C bounds, 30-second generator/archive/link bounds and a
six-GiB address-space and sampled aggregate limit. The original invocation
returns one after configure succeeds in 32.764 seconds: exact graph equality
refuses before any target compilation. Final inventories complete within
116.681 seconds; operation and exception cleanup independently observe empty
actual children and ECHILD. No graph repair, target compile, final link or TAP
execution is claimed. Independent review of sealed failure
`ec1771c71bbd9b45f7842842b1c4c89b8b7075735552359aae47ff131f101591`
authenticates all 35 payloads, 2,911 execution and 86,111 reconstruction
paths, their complete archives and the original raw graph. Exactly 33 unselected
whole-graph command fields differ; all selected edges, 3,304 database variants,
rules and leaves match. Each differing command names a Meson serialized-command
artifact. Sealed diagnosis
`55acb67a9a4a6525bee2c2fba33bda7e1d3e312012abe5d1b61c4b29c263fb41`
binds all 76 payloads and independently derives every old/current filename from
the actual QEMU functional-test environment and pinned Meson hashing code.
Changing only these 33 derived names explains the entire original graph.

Fresh plan `b1370f131dd0d4dccd0b1b754202b8e2152a46ad7a19eebdef99d1c14581f608`
authenticates all 88 payloads, 174 external inputs, ten reconstruction inputs
and the same complete 70 tool roots. Independent review checks every graph
field, schedule and leaf, derives all ten object and 33 serialized-command
coordinates with actual pinned Meson code, and confirms all eight runtime
helpers remain byte-exact. The original new invocation returns zero in
1,602.043 seconds; final inventories complete in 1,626.270 seconds, within the
same 5,400-second ceiling. All 1,952 scheduled effects and 1,960 monitored
operations return zero. The actual 105,818,904-byte companion ELF has SHA-256
`69b7c3cbf2cd358634750e91f631e521479090475921a97cfe80226d3c103fc6`.

Independent review of sealed result
`ca7030ecc91a957df9018ca1cd24e62835d761f592641fcc5037f05f7bae0e2e`
authenticates all 45 signed payloads, all 43,085 execution and 86,111
reconstruction paths against their complete archives, every graph field,
all 1,622 objects and 622,373 actual compiler-dependency observations over
4,424 literal paths. Repeated bounded AOS `nm`/`readelf` output matches the
original bytes and finds all eighteen actual providers. All 1,960 cleanup cuts
observe empty actual children and ECHILD; adoption, signal and reap branches
remain unexercised. The 22,393 aggregate samples peak at 1,027,379,200 RSS and
1,189,502,976 virtual bytes, below six GiB; samples do not prove unsampled peaks.
This establishes compile/link and static ELF observations only. TAP,
installation and activation are not executed.

A separately reviewed 60-second TAP plan
`0e0d60a4eabf475124a9d47a9089b89cd62a5809b3390bad34d4a3da227dd55b`
binds all 44 signed payloads, seven external inputs, 70 complete tool/runtime
roots, and all 6,583 build and 86,111 reconstruction entries. Its historical
86 pure controls precede sealing; independent read-only replay adds the final
`seal.py` syntax check for 87 controls. One original invocation executes the
exact produced ELF with `--tap -k` and the startup selector absent. It returns
zero after 28.934 seconds, including authentication and final evidence; the
actual TAP process returns zero in 0.061314 seconds. All nineteen exact paths
appear once with consecutive ordinals, no skipped or expected-failure case.

Independent review of sealed result
`3c4791791a5be95b92a23e58a2c64d993a81140fbef7a3addeedef8bd18c4ded`
verifies all 35 signed payloads, 24 original execution/archive entries and the
complete source/build before/after inventories. Actual cleanup observes empty
kernel children and ECHILD, with no adoption, signal, wait or cleanup error.
One aggregate sample observes 105,676,800 RSS and 194,097,152 virtual bytes;
559 worker samples remain within the six-GiB ceiling. These periodic samples
do not prove unsampled peaks. Genuine constructors, the detached RCU worker
and normal atexit remain present. Process return supplies no explicit RCU drain,
callback retirement or worker join. This passes only the ordinary/unissued
companion; the legacy fixture, complete paid profile, emulator/guest execution,
installation and activation remain separately unqualified.

The unchanged legacy fixture still has 187 registrations, 179 extracted Source
roots and thirteen lookup definitions. An independently reviewed compile-only
probe retains all three existing utility variants, without linking or changing
production/test source. Its first invocation stops on an unauthenticated zombie
observation and separately retains a missing Linux-header ownership failure.
Sealed failure `a90bd96fe03b4f6134a181199b389b639f6ec182b3d62f3b766c39da88cebf2a`
has all 55 signed payloads and forty original disk/copy/archive entries verified.
It establishes no completed admitted command.

A new finite probe authenticates the complete additional header root already
selected by GCC specs and records terminal zombie observations separately from
live executable identities. It accepts two original C commands, taking 0.302231
and 0.405296 seconds. Their actual objects contain 24 and 56 symbols and 770 and
7,740 relocations, including debug records. The third command stops when a raw
process sample combines state R with no executable or arguments and zero memory.
Its object is absent. All three partial depfiles authenticate 309, 510 and 748
input observations; all 819 completed dependency posts match.

Independent review of failure packet
`9144faaaac741c5798f135227e4de41ede1fe194dd5c4197d0bf42700a8a2573`
verifies all 97 signed payloads, 82 original disk/copy/archive entries, both
complete actual object inventories and all 6,583 build/86,111 reconstruction
entries before and after. The original worker returns one after 46.988958 seconds.
Cleanup retains the killed wrapper's -9 and adopted raw waits 9 and zero,
then observes empty kernel children and ECHILD. All eight independent final
evidence cuts succeed. All 312 aggregate and 597 worker samples stay below six
GiB; unsampled peaks remain unproved. The missing third object, complete fixture
symbol isolation, genuine legacy link and executed legacy cases remain unresolved.

A third finite probe retains independent raw stat-before, executable, argument
and stat-after cuts. Independently verified failure
`1253848ef0fd74b55724b98c4a50c583655cc25688c4cfdf51ed83d0f57e2fa4`
contains 113 signed payloads and 82 matching original disk/copy/archive entries.
It accepts the same two objects and refuses the third command after an
executable read returns ENOENT while arguments are empty. Both actual stat cuts
retain the same PID/start/parent, state R and zero memory; neither proves a
zombie, completed exit or wait. The third object remains absent.

The original worker returns one after 50.530266 seconds. Both independent cleanup
cuts observe empty children and ECHILD, with adopted raw waits nine and zero
retained separately from command status. All eight final evidence cuts succeed;
318 aggregate and 654 worker samples remain below six GiB. Complete build and
reconstruction inventories remain unchanged. No later observation qualifies the
refused command or supplies the missing fixture link/runtime evidence.

A fourth executed compile probe preserves the same three utility variants and
unchanged fixture. It binds retained process descriptors with raw descriptor
identity cuts before and after fresh process capture. Later unavailable process
observations remain unresolved evidence until actual descriptor readiness; they
supply neither a live role nor a wait status. Independently verified result
`d347de9ff105123679eb2ddad9eaf4adc0e1457495c6186c30061655eb1c45a0`
contains 188 signed payloads and 90 matching original disk/copy/archive entries.
All three actual C commands return zero; the original worker returns zero in
53.019206 seconds. The objects contain 24, 56 and 3,342 symbols, with 770, 7,740
and 159,400 relocations respectively. All thirteen exported lookups are defined.

All 1,567 actual dependency posts independently match their authenticated input
owners. Signed erratum
`ba3d0f2d268f165c714e265ae121ff9281c573419392b71202df197c99949e18`
corrects only the packaged summary's per-variant counts to 309, 510 and 748;
the original complete records and result remain unchanged. All ten observation
descriptors have both actual binding cuts, actual exit readiness and recorded
closure. Three unresolved observations remain preserved without fabricated roles
or waits. Final owned-child cleanup observes empty children and ECHILD; no signal
or adoption branch is exercised. All eight independent final evidence cuts pass.
The 328 aggregate and 670 worker samples stay below six GiB. Both complete
6,583-path build and 86,111-path reconstruction inventories remain unchanged.
These results establish the three objects and their complete symbol/relocation
inputs. Provider isolation, the genuine legacy link and executed legacy cases
remain unresolved.

#### Initial loader storage component

The package imports signed `cff34ac416ff0650048fd85d50e156434f5cb9ed`, tree
`9253d845b69f5fc16ab322b38d13b08092d4664f`, as a dormant version-two loader
probe. Independent review verifies all 61 source-packet payloads, all 62 changed
file identities and the canonical complete upstream patch. Independent bundle
and patch reconstruction reproduce that exact tree. The public journal contains
only fixed little-endian scalars and checked file offsets; page-disjoint native
loader/TLS objects use a separate private mapping. Private copy-on-write maxima
are additional liabilities, with separate mapping and child DTV-zero readback
outcomes. Neither file backing nor the receipt grants containing custody.

The earlier `1bf5541` baseline passes its hermetic installed component gate at
`hdqaw72awqdi2n2ybas8zlwpd655fny4`, but fails the shared-memory boundary because
its shared payload contains native objects. That result does not qualify the
corrected version. The new installed-loader gate compiles the original fixture
and real syscall-refusal helper against matching installed artifacts, checks the
C++ header layout, and retains the original runner outcomes.

Independent public version-two qualification now passes the complete sequential
build, all twenty unchanged ABI checks, installation, twenty initial-loader
controls against both build and installed artifacts, thirteen existing bounded
controls, eleven ordinary regressions, and the actual GLib/formatter controls.
All 501 read-only qualification payloads match manifest
`9a5df6c771303ee5132288f5d719ccca108002c47ebae63ae496e104eaacd4d4`.
A separately rebuilt, never-installed DTV-zeroing omission reaches the unchanged
validator and exits 127 with EIO at cut ten; its retained receipt records the
actual attempted/returned history and unreleased debt. Both full builds and
every runner retain their original status and finite limits. These public
component results remain separate from repository hermetic qualification.

The repository version-two package build now passes at
`lk9kpcdiwjcgpil6bfjf9m995xhwfj1a`, retaining fourteen literal passing test
results and a zero-status ABI check. The installed-loader gate passes at
`1c2f91vvhnxaljav1vc93x7nwmwdmb42`, with twenty actual installed-child
outcomes and zero compile, launcher, header and runner statuses. The standalone
ABI gate passes at `2z0vmx98ixwml7pxpsfmkyiqmbwwwki6`. The actual installed
GLib/formatter consumer passes at `n7yxz24yzb6xd1mmrm51dzw91is6vnfs`; the
matching QEMU bounded-thread gate passes all eleven tests without skips at
`2mkaasqmv1pkx29r92spil52c6ggyms9`. Complete process admission, kernel/image/initial-stack funding,
helper and relocation closure remain unavailable; selected probes refuse before
normal relocation and program entry, and `complete_profile` remains zero.

#### Selected allocator fail-stop component

Selected allocator qualification used signed provider
`9ec3dc41fde9abcbd3ce3f1bf91f87fedd63ae3a`, tree
`22720df186fb6f8e071952753462feb33cedb86e`. Its explicit bounded invocation
scope makes a real allocation failure terminate directly through the internal
`exit_group` leaf before GLib can enter recursive logging. Ordinary try-allocation
outside that scope and the checked allocation APIs retain their status behavior.
The scope's nonce, attachment, process and terminal-tail facts remain distinct;
an abandoned scope keeps uncertainty and cannot erase physical pthread debt.
All nine imported commits are signed and DCO-certified, all 46 file licenses
remain inventoried, and independent review matches all 37 import payloads and
the canonical complete upstream-to-target patch exactly.

The initial `34af6e6` full build passed but its application test genuinely failed:
the worker placed its nonce output in its protected supplied stack. The corrected
revision retains that exact EINVAL negative control, places the positive output
in the retained caller's control, and synchronizes entry after actual creation
publication. The original failed application result and original failed
prefix-sensitive ABI result remain preserved. Neither is a qualified result.

The new `checks.crucible.phase7.glibcBoundedGlib` compiles the exact upstream
integration source retained by this runtime's build against the installed
public headers, actual GLib DSO and matching libc/loader. Its real forked controls
distinguish fail-stop exit 127 from GLib logging at 126 and an unexpected return
at 125. Compilation and execution have independent finite limits. A nonzero
complete ABI status refuses before compiling the consumer. Fresh hermetic
provider, ABI and installed GLib consumer results are recorded below.

Independent qualification of the corrected signed provider now passes its full
build, both bounded suites, eleven ordinary regressions, unchanged complete ABI
check (twenty passes, original status zero), installation, actual GLib/hidden
formatter controls and installed geometry. Independent review verifies all 225
sealed payloads against manifest
`5679c5db294d3eec6540403fcee186ccd8dbdb99fde044a580c023569307a0d6`.
The first repository hermetic build compiled the provider but failed while
retaining the GLib source: its out-of-tree build directory made the relative
source path incorrect. That failure precedes runtime and ABI checks and remains
unqualified. The package now copies from the builder's explicit unpacked source
directory. The corrected hermetic runtime now builds at
`3xpzlqvjjh3gp3vdmcq69b3bry6zvs7j`: all thirteen retained runtime checks and the
original complete ABI check pass. Its independent installed ABI gate passes at
`z7m32c2wijyxcaa9583b3sn6ii474zj0`. The first installed GLib gate then failed
at linking because the runtime output has only the versioned DSO; its unversioned
linker symlink belongs to the development output. The corrected gate selects the
actual versioned runtime DSO directly and passes at
`hc9bhpkz5lz1m1y3lcw37mx1hdmv93gp`, including the actual GLib and hidden formatter
controls with the matching loader and libc. Both original failures remain
unqualified. These results qualify the installed package component; complete
launched-profile funding and admission remain incomplete.

The actual registered QEMU bounded-thread consumer also passes against this
same installed runtime at `m4f73yzplspdiyyvc3x1jynjrxi9hals`: eleven TAP cases,
zero skips, with the matching installed public header, loader and libc checked.
The real one-worker build completes in 268.828 seconds of its 600-second limit;
the tests complete in 0.067 seconds of their 30-second limit. This covers actual
birth, physical retirement, TSD last-use, no-birth and stale/copied identities
for the supplied-stack component; it does not admit a full QEMU runtime profile.

#### Installed bounded-pthread QEMU consumer

The preceding signed atomic patch selects `7a6b57edb01b7a5b6d06b11171ecf3a82bebde55`,
conventional source `48867e31f9a74fea78e6178a815bf64094389d51`, tree
`72dd4ea029469cc144141cb69cab3a91ce2e26ae`. It adds the actual optional
supplied-stack pthread consumer while preserving canonical stack debt and
ordinary pthread behavior. The wrapper retains provider control, incarnation,
stack and arena before initialization or birth. Terminal return independently
checks notifier and registry departure, kernel join, TLS tails and external
backing disposition. A linked storage ABI does not admit a runtime profile.

Independent verification matches all 33 sealed payloads, 78,240 source entries
and 72 literal links, 9,259 evidence files and six literal evidence links,
signed stage identities, fixed atomic dates, canonical patch and the exact
single-prerequisite delivery bundle. Its proof is
`a468a2ea4840a4133a30c3217332face170e594c3f833b95097014adb00762de`.
The six consumer implementation files match the separately reviewed signed
consumer exactly. The extracted member-return fixture now includes its genuine
stack-bank closure dependency; its positive and all 25 omission controls pass.

The final composed component qualification passes ordinary and installed-provider
Source, Native and preexec owning objects, genuine Meson unit registrations,
executed layout observations and four separately rebuilt intended-assertion
provider controls. It uses one sequential compiler, unchanged 600-second suite,
180-second compile/link, 30-second run, CORE zero and six-GiB process and sampled
process-tree limits. Actual wrapper storage grows from 504 to 1,152 bytes with
the provider enabled; both measured layouts remain separate pricing inputs.
These results do not establish the joined lifecycle storage floor or admission.

The new `checks.crucible.phase7.qemuBoundedThreadUnit` uses the package's genuine
unpack/configure phases and the matching AOS-built compiler/libc. It authenticates
Meson's actual capability and test registration, builds the real target with one
Ninja worker, then checks installed-header dependencies, ELF interpreter, runtime
libc and execution of real worker birth, terminal return and TSD last use.
Its first attempt refused before compilation because the checker expected an
integer-valued capability marker while Meson emits a valueless true definition.
That refusal is retained; the corrected check accepts the actual true forms and
continues to reject undefined or zero-valued capability. Fresh hermetic execution
passes all 11 registered tests with none skipped, including the real supplied-stack
worker and held TSD destructor. Genuine Ninja compilation takes 185.405 seconds
within 600; the registered unit takes 0.017 seconds within 30. The matching
installed public header, libc and ELF loader are verified. Evidence retains
583 actual objects, three archives and 585 depfiles as identities, with no
executable exported. Core evaluation, canonical atomic reconstruction, the
433-file ledger and engineering hygiene pass. The new complete Native attempt
passes all 187 Source tests and 24 components, including publisher-member-return,
then fails compiling the pending-constructor positive in 0.378 seconds within
its unchanged 180-second bound. Its original compiler refusal is retained;
the stack-bank component is not reached and no complete Native pass is claimed.
A separate correction and full affected-fixture audit are required. Fresh ABI
conformance passes. The strict license gate remains blocked by the actual host
Clippy failure recorded above.

Application allocation remains a separate physical owner: GLib DSO allocation,
Main-created work freed on RR, TCG contexts, translation pools, global caches,
callbacks and RCU lifetimes are not paid by pthread metadata or returned by
worker join. Genuine same-parent application/stack issuance, complete RR stop
and last use, physical debit return and the selected profile remain unqualified.

#### Physical stack/member and genuine fixture-provider composition

The preceding signed atomic patch selects `d1c072e9848e2c06f8d25272e1ae063b65deca61`,
conventional source `a994efb547b925f7c8b0457a2204a04cb10c73e0`, tree
`79cdafeec4443b7315848ca393601a2f8d6b4250`. Its sole atomic parent remains
the pinned upstream source. This checkpoint composes physical stack-recipient
and matched-member storage with the prior physical service and Original bank;
it supplies no selected semantic execution owner. Later role-reservation,
matched-constructor, stack-lender and Core drafts remain excluded.

The fixture correction links the actual 27-translation-unit production provider
instead of omitting the Source dependencies of cleanup. Standalone cleanup,
bridge and Quantum controls receive the actual compile database, build directory,
utility archive and objcopy. Packaged delivery first builds the authenticated
configured provider manifest, then passes it to its unchanged bounded runtime
inventory. The manifest binds actual compiler/tool, source/generated dependency,
object, archive and projected environment bytes; unsupported overrides refuse.
Neither an accepting Source replacement nor a copied authority receipt is used.

The final normal entry passes in 55.961503199 seconds under its original
60-second limit. The separate configured provider prerequisite takes
51.899642279/180 seconds. The full 33-case publisher-access inventory passes in
352.103757387/600 seconds. Standalone bridge, cleanup and Quantum inventories
pass within their original 180-second limits. All 99 preexec variants have
compiled, with the final generated bodies and classifiers byte-exact to that
qualified sweep. The final helper scheduling change reorders the same nine
independent commands within the existing two-worker pool; all join before the
architecture-only checks. All 106 generated cases and 128 emitted commands
match the prior timed-out entry after exact coordinate normalization. No
runtime case moves outside the 60-second body.

Earlier missing-dependency failures, a compiler-query failure, a genuine
60.014-second normal timeout and an input-mutation authentication refusal remain
separately indexed. The final stable runs start only after all earlier writers
finish. The changed configured cohort compiles 720 fresh outputs and
independently authenticates 2,446 retained outputs, then links eighteen genuine
owning targets and both system binaries. It does not claim a fresh whole-build
sweep. The SDK has 449 declarations and 448 definitions; the previously missing
`advance_outcome_observe_v1` producer remains undefined and uncounted.

The actual Source is 254,040 bytes. Its 31 genuine static getters contribute
44,774 bytes, giving the complete 298,814-byte floor. Embedded bank, Native RR,
Main-finish and Core terms are not charged again. Both architectures measure
preexec 215,160, storage 27,992, session 17,288, recipient 3,432 and role 80 bytes.
Two new GPL-compatible files bring the cumulative created-file ledger to 428,
with no deletions. These are measured physical geometry, not funded stack or
semantic operation grants.

Independent read-only verification matches all 78,235 signed/working source
entries, 24,232 regular evidence files, six literal evidence links, 36 sealed
artifacts and the complete source archive's 78,163 regular files and 72 literal
links. Both commit signatures, the raw signed atomic object and detached
manifest signature verify. The manifest SHA-256 is
`2414415907723dd5cee88495de5a40cc36b7a1cf4c8a1866faec318405195f1e`;
the independent proof SHA-256 is
`83fa36cc8b52fbddaf052086b2c4d7380d00238dfb1eb7376b15ca3c04beb11d`.
The checker's first evidence-base-directory error is retained and corrected
without changing source or evidence. Packaged qualification remains pending
at this import checkpoint. CPU admission still refuses with `ENOTSUP`.

#### Ordinary-fork and nonwaiting physical composition

The preceding signed atomic native patch selects `ec33e02897fe424523e1dc755ae0f3f651fdb22c`
with conventional source `45e353b75af24644b9cefc014cfc75323a8705bd`, tree
`12361245265446cff084677143e44d3394f6b8c5`. It composes the ordinary-fork RCU
registry ordering fix, nonwaiting Source/Native terminal metadata, the inline
Core resource bank, exact Setup7/plan10 parsing, completed Original registration
posts and the physical installing-service5 view. Old profile restrictions and
selected preinit refusal remain explicit. A physical bank or service does not
issue either semantic operation role.

The ordinary fork fix orders thread-registry quiescence after existing RCU
locks and releases it before child RCU worker recreation. It addresses the
actual vanished-worker lock implicated by the previous packaged Native custody
suite's discard resize-member timeout; the retained hot-fork transaction and
ordinary mutex behavior remain separate. Nonwaiting terminal sections make one
attempt and retain uncertain debt. Actual born/consumed facts precede independent
posts. Original registration now requires all independent post attempts and
returns; default zero statuses cannot establish completed registration.

The complete actual Source is 254,024 bytes. Its 31 separate genuine static
getters total 44,774 bytes, giving a 298,798-byte floor. The bank (168 bytes),
Original registration (72) and service (296) are embedded Source terms, not
extra charges. Preexec remains 212,752 bytes, with nested storage 26,640,
session 15,936 and RR metadata 232. Eighteen newly created files enter the
preserved per-file license ledger, bringing its cumulative created-file count
to 426, with no deletions.

Independent read-only verification matches every signed/working source entry,
all 26,862 indexed evidence files, twelve literal evidence links, 34 sealed
artifacts and every blob, mode and literal link in the complete source archive
(78,161 regular files and 72 links). It also authenticates both commit signatures,
the exact raw signed atomic object and the detached manifest signature.
The frozen manifest SHA-256 is
`7e873a772db0072c4e462f968a40a40a3fff9a82f7aade1fff8505d5d09385c4`;
the independent proof SHA-256 is
`6111fecafd64e8ca64ca38b3f2bc69699f5d7790fcb3fb9aad2806a15b6deac5`.
The checker's initial archive-prefix and artifact-location errors were corrected
without changing any qualified source or evidence. Raw ambient environment
captures remain local, digest-indexed only; the public projection contains
explicit build inputs. The separately authenticated 684 BSD source blobs for
SoftFloat/TestFloat remain in their corresponding-source artifact.

Qualification compiles 226 changed owning objects and 493 further consumers of
the changed public SDK, with all 3,163 initialized object outputs audited and
719 freshly changed outputs. Seventeen genuine configured links pass. Sixteen
leaf suites, six owning executables, the real service and four independent
omissions, ordinary keeper/fork/RCU controls and all 97 preexec omission
classifiers pass within their original bounds. The latter completes in
410.084/600 seconds. Two compiler lanes remain within the declared six-GiB
bound; separate PID namespaces are reported explicitly and their conservative
summed peak is 1,916,301,312 bytes. The final keeper expectation correction is
qualified separately from the recorded owning production input `d990046b5a`;
no new whole-build or normal-delivery timing is claimed.

The SDK audit preserves 443 actual previous definitions and adds four real v5
definitions. It also exposes the preexisting undefined
`qemu_plugin_crucible_advance_outcome_observe_v1` declaration, which remains an
actual missing producer rather than a counted export or accepting stub.
Packaged atomic reconstruction passes at
`frmq3zmnpr3b4ymczsgyblm5h5zal1qh`; the cumulative license ledger passes at
`drpshm98l1pddb3s4m1glqyqc3v1aaz6`. The packaged Source suite passes all 187
cases at `647ay4jjcn00h45wd1s63mhm6ssx957n`, and ABI conformance passes at
`pin5k79h3gbz10r0rhms2lllw1z6dx73`. Packaged Native custody passes 28
components, including the discard resize-member control that formerly timed
out, then fails at the actual `executor-cleanup-bridge` positive link. The
fixture's extracted `executor_cleanup_begin`/`executor_cleanup_end` now require
`qemu_crucible_source_executor_cleanup_enter_v1` and
`qemu_crucible_source_executor_cleanup_returned_v1`; its link supplies neither.
The failure occurs in 0.529 seconds under its unchanged 180-second and six-GiB
aggregate bound. No remaining-component or complete-suite pass is claimed.
The full failing derivation is
`xrym83aig29my6w8xnnf87qqpl54srj2-crucible-qemu-native-custody-unit-11.1.1`.
A correction must retain the fixture's factual-query scope and genuine
Source refusal without an accepting replacement for the missing owners.
Strict license-boundary qualification fails at controller Clippy
(909 library and 963 test errors); its canonical boundary assertions did not
run. Later stack-recipient and matched-member stages are excluded from this
cohort. Genuine Module/Core issuance, selected
activation, populated reader/RR execution, sequential borrower rearm and full
nonwaiting semantic terminal cleanup remain unqualified; CPU admission retains
`ENOTSUP`.

#### Stack page geometry parity

The Host stack carrier now rejects non-power-of-two page geometry before
encoding or accepting the description, matching the independently implemented
native decoder. A new control first failed at the exact page-three decode
assertion with all other fields and arithmetic valid. Its unchanged checks now
refuse independent literal and typed records for page sizes 3, 6,144 and 12,288.
All fourteen protocol targets pass 295 cases; strict all-target/all-feature
Clippy passes. The ABI stack group now registers six cases. Actual observed
page geometry, concrete profiles and nominal owners remain adoption requirements;
these syntax checks do not grant stack or Cleanup authority.
Mandatory application compilation passes at
`vqz1n80zdnm853h9v2jmrx0dfjnpfdq9`; all 5,332 committed Rust/TOML inputs match
its frozen source (proof SHA-256
`43e0e05ef23adce19e2f3e9d0df1f35a03e929dcf8fcf4ebb5e2dc3e14f14082`).
ABI conformance passes at `nvrh3nsnlr8yfdzhjs8ky62y6w41khqd`. Strict
license-boundary qualification stops at controller Clippy (909 library and 963
test errors); the canonical boundary assertions did not run.

#### Reserved Host Cleanup with separate actual entry

An actual current Quantum can now reserve one deferred Cleanup control holder
in a prepaid canonical output before guest Work effects. The same supervisor
retains the nonreused operation identity and accounts for that pending record
against its existing twelve-record inventory. Reservation allocates nothing
and enters no Cleanup interval. The holder retains the actual supervisor;
entry starts its one finite Cleanup interval later without querying Work,
including after the original Work record is physically retired. The existing
authenticated containing invocation still applies. Ordinary and reserved entry
share one focused policy/capacity/identity implementation. The root's reviewed
implementation shrinks from 1,824 to 1,708 lines; no size allowance increases.

The holder saves actual born operation custody before its independent post.
Negative and interrupted posts preserve the guard and cannot authorize Current,
repeat entry or restart time. An unentered holder returns only its unspent
record reservation on Drop; an entered guard retains ordinary borrower-aware
cancellation and physical debt semantics. Dropping the reservation cannot issue
a replacement for that same Work. The actual Shared and operation layouts feed
the existing structural recipes; the holder exposes its exact inline extent
for its containing owner's admission.

Eight component controls pass, covering zero allocation, real Work record
retirement and canceled outer cap before entry, full record saturation, wrong
class/occupied output/second assignment, a negative Work post, born-negative
Cleanup expiry followed by policy extension, real lock poisoning, interruption
between birth and post, and identity exhaustion. All Host resource targets
pass (333 reported cases), as does strict all-target/all-feature Clippy.
The first all-feature compile exposed a missing private bootstrap initializer;
that constructor was corrected before final qualification. The ABI gate
registers the exact eight controls. Hygiene and ABI conformance pass
(ABI output `2g9j17i6c2cbwcisi38kgjahhq6y0159`). Mandatory application
compilation passes at `hk5f1mkn4l307kxg1g5ngc16p471874w`; all 5,332 committed
Rust/TOML inputs match its frozen source (proof SHA-256
`a1eeab5c10df42cb2b9d5420c3551a788382f768a23b835108a09d0579bab79a`).
All 327 exact supervision cases pass across nine groups at
`wsnmr8wgrwgv8n7akgbnr6a4wb0snpb9`. The eight new deferred-entry controls are
registered separately in ABI conformance and are not added to that supervision
count. Strict license-boundary qualification stops at controller Clippy (909
library and 963 test errors); the canonical boundary assertions did not run.

A follow-up preserves the same actual first refusal when entry is requested
again after a negative reservation or born Cleanup post. Two strengthened
existing controls first fail with generic `Unavailable` replacing the actual
cancellation or Cleanup deadline cause; both pass after entry reports its
retained refusal before checking repeat-entry eligibility. The change enters
nothing, alters no clock or layout, and retains the same guard and reservation
custody. All eight deferred controls, 286 Host unit cases and 38 integration
cases pass; the unit suite retains its one existing ignored case. Strict
all-target/all-feature Clippy and focused formatting pass. Mandatory application
compilation passes at `1bljm3ns6wzafxigp2hpl391fr34f9cc`; all 5,332 committed
Rust/TOML inputs from `77e1fdcff6` match its immutable source (proof SHA-256
`9a2b39101d24fc3497f2cb1e1d15d97da5fd6c42a0c884d539fbf748e681ef02`).
ABI conformance passes at `jcnck0hrq1w71nm565ni0zf9psb3948h`. Strict
license-boundary qualification still stops at controller Clippy (909 library
and 963 test errors); the canonical boundary assertions did not run.

This is genuine local operation-record custody, not a native deferred-entry
contract, stack loan or Module/Core authority. Actual Source ownership,
endpoint-bound publication and independently current native entry/return
producers still require their separately versioned paired implementation.
The existing schema-two already-entered Cleanup profile is unchanged and does
not impose a hidden wall-time bound on otherwise unbounded Work.

#### Rejected Setup views cannot leave Module Source current

Both native Setup acquisition paths now share one completion boundary. A
successful Native scalar does not mark the Module keeper acquired until its
compulsory fixed view is validated and its plan and Setup borrow are retained.
Previously a rejected view left `acquired` true with no retained Setup, and a
later Source check could succeed by skipping the absent view. Native retains
all physical alias debt on rejection; this change neither closes aliases nor
permits another acquisition.

Two new causal controls first fail at the later Source check after actual
view rejection, for the base and publisher editions. Both pass after moving
the success marker, and also refuse observation slices, registration and a
repeated acquisition while every fixture-owned alias remains open. These
explicit status-table fixtures issue no native Source or operation authority.
All 1,187 plugin unit cases and four integration cases pass with every feature;
focused Rust and Nix formatting and engineering hygiene pass. The ABI gate
registers both regressions.
Strict plugin Clippy fails with 110 library errors outside the changed files;
no strict pass is claimed. Mandatory application compilation passes at
`mfi9rlfsg270kmb5xm6l3006l6mcxyhf`; all 5,332 committed Rust/TOML inputs from
`992f6f85da` match its frozen source (proof SHA-256
`0da080ebc6f1f71e1e2db89902ba6a526206b3ff4dc0a6a9c7c71302dc98467d`).
Strict license-boundary qualification stops at controller Clippy (909 library
and 963 test errors), before the canonical boundary assertions. ABI conformance
passes at `fc08xp9ziwy7nhimrbxg5gxkrm93sq98`, including both new rejection cases.

#### Explicit Main/RR stack carrier codecs

The separate pure stack namespace now encodes Setup8 (tag `0x18` with a
nonexhausted grant-set incarnation at full-frame offset 117), plan eleven
(`CRUCSU11`, 56-byte header), and the 576-byte `CRUCSTK1` section. Two fixed
256-byte Main/RR records retain original parent coordinates, distinct role
inventories, profile and cleanup observations. Checked page rounding, two real
RR guards, equal finite Main limits, zero RR limit fields, reserved bytes and
per-role/aggregate arithmetic must match exactly. The process, publisher,
setup and stack observations must agree; no earlier edition is a fallback.
The existing file cap remains 37,748,764 bytes, including the new header/tail.
Encoding allocates its final carrier once after exact extent validation; the
existing nested app/selectable allocations still require the caller's funding.

All fourteen protocol targets pass 294 cases and strict all-target/all-feature
Clippy passes. Eleven new controls cover independent literal bytes, every short
record/carrier, changed fixed and repeated coordinates, valid-but-foreign
parents, overflow, three page geometries, optional workspace, edition refusal
and real eight/nine-alias SCM_RIGHTS transfer with ordered kernel identities
and independent data flow. Refusal controls check malformed and other editions,
wrong roster counts and negative descriptors before peer bytes are available.
The ABI registration names and counts each focused group; the older nine
Quantum controls remain registered separately from the new stack child.
The initial strict check refused an unused import and the manual divisibility
predicate; both were corrected without lint suppression. Final expanded
transport controls pass. Mandatory application compilation passes at
`00r152p2sfc6v479vdnk70fgsp5p0x20`; all 5,329 committed Rust/TOML inputs match
the frozen source (proof SHA-256
`9130890e3c6f95f9faf5cc4c9032a78584df0bb88e01d5e368939b298e56195a`).
Hygiene and ABI conformance pass (ABI output
`5dbpjz6p8i70zg2qf26a9v9ml969wa4d`); strict boundary qualification stops at
controller Clippy (909 library and 963 test errors), before boundary assertions.

These are syntax and transport controls only. Unknown concrete profiles still
require refusal at actual adoption. No decoded inventory, profile digest,
RLIMIT value or copied account identity creates a nominal resource grant,
Main/RR thread, Cleanup operation or Source permission. The real once-only
native-prefix partition and authenticated recipient-specific transfer remain
open. Existing finite Cleanup does not cover otherwise unbounded Work; its
separately versioned deferred-entry producer also remains required.

#### Explicit physical exec Main stack control

The process contract now retains one optional finite Main stack selection in
its existing shared attempt binding. All duplicates observe the same once-only
choice, and the shared prelaunch latch excludes refinement and launch. Both
QEMU and image-helper child cuts install equal soft and hard RLIMIT_STACK before
exec, then independently read back the actual kernel limits even if installation
refused. Failure prevents exec. Existing contracts without a selection retain
their inherited policy. An earlier configured-process observation becomes stale
when the shared stack choice changes; equal numeric copies cannot replace it.
The actual binding layout prices its added scalar through the existing extent
recipe. The focused child uses safe fixed-storage syscall wrappers.

This is physical containment, not a stack resource issuer. The separate signed
public stack contract defines Setup8/plan eleven and real pre-entry Main/RR
subgrants, profile/TLS/control inventory and deferred Cleanup requirements.
The current control does not enable that profile, manufacture a grant or apply
an implicit Work wall-time bound. Actual retained backing and paired nominal
stack issuance remain required before activation.

Four controls cover real duplicated contracts, invalid/repeated selection,
refinement/launch exclusion, stale process observations, and an actual spawned
child reading both installed limits after exec while the parent stays unchanged.
All four focused controls pass. Running the child assertion directly without
the guarded installation refuses at the intended inherited-limit mismatch
(exit 101), so an unconfigured exec cannot satisfy the positive control.
The ABI gate registers the exact count and canonical child-probe name.
Hygiene passes; all-target, all-feature QEMU Host compilation also passes for
the signed `19d2851e02` checkpoint. Mandatory application compilation passes
at `hq7arfj2qcj8rf800z24jjm744pgvqj4`; all 5,325 committed Rust/TOML inputs match
the frozen source (proof SHA-256
`0ecebe055caa6e6ec99e05177b1749dab5d6467be184ed418632671bf8ca65da`).
ABI conformance passes at `d33s40wyhlzi1zm716cd059hppgih7dl`. Strict boundary
qualification stops at controller Clippy (909 library and 963 test errors);
its boundary assertions did not execute.

#### Rechecking stack selection during envelope refinement

Memory and descriptor refinements now share the same locked comparison of all
mutable envelope fields, including the optional Main stack selection. A
selection through another actual contract duplicate between the initial
identity cut and latch acquisition makes the old snapshot stale; refinement
refuses before a cgroup write or descriptor assignment. Refusal preserves the
selected stack limit and leaves the unchanged envelope available to an actual
current snapshot. This adds no storage, backing credit or stack authority.

Two deterministic controls exercise that interleaving through the real shared
binding, with no timing sleeps or fabricated configured process witness. The
memory control checks the exact locked predicate before the kernel write; the
descriptor control invokes the actual mutation path and verifies that the old
snapshot cannot change NOFILE. Both controls fail at their intended assertions
with the old comparison and pass after the fix. All 17 process-envelope tests
pass; every all-feature Host test target compiles. All 14 Host integration
targets execute separately with 131 passing cases and no failures or ignored
cases. The required application
build passes at
`/nix/store/kzmxy8dmn223wp7lyxwk38qswbqq0hwq-aos-test-targets-0.1.0`,
and engineering hygiene passes at
`/nix/store/zcvijji792yblcv5r97p578pnwrl3izi-crucible-phase1-engineering-hygiene-0`.
All 5,332 committed Rust/TOML files at
`e0822869d4fa1319db1dcb107aca1a1d35fcc1dd` match the application
build source with zero mismatches. The comparison record SHA-256 is
`0c8a79fc9e6ced3bdfc7e36cf72d619d312262c90e8aee765ace379acbe48ace`.
ABI conformance, including both new interleaving controls, passes at
`/nix/store/7xq7jbq067bsppqk7ipvq1fc3s33fcjn-crucible-phase2-abi-conformance-0`.

The broader all-feature Host run reports 1,368 passing tests, ten failures and
four ignored tests. Nine failures are in guarded helper/custody paths; the
endpoint worker disposition mismatch test fails with a Setup deadline expiry.
Those failures remain retained and unresolved; the focused results do not
establish a passing full Host suite. Strict license qualification again stops
at controller Clippy (909 library and 963 test errors), before its boundary
assertions execute.

#### Preserving the physical Main stack policy in fork Targets

The retained Target binding now validates its existing family geometry, copies
the actual frozen Source's optional Main stack selection into its fresh
contract, and verifies the refreshed envelope before retaining it. Subsequent
Target envelope checks require the same selected stack policy. The physical
copy refuses stale or unlaunched Source observations, the same process binding,
started Targets and a previously selected Target policy. An unselected Source
preserves the existing inherited policy. Verification after binding uses the
saved family facts and does not query an ended Source operation.

This adds no fields, backing allocation or process/stack grant. Identity and
capacity failures use a small fixed cause; actual Target physical custody stays
in its existing containing owner, including after a failed bind. The already
retained host takes its existing quarantine path on refusal.

Four component controls exercise real shared contract selection, duplicates,
stale observations, already selected or started Targets, same-process refusal
and the unselected policy. They cannot issue a configured cgroup or process
purpose. The first three controls fail against the extracted prior no-op copy.
All 21 process-envelope controls and the four existing Main stack controls pass,
including the actual child soft/hard limit readback with an unchanged parent.
Every all-feature Host target compiles and engineering hygiene passes. The ABI
gate requires the four-case fork-stack set and its canonical inheritance case.
Mandatory application compilation passes at
`j212xqx0icb6ny6xaybmph6npm1svnpd`; all 5,332 committed Rust/TOML inputs
match its frozen source (proof SHA-256
`d4f32253ebba27d67c7ef156a912ff57a3ad999a4a91c1180b4f907f8a15b7df`).
ABI conformance passes at `hss3in2yzj8qb0x1yr3smimyg56la8gd`.
The strict license-boundary gate refuses
at 908 Host library and 962 test Clippy errors; its boundary assertions did
not run. This physical control does not qualify Native stack/profile admission
or a complete launched Source/Target family.

#### Sticky terminal decisions from actual lender collection

The collector now saves the actual typed operation disposition under the same
lender lock and at the same observation cut as its parent snapshot, before any
publisher callback can refuse. Both full-cohort and selected-role collection
retain observed expiry in the genuine operation record. Later budget extensions
cannot reopen that operation. The observation helper returns the typed decision
beside the wire projection; no decoded state byte becomes lender authority.
The fixed prebirth scratch recipe prices this complete returned pair.

Two causal controls first reproduced the defect independently: an authored
Cleanup bound already elapsed from its real original entry, collection observed
Expired, and a subsequent budget extension exposed Running again. Both failed
at that exact terminal-state assertion. Their unchanged controls now pass for
the full cohort and selected Cleanup. They use no synthetic clock, sleep or
intervening operation-status poll; original start and progress coordinates stay
unchanged. Every Host resource target passes (324 reported cases), as does
strict all-target, all-feature Clippy. The canonical ABI registration includes
both regressions, bringing the selected collector group to eight plus the
separate unsupported-publisher refusal. Mandatory application compilation
passes at `d9jbf03n9xb1acxmnnyfr3vm61nzsl3p`; all 5,323 committed Rust/TOML files
match its frozen source (proof SHA-256
`2171e990070c398ab14d59108c7ae87f48ad4ae1b498d560d39fcf76af199f95`).
ABI passes at `pvrpl4w09kqz4gnlswm9yp24gc4lz91x`, and hygiene passes.
Exact supervision passes at `nhic2kysj720rn4qbchwsnyd47al4zsz`. The strict license-boundary gate again
refuses at 909 Host library and 963 test Clippy errors; its boundary assertions
did not run.

This fixes actual Host lender state and does not create a Source or Native
owner. Complete paired publication, deferred independent Cleanup entry for
unbounded Work, actual execution-stack lenders and physical closure remain open.

#### Independent Host Quantum-role collection

The action collector now selects either the complete cohort or one actual
Quantum role. Work retains row zero; independently entered Cleanup retains
row one. Only that primary's registered Preparation dependency participates.
The selection validates real intrusive operation and outer memberships and the
same funded publisher allocation under all selected lender locks. Outer and
operation memberships must also retain the same publisher. Other rows remain
zero. Shared supervisors and shared Preparation dependencies retain their
original identities and use one ordered lock per actual owner.

Cleanup collection selects no Work loan and does not query the Work operation.
It enters no operation, grants no permission, renews no clock and returns no
physical debt. A separate callback receives the selected current facts while
those locks remain held; existing publishers refuse this callback by default.
The fixed collection recipe additionally prices the forwarding selector and
both reference rosters before Source birth. A separate behavior-preserving
commit first moved the original full collector without changing its body.

All Host resource targets pass 320 reported cases, including six new collector
controls and the explicit unsupported-publisher refusal. Strict all-target,
all-feature Host resource Clippy passes. The contention control holds both
ended Work locks in another thread while Cleanup completes; callback controls
check every selected state and outer lock. Separate, shared and absent
Preparation layouts, missing/extra/returned/foreign rows, mismatched outer
publishers and wrong actual classes are covered. These are component-funded
mechanism fixtures with real entered Host operations and directly seeded
memberships; they create no authenticated Source purpose or Native borrower.
The ABI gate registers the seven controls with exact counts and canonical
names. Every QEMU Host target compiles with all features. Required application
compilation passes at `r6w0ws0sbbsvj7yy608y5q380s5lmwa9`, and the registered ABI
gate passes at `xiif841kf3y0vm01a9adnkf5brm38q74`. The strict license-boundary
check refuses; its boundary assertions did not run. The corrected hygiene
check passes. The first hygiene evaluation
correctly refused the stale review digest for the parent module's changed
reexport; its unchanged 1,824-line responsibility and focused child boundary
were reviewed and the exact digest refreshed, without adding a waiver.

The active Source publisher does not yet implement the new callback. Actual
paired Source publication, independently retained Cleanup ownership, Native
role issuance and complete physical return remain open.

#### Explicit Quantum transport and plan negotiation

The separate Quantum namespace now encodes and decodes Setup7, Purpose2 and
plan ten. The exact tuple is tag `0x17`, mapping `CRUCPLM2`/schema two, sealed
`CRUCPSP2`/schema two/224 bytes and `CRUCSU10`/schema ten/48-byte header.
Purpose2 explicitly selects role-map edition one, Quantum-only variant one
and terminal contract one. Its physical storage cleanup generation remains one
and is independent of the publication's actual Cleanup loan and entry identity.

The shared body parser selects an exact outer and nested purpose edition
before interpreting sections. Original Startup, process, workspace and family
relationships retain their validators. Plan ten keeps the existing aggregate
cap and body ordering. Earlier carriers continue requiring their original
magic, schema and reserved zero bytes; there is no fallback to them. The new
observational correspondence check compares every shared lender, Source,
file and event identity across the decoded tuple. Actual sealed-file,
endpoint, mapping and nominal-lender authentication remain the constructors'
responsibility.

The separate Setup7 sender transfers the exact eight or nine borrowed aliases.
Real Unix socket controls verify received alias order, kernel identities and
independent data flow with and without a workspace. Wrong counts, negative
descriptors, malformed and mixed-edition frames refuse before any peer byte.
All fourteen protocol targets pass 283 cases and strict protocol Clippy passes.
Existing Setup6 controls still run unchanged in name and cover the same route;
their shared test helpers also exercise the new route. Three negotiation,
three plan and two new socket controls extend the prior six Quantum controls.
The canonical ABI gate now requires and runs these fourteen cases in three
explicit groups, checking registration count and canonical names before each
execution. Engineering hygiene and Nix formatting pass. Mandatory application compilation
passes at `hb96w9g6bydxay4dislq5rw7j4kmfpl4`; all 5,321 Rust/TOML files from
committed `d5363733cab74102bc14996d07a000f04ac2c12a` match its frozen source
with zero differences. The comparison record SHA-256 is
`13a2040253f7c01d595d774293e5f3d71ea71f2d581af9f8f5b37aa90655c49e`.
The canonical ABI gate passes at `pzfhrbz3fzpp1iak48wvp27gln82rgnr`, executing
the fourteen newly registered controls. The canonical license-boundary gate
still stops at 909 Host-library and 963 Host-test strict Clippy errors; its
boundary assertions did not run.

These public codecs and the sender do not select the live launch route, install
a recipient or enter Cleanup. Genuine producer/recipient construction, complete
execution-stack and Core admission, independent role Current and final physical
closure remain open. The active Setup6/plan-nine selection is unchanged.

#### Separate schema-two Quantum and Cleanup codecs

The permissive protocol crate now has a separate `publisher_subscription::quantum`
namespace for the proposed paired Work and Cleanup publication. Its header uses
`CRUCPLM2` and schema two. Schema-one and schema-two headers, publications and
return records refuse each other's bytes; active Setup negotiation still selects
schema one. No publisher, recipient, Source admission or operation is created
by these codecs.

The immutable role map requires two distinct primary operation identities:
Quantum class one and independently finite Cleanup class thirteen, with their
exact Preparation dependency masks. Only the two independent permission words
may change monotonically under the same command. Cleanup loan and entered
interval incarnations, original clocks, role map and command remain unchanged.
Return and consumption records retain separate role masks, exact loan/entry
and receiver-journal correlation, partial debt and negative first/post facts.
Their validation creates no physical-return or final ticket-transition proof.

All fourteen protocol test targets pass 275 cases, including six new syntax
controls with independent literal bytes, every truncation, reserved padding,
legacy refusal, two/no/shared Preparation layouts, immutable permission updates
and partial consumed-negative journals. Strict protocol Clippy passes without
exemptions. The first lint run found a single-match test expression, corrected
to `if let`. An added legacy-refusal fixture initially used an invalid two-primary
schema-one cohort; its corrected genuine schema-one fixture passes. Both failed
attempts remain separately retained. Engineering hygiene passes. Mandatory
application compilation passes at `nyw4b2z1289ppx2kq7p5grgpy1h5swzk`; all
5,317 Rust/TOML files from committed `a7f3c2fdb792f953438e22d2a3ad6fda7c451460`
match its frozen source with zero differences. The comparison record SHA-256
is `ee7c7a257b508ee473af50be89c9c3414c59b32bca125eab4886a597e8cc82e0`.
The initial ABI build passes at `8jcflvbv4d8v067sk8hpph5kd0ifg2zb` but only
compiles these new controls. The subsequent explicitly registered six-case
build passes at `2dpp04xj8ifhm2qgv5g1cni6lisfcyhb`, executing all six. The
canonical license-boundary build still fails at the existing 909 Host-library and 963 Host-test Clippy
errors, before boundary assertions run.
Actual independently entered Cleanup lending, complete resource admission,
paired Native role projections and terminal closure remain implementation gaps.

#### Borrowed app-random service identity

The live app-random service now owns its immutable node name independently of
its mutable decision state. Each callback borrows that same name while serving
the request. It no longer clones a temporary String before decoding, and the
preallocated logical-restore decision source no longer owns another copy.
Logical restore replaces only the mutable draw state; the service identity
retains the same allocation. Request/evidence objects and stream creation still
allocate and require complete operational funding.

All 1,177 plugin unit tests, compilation of every plugin target and engineering
hygiene pass. Existing draw, reseed, branch, continuation and live routing
controls retain their behavior; no case or binding is added. The actual layout
control now measures the containing Runtime at 18,912 bytes, alignment eight,
and inline white-box state at 9,528 bytes, each 24 bytes smaller. This is a
specific ownership/layout change, not a physical-residency or performance
qualification. Required application test-target compilation passes at
`6ijsfqijpb6k7kprbda5z36gbnwgkvza`. All 5,314 Rust/TOML files from committed
`00b0b274f17c17fc8b10de392412fca185e58ff5` match its frozen source with zero
differences; the comparison record SHA-256 is
`e1f70aa65982cd35e40d635e847d8e20ad7b475cbcbf2687414f38e5cd36ab91`.

#### Retained Native RR actor and sticky pre-exec refusal

Atomic signed DCO checkpoint `5b7be4763f681e1e0237b61b24708654a510225f`
imports conventional signed union `137ce45cb65e3ef5b5ae5c295f350d403c6171cf`.
Its tree `a152cc6c0a224af19762436e7432ea86636f9225` is byte-identical to
executed actor `d37691e8f1ade403e02515431441234f1910ba6f` and retains
`af148f6de3`, corrected `c441384d5c` and their complete source histories.
Independent review matches all 27 changed signed/working sources, 10,293 regular
actor evidence files, six literal links and seven artifacts. The comparison
record SHA-256 is
`6f49fa142673e7774bc294c7f38412a1eca1c9e46726ae07521f50af5d076708`.
The composed seal independently matches 32 local evidence files, four artifacts,
all 78,215 archived Git blobs, exact regular Git modes and 72 literal source
links. Its comparison record SHA-256 is
`3b9d6120e38618d9d635829e34186a7c3d98fb9cad37047c6b6094247fc53685`.

The Source actor retains the actual constructor, producing borrower, deferred
child, Original, Advance, Main-finish and terminal parent. It publishes its
canonical relationship before Native/Module entry, captures born outputs before
independent posts and retains consumed-negative or uncertain cleanup history.
Normal, longjmp and atomic physical unwind withdraw work Use before return.
The external terminal observer retains consumption independently of the retired
CPU/QOM object. No CPU or executor frame is read after physical QOM return.
Untouched-constructor closure requires all real fields and callback histories
to be empty; contradictory held outputs refuse. Corrected pre-exec RR access
also preserves its first failure across reinitialization, independently queries
Source first/post and records actual access-return facts without restoring a
consumed holder.

Actual Source is 253,240 bytes and 31 genuine getter extents sum to 44,750,
for a complete fixed floor of 297,990 bytes. The Source actor is 4,680 bytes,
its tail registration 120, the separately priced Native actor 408 and CPU
allocation header 888. CPUState 16,992, Core 160 and keeper 72 remain unchanged.
The cumulative license inventory contains 408 created files, including eleven
new paths and no deletions in this cut. The publisher RR documentation has an
explicit GPL-2.0-or-later marker; the actor design note uses QEMU's default.
The immutable handoff's contrary sentence is corrected by a separate preserved
note, SHA-256
`3bb3209981202933168de76ca892ba4eb4347d720ede70e9913b2cce60b8f8e3`;
the correct inventory and original seal are unchanged.

The authenticated corrected 987-object cohort passes in 391.116 seconds under
its declared 600-second outer bound, two-compiler and six-GiB address-space/tree
bounds. Later four-object semantic and two-object EOF deltas pass separately in
12.483 and 11.663 seconds; they are not relabeled as another full-cohort run.
Seventeen owning links, Source-layout and isolated preinit units, 47 physical
omissions, 40 unentered-edge and fifteen callback-history controls pass.
Twelve actual ordinary keeper cases pass in 37.312 seconds and two complete-
provider no-entry reciprocal controls pass in 8.458 seconds. Earlier compile,
link, provider, omission and reconstruction failures remain separately retained.
The isolated preinit guard does not qualify actual RR entry; that refusal uses
the genuine complete provider. No compilation or timing is attributed to the
byte-identical history merge itself.

The packaged license ledger passes at `lflmw9310swbwsz6080rp9y1d0fxx3wv`.
Raw signed reconstruction passes at `vlvcadq3w85mji9k8zxyn7n71xnjf8qq`.
The registered Source unit passes all 187 cases at
`x0bx00wnmwwi5mm8nn9r355h9zv1vyvz`. ABI conformance passes at
`95098lm92rr9q77dl89ylq7rq8hgcdnh`. The Native suite fails when the
`memory-discard-custody/resize-member-limit` omission child exceeds its unchanged
30-second bound; its containing component records 36.222 seconds and 224,358,400
peak aggregate address-space bytes. This is an investigation, not a passing
36-component qualification. The canonical license-boundary check still stops
at strict Host Clippy: 909 library and 963 test errors; boundary assertions did
not run. Actor birth remains unwired and CPU admission returns ENOTSUP.
Actual Module/Core operation issuance, full semantic RR execution, complete
return/rearm and nonwaiting terminal cleanup remain unqualified. Source and
Native blocking synchronization is an explicit remaining gap; a prepared Module
guard alone does not establish a nonwaiting route.

#### Typed actual guest-write failures

The live callback and resumed per-vCPU writers retain coordinate mismatches and
Native write refusals as typed fields. Their failure paths no longer allocate
formatted Strings. Each writer retains only the actual QEMU write function it
uses. Validation, reply consumption, guest-write ordering and complete rendered
diagnostics remain unchanged. The public guest-write error is a non-exhaustive
enum; its reporting-only `message` method now returns `Cow<str>`, borrowing
original backend diagnostics and formatting typed causes only on that explicit
call. This coordinated Rust API change does not alter either process ABI.

The existing reply-failure control still requires the original custom backend
buffer through its source chain. It additionally exercises both actual writer
implementations: coordinate mismatches make no Native call, and a refused
per-vCPU call retains the exact vCPU, address, original workspace pointer,
reservation length and resume count. The consumed ring entry remains consumed
while the pending catalog request and completion count remain unchanged.
All 1,177 plugin tests and compilation of every plugin target pass. The final
fifteen adapter controls pass after the test helpers' readability adjustment.
The 1,120-line test module has a content-bound responsibility review. The
containing Runtime remains 18,936 bytes, alignment eight, with 9,552 inline
white-box bytes. Engineering hygiene passes. Required packaged compilation passes at
`26wdprd9b4prqwnhp4pmj67vjyiyipf5`. All 5,314 committed Rust/TOML inputs at
`d2eee05595cf21362d375ef313218013cc13c6c7` match immutable source
`989f8vz8pjbw71lqf2xllxdcqfrwspxz`, with comparison record SHA-256
`436b1a42a6a0102706948dabae9b46520b614e7f4a828fc2d616c06c61282145`.
ABI conformance passes at `8ym8sksxrcvg794g3m7fqsr09q3znjqm`.
The fresh exact supervision check passes all 327 cases in nine actual groups at
`359ch72b5a47ng86h66ias1vf8l8bp45`.
No case name, binding or policy exception changes. Remaining dynamic
payloads and complete operation/resource funding remain open.

#### Typed selectable service failures

The live and combined catalog services retain their original catalog and
pending-transport errors through the standard error-source chain. An occupied
VMStop handoff and rejected translated-block exit retain fixed variants and
the original QEMU status. Both eager catalog-formatting adapters are removed.
The rendered service diagnostics and validation, request-retention and handoff
ordering are unchanged.

The Rust service error is now a non-exhaustive typed enum. Its `new` constructor
still retains the authority's original String. The reporting-only `message`
method returns `Cow<str>`: authority diagnostics remain borrowed, while typed
causes are formatted only on that explicit call. Normal Display writes directly
to the caller's formatter. This is a coordinated Rust API change; neither the
process protocol nor the shared-memory ABI changes.

Existing controls require the concrete original transport error through the
source chain, exact handoff variants/status and unchanged complete diagnostics.
The combined-service control requires the original catalog cause after actual
request completion, unchanged dynamic identifier storage through conversion,
and the original authority diagnostic buffer through `new` and `message`.
All 1,177 plugin tests and compilation of every plugin target pass. The expanded
1,016-line adapter test file has a content-bound responsibility review; the
production catalog shrinks to 1,311 implementation lines. The first hygiene run
correctly refused the missing test-file review. The corrected check passes.
Required application compilation passes at `9spq6h5a233ddh6q208gh7iyc4124f40`.
All 5,313 committed Rust/TOML inputs at
`3d18b5cb87e1d1143a8838b4f5c4f27ed0349160` match immutable source
`b77b1fxr3r93sjxp77pnxjaxzwvr1q61`, with comparison record SHA-256
`41a54d89adeb1f31e95284dc922fed87e9bd6f2b33a6c2fc5b2adf7b8cebf11e`.
ABI conformance passes at `yx01d33c46l6j6jh8dy13nbyl0491m2y`.
The fresh exact supervision check passes at `0d0wgdbgcasxjpsq1n9rbzv7f6fh5ijf`;
independent inspection confirms all nine groups and 327 cases.
The final fifteen adapter controls pass,
and the actual containing Runtime remains 18,936 bytes, alignment eight, with
9,552 inline white-box bytes. No case name or binding changes. Original
backend/catalog dynamic payloads and complete operational funding remain open.

#### Typed selectable callback and publication failures

Trap preparation and service, catalog freeze/rebind, pending projection and all
three catalog-delta publications now retain their concrete original errors.
They no longer format another String in the live adapter. Missing pending state,
reset-held restore and handoff overflow are fixed variants; a drift refusal
retains the original, actual and required retirement/tick coordinates. Display
preserves the original diagnostics and formats these fields only at reporting.
The generic selectable callback formatter is removed.

Existing controls require all six handoff coordinates and its exact diagnostic.
The live ring control additionally fills the real queue, requires the concrete
marker refusal through the error-source chain and verifies that the original
queued registration, coordinate and bytes remain intact. Missing-token controls
require their exact typed refusals. All 1,177 plugin unit tests, every plugin
target and engineering hygiene pass. The existing actual-layout control measures
the containing Runtime at 18,936 bytes with alignment eight and its inline
white-box state at 9,552 bytes. Required packaged compilation passes at
`b60cbfavhxm2krlanlmscaqhd1006ais`. All 5,313 committed Rust/TOML files at
`7b43dc43ced5b970cb128a2e6e3087623e44f504` match immutable source
`nch5aq9n42p0xh76xszqxcxhk4px0v9h`, with comparison record SHA-256
`d3ce65a32dc59c80d37e158f426875375a03d86c499dd757461c3e163bba3335`.
ABI conformance passes at `77wafcqjalp9mw5v6ccqmfcybkqjmw6y`.
The fresh exact supervision check passes at `3vq80dqrjq33l51nrxd5paa12fl9gj8y`.
Independent inspection of its actual inventory confirms nine groups and all
327 cases. No test case name, binding or policy exception is added. Backend/service-created dynamic
payloads and full operational funding remain open; this does not admit CPU work.

#### Borrowed pending transport

Deferred-profile validation and live pending publication now borrow the retained
request through `SelectablePendingTransportView`. Neither step clones its
identifier, domain or tag merely to check length or encode the ring entry.
The owned transport delegates to the same immutable view and encoder. The
existing 4,608-byte Runtime workspace still holds the canonical encoded prefix;
wire fields, complete zero-filled reply reservation and suffix behavior are
unchanged. Initial catalog admission and decoded messages still allocate and
require complete funding; this view grants no execution authority.

All three existing transport controls pass. They check borrowed request identity,
owned/borrowed byte equality, the maximum message, oversized refusal and an
unchanged caller buffer after validation or capacity failure. The existing live
catalog/ring control also requires the transport to borrow the actual retained
catalog request. All 1,177 plugin unit tests, compilation of every protocol/plugin
target and engineering hygiene pass. Mandatory application compilation passes
at `ypga59sr49h0niaw5ync41mwcv7mx6zq`. All 5,313 committed Rust/TOML files at
`a960a98b7c9f3246a232e16a990aae3a5030c9b9` match immutable source
`afp0zxpiiy1bjyjl05bm94p0plg0ld7x`, with comparison record SHA-256
`c433ca0ce871ffcba86d18b432fca4588d662b416962014a404ff53b7f908047`.
ABI conformance passes at `q8a0i5mmvs05s6fvl1dma3x70q71z4qr`.
No case name or binding is added.

#### Typed selectable reply failures

The actual reply consumer and resumed delivery path now move typed ring,
envelope and protocol refusals into the existing live error. Unexpected kind,
coordinate mismatch, early resume, sequence mismatch, reservation bounds and
peek/consume failures retain fixed fields instead of allocating formatted
Strings. A guest-write refusal retains its original typed backend cause plus
trap/resume coordinates; the existing bounded diagnostic writer formats them
only when reporting the failure. The rendered diagnostics and consume/write
ordering remain unchanged.

All 1,177 plugin unit tests pass. Existing controls now require exact typed
unexpected-kind, unsolicited, early-resume and malformed-protocol refusals.
The write-failure control requires its exact original full diagnostic, concrete
trap/resume fields and the same original backend diagnostic-buffer address
through the standard error-source chain. No new case name or binding is added.
Compilation of all plugin targets and engineering hygiene pass. Mandatory
application compilation passes at `4jizwdf0gwamjxg59ncacrnmpz6s5h2b`.
All 5,313 committed Rust/TOML files at
`c4b0e52be4016d2fe2f90173f9a6aef077a0739c` match immutable source
`fc8sn62ra322kp3nldab6q65z2jdbq6p`, with comparison record SHA-256
`5c60a93450ab8558f900178b3dbe663a9c691c64d49113766b2e39dbfce78c36`.
ABI conformance passes at `h2qgnpc33w5jkm4wz165ir8k4f0ncpmw`.
The fresh strict license check still stops before its boundary assertions with
909 host-library and 963 host-test Clippy errors. The fresh exact supervision
check passes at `d6ayhy4r1303czmxjhhswq0cqd7mqwwf`. Independent inspection of
its actual inventory confirms all nine groups and 327 cases. Backend-created
dynamic diagnostics, decoded payloads and remaining catalog service errors
still need complete funding; this is not an allocation-free execution or
Source-admission qualification.

#### Borrowed selectable resolution

The decision service and actual resumed guest-reply path now borrow the same
catalog-owned pending token through resolution and delivery. They no longer
clone its request strings, domain/tag vectors and declaration merely to clear
the token after a reply. The exclusive catalog borrow prevents replacement
during the resolver; Pending, callback refusal, wrong sequence and unwind keep
the original token in place. Existing public token completion still checks the
catalog incarnation and exact token. Repeated completions update the existing
counter entry without allocating another identifier String.

The existing retained-request control checks actual request/declaration addresses
inside resolution, Pending and negative dispositions, unwind, wrong-sequence
refusal and stable counter-key storage across two completions. The actual
combined-service control also requires its resolver to borrow the retained
request address. All 1,177 plugin tests and compilation of every plugin test
target pass. The first focused run passed 48 controls and failed the original
unsolicited-reply diagnostic check; retaining its exact text as a typed static
refusal corrects that regression. No assertion is removed or renamed.

Decoded messages, initial counter-map insertion, admission-time pending copies
and remaining diagnostic payloads still allocate. This removes repeated copies;
it does not qualify complete funding, a Core Quantum issuer or CPU admission.
Engineering hygiene and mandatory application compilation against the final
committed source pass, the latter at `wc21r06rqxsal59vh8kcrxni047zpc7g`.
All 5,313 Rust/TOML files at
`b077245bdba7c982707dcd73f1b1115fbee1bb8c` match immutable source
`66djsciyjq6gkig2d1b3ri7kv8jfiadq`, with comparison record SHA-256
`07e2ce704ca9046042eacfe43ed74067d0f10b9893a0e0cc8f4c81810597b4e4`.
An earlier compilation passes against `06nq3g8qwd5yiyrgc8sm346f9v5clr1y`,
but that precedes the final catalog whitespace/digest refresh and does not
replace the committed-source check. The initial hygiene invocation refused a stale 1,314-line digest/count record;
the final refreshed 1,315-line record passes. No source-policy exception
or test binding is added.

#### Selectable catalog deltas in the retained workspace

Registration, request and pending-transport encoding now accept caller-owned
storage with validation and capacity checks before every write. The canonical
prefix is overwritten, including the request's full zero-filled reservation;
the remaining suffix is preserved. Owned encoders allocate their final extent
once and delegate to the same writer. Pending-record construction validates
length without serializing the request. Request range validation borrows a
fixed array instead of allocating a temporary range Vec.

The actual live registration, pending and completed ring publications borrow
the containing Runtime's existing 4,608-byte reply workspace after its previous
synchronous use finishes. They create no new output or nested-request Vec.
The ring still copies only the exact canonical prefix into its existing entry;
coordinates, kinds, reservation bounds and compatibility editions are unchanged.
Decoded fields, catalog allocations and error payloads still need complete real
funding; these buffer cuts do not create a Quantum Original or CPU admission.

All 22 selected protocol controls and all 1,177 plugin unit tests pass. Existing
frozen registration/request vectors remain exact. Nonzero caller buffers cover
suffix preservation, complete zero padding, insufficient capacity, invalid
messages and the maximum 4,608-byte transport. The existing live-catalog control
also publishes each of the three real delta kinds through an actual SPSC ring,
checking its exact coordinate and bytes against the canonical owned encoder.
Engineering hygiene and compilation of all protocol/plugin test targets pass.
All 73 focused source-policy controls pass. Mandatory application compilation
passes at `bml9j24nc1jgkya364678pv6lk04a47f`. All 5,313 committed Rust/TOML
files at `f765fe354e1ce5c2e2e23ba210d65b32e57d4086` match immutable source
`qsxggcjh567dgaw25nakp115kbxp9cia`, with comparison record SHA-256
`1dd54536105d789fb29ea0d92032d316e4a8895f6f909f046c06696693cfbc76`.
ABI conformance passes at `d9dcfc7i0h6a2jczh9znkldxjg6fyps2`.
All 327 exact supervision cases in nine groups pass at
`wp33x0dzka9d65dsh6l5db9l0yx19wcf`. The fresh strict license check
fails before its boundary assertions with 909 host-library and 963 host-test
Clippy errors. No test binding is added.

#### Typed debugger-custody poison refusal

The actual retained-debugger cleanup path now returns the existing typed
`ProductionVmConstructionCleanupError::Poisoned` directly when its custody
mutex is poisoned. It no longer allocates a boundary-message String while
refusing cleanup. The original retained body remains in the same slot and the
same typed, file-owning first causes remain reachable. The existing poison
control now requires that exact error alongside its original descriptor,
identity and ownership checks. The existing closed source contract follows the
actual helper and exact assertion; it gains no classifier exception.

All six actual retained-debugger controls and engineering hygiene pass.
Mandatory application compilation passes at `p0kq5g267rps5i3aazcja58ya263y2kh`;
all 5,313 committed Rust/TOML files at
`ae3aab1ae41f604cea5b6fc76906091e2fc5058c` match immutable source
`n1p5sxrf6967wsbmihnxwf3xzc11bs40`, with comparison record SHA-256
`a26a6912bc39cf54936936bced22a0ab4227043b765396732fadf821b6baf539`.
The first focused policy run passed 72 controls and failed the old mutation
inventory's expectation of five generic refusal assertions. That inventory now
mutates each of the four generic and one exact typed-poison assertions
independently. All 73 focused controls pass after that correction; the initial
failure remains separate from the corrected run.

A fresh broad source-policy run reports twenty paths: thirteen daemon and
seven host/plugin paths. The additional findings include negative-control
function names containing `retry`; the scanner treats underscores as word
separators. This remains a failing check. No test rename, source mask or new
waiver is used to remove a finding. Complete producer funding, Source activation
and physical-return qualification remain open.

#### Exact configured-input recovery

The prior configured build's link chain ended at a removed build directory.
A separate immutable af148 snapshot recovers the actual generated inputs without
editing shared links or the previous seal. All 5,541 original GCC dependency
rows match; the retained 3,388 compile commands are rebased only to the recovered
source/build coordinates. The fresh 3,456-entry Meson inventory is recorded
separately. No owning object, provider or execution result is supplied by this
recovery.

Independent review matches 116,786 regular files, 228 literal links, sixteen
manifest records and all 5,541 dependency rows with zero differences. Its record
SHA-256 is `a5a2d785af38371253e2308020ab660338cf3b49a2f4d21925494e02fadcdc60`;
the sealed recovery manifest SHA-256 is
`7866c2f4356d4508695f2b9c88fd11a939a2a40d61d1a18324f7205e8452845f`.
Configure and generator recovery pass in 29.451/600 and 23.100/600 seconds, with
core dumps disabled, 6-GiB per-process and aggregate virtual-memory bounds and
one compiler lane. Fourteen initially different decoder outputs remain retained;
the exact original generator commands with `PYTHONHASHSEED=0` reproduce their
sealed bytes in 2.732 seconds. These are recovered inputs, not new compilation
or semantic qualification. Later owning changes retain their own build identity.

#### Permanent Core keeper and registration composition

The signed atomic union `3711dfbb6f9b4df98793dca52199ae312a61a705` imports
conventional `af148f6de3561596ec5a9d778e00843536077279`, exact tree
`1296e452a841d67ca778ed793eb27bc44d3f0f0f`. It joins the registration union
with the real permanent Core keeper. Transfer retargets the actual frame and
execution holders before independent posts. The keeper retains uncertain debt
and actual reference consumption; ordinary reuse requires completed physical
return. Caller-stack coordinates remain borrowed, and no CPU is read after
QOM unref. The public SDK, CPU admission refusal and sticky one-attempt
borrower guard remain unchanged.

Actual complete getter measurement is Source 248,440 plus 44,342 bytes from
30 separate providers: fixed floor 292,782. Core storage is frame 88 plus
keeper 72, totaling 160 bytes. Native frame/registry remain 288/10,856;
CPUState/ARMCPU/X86CPU remain 16,992/97,712/33,568. The sole new file versus
the registration union is the GPL-2.0-or-later keeper test; the cumulative
license ledger now contains 397 created files and no deleted file in this cut.

The fresh 656-object affected cohort passes in 331.095/600 seconds with two
compiler workers, core dumps disabled, per-process address space 6 GiB and
sampled aggregate virtual size bounded by 6 GiB. Its actual start is signed
`230cb9e5f2e460cbc1d94b817b5a8f8edcc96791`, with fixture-only completion
identity `f95279b14d55e1861b3446980116281d022b6b41`. All 5,541 dependency
inputs and 97 regenerated C/header inputs match the final signed candidate;
this does not relabel the executed build as starting on that later commit.
Peak process-tree virtual size is 1,825,333,248 bytes. Seventeen genuine links,
both system binaries, 104 actual provider resolutions and existing SDK exports
pass. Fresh Meson queries authenticate 280 paths among 281 inputs and 70 tests.

The whole-provider keeper suite passes all twelve cases in 41.880/1200 seconds;
the corrected Core-frame suite passes twenty in 87.290/600, and reference
return passes six in 19.389/600. Pending-deferred and Main-finish pass in
70.600/600 and 19.372/600 seconds. All sixteen composed leaf suites and 59
span variants pass within their existing 180-second bounds. All 92 preexec
controls pass in 395.287/600 seconds; 69 are selected by Meson and 23 run
separately. An earlier compound-reentry selector removed a transfer guard
instead of the begin guard and unexpectedly passed; its failed run is retained.
The corrected selector binds each omission to its exact owning definition and
requires the intended detector. Provider-unavailable aborts do not count.

Independent source review matches all 1,036 signed/working changed files and
three artifact hashes with zero mismatches; its record SHA-256 is
`33ec02b2343c34ee04356dbbf86fbfe1fb0c27cc623b044065164dc3e4ca91a4`.
Independent final evidence review matches 7,035 regular files, 156 literal
links and 44 manifest records with zero mismatches; its record SHA-256 is
`efe39e8c335379b8e49d79a5f5897a6ae550953e0cd2d8bcb4d26c978b0b24cf`.
The sealed manifest SHA-256 is
`cea97e7bb079ea81c786f2e96a29b6649142032e4e5333d1c376cfa767097cc6`.
The producer verifies complete archive contents and exact Git permission bits
for 78,204 blobs and 72 literal links. Root review hashes that archive without
independently repeating member verification. The input archive's earlier strict
POSIX-permission refusal remains distinct from its passing Git mode-class audit.

Packaged exact reconstruction passes at `l3bnfr7m9lz24c3gk03aihjldd1wzvvp`;
the updated license ledger passes at `kygblnk27v53403lnpz8mg1cw9fky8xm`.
All 187 packaged Source cases pass at
`k62njmk1rnbsv5zg54l0dwp5n2wcjz8l`. ABI conformance passes at `2zwqvs57k8a0qyna2vj5qlxgwpg8wwra`.
All 36 Native custody components pass at
`krxgnkrz9bmjw6k9vbfdv9949kbr63sk`. Independent review of the actual
component inventory confirms every component started and returned zero within
its unchanged 180-second and 6-GiB bounds. Maximum elapsed time is
81.831 seconds and maximum aggregate virtual size is 398,893,056 bytes;
the inventory SHA-256 is
`ff447ca813b11a61875eb1841ce208238e9fca75bca4fd309714ef1bf65742fe`. Strict
license-boundary checking retains 909 Host library and 963 test-target Clippy
errors; subsequent boundary assertions are not reached. The raw dirty iterator
retains its mandatory genuine lifecycle refusal: exit one in 1.901/180 seconds.
Earlier normal/full-cohort measurements retain their original source identities;
neither was rerun for this union. This creates no Module/Core Quantum Original,
independent Module cleanup guard, semantic RR actor or selected CPU admission.
Complete return, Source activation, paid producers and semantic rearm remain open.

#### Retained RR parent and wrapper-retirement composition

The signed union `7dcd9a8912f74d6b51ee97b1dcb4a13c44a2713f` imports
conventional `218291844a677c428eda57410dfa44846e0a8f07`, exact tree
`1a82444e99cbdfa32ffc2383be19cee202d812ce`. It composes the corrected
Main-side RR parent and wrapper-retirement history with the preceding reader,
deferred-return and cleanup union. Both parent registration post histories
require actual completed attempts and zero statuses. Retained wrapper history
precedes borrower consumption and preserves once-only terminal facts without
querying an ended Original or dead wrapper. Returning-only physical identities
remain nonrecursive. No Module producer, semantic RR execution or reusable
borrower is issued; the process-wide one-attempt guard and CPU `ENOTSUP` remain.

Independent import verification matches 1,031 signed changed-source hashes,
8,313 regular evidence files, 156 literal links and three artifact hashes with
zero mismatches. The source comparison record has SHA-256
`c37d3af2197df0941faf6e39a198e7cb0378cd2c592cd25b3adec5bef4a6898b`;
the evidence comparison record has SHA-256
`b9678ca9cd055dcb3aa8310d4951f1abbc56c102c908a7b3e052c676924e3fd0`.
The producer verifies all 78,199 archive blobs/modes and 72 literal source links;
the import comparison checks the archive hash without independently re-auditing
its members. Six new files bring the cumulative license ledger to 392 created
files, with no deletions. The bounded custody runner selects the two actual
standalone suites with their positional arguments, bringing its total to 34.
Exact signed patch/bundle reconstruction passes at
`166a2q7n1my039vm7nnz78qsarl0pr0g`; the complete 392-created-file license ledger
passes at `2gk9ikpjjw3yl9zw9iyxxy6ay9xmf80i`. All 187 packaged Source tests
pass at `8053hs8p2dbnp73qip9zf6c5cs6cc0mx`. All 34 bounded Native custody components pass at
`wdcck13f8myr8izm43ysszq76mv0gfqp`, with maximum elapsed time
92.33768035999674 seconds and aggregate virtual memory 398,880,768 bytes, under
each component's unchanged 180-second/6-GiB bounds. Fresh ABI conformance passes
at `7aj6hwvmkgy5m0pxg6444zn2yp4hhmpb`.

The changed 713-object configured cohort passes in 297.913030706 seconds under
its unchanged 600-second/6-GiB bound, on actual input `6318dee1de`; all 99 final
fixture compiler fragments are byte-identical. Both real system links export
the new SDK APIs. All 27 composed/previous bounded suites, 45 joined span
controls and 92 independently rebuilt preexec omission classifiers pass; the
latter take 346.519024266 seconds under the 600-second/6-GiB bound. Genuine
pending-deferred, physical Main-finish, Core and Core-reference providers pass.
The first canonical-link and foreign-output-symlink refusals remain preserved;
the corrected metadata/topology authenticates genuine exact objects.

Actual Source is 248,088 bytes plus 30 genuine external getters totalling
44,270, yielding fixed floor 292,358. RR registration/parent are 152/352;
wrapper registration/owner/history are 112/3,096/768. Native 288/10,856 and CPU
16,992, ARM 97,712 and x86 33,568 extents are unchanged. Neither normal timing
nor the full 1,918-object cohort was repeated; their preceding actual inputs
remain separately identified below. The mandatory dirty-lifecycle entry still
fails for missing genuine launched lifecycle. Selected execution, full return,
sequential rearm, stack funding and performance qualification remain open.

#### Reader, deferred return and cleanup composition

The signed union `cbcf3ee95a3d9f15dc1b13bd5479cb9a99d32379` imports
conventional `721cc10ccb37775d1f71306e59056fee8b78d6b8`, exact tree
`0c3b534fdcffa1d5c3ac1da3966fec4ef33f70af`, with sole upstream parent
`1ed046750938db278a12dc55c6a7934d5fc68c14`. Both atomic dates remain
2001-01-01; the signature, DCO, exact message and artifact hashes are checked.
This composes the retained reader with Source Original borrowing, deferred
Main-finish receipts, Core execution/cleanup journals, cleanup registration and
independent Source physical posts. The Native runner adds six self-contained
suites to the existing 26, preserving each suite's 180-second/6-GiB bound.
Whole-provider suites still require their genuine configured object closures.
Exact reconstruction passes at `6q1641k3gg6hgfgvkn0qw8489jdarafl`; the
386-created-file license inventory passes at `3a800w0v9fzdq3fz13hgyn49is3x8sx5`.
All 187 packaged Source tests pass at `12bg9s0kjac9a3hxb1da897l7nfrd1ic`.
The first fresh ABI check stopped at its stale doorbell inventory: 61 actual
registered tests versus 60 expected. The marker-entry change updates this to the
new exact 62-test set; its rerun passes at `68yqsj468pfjh4v2crw70dgak6454mj1`.
The fresh canonical license check
stops at strict controller Clippy with 909 host-library and 963 host-test errors;
its boundary assertions did not run. All 32 bounded Native components pass at
`crkbhw46pmy41jmxfqxhbkvasvkaccq3`; the longest takes 81.1963 seconds and
the largest measured aggregate address space is 398,880,768 bytes, below each
component's unchanged 180-second/6-GiB limit.

Independent signed-source and working-source verification matches all 1,025
changed files and all three integration artifacts. Its record has SHA-256
`3d02bb5d7e8e077978ca117bbd37f669cc18d1f4bde025a3230a27142c7d5431`.
The final sealed evidence rehash independently matches 13,711 regular files,
156 literal namespace links and 26 manifest entries without following links.
Its record has SHA-256
`8576fd3f1679743a8a5ea8a01def6a7a38b54083d6a304793229533edd5a6d3c`.
The complete archive's hash is checked; its producer separately verified all
78,193 Git blobs/modes and 72 source links. That archive-member verification is
not an independent host re-audit. The license ledger adds 35 files, distinguishes
explicit SPDX from QEMU defaults and now covers 386 created files, with no removals.

Actual compiled Source is 244,376 bytes. Thirty genuine external getters sum to
44,270 bytes, yielding fixed floor 288,646, including Native Main-finish 96,
Core 88 and Outcome 144. Native frame/registry remain 288/10,856; CPUState,
ARMCPU and X86CPU remain 16,992, 97,712 and 33,568. Geometry grants no issuer.

The full 1,918-object cohort began on `f6d3a6543b` and passed in
592.310875109 seconds under its unchanged 600-second/6-GiB bound with two
compilers. The Meson-only `fb72822d57` edit occurred during compilation; it is
not the executed starting source. Normal delivery first failed on `6d120f8ff2`
for a missing real Native fixture link. The first and only changed normal run
on `b9a0c0f71b` passed in 53.120025402 seconds under its unchanged
60-second/6-GiB bound. Later `721cc10ccb` standalone fixture corrections are
not a fresh whole-cohort or normal timing claim. All 97 final authenticated
compiler inputs remain byte-identical and 411 selected functions match the
actual bodies. Earlier failing inputs and their evidence remain retained.

All 47 delivery/fault/TCG causal controls, 92 preexec classifiers and four
whole-provider groups pass in the public handoff. Publisher access passes 26
scenario rows across 16 rebuilt variants in 209.857780791 seconds; per-process
limits remain 30 seconds. Mapping observations and three independent producer
omissions pass. Twenty-three direct ordinary entries pass; raw deferred linkage
still refuses, its genuine configured closure passes, and mandatory dirty
lifecycle still refuses. Intentionally unavailable or aborting providers prove
no later assertion. No installed Module Original, semantic RR, independent
Module cleanup actor, paid selected reader or CPU issuance is claimed. The
borrower retains one process-wide attempt; sequential reuse and rearm remain open.

#### Native receiver and Initial-read composition

`12fbae747e` imports signed QEMU atomic commit `f9d1c47a9d`, composing the receiver/Entry subset
with retained Native Initial-read custody. Its sole upstream base remains
`1ed0467509`; the reconstructed tree is `c10be7dbf460b809f437f43124500c64a3f07f9f`.
Independent review matches all 977 signed changed-source hashes, 15,349 regular
evidence files, 156 literal symlinks and three integration artifacts without
traversing those symlinks. The verification record has SHA-256
`b41e310beb7e0f94f579a213cb9b122ef35848b8ba42501e5455593b539bd1d9`.
The independently configured 1,918-object cohort passes under its original
600-second/6-GiB bound; first normal delivery passes in 55.286 seconds under
the unchanged 60-second/6-GiB bound. Complete fixed geometry is 277,734 bytes,
including the actual 233,888-byte Source.

Exact signed patch reconstruction passes at
`qvzfc2q1l07xv39r0nsjn74z1jb0h404`; the 338-created-file license inventory
passes at `b9ch1pz611d52sivak2f0x01c1pf9ang`. Fresh owning Source qualification
passes at `5sjrrsyjp5hkbymmwzjljyfgh62qwq9z`, and ABI conformance passes at
`gdj14hqq2pfjvlmrhrsx4mpmkjc845h1`. All sixteen prior custody suites and six
additional suites pass in the updated independent Native runner at
`wzka0awsyi1jbwa236pi53zykjpchb0i`.

The first raw reconstruction failed because the signature-header parser stopped
reading a large signed commit, causing Git SIGPIPE under pipefail. `cb6546b6ee`
drains the full object while counting signature headers only; the corrected
raw reconstruction passes with every signature/tree/DCO check retained. The
aggregate regeneration target additionally builds the full QEMU package. That
package completes 4,060 actions and still fails mandatory launched dirty capture,
passing 25/26 fixtures. The raw reconstruction result does not qualify that
package or its aggregate gate. Receiver/Command/Entry implement three of the
seven proposed observation families; Use, Outcome, CleanupUse and Tail remain
open. No actual Module Original, selected paid Source or CPU issuer is claimed.

#### Source Quantum command handoff

`2ce72df77c` connects the actual driver's existing Quantum Original and unique
live Source producer to the mapped scheduler channel. The runtime's independent
mapping must name the same backing and node slot as the actual channel. The
move-only prepared writer retains the real Quantum and Preparation memberships
before tuple commitment; the complete locked lender collector then publishes
the immutable command and recipient ticket through the paid session. Its native
ceiling includes every present end in every retained row. Raw instruction limits
preserve the actual logical calibration and round conservatively.

Publication precedes the node event and once-only scheduler wake. The same
Original post and an independent full Source post run after either a successful
or failed publication, outside the session and lender locks. Negative posts,
publication failure and notification failure revoke the born offer without
consuming its borrowers. A changed standing sequence or cohort cannot rebind
the command. Ordinary control ACKs and their old return journals explicitly
refuse Quantum membership return.

All 23 focused Source controls, 67 quantum/mapped cases and 33 driver cases
pass after the publication-failure post correction. Engineering hygiene passes.
All 5,288 committed Rust/TOML inputs match immutable application-test source
`sig08w0fs3vfzf3y3crg37bxlmkr9l4m`; the comparison record has SHA-256
`8baf8032a34710462bac4844a9840aa76629b0a88d0f5b6f020edb4da6336e45`.
Mandatory application compilation passes at `vf237hxz9r17sqy0mvfarvkq61hz81pg`;
all 269 exact supervision cases pass at `bcdf5d4w1gcphxgygmbdrrjjxnd32s3q`
in nine groups.
The earlier source snapshots and failed local
attempts remain separate. Genuine Module construction, Native execution,
producer consumption, receiver Closed and ticket reuse remain unimplemented.
The first offer therefore retains real debt through every uncertain path.

#### Bounded peer-return observation

`29c1c400f6` connects the actual Source collector to a bounded return observer
inside its retained paid publisher session. One ticket/sequence cut copies the
exact 504-byte return, then independently rechecks both atomic words. The
observer verifies the original born offer identity, reserved bytes and mask
bounds, retaining the first exact record and refusing later changes. Negative
first/post statuses, partial physical-return masks and revoked permission remain
factual observations. The observer writes no shared word, sends no notification
and consumes no real Source borrower. It cannot publish a terminal, close the
receiver or authorize ticket reuse.

All 55 local Source-supervision tests and engineering hygiene pass. Mandatory
application compilation passes at `1qmpss3i54xpxzm5g6jpvvfaf16m2c7n`.
All 5,290 committed Rust/TOML files match immutable source
`i2fjyl7d6fkaq0lkyac8mnz8c3nzmnnd`; the comparison record has SHA-256
`5b65e9dc858c2a33b65777dda5edb9f75291f753723b6fc5cac892bdfd0ce602`.
The five added controls exercise actual kernel-backed mappings and descriptors,
including independent final-cut mutations and zero allocation. Their fixture
writes do not represent a genuine paid Native peer. All 274 exact supervision
cases pass in nine groups at `s0akn0gbq17c00q5r9416ph04969l8k6`.

The fresh canonical license-boundary run retains 1,210 Host-library and 1,285
Host-test strict Clippy errors. Boundary assertions did not run. The larger
owner-bearing error representations need a funded design; these failures are
not waived by the passing component or compilation evidence.

#### Typed runtime refusals and channel storage

`7dd88492cb` moves authored channel text into the same enum alternative as typed
channel causes, eliminating their duplicate storage. Callers borrow authored
text with `message()`; this intentionally replaces the previous public channel
field. Existing owned text retains its original allocation through conversion.
The runtime error keeps its separate authored field because pause rollback
legitimately retains both the initiating typed cause and a combined diagnostic.

Actual mapped-region access failures now move into the runtime error without
formatting. Their original typed source and the same Original's independent
post remain separately queryable; display defers formatting. The new control
uses a real mapped region and canceled Original and observes zero allocations
and reallocations while constructing the combined refusal. Nine channel-error,
two runtime-error, three driver-error, eleven actual-Original, three quiescence,
six fingerprint, forty-four quantum, nine mapped integration and two control
channel tests pass alongside that new control. All Host targets compile and
engineering hygiene passes after the content-bound source review. Mandatory
application compilation passes at `4gq83s5n8ax5kh1wp3sn0lj1lzj32v6c`; all
5,290 committed Rust/TOML files match immutable source
`8sx7fal7v851gybjpa14kys1vvf13nf8`. The comparison record has SHA-256
`050ff814bb59e790d108c36b29f955f9e1c50f84bfa52e6ae11975242b11e379`.
All 276 exact supervision cases pass in nine groups at
`lf4lxnlmfr405mlz0dq73a4a8j6gra0v`. The fresh canonical license-boundary
check stops before its assertions at strict controller Clippy, with 1,188
Host-library and 1,260 Host-test errors. Complete diagnostic-owner funding and
strict controller Clippy qualification remain open.

#### Typed fault transport mapping refusals

`bc3a98338a` extends the retained mapped error to all five fault event/result
transport access sites. Their operation labels remain unchanged, while the
original mapped cause replaces eagerly allocated diagnostic text. A real mapped
runtime control exercises the index and event-drain entry points after actual
Original cancellation. Both retain the same typed mapping cause and independent
Original post with zero allocations or reallocations and no staged event.
All 64 host-runtime regression tests and engineering hygiene pass. Mandatory
application compilation passes at `qjhdzb87rilykfqpj3ffajjk1rzfw46s`; all
5,290 committed Rust/TOML files match immutable source
`hwmcm3na10y4i66nsw75a7lh2s88gasd`. The comparison record has SHA-256
`01b7784a9b65744c6d563d91376e28a5b1c6784f8c915da6d615c0a7e663ba42`.
All 277 exact supervision cases pass in nine groups at
`yml9c0hwf5pv0ziiwi326qaqs4w2dkp9`; this result is separate from the preceding
checkpoint.

#### Fixed-width Source publication words

`8196e2f1a3` uses fixed eight-byte arrays in actual standing publication,
command publication and peer-return observation. Endianness, atomic ordering,
sequence transitions and bounded payload sizes remain unchanged. All 56 local
Source-supervision tests and engineering hygiene pass. Mandatory application
compilation passes at `8a0fia46slg85f8k025l7z7kdxga96ll`; all 5,290 committed
Rust/TOML files match immutable source `xy4mqw0x9vwrqr7klydhmcs876c1bagd`.
The comparison record has SHA-256
`c06ab9fd45fdbcc94c9c0bc1a4d9e3de477253a73b904234c29926296f3ad193`.
All 277 exact supervision cases pass in nine groups at
`p9pvymbzif2q2parll6px5c0nkcr9w6z`. These changes remove five fixed-chunk Clippy findings without waiving the remaining strict
gate failures.

#### Typed control and fingerprint publication refusals

`74cbfe0cf9` retains actual node-slot and fingerprint-sample causes at five
publication/refusal sites. The causes and independent Original posts remain
separately queryable; formatting is deferred and keeps the same displayed text.
A kernel-backed runtime control seeds exhausted generations and proves that
both real publication paths refuse with zero allocations or reallocations,
unchanged mapped bytes and an untouched wake descriptor. No Native issuer is
created by those fixture bytes.

The first broad runtime run passes 63 tests and fails two assertions that still
expect eager message text. Those assertions and the paired-feature counterpart
now check the retained typed cause and deferred display. All 65 runtime tests
pass in the corrected run, including the three actual mapped-refusal controls.
Engineering hygiene and all nine paired-feature fingerprint checks pass.
Final-snapshot mandatory application compilation passes at
`90fmbp0fb2ljfys2rc64q81pvhhbv9ib`; all 5,290 committed Rust/TOML files match
immutable source `by91dypky1ndbwxcyyax01kizd9apw2c`. The comparison record has
SHA-256 `d3d186b31267c71f3c48a7b78bcbbfb104a302ca139311dbed2e6ce09563930c`.
All 278 exact supervision cases pass in nine groups at
`8m5pxppgf921jzaknh799h8fggwyhjdc`. These checks do not establish complete
error payload funding or Source activation.

#### Typed control preview refusals

`d72549bf86` retains the actual action-decode cause at both control preview
sites without formatting a diagnostic. `d946be2eec` migrates an existing
exhaustion assertion to the typed cause and deferred display. The first broad
run passes 65 cases and fails that eager-text assertion; the corrected run
passes all 66 runtime cases. The new mapped control covers final-token
exhaustion, a mismatched frontier and a mismatched pending capture. Each path
retains the same independent Original post with zero allocations/reallocations,
all shared bytes unchanged and no wake. The private-domain variant and all nine
paired-feature fingerprint tests pass. Fixture bytes issue no Native action.

Engineering hygiene passes. Final mandatory application compilation passes at
`65hsi18j9kpwdxlf8g6wyfir2j6if6p6`; all 5,290 committed Rust/TOML inputs match
immutable source `5b0zps75v5dq8lgs6y5mv309w99nfnma`. The comparison record has
SHA-256 `96a1506b28e3dca8a5e22ba9b19828e3cabf255832841548b581a1a82a8c6585`.
All 279 final-snapshot exact supervision cases pass in nine groups at
`2blmnkq8l4z2kpirk6kpsc99arfpdshl`. The checkpoint adds one component binding;
complete diagnostic funding and genuine Native admission remain unqualified.

#### Module Root read subloans

`7e8526f394` retains a real nested backing-read loan beneath the already borrowed
Root view. Its inline ledger belongs to the actual paid Runtime; prebirth
accounting uses the complete Runtime layout rather than a new scalar estimate.
The non-cloneable loan blocks Root view return, reborrow and physical retirement
through synchronous result construction and unwind. Completion does not release
the physical loan before the callback scope returns. Busy release or changed
identity retains parent debt without waiting. Local checked serials identify
custody only; every semantic query still observes the existing Source Original.

Four component regressions cover scope/unwind, changed parent, contended return
and serial exhaustion. Their opaque fixture addresses issue no Source Original
or Native custody. All twelve Original controls and all twenty-seven fingerprint
controls pass. The first broader source run passes sixteen cases and fails an
assertion expecting the former generic unavailable diagnostic. `552b160ea5`
checks the actual retained operation kind/static cause instead; all seventeen
source tests and both Runtime prebirth controls then pass. Content-bound hygiene
review is refreshed after inspecting that exact assertion change and passes.

Application test-target compilation for `7e8526f394` passes at
`z1slwb23r1n3r12pxghd9fm02qgryy2m`. All 5,291 committed Rust/TOML inputs match
immutable source `f99b0v2z37yaivrq4jmm6grygfdsn567`; the comparison record has
SHA-256 `4b724d844007c340ecdf0ec128d9b3cdbdf25dadb5ba417125aea070fe0bc29a`.
Corrected-snapshot application compilation also passes at
`mdqkrrfa1xfb123bsqc54iyhd1yn128r`; all 5,291 Rust/TOML files match
`gdbfiilk8s0g6mg4gcvflbcnvj2xcmzk`, with comparison SHA-256
`03a5e7245f638d772447fb1469de999d390c8b72043489a284ba6225e82858ea`.
All 283 corrected-snapshot exact supervision cases pass in nine groups at
`g815fg39fw3lz7j1w4mp8s0szfi1jk4g`. These four bindings do not establish registered Source read-child
callbacks, selected Native capture, physical Source return or complete funding.

Source contract review exposes a receipt-ordering gap: the next page read can
replace the Source cell before the Module observes its final consumed facts.
The registered reader implementation below retains the actual completion
handoff; returned-current alone is not final Source closure.

#### Registered Module RAM reader

`4ad17a2d6c` retains the actual reader inside the already priced, pinned Runtime.
Paging enrollment resolves the frozen Source SDK r2 and registers the exact
canonical owner fields, callback table, 128-byte Module journal and 240-byte
completion copy. Each actual Source read child retains the same non-cloneable
Root subloan before any fallible post. Backing exchanges borrow that existing
loan; they issue no second Original or clock. Physical return retains the same
loan on nonwaiting refusal and saves known consumption before later posts.

The completed callback authenticates Source's exact argument and copies both
actual journals before acknowledging them. A later independent 160-byte Source
completion observation must corroborate callback return, acknowledgment and
consumption before journal reuse or parent return. No-call birth failures keep
the prior Module journal intact. Registration closes and returns before its
containing command member, component, registration owner and callback child.
Consumed-negative replay retains the first and post failures without another
destructor. Unknown return keeps physical debt.

All fifteen Original controls, thirty fingerprint controls, seventeen source
controls, two prebirth controls and five operational read controls pass. The
three new bindings cover explicit nonwaiting read return, changed-parent debt
and literal SDK geometry; their opaque fixture addresses issue no Source
Original. Final plugin test-target compilation and content-bound engineering
hygiene pass. Mandatory application test-target compilation passes at
`47z2svj8p852c9w8dfm33lckmck8i4f1`; all 5,298 committed Rust/TOML files match
immutable source `cdbvbjpnxnl2qr8hn30kvzi3g5bdylry`. The comparison record has
SHA-256 `da55628b1c34cd6d5fd5230fabe3440078532456c315269654556f654dae5b88`.
ABI conformance passes at `3wxg0f5v6bvbhhkcjgsdhanxm5q1s4qw`;
all 287 exact supervision cases pass in nine groups at
`mh6vha4nls2xq5gz9m519s6hdsr7c11p`. The fresh
canonical license gate stops before its assertions at strict controller Clippy:
1,184 host-library and 1,255 host-test errors.

The matching public Source reader is imported as signed atomic
`8c55fe5743a4df1db55ffb25682c298e6b8bd6fe`, tree
`27234c29ba1a821c67a9b08126d7ac79611f3069`, from conventional
`0137bd538c458b0c225d86b561fb886895c5e881`. Review caught an
ordinary-parent-current cycle in the earlier signed `881048e437`: retained
reader debt incorrectly refused identity observations needed by that reader.
The correction restricts those five debt checks to actual parent return.
The original 49 and six paired omission controls pass in 39.807 seconds.
All 1,918 fresh configured objects pass in 150.398 seconds under the unchanged
600-second/6-GiB/two-compiler bound. The first and only corrected normal delivery
passes in 52.927 seconds under the original 60-second/6-GiB bound.

The final independent sweep passes 92 preexec omissions, 47 causal controls and
four late controls. Both system links and six owning executables pass. Raw
ordinary fixtures retain 23 passes, a separate incomplete direct-link failure
for control-deferred (whose configured closure passes), and the mandatory
genuine dirty-lifecycle refusal. The earlier 881 first normal pass (48.462
seconds) and interrupted sweep remain separate. None of these results qualify
genuine installed Module reads, selected activation or complete physical return.

Independent import verification matches 990 signed changed-source hashes,
10,908 regular evidence files, 156 literal links and three artifact hashes,
with zero mismatches. The comparison record has SHA-256
`d13608cee6f125423f26dd36cb65bd888bd5a894930b7138dd37e02080138610`.
The agent's complete source reconstruction records all 78,158 tracked blobs
and modes; the import comparison does not independently re-audit that archive.
The exact raw patch/bundle reconstruction passes at
`l3y4q9dpgh08dcfa5bjxpqpk74hb0nxn`; the 351-created-file license inventory passes
at `62hq7qrc96jk5b7i37sawmwgbfdvv5n9`. An initial descriptor included an extra
message newline; the failed reconstruction remains recorded and the corrected
descriptor reconstructs the exact signed subject, body and DCO. All 26 bounded
custody components pass at `3cb9frb6ydjxcv66qpjszpw98fpirl8v`. All 187 packaged Source
tests pass at `qiky21gqqq0w3c6nljllazw78ayyz3vp`; fresh ABI conformance passes
at `85lnp7g1sypbwsb3cww4j066qfidnqh4`. Canonical license checking again stops
before boundary assertions at 1,184 host-library and 1,255 host-test Clippy
errors. The immutable SDK r2 is unchanged. Actual Source 243,112 plus 27
real getter terms 43,942 gives the 287,054-byte fixed floor; reader owner 632
and child 272 are inline, and the Native RAM frame contributes 96 through its
actual getter. Module storage and execution stacks remain separate payers.

`31fe9199e9` corrects registration-return history after an earlier close
refusal. Physical cleanup can finish, but its saved first close status remains
visible on every later return. Known-consumed replay runs before any API
lookup, completion query or destructor. The return and completion methods take
only their existing plugin identity rather than an unrelated enclosing Owner.
A component regression calls the actual return method twice with retained
known-consumed history and no Source API; it preserves the close error, null
canonical fields and separate successful physical return/post facts. That local
journal supplies no Native owner or physical return authority.

All sixteen Original controls and all 31 fingerprint controls pass; all plugin
test targets compile. Engineering hygiene passes. Mandatory application
compilation passes at `aff9nd5z7nn1vny4xjf8hlhifb4kmyqh`. All 289 exact
supervision cases pass in nine groups at `pr49c7ypdq47frmv8gia4fzqp3gfmjfr`. All 5,298 committed Rust/TOML files match
immutable application source
`5ya73iji71gv4lpc8mbmgf59cjyv60ga`; the comparison record has SHA-256
`c306fd48b5f8c9e24a75d082b9fbed593435ffb2296473fd179b34df6cb74ec6`.

#### Received delivery post-refusal replay

The actual received-delivery keeper now preserves its saved Ready and payload
post refusals after known physical lifetime consumption. Repeated return calls
project retained history before any Native callback, so they cannot report a
fresh success, reclaim the delivery twice or erase the failure before parent
cleanup. The existing inline status fields carry this history; the complete
paid Runtime layout is unchanged. Unknown lifetime consumption still retains
its exact canonical field and parent debt.

The two existing local-model regressions now repeat cleanup after changing the
modeled provider's result, verify the original refusal and assert exactly one
Ready, payload and lifetime return. Their addresses and copied output facts
supply no real Native or publisher authority. All 21 command-receive tests,
all plugin target compilation and content-bound engineering hygiene pass.
Mandatory application compilation passes at
`cxj15pkm32kkg6l1shkn40j86li9a0ir`. All 5,298 committed Rust/TOML files match
immutable source `a557f0sfpnj1h8qv3382gsvnn4l457r5`; the comparison record has
SHA-256 `2b0a4701cdb050bb1a9b79a968162104e4d3c1abc0d20d6a375577725968c98a`.
All 289 exact supervision cases pass at `crd0zlsfjkqrdvwc52c6kkiycnvn7z8a`.
Full Source/Module physical return remains unqualified.

#### RR execution and terminal registration composition

The QEMU artifact now composes signed RR execution and terminal registration
with the retained reader, parent and wrapper custody implementations. Atomic
commit `91aec7e4401204c0ef9aa9be8f4cb2581b57be89` reconstructs tree
`8be2496e84c13e742adc5e56ca0cf19975dbea55` directly over the pinned upstream.
Its signed author and committer dates are both 2001-01-01 UTC. The conventional
signed head is `99f1080cb2019b3c9e99e7f8ffe49e33846ff108`.
Four new GPL-2.0-or-later files bring the license inventory to 396 paths.
The registered Native custody runner now includes both new factual suites,
for 36 components with unchanged 180-second and 6-GiB per-component bounds.

Source measures 248,440 bytes; thirty genuine getter extents total 44,270,
for a fixed floor of 292,710 bytes. Execution and terminal registration storage
(200 and 152 bytes) is already included in Source. Native frame/registry remain
288/10,856; CPUState, ARMCPU and X86CPU remain 16,992/97,712/33,568 bytes.
The public SDK changes insert registration entry points without changing
existing definitions. Copied callback metadata and completed independent
posts preserve the existing attempted/returned journals and span exclusions.

The producer freshly compiled all 713 affected configured objects in
334.029 seconds under the declared 600-second aggregate bound with two workers,
6-GiB address-space enforcement and peak aggregate VM 1,827,233,792 bytes.
Its inherited core limit was not recorded; this cohort supplies no CORE0 claim.
The 2,450 unchanged configured outputs were retained byte-exact, not rebuilt.
Both real system links, 103 owning provider bodies, 16 composed suites,
13 retained groups, three additional consumers and 59 span variants pass.
The new leaf suites cover 17 execution and 20 terminal cases. All 92 independently
rebuilt preexec controls pass in 414.706 seconds with explicit CORE0 and 6-GiB
limits. The mandatory dirty-lifecycle run still refuses with status 1 at
2.275 seconds; this is the expected component refusal, not Native admission.
Normal-delivery and full-1,918-object timings were not repeated and retain their
previous source identities.

Independent import review matched 1,035 signed/working sources and three
artifacts with zero mismatches; its record SHA-256 is
`7fc0b08aed9393d65ae4e6b60c6a204b6be575c2d763e937bc17288b00799d31`.
Independent evidence review matched 8,939 regular files, 156 literal links and
213 manifest entries with zero mismatches; its record SHA-256 is
`ff60ecf0d23703738971289e1dcd069eb53f33c01824248f8e03d6cfff596f24`.
The sealed manifest SHA-256 is
`000010e89aea5cf5cab501a1b9c0b424cd19eb1cbc107a20c5904f50ce19bb21`.
The registered 396-file license ledger passes at
`vm79d022xs6lnrhsw8cjnsnkcpsrkfmp`. Exact reconstruction passes at `g2hys8casfrhqnfj47ch9bmy221jmzs7`. All 187
packaged Source tests pass at `6x4h7x6r2ay2v08a4w5lr3c8vy2qhs2k`.
ABI conformance against the imported artifact passes at
`lrpg81g6mxq30ph6ci5maaxx6yxv4ykh`. All 36 packaged Native custody
components pass at `1h7z2d6rh01kz0w6ksfnhf4bp4ph33b9`. Independent review of
the actual component inventory confirms every component started and returned
zero within its unchanged 180-second and 6-GiB limits; the maximum elapsed time
is 86.337 seconds and maximum aggregate virtual size is 398,888,960 bytes.
Canonical license checking stops at 909 host-library and 963 host-test
Clippy errors; its boundary assertions do not run.

These are metadata registrations. They create no SourceUse, Module owner,
execution actor, cleanup guard or CPU admission. ENOTSUP and the one-process
borrow-attempt restriction remain. Genuine Module issuance, ordinary RR actor
execution, terminal return and sequential rearm remain open.

#### Permanent selectable reply workspace

The inline white-box owner now retains one fixed 4,608-byte reply workspace,
covering the exact selectable protocol maximum. Live trap and resume callbacks
borrow that same body synchronously. Both paths encode directly into the full
guest-reserved prefix, clearing it before reuse and preserving the suffix.
Neither live path allocates a separate delivery or padding Vec. The public
reader-based safe core retains its explicit owned fallback through the same
checked borrowed-input writer and codec; reply bytes and delivery rules are
unchanged.

Existing reply controls reuse a nonzero workspace for successive longer and
shorter values, comparing each canonical prefix with the owned encoder and
checking cleared padding, untouched suffixes and exact same-icount writes.
Pending service and empty resume leave it untouched; completed delivery retains
the same catalog and ring consumption behavior. All 1,177 plugin unit tests,
all plugin test-target compilation and engineering hygiene pass. The initial
compile found one direct slow-path test call missing its new workspace argument;
that refusal remains separate from the corrected passing run. Existing prebirth
geometry controls pass and measure the actual containing Runtime at 18,936 bytes,
alignment eight, with the full inline white-box body at 9,552 bytes. These Rust
allocation measurements are distinct from the Native/Source fixed-floor sum.
Mandatory application compilation passes at
`6p06q2z9zlwhqw3b078xfpb0nxn5mfp6`. All 5,313 committed Rust/TOML files at
`7c54cbb0851efc6845da829f44940443ef5ff2e0` match immutable source
`c938p7v9ica20c37ihlinhavj5m38acg`; the comparison record SHA-256 is
`b2997b7bada1e642fcacf758d545889d9e924572f8613ed8a92d0ec4e4f0d939`.
There are no new bindings.

Decoded request/reply fields, catalog storage, service decisions, diagnostics,
allocator backing and creator stack/TLS still need complete genuine funding.
The fixed workspace supplies no operation owner, cleanup guard or eligibility.

#### Inline white-box callback storage

The complete pinned callback Runtime now contains the optional white-box state
inline. Its existing before-birth `Layout::new::<OwnedCallbackRuntimeState>()`
therefore includes the full body; preparation no longer creates an unlisted
independent Box. A second preparation refuses before borrowing mapped queues
or consuming launch plans, preserving the address already handed to callbacks.
The field is initialized only after the containing Runtime is pinned and remains
beside the setup mapping. Coverage borrows its translation consumer from the
same field. Two unsafe raw-pointer conversions are removed.

All 1,177 plugin unit tests, compilation of every plugin test target and
engineering hygiene pass. The existing prebirth controls continue checking the
actual containing allocation and configured fixed/scaled rows. Mandatory
application compilation passes at `mqg27a03vk54piz2jfn6z7d9mb7bzlzs`.
All 5,313 committed Rust/TOML files at
`e1f925b1e792c387f1ab674fb4772b42f9df8d14` match immutable source
`55w2sk364ls5hwjvj98517r2n6zm8s88`; the comparison record SHA-256 is
`055e57edcc4419f0640ee7f474cac1bf83cae4873c162ae62b7672c33ac53541`. The cohesive Runtime source review
records the changed geometry and exact digest. There are no new test bindings.
Dynamic catalogs, decoded payloads, replies, diagnostics, allocator backing and
creator stack/TLS still require complete real funding. Container inclusion does
not create Source activation, a Quantum Original or Native eligibility.

#### Selectable replies in caller-owned delivery storage

Selectable reply encoding now validates its canonical length before allocating
or writing. The public `encode_into` entry writes into a caller-owned prefix,
returns the exact encoded length and preserves its suffix. Invalid replies and
insufficient destinations leave all destination bytes unchanged. The explicit
owned encoder allocates the final canonical length once and delegates to the
same writer. Wire fields, edition and golden bytes remain unchanged.

The live selectable service checks sequence and canonical length before
allocating its complete zero-filled guest reservation, then encodes directly
into that allocation. It removes the intermediate encoded reply and copy while
retaining the same full-reservation guest write. Deferred resume delivery also
validates length before allocating its final reservation once, removing its
encode-then-resize growth. Existing selected/rejected
codec controls check canonical prefixes and sentinel suffixes; existing length
controls check capacity, missing-value and oversized-value refusals without
mutation. Existing callback controls retain same-icount, padding and oversized
reply expectations. The source-size review retains the cohesive selectable ABI
module and updates its exact source digest and implementation count.

All nine selectable codec controls, all 129 white-box controls, compilation of
every protocol/plugin test target and engineering hygiene pass against the
final source. Mandatory application compilation and ABI conformance pass against the final
source; ABI output is `fw218gb29p4ibg2rskcsh0q9axzh7n3n`. The unchanged
327-case supervision gate passes at `ba0hgl556cs3p56rxcd1g2srqaplv7vm`
with nine groups and the exact inventory. Strict license-boundary checking
retains 909 Host library and 963 test-target Clippy errors; later boundary
assertions are not reached. The first hygiene snapshot preceded the
required source-review digest update and retains that refusal. Earlier checks
preceding the deferred delivery change remain separate from final-source checks.
There are no new test bindings.
All 5,313 committed Rust/TOML inputs at
`c2dc3908cc607c073e6b4a80247cebbf417413bd` match immutable application
source `2lx7h8zi1hq8xbaj2p6kamlf4jcimqz9`; mandatory application compilation
passes at `zv089iyv1yrj0bcj6iamsbfwx0cgk575`. The comparison record has SHA-256
`99a7ae9478ff58632534b9a9ce1dc30c3dd93933844ded82ecf1c20304914090`.
The one delivery buffer, decoded fields, decision records, diagnostics and
complete operation funding remain open. This creates no Native authority.

#### Selectable decoding before pending service

The selectable path now prepares the complete declaration or request from the
retained initial trap snapshot. The prepared value owns its decoded fields and
retains the immutable doorbell configuration, event and coordinate. It borrows
no encoded bytes. The dispatcher releases the native array before catalog or
selection service, including a pending request that defers VMStop. The existing
reader-based API uses the same preparation and releases its encoded buffer
before service. This removes the final selectable reread and its encoded Vec;
owned declaration/request fields and existing reply buffers remain.

The existing pending-request control drops the encoded snapshot before service,
checks that preparation performs no service/write effect, then verifies the
same pending request and unchanged reservation. Existing refusal controls add
independent mode, exact-length and coordinate precedence expectations. The
initial compile found a reference to another module's private error adapter;
preparation now uses the existing selectable live adapter. All 129 white-box
controls, compilation of every plugin test target and engineering hygiene pass.
Mandatory application compilation passes at
`9h62s6rhwp2snn03mzbqjwc8p3qrndzd`; ABI conformance passes at
`g3xdq6rmnra1cddjajj9aqa4b09p97ms`. The unchanged 327-case supervision gate
passes at `hnl9dwiyxwjj88vn802xbv3z12qz5m3q`. All 5,313 committed Rust/TOML files at
`218cbc19db0c1d5723662ec526de25bcec8418d4` match immutable application
source `wrq3kpm2zmb8cpx85z8h92l5ixwm5vvn`; the comparison record has SHA-256
`ee915a574cdf0bdcdba74b2c6d5bd2630376bfa67a03b886a7d1411e48ef2a0d`.
No new test bindings or Native authority are claimed.

Decoded request storage, reply encoding/padding, diagnostics, the initial native
array, complete callback funding and genuine Module Quantum/cleanup issuance
remain open. Snapshot preparation supplies none of those owners.

#### Ordinary marker service from the retained trap snapshot

The live ordinary marker path now decodes the retained initial guest snapshot.
It no longer repeats the guest read or creates an intermediate owned frame
payload. Explicit reader-based APIs still return the same owned marker and
use the shared borrowed decoder. Marker payload ownership, typed fields and
sink recording remain unchanged. The native read array returns after recording
and coordinate clearing, before readiness callbacks or deferred VMStop work.
Snapshot validation is shared with app-random: mode, range bounds and exact
length precede decoding or service effects.

The existing snapshot control checks that service retains the trap's coverage
value while guest memory contains a later mutation, with unchanged recorded
coordinates and one reader call. The malformed-frame control checks the live
snapshot entry against its independent typed-error and diagnostic oracle.
All 129 white-box controls, compilation of every plugin test target and
engineering hygiene pass. Mandatory application compilation passes at
`1fk9f14swimw8wyx4a6w4mqpzjkw7l9s`. All 327 exact supervision cases in nine
groups pass at `znjabz0czpyca5zq8ai6jy4rqwkyn09g`. ABI conformance passes at
`czflvr73w9gksavyhikfxjm0vn97qyxf`. All 5,312 committed Rust/TOML files at
`b2ae976781cfe7043614e1790ee4aeedf6446602` match immutable application source
`2mv8znji1i1h2n0kv91d2i74himbkg7v`; the comparison record has SHA-256
`99394a17e530ccfd4c4dc1c0b89f757ccf9daa0c26f9359f92d1c045eecde540`.

The returned marker still owns its raw payload and variable-length decoded
fields. Selectable service still rereads its request. The initial native array,
sink/transport storage, complete operation funding and Native authority remain
separate open work.

#### Borrowed app-random request service

The live app-random service now consumes the retained initial native snapshot,
removing its second guest read and the owned containing-frame payload copy.
A public borrowed marker decoder uses the existing kind/body validation;
explicit owned marker decoding delegates to that same path. Variable-length
marker fields still own their values. Setup-complete probing validates only
lifecycle bodies, avoiding construction of unrelated marker strings and vectors.

The existing service control now exercises all reply widths directly through
the production borrowed service. Existing malformed-request controls compare
owned-reader and borrowed-snapshot outcomes and verify that disabled mode,
range bounds and exact snapshot length refuse before drawing or writing.
The setup-complete control adds every truncation, malformed headers/bodies and
trailing bytes. No new case bindings or requirement qualifications are claimed.
The first compile caught two remaining test call sites passing owned frames;
those call sites now explicitly borrow the frame. All 129 white-box controls,
all codec and golden-vector integration controls, compilation of every
protocol/plugin test target and engineering hygiene pass against the corrected
source. Mandatory application compilation passes at
`k6dazcm1n34zb7fv1bqsdshkh2dbxna3`. ABI conformance passes at
`z02p20m7asw8paqp7xh9n9w1sr1svzwm`. All 327 exact supervision cases in nine
groups pass at `v0n112bv03yskirav35f0bvnh9kplc3h` against that final source.
All 5,312 committed Rust/TOML files at
`3259e4797771b3a039a56459f28a3d13f6332015` match immutable application source
`m4jih9wff12azk5vn4w9nrp9zj89ph6x`; the comparison record has SHA-256
`07342d829bfbde04090d539f05a46ad9c0453c04e9e48aa10d7b9afedced9e92`.
The initial ABI and supervision snapshots retain the same two outdated test
call-site compile refusals; their corrected-source reruns remain distinct.
Canonical license checking stops at 909 host-library and 963 host-test Clippy
errors before boundary assertions.

The GLib read allocation, owned request fields, decision records, transport
encoding, dynamic callback errors and complete operation funding remain open.
This supplies no Native execution authority or lower-residency qualification.

#### Borrowed ordinary doorbell frame inspection

The public ordinary doorbell frame view now borrows the original payload after
validating the complete header and caller bound. Explicit owned decoding uses
that same validation path and copies only after success. The live app-random
probe uses the view to inspect the kind without constructing a payload vector.
Wire bytes, protocol edition and validation priority remain unchanged.

Two exact component controls pass: the first compares independent literal bytes,
original payload addresses, owned round-trip values and an empty frame; the
second checks every truncation and overlapping magic, version, bound and length
refusals against explicit expected typed errors through both APIs. Engineering
hygiene, all 129 white-box tests and compilation of every protocol/plugin test
target pass. Mandatory application compilation passes at
`zsqaqghzjfyicmkhnn454f6sxpv791q8`; ABI conformance passes at
`g5ih403gr3d3ixgpfifd97fkc4kwh2dk`. All 5,311 committed Rust/TOML files at
`1d467f1233e550c66102e1848ce84e1bf1573499` match immutable application source
`1a57qp7wg7l2gx99ralx182h8h06cdgi`; the comparison record has SHA-256
`f2bb9b42c4b6736aa730a4733a44f323e25cab1cc0a536a03258732894d165ea`.
All 327 exact supervision cases pass at `glac900yjv19yncg14ismn272hsvd203`,
with nine actual test groups. The 444 bindings comprise
425 component cases and nineteen native cases; 148 of 243 requirements remain uncovered and none fully qualified.
This borrowed view issues no Native authority or complete operation payer.

#### Fixed app-random reply storage

App-random delivery now borrows the admitted one-to-eight-byte prefix of the
selected value's fixed little-endian array. It no longer constructs an owned
reply vector before the synchronous guest-write gate. Decision recording,
metadata validation and trap-coordinate delivery retain their ordering.
The existing service control retains its two-byte mixed-value case and now
executes every admitted width through actual request decode, decision source
and reply delivery, including the full-width maximum value.

All 129 white-box tests, compilation of every plugin test target and engineering
hygiene pass. Mandatory application compilation and the unchanged exact
325-case supervision run were collected. All 325 exact cases pass at
`dzypdrngbc2f4bhfpllvcg9k570998s6`, with nine actual test groups.
Request decoding, decision
storage, callback errors and complete operation funding remain open. Mandatory
application compilation subsequently passes at `1yiz4pkj33pixl3hzkdg29r0kv6ci9jn`.
All 5,310
committed Rust/TOML files at `64619b4aab40787ff51c4c6d8ce2ba90617dba34` match
immutable application source `n5mq2477wdifk5sfzpcfs1j5sgriw6aq`; the comparison
record has SHA-256
`40f3b85f522c66d50c5cf46febd10fcf5e1a6b526eb05ab344c1e3fac430ac21`.

#### Borrowed static guest-write diagnostics

Native introspection/app-random writes and selectable virtual-range refusals now
retain their static diagnostic text directly. The public guest-write error keeps
its existing explicitly owned constructor and message/display behavior. Its
static constructor and clone preserve borrowed storage through the actual
borrowed input-delivery error path. The existing delivery refusal control now
checks both owned and borrowed backend errors, unchanged delivery coordinates,
the original diagnostic address and its complete display context.

All 129 white-box tests, compilation of every plugin test target and engineering
hygiene pass. Mandatory application compilation and the unchanged exact
325-case supervision run were collected. All 325 exact cases pass at
`78zhc079klc2369pbvzw4n75lx3gpn1i`, with nine actual test groups.
Mandatory application compilation subsequently passes at
`z2wa8m458jrm5vzlnx1yy4fj63fsg364`.
All 5,310 committed Rust/TOML files at
`f65958fe11d6007750ab7804f5d21133b31697f6` match immutable application source
`vdsriw89sy9zgd4cq9dsz5y0x002m2hc`; the comparison record has SHA-256
`612a1dbad8f9abafe77c0c15294760c2d8673b94167c37dbb3a61c6c0708f046`.
Dynamic coordinate and native-status formatting, other service error paths and
complete operation funding remain open. This issues no Native authority.

#### Borrowed initial native trap reads

The live trap dispatcher now retains the original GLib read array and borrows
its bytes through introspection routing, replacing its initial native-to-Vec
copy. App-random, selectable and marker handlers retain their existing own-read
interfaces; their initial inspection array returns before those reads,
publications or deferred VMStop work. The setup-complete predicate is computed
before that return, so its borrowed bytes are never used after release. A focused
owner returns the native array exactly once on scope exit or read/shape refusal.
Explicit owned reader APIs still copy when their callers require owned bytes.
Buffer construction checks exact requested length, a representable slice extent
and nonnull data for nonempty reads before exposing any slice; an empty native
array returns an ordinary empty slice. Static native read failures retain
borrowed diagnostics, while the existing owned error constructor remains.

Three controls exercise the actual read/borrow/Drop adapter with instrumented
native entry points: 4,096-byte payload pointer identity and scoped release;
prebirth allocation/range refusal versus born read failure; and malformed or
empty native buffer handling. The first focused run compiled successfully and
passed ten controls; its one failed assertion incorrectly required duplicate
literal expressions in separate modules to share an address. The corrected
control compares the actual error and its clone: a retained borrowed diagnostic
preserves its address, while an owned String clone would allocate separately.
All eleven focused guest-memory controls, 129 white-box controls and every
plugin test target's compilation pass. Content-bound engineering hygiene
passes. Mandatory application compilation, ABI/license checking and the exact
325-case supervision run were collected. Mandatory application compilation
passes at `jh4w82m0d5k3g5prx2a157jrz8x6rjg5`; all 325 exact cases pass at
`nkc6mvzmxsk6yw6alwfh94lpqjlifpn7`, with nine actual test groups.
The subsequent early-return change passes mandatory application compilation at
`r6lmcgvs4rxb9yzp5k73567h941ahbg6` and all 325 exact cases at
`pnxvkgzb382hm50n9jgkipaf5rgq548m`, with nine actual test groups.
All 5,310 committed Rust/TOML
files at `6dca2ad40a4c55aad8de4f7e32e4b126a613944d` match immutable application
source `cknjvgv11vnmj2x0al64a6czfcav2rpk`; the comparison record has SHA-256
`081b5e0013afd63ad5b0fcbbf3be8734a938856936e5ee8163c68550d2bad378`.
The retained GLib allocation, explicit owned reads, other service parsing,
callback stacks and complete operation funding remain open.
This introduces no Source activation, Module permission or residency claim.

#### Typed live guest-introspection refusals

The exchange router now retains original protocol, entry and ring error values,
sequence coordinates and static invariant messages. Live frame decoding,
transport routing and guest reply delivery carry those typed causes into the
callback error instead of formatting new diagnostic Strings. Ring-full remains
an explicit retry; direction checks precede sequence overflow, response
publication precedes request lookup, and delivered requests are consumed before
the terminal request-sequence overflow refusal. Human-readable diagnostics keep
the same context and are formatted only by their consumer.

Three controls exercise actual routing refusal precedence, modeled ring failure
with its complete Error source chain, and known request consumption followed by
sequence overflow. All nine focused router tests, 126 white-box tests and every
plugin test target's compilation pass. Corrected content-bound engineering
hygiene passes. ABI conformance passes at `ayl6az368908mjim2njpvym8h1jr56hi`.
Canonical license checking stops at 909 host-library and 963 host-test Clippy
errors; boundary assertions do not run. Mandatory application compilation passes
at `9g8b6qm724w9rn9pgbnk5zcyafl78cln`. All 322 exact supervision cases
pass at `js0i8xhkshvs4wzhm7a4insw6mwcazyx`, with nine actual test groups.
All 5,308 committed
Rust/TOML files at `0b2dc41ac5e3343dfebb98d1d7ebde8a89983c6c` match immutable
application source `n48s1b82xdjclagrbz1r7z2yl2pirc77`; the comparison record has
SHA-256 `fe13ce9c055fc63f6dfe8e1b025ad09455c3dccfa512c5e775d703f5e4fcc22e`.
The first hygiene attempt rejected the stale whole-file Runtime review digest after its one-line typed-error re-export. Reviewing that
exact diff and retaining the 2,593 implementation-line count corrects the
content-bound review record; the scanner and thresholds are unchanged.
This removes callback diagnostic construction on this path; it does
not fund surrounding trap buffers, every guest-write error payload or complete
operations and supplies no Native execution authority.

#### Borrowed live guest-introspection exchanges

The live exchange handler now borrows the complete encoded response from the
original fixed guest frame, validates direction through the canonical borrowed
record decoder, and publishes its bytes directly into the fixed response entry.
Queued requests retain their encoded bytes through direction validation and
copy directly into the fixed reply. Successful exchange routing constructs no
owned record, argument String or payload Vec. Explicit owned protocol APIs
remain available to callers that request them. Error diagnostics, surrounding
trap-buffer ownership, callback stacks and complete operation funding remain
separate obligations.

A public borrowed exchange view shares all framing checks with the owned API;
its private validated fields preserve exact wire bytes and zero padding when
copied to a fixed frame. Existing owned and borrowed direction methods share
the same kind/channel policy. Existing response-before-request publication,
backpressure, sequence checks and delivery-before-consumption ordering remain.
Two protocol controls cover maximum payload/address/header equality and exact
mutation/truncation refusals. One live-router control exchanges maximum request
and response payloads and verifies deferred request consumption. Every existing
record variant compares both direction APIs. All fourteen protocol controls,
seven shared-memory controls and six live-router controls pass. All 123
white-box controls and every affected target's compilation pass. Content-bound
engineering hygiene passes. Canonical license checking stops at the unchanged
909 host-library and 963 host-test Clippy errors; its boundary assertions do
not run. ABI conformance passes at `6h6ydy3382gixqz06f52m37kn76j22lb`.
Mandatory application compilation passes at `2mna23zbrz1k9fgicnrrv0n5s1gcssws`;
all 319 exact supervision cases pass across nine groups at
`nckp7w26lkz429d69dcscivfg39vjra8`. All 5,307 committed Rust/TOML files at
`4189ebf43165ddfb08a669b6431878df8fccf72f` match immutable application source
`s6aid5fgzgh6rjgjla0y2acbyaaxw2g4`; the comparison record has SHA-256
`4621607d1c4ac8ca88ce6eafb0f68cef1801eee3782d358b8d29e5601f649dd7`.
This supplies no Native execution or cleanup authority and does not finish the RFC.

#### Borrowed guest-introspection wire validation

Shared entries now validate complete encoded records through borrowed message
fields rather than allocating an owned record and immediately discarding it.
The explicit owned decoder uses those same framing, UTF-8 and semantic checks,
then constructs owned strings and byte vectors only after complete validation.
A forged argv count cannot size an allocation before its framing and bounded
count are checked. Existing error precedence is preserved, including framing
and UTF-8 before argv count/length, and zero channel before message semantics.
Both shared-entry construction from bytes and repeated ring-entry validation
use this path. The wire edition, layout and direction rules are unchanged.

Three controls verify original payload/argv addresses, exact refusals for forged
argv counts and malformed fields, and every truncation of a canonical argv
frame. Every existing record variant also exercises borrowed validation. All twelve focused protocol controls, seven shared-memory controls, all 122
white-box controls and every affected test target's compilation pass.
Content-bound engineering hygiene passes. All 5,306 committed Rust/TOML files at
`891a6d5e44aef4fce66fde9e1f45b79b1eae9e00` match immutable application source
`a14jgf3h0iw4wqqgq3fifk46r58ki6mb`; the comparison record has SHA-256
`ed17ed3a7cccb1f95e87a45b63e6b76f62a62d04af3bf82252cb83abc4c60ab4`.
Mandatory application compilation passes at `rs5a7rhy14srbhy1z71435h01r5nifiy`;
ABI conformance passes at `7aj6hwvmkgy5m0pxg6444zn2yp4hhmpb`. Canonical license
checking stops at 909 host-library and 963 host-test Clippy errors; boundary
assertions do not run. All 316 exact supervision cases pass across nine groups
at `60qnwkv5azn8pjxn1kwqy88py6vvxq34`.
These components establish no operation payer, Native
issuer, allocation funding for requested owned decoding or full RFC completion.

#### Direct fixed-storage guest-introspection encoding

The canonical record encoder now writes directly into caller-owned slices after
validating every field, the complete length and destination capacity. The owned
Vec encoder shares the same canonical implementation. Doorbell replies encode
into their fixed frame, and live response entries encode into their fixed ring
storage without an intermediate encoded Vec or a second owned record decode.
The existing wire editions, layout, padding and sequence refusal order remain
unchanged. Decode allocations, error payloads and complete operation funding
remain open.

Four controls cover independent literal bytes, unchanged destination tails,
pre-mutation capacity and field refusals, maximum-chunk canonical entries with
zeroed padding, and zero-sequence/oversized-record refusals. Every existing
record variant also compares owned and fixed encodings. The nine focused
protocol controls, seven shared-memory controls and all 122 white-box controls
pass. Every protocol, shared-memory and plugin target compiles, and engineering
hygiene passes. All 5,305 committed Rust/TOML files at
`8f98f77f18f0c5e1d74f2ae50d34245553a2124b` match immutable application source
`l0d3xgaxgg7z7yy8jv7va11i4gs5z9gl`. The comparison record has SHA-256
`b2884edbefbdbc1372951748b7273cf17facb08e98a82feb1cea8e5798ad84c2`.
Canonical license checking stops at the unchanged strict controller Clippy
failures: 909 host-library and 963 host-test errors; boundary assertions do not
run. Mandatory application compilation passes at `5rnayzdd30h7mjvqygw79n6jq9py1wm6`;
ABI conformance passes at `a59lvvq08snpgphamh8v3xxd0k6sivbl`. All 313 exact
supervision cases pass at `qdnkjfy4md6l85ymm69gddqak7gbsvfv` across nine groups.

#### Borrowed live guest-introspection replies

The live guest-introspection callback now passes the original encoded 4,608-byte
reply directly to its synchronous guest writer. It no longer allocates and
copies a Vec solely for immediate delivery. A focused guest-input module owns
the common validation for borrowed replies and existing owned inputs: disabled
mode, matching range/length, configured capacity and exact delivery icount are
checked before the writer is entered. This does not fund the remaining decode,
record or error payloads, nor issue Native execution authority.

The fixed-frame control verifies the writer sees the original slice address,
bytes, range and delivery icount exactly once. A separate control covers all
pre-write refusals, early delivery and the original modeled writer error.
All 122 focused white-box tests and every plugin target's compilation pass.
The exact doorbell ABI inventory becomes 64. Engineering hygiene passes;
ABI conformance passes at `m9rw1vv4v7f3ck2dgmp1wmwzg60gmni7`, and mandatory
application compilation passes at `w1nhclmwm8fnmj4aicjx4bai8kd12p22`.
All 5,304 committed Rust/TOML files match immutable source
`8hmig3n6ir4633klj2w64rg2rx3lb57c`. The comparison record has SHA-256
`5ce6d28f1fc9674374b88186c29a56109600485bdd91c6086c65087e0c20347b`.
All 309 exact supervision cases pass in nine groups at
`r4ans31snsx3mqqk1s774g1zwlb4q6l0`.

#### Callback failure reporting

Live white-box failure reporting formats directly into borrowed diagnostic
fragments instead of first allocating a complete message. The writer preserves
the existing displayed error text and original owned names. Short writes retain
exact typed counts; kernel refusals retain their original I/O cause. Either
failure stops reporting without retry and still requests shutdown once. Writes
can now contain individual formatting fragments; a complete operation payer,
descriptor deadline and full diagnostic lifetime qualification remain open.

Three controls exercise exact output through a real socket, a short write and a
kernel refusal. All 54 focused live white-box tests, every plugin target's
compilation and content-bound engineering hygiene pass. Mandatory application
compilation passes at `1wsyi8v01mvr9dsh98jlayn142l75gw1`; all 5,302 committed
Rust/TOML files match immutable source `01n6dsspl7vf79qfxhm1bxsgqcr8vw6d`.
The comparison record has SHA-256
`d0e344d8b3cb15079f5858f7603be56223f9d2a1e5dd4377a526037e62f2ae01`.
All 307 exact supervision cases pass in nine groups at
`bvlj9bj30lzfx70g8bb70b2syqid9n87`. These components grant no Native Source,
executor or cleanup authority.

#### Typed marker entry validation

The live marker producer now moves the concrete shared-entry validation cause
into its sink error instead of formatting an owned String on refusal. The
focused error module keeps authored owned/static diagnostics and typed causes
in separate inline alternatives; Display preserves the original text and exact
coordinates. The error chain now exposes the original validation type. Existing
owned diagnostics retain their input allocation. This supplies neither Native
authority nor complete operation-payload funding.

The actual oversized-payload control verifies the typed length/capacity cause,
no ring publication and a subsequent valid entry. A separate control preserves
all three validation variants, maximal numeric coordinates, clone equality and
error downcasts. All 117 focused white-box tests, every plugin target's
compilation and content-bound engineering hygiene pass. Mandatory application
compilation passes at `imqiakkd1bcb95lkhz0lc3gsg58y8p3i`; all 5,301 committed
Rust/TOML files match immutable source `4rgf3chgidfa18842zv878vcc2h3nxh5`.
The comparison record has SHA-256
`ebcf1b526e64c3cebfc021842d53e047602a3a5e84a4cfb96785e7ca6c09c7a9`.
All 304 exact supervision cases pass at `igh57sscj6m38j8z22hiyp6k2j296kn6`;
corrected ABI conformance passes
at `68yqsj468pfjh4v2crw70dgak6454mj1`.
The initial ABI failure retains its exact 61-versus-60 inventory drift;
the corrected count is 62 because the new typed-diagnostic control belongs to
that same selected module test set.

#### Checkpoint component lock refusals preserve cleanup

The checkpoint component's live-compiled support now propagates Original status
failures and poisoned client/observation locks instead of panicking. QMP adapters
and runtime checks retain typed unavailable causes. Poisoned wire observations
refuse a begin reply. Final owner destruction still closes its retained aliases
without clearing poison or admitting more work. Fixed queue reads consume the
bounded prefix directly instead of relying on an unchecked pop.

Two focused controls cover typed refusal after QMP poison and real locally held
event-alias cleanup after observation poison. These peers issue no Native Source,
checkpoint receiver or Stop authority. All six focused retirement controls and
content-bound engineering hygiene pass, including the final exact test names.
Every host target compiles. Mandatory application compilation passes at
`01rri19z94sjr70b9ms3l2zb2hdfs0d0`; all 5,300 committed Rust/TOML inputs at
`c8c8014091309a994d7d14722d157b8ef8e68da4` match immutable source
`s5namavg5f88s77p5cs10gx399qxqxjb`. The comparison record has SHA-256
`e34c8f2329f1fb97b36fbdbf5bcc2cc33db9cbb5f1e5157bb7de1ba1061ca51d`.
All 302 exact supervision cases pass in nine groups at
`skfakchnr4g9hgrzfjrnp3045zswc4gm`.

#### Complete lazy resource-refusal diagnostics

Fault-result allocation, fault-event record and scenario-resource errors retained
numeric coordinates but their runtime Display fell through to the empty authored
message. Display now renders those retained fields only when requested, including
the independent Original post. An explicitly authored message keeps precedence.
The error representation, coordinates, ownership and operation behavior are
unchanged. A fixed stack-output control checks all three diagnostics before and
after a post refusal without allocating during formatting. All three focused
runtime-error controls and content-bound engineering hygiene pass. Mandatory
application compilation passes at `iddpfyqs5iqsn100mjjbjnmsn7vzgfpi`; all 5,300
committed Rust/TOML inputs at `db25f7eebcef8ee45b3d9e625de7d8eab8f08228`
match immutable source `z97lx5ybn7qhhyhyl44xwx725fs269w4`. The comparison record
has SHA-256 `4bbcf3a1026273d291263d73e404f89d048f6efaeb8f5920818f58fd5b78004f`.
All 300 exact supervision cases pass at `1mr3nqmlak3fc4453ijsdlxgdl3par93`.
This does not supply complete stderr or output-buffer funding.

#### Compact typed parent-Park QMP context

The two existing parent-Park adapter refusal sites retain their context in a
closed operation enum beside the full inline runtime error. Display preserves
the existing diagnostic text. The initiating typed cause and independent post
remain available through the original error chain, without boxing, discarded
coordinates or a lint waiver. The focused allocation/error-chain control passes
for both actual contexts and verifies that inline QMP errors stay below 128 bytes.
All 137 QMP unit controls and host target compilation pass. Engineering hygiene
passes after refreshing the content-bound review for the unchanged transport
implementation and its error re-export; the initial stale-digest failure is
retained. Mandatory application compilation passes at
`0czsv04w1aqgbq7h13f81kxfxj31sjbc`; all 5,300 committed Rust/TOML inputs at
`f4bb9a10f6c67f7412f2ef269a34b2d5190f64fb` match immutable source
`xj9vcv8alwpwvh20im90zp3dyvp798xs`. The comparison record has SHA-256
`052934c30fdce24d93e6540bc904dda73cf85ada9e9387091f58caeb2bc2a664`.
All 299 exact supervision cases pass at `81vimp7hqy94l6j816xd98xnrlh2arfy`.
The fresh canonical license check stops at strict controller Clippy with
923 host-library and 977 host-test errors, down
from 1,184 and 1,255 in the earlier reader checkpoint. Its boundary assertions
did not run. This representation change supplies no new operation or custody.

#### Borrowed fixed marker refusal diagnostics

Four existing marker publication and coordinate refusals now borrow fixed
messages. The owned-diagnostic constructor retains its existing signature and
moves an incoming String without copying. Diagnostic text and ring behavior
stay unchanged. The existing coordinate and full-ring controls now check that
clones share fixed message storage; the full ring still yields exactly its two
original entries. A malformed-capacity control exercises the real ring validator
and verifies that no entry was published. A separate diagnostic control checks
both static borrowing and preservation of the incoming owned allocation.

All 115 focused white-box controls, all plugin target compilation and content-bound
engineering hygiene pass. Mandatory application compilation passes at
`wgq36bw7g56p97xgm2a3jmvvy0xdc18j`; all 5,300 committed Rust/TOML inputs at
`908cbce844649982c54f6ef8b08efa2100133901` match immutable source
`v3jzypjkf51yv2hy5vkz0jv1lrbcivix`. The comparison record has SHA-256
`22f1361852010a8b5d460d3eec8240fde3b3f97952b0119682007c8c56e3f847`.
All 298 exact supervision cases pass at `kyprn2gnikz2s4zb8xbanvk99pkhm1w6`. These component controls
do not establish complete dynamic diagnostic funding or Native admission.

#### Typed marker callback refusals

The live observational marker path retains the actual guest-memory and safe
callback causes as typed errors. Ready-marker, campaign collision and TB-exit
refusals move the decoded event's existing name allocation into the error with
its original numeric status. Marker consumption exposes the decoded payload
without cloning it. The provider ordering and diagnostic text are preserved.
A focused child owns the marker/VMStop boundary; it grants no Source or cleanup
authority and does not resolve the underlying payload-funding obligation.

All 113 white-box controls, all plugin target compilation and content-bound
engineering hygiene pass. Mandatory application compilation passes at
`rdb5any9hajs8qxl08gflrglhbq80rmc`; all 5,300 committed Rust/TOML inputs at
`4d04e7b09987a676334ac2f419ddb5d63685e2a3` match immutable source
`m2gzhlaa26csr49v1yv1xsh6zbf01w63`. The comparison record has SHA-256
`013705a3d5fe88bc4795b7b7ed6dc8cc283919e5a07a67fd837c874ba98a6749`.
All 294 exact supervision cases pass at `7vnsvvdrhv6afh58frkyfh15fjpyba7l`.
The new controls check the original
string address, exact provider status, absence of a TB exit after ready refusal,
and retention of the actual already-deferred stop after collision. The existing
safe-decoder control also checks that consuming a marker moves its allocation.

#### Sealed Native borrower and physical Main finish awaiting composition

Signed `dacbcdbd16277d4c20b945e3f075cb709b66b7bb` implements the nominal
Source borrower of the already-entered producing Quantum. It retains the real
constructor and original cohort without starting another operation or clock.
Its Current is a one-way Source leaf. After the actual registered Module return
confirms Core-local consumption, Source saves that fact before the independent
physical-parent cut. A refused cut retains Source custody and both original
holders, marks uncertainty and permits no second Core callback or destructor.
The factual consumed observer supplies no execution or cleanup permission.

This branch passes 25 actual owning outputs, fifteen literal borrower controls
and 55 constructor controls. Nine additional dependency edges are structural
and unexecuted. Its complete configured Source/floor is 243,280/287,454 bytes;
its exact 216-byte increase is the embedded constructor reciprocal, registration
and borrower. The separate paid Module/Core journal remains unpriced here.
No genuine populated Module borrower, RR or cleanup issuer is qualified. The
borrower remains one attempt per process: known physical consumption does not
authorize clearing its retained attempt or reusing the constructor journal.
Actual parent retirement and deferred receiver closure remain unjoined.

The earlier signed Main-finish `4d354ac595` has a distinct external consumed
receipt and separate first/post history. Its first broad cohort stop and omitted
generated-directory-link failure remain recorded; the corrected immutable
1,918-object cohort and both complete system links pass under the original
bounds. Signed `1c9ce6387f` preserves physical return independently of semantic
health without changing that measured floor. Separate fixture `4866765d33`
retains the real system-main attestation while renaming only its entry symbol;
all five corrected whole-provider cases pass. Its first missing-attestation
link failure is retained.

Independent verification checks all four signed identities, changed-source
blobs, 187,932 indexed evidence rows, 87,508 literal links and 28 artifacts,
with zero differences. The record has SHA-256
`1aaacc11ba3268e4cf46b8bb4524c3c8fc8941c21903723694892aab97908c67`.
Archive bytes are rehashed; their full contents were separately audited by the
Native integrator. The combined reader/deferred/cleanup/borrower tree is still
under fresh qualification and is not the imported Native checkpoint above.

#### Typed white-box registration refusals

The actual registration path retains its doorbell and selectable-catalog
validation errors as typed sources. Static plan refusals are enum variants;
missing observation symbols and catalog-owner refusal retain their original
static symbol and numeric status. These eleven existing registration paths no
longer construct owned display strings. Their displayed text stays unchanged.
The same launch-plan check rejects absent and foreign app-random producers
before constructing producer state, without consuming branch decisions.

All 111 white-box controls pass, all plugin targets compile and content-bound
engineering hygiene passes. The new exact component binding exercises both producer
refusals and the matching-node configuration. Mandatory application compilation
passes at `iksqy0zq7dygva09m83ck3z5l19x1y9x`: all 5,298 committed Rust/TOML
inputs at `17af9ee4221577c18294228bad7c5db7dea63a2d` match immutable source
`x46gjjy0n2iycsffa5qqjvbgdzqm05d4`. The comparison record has SHA-256
`c18b360377b8d026c5d23f882f31095ef9948a3c853aeec3315c96083111769a`.
All 291 exact supervision cases pass at `shzc4c3w15lhnhhqjs6rbh0q1p1lga4n`.
The moved catalog and doorbell causes can themselves own diagnostic payloads;
this change does not establish their complete funding or Native admission.

#### Typed white-box callback refusals

Seven existing preflight, registration, restore and dispatch boundaries now
move the original `LiveWhiteboxError` into `WhiteboxCallback` rather than
allocating its display string. Standard error sources retain the typed cause;
formatting preserves the prior diagnostic text when a caller requests display.
The public error type supports the existing clone/equality contracts without
boxing the cause or adding a new allocation to these conversions. Underlying
white-box error payloads, callback output, stderr and complete stack funding
remain separate obligations.

The actual missing-symbol installation regression verifies the exact typed
capability through the three enclosing error sources, with no control traffic,
QEMU registration, time-control request or wake registration. All 110 white-box
controls and all plugin target compilation pass. Engineering hygiene passes
after refreshing the stale content digest and line count of that strengthened
existing test; its first failed check is retained. The coordinator's existing
responsibility reviews are content-bound, with unrelated formatting restored.
Mandatory application compilation passes at
`h5qfmdrrxj98ycnnp2c05bp8fv1fxfg1`. All 5,298 committed Rust/TOML inputs at
`66bb8fe701b3e681469624c5a1370f873518d0a2` match immutable source
`s000y3y08k9wxcqha4iy7p5rx5q6lqxm`; the comparison record has SHA-256
`8a32d76d7bc96ab79005ad5a8e89d0788f8125157270bc11193ce988c150b1c2`.
All 290 exact supervision cases pass at `mbhrvsp67nw5g09g5mk84gz8fws8g3if`.
This component control
grants no Native Original or activation.

#### Typed network stop refusals

`27659ae233` retains the actual network ring error or inline frame/stop
coordinates at the stop-consistency boundary. Display formatting remains lazy;
the same Original's independent post still runs after either refusal. A real
memfd-backed ring regression covers a corrupt tail, a mismatched source slot
and a mismatched instruction count. Runtime binds before publication so the
control exercises the actual unpublished frontier. All three refusals allocate
and reallocate nothing, leave the ring and wake unchanged, and retain the typed
cause. These inconsistent component snapshots grant no physical Native stop.

The initial compile exposed the actual 32-bit frame sequence; a subsequent
control setup bound Runtime after publication and therefore observed no new
frame. Both failed attempts remain recorded. After correcting those two test
assumptions, the mapped regression and all 68 runtime regressions pass. The
private-feature mapped regression and four paired fingerprint controls pass.
Content-bound engineering hygiene passes. Mandatory application target
compilation passes at `rvx6s8vrfhh0pzmwnyc3dlm8fch7vi5j`; all 5,298 committed
Rust/TOML files match immutable source `mqczf8kqqy5svsg6brg4h6202jzkpq99`.
The comparison record has SHA-256
`9abfaaeade9b42f5ef053b2b05b613d10287ca0ce13031a072d8260265fd66e5`.
All 288 exact supervision cases pass in nine groups at
`il7xpcllfdzk2dahm7ns4qsiy39ancqz`. Complete diagnostic funding, actual
Source stop custody and Native admission remain open.

#### Typed fault consumer refusals

`3a36467830` retains actual fault transport and fault event causes at inspection
and three dequeue sites. It defers diagnostic formatting while preserving the
original display and standard error source. A kernel-backed event-ring control
seeds impossible indices and a zero-filled event header; actual inspection and
dequeue refuse without allocations or reallocations, preserving all mapped
bytes, the untouched wake and the same Original's independent cancellation
post. The prepared event staging capacity is reserved before the measured cut.
Those malformed wire observations grant no Native event or consumer authority.

All five mapped-error controls and all 67 runtime regressions pass. The new
control also passes under the private measurement feature, alongside all nine
paired fingerprint regressions. Engineering hygiene and mandatory application
compilation pass. All 5,291 committed Rust/TOML files match immutable source
`wpswyr9bjhsabp1i6q5m606bp3cjy48d` for application output
`wifzdjnprlb2aal6v4hnhd3fkgliqnwg`; comparison SHA-256 is
`a3d08ac6ca4e17d4ed068d232a860686c00e1c6a3c850d5feb08ff7d17f4895e`.
All 284 exact supervision cases pass in nine groups at
`gzxikpm8axv29vmidcvm93zv4jhpq532`. Complete error payload funding and
Native admission remain open.

#### Staged Native physical publisher access

Signed `8f188d7b6531f62a284cf7a38b05f536948d3236`, tree `57172146`, remains a
public Source checkpoint awaiting cumulative integration. The persistent
nonwaiting preexec gate publishes canonical transitions before unlocked Source
reciprocals; separate physical identity reentry retains its own receipt. Actual
callback return, first status, independent identity post and consumption stay
separate. Known returned negatives can release physical access while semantic
debt remains. Unknown return or a refused physical post keeps the parent held.

The focused matrix passes 26 cases, with fourteen final owning/configured
objects rebuilt sequentially under the retained worker/resource bounds. Actual
preexec ownership grows by 9,040 bytes to 211,176, charged once by its real
prebirth layout; Source/fixed floor remain 242,328/286,262. Root verification
matches eleven signed source files and 1,093 regular evidence files, checks
GPG/DCO/tree/parent and the complete-source archive hash. Its comparison record
has SHA-256 `bc2fd90fa79aa8db34b47756aa3dda056de4bceea88517c2ef7e6397bea83322`.
The agent's 78,166-blob/mode reconstruction was not independently rerun by that
comparison. Initial component stripping failures, noncausal omissions and an
excluded diagnostic compiler overlap remain retained. These controls do not
execute genuine populated Module/deferred/RR admission or qualify a whole ELF.

Signed `02d783addb`, tree `77fd0315`, adds the Main-issued deferred lifetime
prerequisite beneath that same pending constructor. Five Source parent
reciprocals and the actual gated preexec recipient child precede Module defer
and its independent current callback; born-negative Module fields remain
retained. Main preparation supplies neither physical Main return nor RR
eligibility. All 28 affected configured owning outputs, four complete-provider
entry/refusal controls and 26 access controls pass; both configured system
ELFs link with the actual regenerated SDK export list. Source/fixed floor become
243,032/286,966 and the separate preexec owner becomes 212,120. The real Module
deferred/Core/cleanup journal and execution stack remain external prerequisites.
Independent verification matches twenty signed sources, 788 regular evidence
files and five artifact hashes, including the complete-source archive and
conventional bundle. Its record has SHA-256
`2f91636f8e07eda71d29105ebe183953a5022998733680595dd98b1441f3ee2e`;
the archive's 78,170-blob reconstruction was not independently repeated. Initial
link/export/fingerprint refusals remain retained. Review identified duplicate
Meson dependency entries for correction in the subsequent cumulative cut.

Signed `adacca21ec`, tree `192a138b`, composes that deferred lifetime with
the separately retained `43fa571778` physical executor/boundary lineage. Its
production executor files match the reviewed 43fa parent exactly; extractor
fingerprints reflect the joined Source. All 27 configured objects and 55
physical controls pass. Source/fixed floor are 243,032/287,110; the extra 144
bytes are the actual boundary journals. Independent verification matches
nineteen signed sources, 542 regular evidence files and five artifact hashes,
with record SHA-256
`4ee76f338ebf3be53d3754625378781dab451351fc2db267c7f218ce678d2014`.
The complete archive's 78,178-blob/mode reconstruction was not independently
repeated. Signed `b1663af68d` removes the three duplicate Meson dependencies;
its sole parent is adacca. Neither cut qualifies a complete matching ELF,
physical Main finish, semantic RR permission or a borrowed class-one Original.

#### Staged Native executor and cleanup prerequisites

Signed `1ea154f505` retains separate actual normal, longjmp and atomic executor
cleanup journals after execution permission is revoked. Signed `43fa571778`
joins that physical lineage and retains distinct dispatch and settled-idle
boundaries in their real RR paths. Refused diagnostics do not suppress physical
unwind or ordinary scheduling. Neither physical markers nor completed callback
status issue semantic cleanup authority or a work-unit outcome. The executor's
fifty omission controls and the boundary's 24 controls pass, alongside their
configured object and extraction cohorts. Independent boundary verification
matches ten signed source files, 1,237 regular evidence files, 72 literal source
links and four artifact hashes, with record SHA-256
`5812d13becaa53d7060dbac834edf0728f66191f56988f5d362670b7c5a8d1ab`.

Signed `28fc4cd700`, tree `c1954a38`, adds only actual installing cleanup-provider
registration on that exact 43fa base. It authenticates the real member, service
and paid Runtime before publishing the binding, then retains independent
Original and physical identity posts. It invokes no Module callback and births
no cleanup owner. Holder, epoch, 176-byte observation and separate 32-byte result
require 224 actual Runtime bytes before the complete Module journal. Unproved
Runtime backing withholds the result write and retains Source debt. The actual
192-byte Source registration raises that base's fixed floor to 286,598. All 33
configured production objects, three full extractors, complete floor omission,
fresh CPU geometry probes and 21 component omissions pass. Independent review
matches eleven signed sources, 857 evidence files, 72 literal links and four
artifact hashes, with record SHA-256
`885db0a44d83ca458d80e9bff80389f61efbabe32f91fe8b40c8e21e2880fe2b`.
The initial comparison accidentally retained the previous snapshot's literal
inventory hash; its failed record and corrected comparison remain separate.
Complete archive contents were not independently re-audited. These staged
checkpoints are not imported; genuine Module/Core cleanup preparation, actual
Main/RR/deferred ownership, persistent Outcome and selected execution remain
unexecuted. Inline storage does not price the execution stack.

#### Independent revocation and return refusals

`be75007902` runs actual physical offer revocation and bounded return observation
independently, including when either refuses. `538e23716f` retains each cut's
own first refusal alongside the unchanged session-wide first cause. Four
kernel-backed combinations prove that a negative revocation cannot skip the
return cut and a negative return cannot erase successful revocation. The
original ticket remains unconsumed and return bytes unchanged.

All 56 local Source-supervision tests and engineering hygiene pass. Mandatory
application compilation passes at `5hjsihirdn366jnk3w9d6n2frsyiqyil`.
All 5,290 committed Rust/TOML files match immutable source
`rsd7nilp1kvqlkm35h8jq8xflw03g5qq`; the comparison record has SHA-256
`9b2b0e6b701f861ef0a888cd787fa2c4bb76386d6b6b9d7f4034b92da8d6a853`.
All 275 exact supervision cases pass in nine groups at
`8303673rvih1c3mljhhplfpicidrw5fk`. Physical terminal
consumption, actual borrower return, Closed and reuse remain unimplemented.

Signed `15a7a00279`, tree `facf7b3a`, adds factual Core Current/returned
queries over the existing CPU-local normal, longjmp and atomic cleanup frames.
It authenticates the actual current CPU and retained RR parent before nominated
frame payload. Returned observes irreversible local consumption and its cleared
holder independently of a saved negative first, while the genuine CPU/QOM pin
remains required. No new Original, cleanup guard, Source owner or permission is
issued. Source/fixed floor remain 242,520/286,598 with no added record storage;
individual function stack estimates (48/80 bytes) are not a complete stack payer.

All 36 configured objects, three extractors, two preexec extractions, architecture
probes and complete floor measurements pass. The bridge's 22 independently
rebuilt omissions and retained journal/atomic/execution/Main controls pass under
their original bounds. Some inherited inner calls lack a separate timeout; the
legacy 180-second outer bound remains explicit. Independent verification matches
eleven signed sources, 1,373 regular evidence files, 72 literal source links and
four artifact hashes, with record SHA-256
`7b34bc086530376830304411d0b9be9d45b625a64c5e6c78ae1a891a323f305f`.
The agent's 78,174-blob/mode archive reconstruction was not independently
repeated. Actual QOM/RR/Module enrollment, cleanup Prepare/Enter, semantic Outcome
and selected execution remain unexecuted. This cut is staged, not imported.

#### Native pending lender and offer composition

`a6dfafc5ac` imports signed atomic commit `075832a98a`, tree
`6e6ecba6ed95a7bbbaba681be8640315359e25c8`, retaining upstream base
`1ed0467509`. The composition adds pending-command custody and nonissuing
offer observation. The independent verification matches all 984 signed changed
source files, 11,787 regular evidence files, 312 literal symlinks and three
artifacts. Its comparison record has SHA-256
`2519dc27a8fc4485d880ff530c87fbecb9ab1ecabeabff9a1625885e6adcb63a`.

The independently configured 1,918-object cohort passes in 261.582 seconds
under its unchanged 600-second/6-GiB bound. The first normal delivery attempt
on `db3a4dba7` times out at 60.021 seconds; that failure remains preserved.
The signed `d009060d57` scheduling correction uses two workers for the same
nine independently generated writers, retaining their deterministic proof order
and joining before the existing seventeen-case access sweep. The generated
inputs, commands and proof ordering match. Its first normal delivery passes in
53.514 seconds under the original 60-second/6-GiB bound. Earlier stable
qualification results are explicitly bridged, rather than relabeled as reruns.

The actual Source is 240,544 bytes. Twenty-seven separate physical getters add
43,846 bytes, for a complete fixed floor of 284,390 bytes; embedded owners are
counted once. The updated 345-created-file license inventory passes at
`x36qci0p0j02d1j58z7fdly2nzfw4mkk`. Exact raw atomic reconstruction passes at
`1axn9nmvybxzl2xrjwb9z9v4gcnvxzj6`. Fresh owning Source qualification passes
all 187 tests at `bzmc89qmgxqxgwwlxslzsl55db799n1r`. ABI conformance
passes at `x9i3502ir12did03rlxqccsvmqi0g7vh`. The twenty-four-suite
Native runner passes all twenty-four independently bounded custody suites
at `1hmlbxqk98hdd3hvczj3xn9vlzi1v6av`. The full package still fails
the genuine launched dirty-iterator lifecycle check. Neither these observations
nor the passing physical controls supply an actual Module Original, selected
execution, terminal consumption or callback activation.

#### Native pending constructor custody

`a0651364c1` imports signed atomic commit `eb298a8e1c`, tree
`d940cee896d4bc88080fa9be294fac808f7da67c`, retaining the same upstream base.
The constructor retains canonical member/lender reciprocals before the Module
callback, separately journals born negative children and independent posts, and
preserves actual attempted/consumed physical facts through returned-current
observation. No-birth and parent returns refuse unresolved constructor debt.
Current observation uses the authentic callback frame and disjoint output;
it does not issue a Module Original or authorize CPU execution.

Independent verification matches 987 signed changed source files, 10,667
regular evidence files, 156 literal symlinks and three artifacts with zero
mismatches. The comparison record has SHA-256
`428a6221a6c8dda69eda4b267738bcf809a08edf5b76bc67d6f2eb9e762e48fb`.
The complete actual Source is 242,208 bytes; twenty-seven separate physical
getters add 43,846 bytes, giving a fixed floor of 286,054 bytes. Constructor,
registration, member and lender extents are counted in that Source, not added
again. This measures the joined configured types and actual provider floor.

The fresh 1,918-object cohort passes in 193.501 seconds under 600 seconds/6 GiB.
Seventeen normal ELF links pass in 7.794 seconds with 51 genuine providers.
The first normal delivery fails in 6.257 seconds because its generated fixture
omits a newly used output helper. Signed `9e46dbbedb` selects that helper in
both delivery closures and the service fixture; its first normal delivery
passes in 55.873 seconds under the unchanged 60-second/6-GiB, two-worker bound.
The stable sweep then exposes a member-return fixture missing the constructor
closure check. Signed `065a246187` repairs its exact callee and six hash pins;
the positive and twenty-one original omissions pass in 12.957 seconds.
Normal delivery remains attributed to `9e46dbbedb`; the final bridge verifies
86 compiler inputs and 97 generated owning C files, with seven focused
fixture/hash changes. Earlier timing failures retain their own attribution.

Constructor controls rebuild 54 omissions and retain nine additional structural
guards. These controls do not execute a genuine Module issuer. An auxiliary
setup helper overwrote one initial stale-helper diagnostic with its later
success log; the retained note and original tool traceback disclose that gap.
The two failed archive audits and metadata-wrapper Git-path failure remain
recorded separately from their corrected results.

Exact raw atomic reconstruction passes at `qfg1q9dxgxkw54ypk1aqxnhg78zc854q`.
The 348-created-file license ledger passes at `2xagzn6cil3pw3jd2l5m4jlqd0f2z92m`;
all 187 owning Source tests pass at `6bi6czwabzvzrfyk29fxdqbm8rxmnv2l`.
All twenty-five bounded custody suites pass at
`jpa5vrqsrbxj1j6lw2awhwl5j6qc95zf`; ABI conformance passes at
`wn736jkph0lkgypzf97gwjlcx1wiyl3a`.
Aggregate regeneration still fails because full QEMU fails the mandatory
launched dirty-iterator lifecycle fixture. Genuine Module issuance, selected
execution, deferred RR custody and complete read/cleanup returns remain open.

#### Physical command publication and revocation

`3558879a7c` retains each exact command and its canonical encoding in the paid
session before shared effects. It publishes one physical offer and fresh ticket,
and implements one attempted withdrawal that preserves a lost acquisition race.
`9e568305c8` adds once-only revocation: the next publication sequence changes
permission while preserving the immutable command, original offer identity and
ticket phase. An uncertain CAS cannot be retried. These physical operations
alone grant no Source membership or Original and return no borrower.

Thirteen publication/withdrawal controls and the later sixteen-control publisher
cohort pass without allocation in their measured physical paths. Hygiene and
mandatory application compilation pass for both checkpoints. The latter output
is `fmi8addgh510a0hr2nrrra57654l93sq`; all 5,285 committed Rust/TOML files match
immutable source `v0yb846wswhhqmp4bkjr926x6fhzfswb`. Its comparison record has
SHA-256 `26577943bb2f53c389a1aa927a788575040226b96a9e053000af440745c92cc0`.
The publication checkpoint passes all 262 exact supervision cases at
`rnkip1vqcyggd9d6sw4hlgw7161dzsnf`. The later revocation checkpoint passes all
265 exact cases at `l78l8s375lyd3sspcb0baspsjz68v2kb`. Complete stack/error-carrier
pricing and genuine remote return remain unqualified.

#### Retained pending Quantum reports

`f8316aa139` retains the actual pending report's current and ceiling coordinates
inline through the channel and node errors. Repeated polls preserve the same
pending Quantum, tuple and wake generation without formatting or allocation.
The diagnostic text is produced only when displayed, and the typed source
survives scheduler conversion. A later genuine report completes that same
pending operation; an observation refusal grants no publication or retry
authority after its actual Original refuses.

All 63 quantum/mapped tests and nine node-error tests pass against the final
source. Engineering hygiene and mandatory application test-target compilation
pass at `nx01yx25kxphx01k84bdiarcaryp8a6i`. All 5,283 committed Rust/TOML inputs
match immutable source `by0p78szxkbvxb21xyp3l843wqi1ry5v`; the comparison record
has SHA-256 `bcd922d4e1f332df5d1cc6d49432b9ef7f56ad5e0202bddec9b421ad1628d768`.
The earlier local run was superseded after a final source-chain assertion was
added. Backend conversion still uses the shared diagnostic carrier, whose
complete prebirth funding remains unproved. This component establishes no
Native operation authority or physical-return receipt.

#### Observed scheduler command reservations

`774e1287b0` retains the actual bounded node snapshot in a move-only receipt,
reserves that exact observed scheduler generation with one CAS, and checks the
report before and after reservation and before commitment. Quantum start uses
this receipt after computing its effective ceiling once. Input preflight precedes
ring effects; tuple commitment retains its separate once-only wake. An abandoned
writer consumes its fresh generation without changing the previous tuple or wake.
Inputs already published before a later refusal remain actual caller debt.

All six physical receipt controls, 62 quantum/mapped cases, strict shared-memory
Clippy and engineering hygiene pass. Mandatory application test-target compilation
passes at `s92bz19y9f49ghr4kdnz556jp508qa5b`; all 5,283 committed Rust/TOML files
match immutable source `9pdm4gqad3ww1n784a4n56yhh76n3l96`. The comparison record
has SHA-256 `5ef090e653efb784db1c6739af38845c5b90bd945a5206c96f590a2ac104cd84`.
The initial module-path compilation failure, moved-test-input failure and stale
source-order assertion remain separate from this corrected final run. The
expanded supervision cohort passes all 254 exact cases at
`lpqbgxb5dsi2hqa6ch6zfkfcxpmcxk52`. That frozen run predates the pending-report
checkpoint above. These physical checks issue no semantic
Original, Source lender, deadline or Native execution authority, and do not replace
independent control/restore validation or actual immutable command publication.

#### Independent health and Quantum posts

`6e18b93b75` checks the same entered operation after every quantum health
return, including successful health observations and Source refusals. The
initiating Source owner and operational category remain intact; its independent
negative Original post stays inline through driver and scheduler propagation.
A runtime refusal already paired with a negative Original post returns before
later health can replace it. Ordinary Source-health priority over an unpaired
transport failure remains unchanged.

All 33 driver tests pass in both default and private-measurement configurations,
along with eleven worker-failure and nine node-error tests. Engineering hygiene
passes. Mandatory application compilation passes at
`37vd3x9nskvvh2ppjyrv6rkwz3zzf4yv`; all 5,281 committed Rust/TOML files match
immutable source `n1rqh4clizyjpr6dx6aqh3dddnjlg3a5`. The comparison record has
SHA-256 `f674716588f0c3a337b1ab44381e60e880f73987070508b9432dd4ee6e6c293e`.
All 248 exact supervision cases pass at `qs376ksdwzfk87r71pwmfpnbg7az22r2`. The helper's first/post join allocates nothing; this does not
prove complete diagnostic-carrier funding. In particular, scheduler conversion
of a worker failure with a newly retained post needs the complete paired
carrier, rather than the worker-only shared-control shortcut. Genuine Native
execution and physical return remain unqualified.

#### Bounded completion and typed channel observations

`c6ce47af32` makes the five quantum channel readers and pending-completion
observation refuse an occupied node publication after one bounded attempt.
The refusal retains its typed slot coordinates inline through channel and node
conversion. Only a changed report or occupied advance publication is retryable;
a terminal report failure cannot authorize another attempt. A pending quantum
survives observation refusal without republishing its tuple or waking again.
Compatibility readers outside these six paths still need separate review.

All 62 quantum and mapped-adapter cases, seven focused mapped-read cases and
eleven postcheck cases pass against the final source. Engineering hygiene and
mandatory application test-target compilation pass at
`r7590d54v44czcvi867ra5zdgh3scx5z`. All 5,280 committed Rust/TOML inputs match
immutable source `y4mqafwvaryc96fk21j25f1n913wgdaz`; the comparison record has
SHA-256 `fac5f7071a7943667325e0424cc5398d2e83f0d79c916fbd182ce6400650895a`.
The initial missing-match compilation failure and the test's repeated-view
log-spill allocation failure remain recorded separately from the corrected
final run. All 245 exact supervision cases pass at
`j8rnm0wb98h2xw1qr2zxw3imc0i3j3j9`. These component checks establish neither the actual publisher command join nor Native Advance
admission, complete diagnostic funding or physical return.

#### Independent channel refusal and Quantum post

`23c1def9c3` observes the same retained operation after every quantum start,
post-publication hook and completion result, including failed channel returns.
The initiating channel cause and independent negative Original post remain
inline and both survive scheduler conversion. An initiating typed operational
category takes precedence while the complete pair remains downcastable. A
retryable completion failure cannot trigger another poll after that Original
has refused; neither failure completes work or proves physical return.

All eleven focused postcheck tests and all thirty async-driver tests pass,
including the thirty-test private-measurement configuration. Engineering hygiene
and mandatory application test-target compilation pass at
`9d0j3iacz3app1icsza2gkx1n8wsmvnd`. All 5,279 committed Rust/TOML inputs match
immutable source `93shk08abmwj6jz5cd60azydg35m8w5m`; the comparison record has
SHA-256 `505fd3bb41455ee99f94dc3793844d81161988253e10db0529121556bb5ddd6a`.
The first missing-test-import failure remains recorded separately from this
final stable-source run. Five exact component bindings bring the committed
inventory to 359. The actual command producer, Native Advance and selected
physical lifecycle remain unqualified.

#### Bounded command observations and scheduler wake receipts

`a9b46e94e8` exposes the actual scheduler writer reservation, tuple commitment
and separate once-consumed wake receipt. Real slot identity and the reserved
generation remain attached to those move-only receipts. Tuple commitment can
precede the actual producer's command publication; a dropped receipt never
rings a wake, and replacement refuses another wake. These physical receipts
issue no Source, lender, deadline or execution authority. All nine focused
scheduler controls and strict shared-memory Clippy pass. Mandatory application
compilation passes at `2c4jfg9mnv2vyrc44kchnbzp21nbjjqc`, with all 5,279 committed
Rust/TOML inputs matching immutable source `gja61qxvs3mx836dfv4nngh8byssi0y4`.
The comparison record has SHA-256
`fda75e87f83858c0915af40e3067991051b62d99f02ba199100f01e66ef1d68d`.

`5403c5f04b` adds one bounded node report and scheduler-tuple observation and
uses it at the actual hot-path quantum start. An odd or changing report returns
a typed refusal rather than spinning inside a retained operation or scheduler
reservation. Compatibility readers retain their existing waiting behavior.
The real held-writer control refuses before inbox, tuple or wake effects.
All eleven scheduler controls, 36 quantum tests, strict shared-memory Clippy and
engineering hygiene pass. Mandatory application compilation passes at
`xdyyhik7xg9hid3d3ckl5cmfq351n2p5`; all 5,279 committed Rust/TOML files match
immutable source `k3k7blb7ij1nv3bmszs9pr5y094a4j21`. The comparison SHA-256 is
`279103214b73bdbec4d58945a9a9748d81dda00fc15da8c0068e34235129c9d6`.
Seven exact component bindings bring the committed inventory to 354; the
expanded 237-case supervision run passes at
`sb0s2grwrm3kgh04nn88l8y332dp483j`. Neither checkpoint integrates
the actual immutable command publisher, recipient or asynchronous Advance.

#### Paid host publisher handover and cumulative Native custody

`e9784079c4` retains the actual publisher memfd, shared mapping and two distinct
events inside the Source's prepaid once holder. The complete allocation and
scratch overlap, page-rounded backing and four-descriptor physical peak are
reserved before birth. Each born mapping, descriptor and exported alias is
journaled before its independent Original post. Uncertain physical return keeps
the complete allocation and payer; exported roles require actual launch cleanup
proof before local physical disposal. Existing single-node admission remains
in force. This physical session does not issue a Quantum command or operation.

The six new real-syscall component controls, five existing alias controls and
seven startup controls pass. Setup completion passes at
`lsgy96d0w853f2sxbm477milc6w2921i`; engineering hygiene passes at
`zcvijji792yblcv5r97p578pnwrl3izi`. Mandatory application test-target compilation
passes at `k68kwnrn96al45149r04jpway1i91mqs`. All 5,279 committed Rust/TOML files
match immutable source `i01q6vamp0b3q5ymb5k7lpyqyxmdqws6`; the comparison record
has SHA-256 `e5ae25b46977de09b3777bf8a359621ec44dec1af5606de35713007eacd5d103`.
The receiver's 224 exact supervision cases pass at
`c8chba6qq90s5rs7g64nh4aycg4wg8ld`; all 230 expanded host cases pass at
`5k9ppsxby5s1wbxpc4pc1acbp9w5i1ig`.

`3811d30684` retains atomic Native commit
`e1dde9de5750f667487389a80533020641c0b249`, exact tree
`446bedad29f0a2b646ba03c0a63da8e61413cdcd`, on the sole pinned upstream base.
Independent verification matches 8,855 sealed evidence files, 156 literal
symlink targets and all three artifact hashes. Deterministic signed
reconstruction passes at `6kks9n3b5mmydlxhnd102djcc4kkmr4k`; the complete
327-added/zero-deleted license inventory passes at
`cjd2aj9hwb94y46y3s1jaj8q7a6vhmq5`.

Its retained configured evidence includes all 1,918 affected objects, both full
system links, six owning units, 69 preexec omissions and the first and only
normal delivery entry at 51.556 seconds under the unchanged 60-second bound.
Actual Source/fixed-floor extents are 230168/274006 bytes. Runtime service
custody remains attached to the actual registered component through genuine
Source group closure; independent drain and physical-return observations retain
all eleven group owners' debts. Construction register reads require their own
actual entered producer and read children. These facts do not qualify a genuine
selected external caller. The raw deferred fixture still has its direct-link
gap despite a separately passing authenticated complete closure; the mandatory
dirty launched lifecycle still fails. Prior conflict-resolution, configuration
and output-audit failures remain in the sealed evidence.

The configured proof's seventeen standalone suites are not selected by its
owning/delivery entry. The repository custody runner now selects sixteen of
those suites, including Runtime service transfer, construction read and mapping
journals, with each suite's original independent bounds. The ordinary QMP
physical mapping observer remains separate. Fresh owning Source qualification passes at
`5bglky5igc4s7izz6nc79gvdxz51jvq6`. The full package completes all 4,060
build actions and passes 25 of 26 fixtures; mandatory launched dirty capture
remains its sole failure. All 966 changed signed source files match the kept
package build; comparison SHA-256 is
`da5f81873fa59b034b2dda67eb037152542ab91f4eec9fcfb693865fbd8ed4fa`.
All sixteen expanded custody suites pass at
`gbmn0p5dbslkg8ibccmkdcm5nwnsyba2`, retaining each independent bound. Fresh ABI
conformance passes at `kn0zhw67nvzr9frjwhvlv0qpwx3j0ylf`. Header/service custody and
these component observations do not enable Source activation, an immutable
command membership, asynchronous Advance or CPU use.

The fresh canonical license-boundary gate fails before its boundary assertions:
strict controller Clippy reports 1,189 host-library and 1,262 host-test errors,
including retained large error owners and unused unfinished ownership paths.
The prior counts were 1,177/1,250; the added host methods add twelve diagnostics.
No check or owner is removed to turn those failures into qualification.

#### Rust publisher receiver and paid Runtime custody

`c37c5a1808` adds the strict v4 process-private Setup6 receiver. It borrows the
Native-owned base and publisher roles without importing descriptor ownership,
retains the first current-view failure, and refuses mixed output or plan
editions. The actual component registration path transfers service custody into
a canonical field of the same prepaid pinned Runtime. Teardown returns actual
Source registration groups and workspace custody before the component can drain
the service; uncertain return retains the entire Runtime.

All 1,150 plugin unit tests pass, including six new ABI, real-alias and refusal
controls. The hermetic setup gate passes 45 selected tests at
`6q2bbd72gg45ixw7iw40r0111xsr5mq0`; engineering hygiene passes at
`zcvijji792yblcv5r97p578pnwrl3izi`. Mandatory application test-target compilation
passes at `7g4cs18mj0a4yhwwmdw7na1j53flhxaw`. All 5,277 committed Rust/TOML files
match immutable source `lwlbbzllsj404ymsqvx8447syi3k4mwv`; the comparison record
has SHA-256 `1d998b932d19b365999593ee7df8f1f8aa88f1ebb2404bdd3ed6a59a358dda67`.
These are component and compilation results. The paired host session and Native
artifact are retained in the later checkpoints above; actual installed service transfer,
its physical return, Source activation and command execution remain unqualified.

#### Installing plan reads and setup gate correction

`54caaed474` keeps every immutable plan `pread`, including an EINTR retry,
inside checks of the same retained installing Source. It saves the syscall
result before the independent postcut, refuses another read after a negative
observation, and preserves an initial plan-validation failure alongside a later
failure-ACK error. Six read controls use real file reads and injected refusal
boundaries; a seventh exercises the outer validation/ACK failure path. These
component controls do not construct an accepting Native Source.

All 24 narrowly selected setup tests, 73 focused policy checks and five local
hygiene checks pass. The hermetic hygiene check passes at
`zcvijji792yblcv5r97p578pnwrl3izi`. The first local hygiene attempt refused the
changed setup source's stale review digest; the final reviewed digest passes
without changing the scanner or shape limits. Mandatory application test-target
compilation passes at `hdn3j82dbk4kgckr2nk80rhij8daqccb`. All 5,274 committed
Rust/TOML files match immutable source `np2iydgssjn4ggn8g0xrb2ny180k115f` and
the then-current working tree; the retained comparison SHA-256 is
`5f47fb47b778ed908934e2c7794ab4945723ea4968fe8ad230abd575469c69eb`.
All 218 exact supervision cases pass at `7iwxg7vg1r0gxwv39ajixz95n45jg9b4`
with component-only qualification and no advertised capabilities.

The first setup-completion gate evaluation refused three stale source contracts:
a three-descriptor roster, a direct Rust-owned mapping call and the old wake
arming call. `edb742a73f` checks the actual five mandatory roles, optional sixth
workspace role, retained installing Source, corroborated backing identity and
Source-created Native mapping. The standalone Rust mapping remains confined to
component fixtures. The gate passes all 39 tests selected by its broader `setup`
filter at `b190pkxl1afi8alhddxns8sn76zrwa3x`. Its result explicitly records
component/source-contract coverage and an unexecuted genuine Native positive.

#### Earlier workspace evidence

The following historical evidence distinguishes the then-complete workspace run
from its whole-node RAM cleanup changes. Local Cargo uses the AOS toolchain with
remote builders disabled; a packaged Rust application build is not a prerequisite.
Passing historical results do not qualify the later ownership changes.

| Surface | Latest local evidence | Remaining qualification |
| --- | --- | --- |
| Workspace | All 520 test targets compile after the whole-node RAM cleanup cutover. Workspace doctests also pass after that cutover: 41 passes and 26 ignored cases. Before the cutover, the 510 non-daemon targets completed with 12,085 passes, 88 failures and 75 ignored tests. | Rerun the complete workspace after the affected integration failures are fixed. Earlier targeted tool/configuration and watcher reruns do not establish a passing workspace. |
| Affected host, daemon and test support | All 68 all-target, all-feature targets complete: 3,611 passes, eleven failures and 51 ignored tests. The daemon library passes all 1,881 active tests, including the physical 512 MiB quota case. The host library has 1,210 passes, eight guarded-helper failures and four ignored tests. | The three source-policy failures include two stale shutdown companions, subsequently repaired and rerun below. The eight helper paths still need genuine receiving and funding integration. |
| New RAM cleanup controls | All 22 cleanup controls, both registry controls and all eight whole-set teardown controls pass in the affected runtime run. The latter include actual descriptor destruction and a panicking node-field destructor that permanently refuses return. | Component success does not qualify complete native provider return, failure payload funding or lower physical peaks. |
| Source policy | All 66 specific controls pass, including the imported replay terminal route. The broad gate reports 21 paths: fourteen daemon and seven host paths, one fewer than the preceding whole-node run. An obsolete baseline entry for the relocated RAM wait was removed without a replacement waiver. | Complete the owning caller cutovers. Scanner bounds, classification and assertions remain unchanged. |
| Boundary and hygiene | All 65 unsafe/ABI/license controls pass against the current cleanup implementation. All five hygiene controls, 36 harness controls and both Rust documentation controls pass. Eight content-bound review records were refreshed after source review using the unchanged counter. | Keep original shape limits and recheck subsequent functional changes. |
| Native build | Signed source `68dd4a6b902e` completes all 3,863 C compile/link actions. Twenty-five of twenty-six standalone fixtures pass, including sixteen received-delivery lifetime, thirteen module-payload and eight Ready handoff component scenarios. Their installation, standing, module journal and Main-loop entry inputs remain explicitly modeled. The final independent causal sweep timed out at the unchanged 60-second limit on Ready absence reissue; its failed stage is unresolved and later sweeps are diagnostic. The worker inventory retains the genuinely linked RCU registration and its actual task census. | The regeneration gate fails at the unchanged mandatory launched capture lifecycle refusal. Component passes do not establish Source activation, real read/post/rearm/ACK or physical-return qualification. |
| Deferred control | The retained object has 124 private component definitions plus `main` and 28 genuine provider references. The owning runner resolves QOM support from the configured Meson build. All positive scenarios and both exact native assertion mutations pass. | Component linkage and runtime checks supply no Source activation or physical CPU-pin return evidence. |
| Native cleanup | All four changed production C units pass syntax checks; the actual generated fixture compiles and links. Ten new controls, the replacement capacity control and four independently rebuilt causal mutations pass their exact checks. | Positive RCU grace, launched capture and resource/performance qualification remain required. |
| Native Source unit | All 187 scenarios pass with matched compiled C layouts, actual worker backing charges, canonical Bridge/Child holders, RUN socket handoff, teardown semaphore entry, bounded join, control destruction and stack/storage return. The original 1 MiB budget remains an insufficient-budget negative. | Prepared-family and completion-binding enrollment remain explicitly modeled inputs. These component lifetimes qualify neither the production Rust module nor standing/Original/Source/CPU activation. Positive lifecycle qualification requires a paired normal-service flight. |
| Earlier worker and diagnostic cutovers | Before whole-node RAM changes: 2,716 passes across 43 host-resource, QEMU-host and plugin targets; campaign 448 passes; twelve owned-process diagnostic controls pass in both CLI targets. | Later host/daemon integration failures supersede the historical host-runtime pass claim. |
| Native settlement fixture | All 112 publication cases, 16 intentional waits and the control boundary pass with genuine QOM/support linkage. Exact guard deletion aborts at its blocked-count assertion. | Component success does not qualify Source or CPU activation. |

The subsequent helper-polling increment passes 1,233 QEMU host library tests,
with the same eight missing-receiver failures and four ignored probes as its
1,230-pass baseline. All host integration targets pass. Both image and setup
probe loops now borrow the actual creation Original on every iteration and cap
their sleep to its remaining slice. The receiver still saves output and the
independent post before interpreting the result. A real component child proves
successful completion under the same operation and cancellation after birth
while the live child remains owned for containment. These controls issue no
native Source, recipient or funding.

All 70 specific source-policy controls pass after that increment; the broad
gate still reports the same 21 unfinished owning paths. Its new exact contract
binds the borrowed Original through the receiver and both polling loops, and
the existing mutation runner rejects omission of those obligations or removal
of the sleep bound. All five hygiene controls, both rustdoc controls, eighteen
ABI controls and four license controls pass. This targeted run does not replace
complete workspace or native lifecycle qualification. The required application
`checks.rust.aos-test-targets` derivation also builds successfully.

The RAM gate inventory now selects the current Cargo packages from their owning
manifests. HTTP operational cases belong to `crucible-control-server`; the dense
capture case binds the current sticky original-admission control. Failed Cargo
listing and case execution print their saved diagnostics, and absent exact cases
identify the selected package, target and name. Coverage evidence paths and
component owners follow the current crate layout. The repaired store-transfer
and runtime-policy gates pass, as does the expanded supervision gate. The two
new helper controls bring the component inventory to 105 cases. The inventory
still has 149 requirements without named cases and no qualified requirements;
named cases remain distinct from native qualification.

The partial-probe increment retains stdout, stderr and observed exit status in
that same helper journal while polling. Timeout, excess output and unwind cannot
destroy an already collected prefix. The fresh-launch recipe reserves both fixed
1 MiB capture capacities before process-family sizing; the probe allocates them
before helper birth and cannot reuse that capture reservation for another probe.
The whitebox probe uses the same bound. Three new controls exercise actual probe
processes and bounded capture growth. They establish neither genuine Main funding
handoff nor native helper/Source return.

The updated host run passes 1,236 library tests with the same eight missing-receiver
failures and four ignored probes; all integration targets pass. All 70 specific
source-policy controls pass, while the broad gate retains the same 21 unfinished
paths. The moved polling removes its obsolete parent-module sleep baseline. Five
hygiene, two rustdoc, eighteen ABI and four license controls pass; the Nix hygiene
check and required application test-target compilation also pass. The expanded
supervision gate passes all ten exact cases. Coverage now binds 108 component
cases and still has 149 uncovered requirements and zero qualified requirements.
The full plugin run also passes 1,088 unit tests and every integration gate.
Native activation, complete diagnostic funding, genuine receiving ownership,
simultaneous families and CPU/wall parity remain implementation obligations.

The Main helper-funding increment moves the authentic Source host reservation to
configured-family binding, before the helper route becomes ready. Artifact
verification borrows that same retained purpose instead of reserving a second
Source window. Each helper borrows a checked control and descriptor overlap before
probe storage or process birth. The descriptor recipe includes all three stdio
pipe pairs and the pinned libstd fork/exec error-channel pair, including endpoints
that disappear before `spawn` returns. Unknown process return and unwind retain that
loan; successful image completion returns it only after observed reap. Probe
controls remain retained for their one-use capture reservation. The negative
component control verifies that an absent Main payer refuses before probe storage
or spawn. This closes the earlier ordering gap, while complete command/error
payload funding, returned-output lifetime and diagnostic allocation destruction
still require their receiving-owner cutovers.

The host funding run passes 1,237 unit tests with the same eight missing-receiver
failures and four ignored probes; every integration target passes. The new
missing-payer control passes, and all 70 specific source-policy controls pass
alongside the unchanged broad-gate refusal on 21 paths. Causal mutations cover
the Main-purpose handoff, actual control borrowing, allocation ordering and the
complete descriptor recipe. Hygiene, rustdoc, ABI and license controls, the Nix
hygiene check, and required application test-target compilation pass. Coverage
now names 109 component cases, with 149 uncovered and zero qualified requirements.
The updated hermetic supervision gate passes all eleven exact cases.

The Source control-lifetime increment replaces the weak payer facade with a
retained observer of the same authentic purpose. Its private shared-control
owner consumes every alias through `Arc::into_inner`, freeing the allocation
before dropping the extracted state and its actual Main loans. No raw Arc or
Weak observer escapes this control owner. The same recorded child reap and
returned-control checks still decide physical return; alias closure is not a
process-return oracle. The payer retains only the existing Main purpose and
adds no back-reference to the QEMU roster.

Two component controls observe actual allocator deallocation with both original
service-account charges still live, including concurrent final observers. An
independently rebuilt ordinary-Arc-drop mutation fails both controls, observing
zero original charge at deallocation instead of the retained charge. These
controls exercise the production shared owner without constructing a Native
Source. They do not qualify actual Native Source activation, every diagnostic
payload or the separate original-error controller allocation.

After that cutover, all host-resource targets pass: 258 library tests, one ignored
case and every integration target. The QEMU host again passes 1,237 library tests
with the same eight missing-receiver failures and four ignored probes; all its
integration targets pass. Seventy specific source-policy checks and the five
hygiene, two rustdoc, eighteen ABI and four license controls pass. The broad
source gate retains the same 21 unfinished paths. The hermetic supervision gate
passes all thirteen exact cases. Coverage names 111 component cases, with 149
uncovered and zero qualified requirements.

The helper receiver cutover replaces weak original-error references with the
existing Source lender's roster, slot, generation and incarnation identity.
Every resolution revalidates the active, ready and sound Source, including the
recorded process incarnation when one is bound. The helper entry point checks
that this lender resolves to the same controller before locking its journal or
performing effects. Cleanup revalidates the saved lender and actual Original;
it no longer retains a weak original-error allocation header. Nominal identity
comparison grants no helper, cleanup, funding or physical-return authority.

The negative component control exercises cloned and foreign observers without
issuing a Native Source. Missing custody cannot return either original service
loan. The original-error controller's strong allocation, diagnostic payloads
and weak roster allocation still require their own funded lifetime closure.

The nominal receiver control and all three retained-preparation daemon controls
pass, and the daemon library compiles with all features. Seventy specific
source-policy controls pass, including the updated identity and Original
omission mutations; the broad source gate retains its same 21 unfinished paths.
Hygiene, rustdoc, ABI and license controls pass. The hermetic supervision gate
passes all fourteen exact cases, and coverage names 112 component cases with
149 uncovered and zero qualified requirements. The changed Nix file passes
formatting; the whole-tree format check separately reports 405 unrelated files.


The launch controller now reserves its actual Main Source purpose and controller
loan before allocating its shared body. Family binding borrows that same purpose;
it no longer creates the controller's payer after controller birth. The roster
publishes the funded controller before its independent preparation postcheck,
retaining it and excluding slot reuse if that post refuses. Production cannot
construct an unfunded controller; mechanism-only constructors remain test-only.

Typed original-error observers and the portable lifecycle construction error use
the existing closed operational owner. The last typed or erased observer frees
that shared allocation before destroying the concrete cause and its loans. The
portable error preserves the actual concrete cause's downcast identity without
allocating a second shared control. This closes the controller allocation's
strong-observer lifetime; separately allocated diagnostics, helper first-error
controls and weak roster headers still need their own funding and closure.

Two allocator controls observe both original service charges before and after
physical deallocation, including eight concurrent typed and lifecycle observers.
Restoring ordinary Arc destruction makes the deallocation control fail: both
charges have already returned. The complete control API targets pass. The host
passes 1,238 library tests and all integration targets, retaining the same eight
missing-receiver failures and four ignored probes. Seventy specific source-policy
controls, five hygiene, two rustdoc, eighteen ABI and four license controls pass;
the broad source gate retains its same 21 unfinished paths. The hermetic
supervision gate passes sixteen exact cases. Coverage names 114 component cases,
with 149 uncovered and zero qualified requirements. All three retained-preparation
daemon controls and the required application test-target compilation pass.


Helper first-error controls now receive a distinct actual Source host loan during
controller preparation, before helper effects. The journal transfers that loan
into the closed shared first-error body before publishing independent observers.
The last observer frees that control before destroying the concrete error and
returning its loan. The public wrapper borrows the same typed cause and creates
no independent account, deadline or return authority. An unissued journal can
retain its actual local refusal without allocating a shared diagnostic.

Two paired-credit allocator controls pass, including eight concurrent observers;
they exercise the production generic cause body without issuing a Native Source.
The unfunded-journal control observes zero shared allocations, and all five
helper-journal controls pass. The complete host run passes 1,241 library tests
and every integration target, retaining the same eight missing-receiver failures
and four ignored probes. Source-policy checks bind the separate reservation,
Original verification, journal handoff and closed owner, including omission and
first-cause replacement controls. The broad gate retains the same 21 unfinished
paths. Hygiene, rustdoc, ABI and license controls pass. Coverage names 117
component cases, with 149 uncovered and zero qualified requirements. The
hermetic supervision gate passes all nineteen exact cases.

This fixed control loan does not fund an error's separately allocated payloads,
command construction, returned output storage, or weak roster headers. The final
diagnostic quarantine remains. Late helper work still needs its actual entered
Work or Restore Original and current Source incarnation; retaining the creation
Original cannot authorize that later action.


The bounded RAM-source shutdown wait now has an exact source-policy contract.
Classification requires the actual saved Cleanup, current-process check, native
join observation and independent cancellation, join and wait posts. It also
requires the real worker result, panic and uncertainty history to remain owned.
The wait is exposed again if any one of these obligations is removed, including
through the generic omission control. Nine specific mutations reject foreign
Originals, invented return, discarded history or posts, and an unbounded sleep.

All 71 specific source-policy controls pass; the broad gate reports twenty
unfinished paths, fourteen daemon and six host. Five hygiene, two rustdoc,
eighteen ABI and four license controls pass. This review changes no shutdown
behavior and proves neither native activation nor cached-stack physical return.


Successful probe output now moves both capture buffers and their existing Main
control loan into one closed receiving owner. Callers borrow the output; they
cannot detach a buffer or refund its loan independently. Both buffers are
destroyed before that loan returns. Whitebox parsing borrows UTF-8 directly,
including on invalid input, rather than moving captured bytes into an error.

Two paired-account allocator controls observe the original charges through each
actual buffer deallocation, including a receiving-thread move. Reversing the
production field destruction order makes the control fail with both charges
already returned. The host run passes 1,244 library tests and every integration
target, with the same eight missing-receiver failures and four ignored probes.
The daemon compiles all targets with all features. All 71 specific source-policy
controls pass; the broad gate retains twenty unfinished paths. Hygiene, rustdoc,
ABI and license controls pass. Coverage names 119 component cases, with 149
uncovered and zero qualified requirements. The hermetic supervision gate passes
all 21 exact cases, and required application test-target compilation passes.
This closes successful capture-buffer
funding, while separately allocated parser diagnostics, command construction,
weak roster headers and genuine native activation remain unfinished.


The module now deposits each received request payload in its complete child's
paid inline journal before the independent read postcheck. Ending the local read
does not destroy or replace that payload. A mapped ACK and later tuple cannot
replace it, and a local receiver borrows the same journal until it returns.
Post refusal preserves the received tuple; unwind poisons the journal and keeps
uncertain custody. An empty read creates no payload owner.

All 1,093 plugin unit tests and every integration target pass. Five new controls
exercise these lifetimes, and independently rebuilt deposit/reuse omissions
fail at their intended assertions. All 71 specific source-policy controls pass,
with the same twenty unfinished broad paths; hygiene, rustdoc, ABI and license
controls pass. The hermetic supervision gate passes all 26 exact cases.
Required application test-target compilation passes. Coverage
names 124 component cases, with 149 uncovered and zero qualified requirements.
This owner retains module payload bytes only. Native delivery ownership, actual
module holder transfer/return, Host publisher loans, action Originals and
callback activation remain separate unfinished cuts. There is no payload
retirement route until the genuine module/native lifetime integration exists.

The received-delivery increment retains the actual completed Native receive in
Source's prepaid inline lifetime owner. Creation records its exact output field;
transfer consumes that field into the paid pinned Runtime. A constructor's
negative result does not discard born custody. Pure identity return consumes
only the canonical field, refuses live local borrowers and permits no rebirth
from the same retained receive. The one prepaid same-thread use slot refuses
saturation; it admits no nested, worker or multi-vCPU borrowing cohort.

The Rust keeper's twelve receive/delivery controls pass, including seven new
field-consumption models. Two independently rebuilt defects fail the intended
assertions for lost born-negative transfer and premature return clearing.
Native's sixteen new lifetime scenarios execute the actual C reader and
receive/delivery bodies with real mutex/thread/runtime storage; member and
standing boundary providers remain explicit modeled inputs. Three independent
native rebuilds detect omitted use retention, copied-holder acceptance and
delivery rebirth. The hermetic supervision gate passes all 34 exact cases.
Coverage names 132 component cases and nineteen native cases,
with 149 uncovered and zero qualified requirements. These controls establish
local custody only. Module payload
transfer/return, live publisher membership, entered action Originals, real CPU
borrowers, ACK and physical peer return remain separate unfinished work.


The compiler-compatibility follow-up preserves admitted inline refusal custody
and existing shared-memory bytes. Strict all-target, all-feature Clippy passes
for the affected host-resource, shared-memory and store crates. Their complete
unit/integration runs pass, including all 693 store unit cases, all 105
shared-memory unit cases and the actual 512 MiB capture/restore/repack workloads.
This does not clear the separate unfinished controller compiler gate.


The paired v3 member now first-binds actual module payload claim and release
callbacks alongside the existing reader and Park writer. The Runtime requires
that constructor without falling back to v2. Claim records the exact stable
Source field in the actual non-Copy pending request inside the pinned complete
child. A copied field or local serial cannot replace that holder. Return holds
the real journal lock, destroys the pending request, then clears only its exact
holder. Contention, stale identity and poisoned ownership preserve custody.

Source journals callback entry, born output and its independent post separately.
The Runtime attempts payload claim even after a born-negative delivery result.
Cleanup independently attempts pure lifetime return: actual module destruction
followed by a negative Native post retains the diagnostic without resurrecting
consumed debt. A refusal that leaves the module payload retained blocks lifetime
return. The containing receive remains retained and cannot return a Host
publisher or peer merely because its local delivery closed.

All 1,110 plugin unit tests pass, including seven actual module-journal controls
and fifteen receive/delivery wrapper controls. The expanded hermetic supervision
gate passes all 45 exact cases. Required hermetic application
test-target compilation passes. Four independently rebuilt Rust defects fail the intended
assertions for copied-holder acceptance, omitted payload destruction, lost
born-negative claim and skipped lifetime consumption after a negative payload
post. Native component coverage uses its actual v3 constructor and transfer
with an explicitly modeled C module journal; this does not qualify the actual
Rust/QEMU pairing. Coverage now names 143 component cases and nineteen native
cases, with 149 uncovered and zero qualified requirements. Operational payload
use, live publisher membership, entered action Originals, actual CPU borrowers,
ACK and physical peer return still require genuine integration.


Normal roster publication now reserves the entire actual Arc allocation from
its same authenticated Main before moving native credit or allocating the
roster. This independent charge includes the funding control and its own
construction/lease storage. Closed strong and Weak wrappers retain that charge
after their Arc fields. Every actual Weak upgrade holds one common gate through
strong acquisition. Final retirement checks the physical slots and same retained
Original, then checks real strong uniqueness under the gate before sealing it.
The body dies before native credit return; its entire allocation remains paid
until the final Weak deallocation. Private/component rosters retain their prior
strong-and-weak uniqueness requirement.

All 53 original-roster controls pass, including seven new allocation controls
with real paired counters and observed Arc deallocation. All 261 active
host-resource unit cases and their integration targets pass, with one existing
ignored case. Five independently rebuilt defects fail their intended assertions
for omitted strong uniqueness, omitted sealing, early strong/Weak funding
refund and pricing only the Arc header. Strict host-resource Clippy, engineering
hygiene, and the 71 focused custody source-policy controls pass. Component
storage tests use explicit mechanism pairs and cannot authenticate a Main,
Source, native process or action. Coverage names 153
component cases and nineteen native cases; 149 requirements remain uncovered
and none qualified.


The actual Ready factual dispatch now nominates its receive at birth and retains
that delivery's canonical module payload, child/member and standing lender in
paid Source storage before independent post. Its genuine execution carrier
retains that exact handoff across normal observation return and Ready exit;
the Ready entered marker does not extend. Ready cleanup reports factual
consumption independently of its signed post result and blocks uncertain or
still-borrowed dependencies. Payload and pure lifetime returns each authenticate
actual native debt independently; a copied output grants no permission.

The Rust keeper requires this exact Native ABI. It saves factual Ready
consumption before interpreting status, preserves the first cleanup refusal,
and independently attempts both later returns. All 1,114 plugin unit cases and
the integration targets pass, including nineteen receive/delivery controls.
Three independently rebuilt Rust defects fail their intended assertions for
lost negative-post consumption, skipped independent returns and overwritten
first error. Required hermetic application test-target compilation passes for
the paired roster and Ready keeper increments. Native owning component coverage remains 187 cases; the 37
lifetime/payload/Ready scenarios use explicit modeled entry inputs. Raw ABI,
signed reconstruction and the license ledger pass. The native causal timeout
and mandatory launched Source/Root lifecycle refusal remain unresolved; this
is not full native qualification. Coverage names 157 component cases and
nineteen native cases, with 149 requirements uncovered and none qualified.
Actual Main borrowers, CPU-operation authority, entered action Originals,
activation, ACK and physical peer return remain unfinished.


The late hot-fork image-helper route now resolves the genuinely installed
Source allocation and retains its exact process generation in the helper's
cleanup recipient. It checks that binding before constructing the helper
command and independently at the actual receiving route. An unissued,
retired or replaced Source cannot promote the launch construction recipient
into a late-helper lender. All 53 roster controls, the 71 focused source-policy
controls and engineering hygiene pass. This is physical cleanup identity only:
the late helper still requires its genuine action Original instead of the
launch Preparation clock, and detached-overlay preparation is not qualified.

The paired roster/Ready hermetic supervision gate passes all 59 exact cases.
Checkpoint Original loans now use a closed strong owner: the final borrower
extracts the value only after freeing the actual shared allocation, so its
existing service credit cannot return ahead of that allocation. Cloning keeps
the same entered operation without allocating or renewing it. Twenty active
checkpoint Original controls pass, with one existing ignored case. Two new
controls observe real credit immediately before and after actual deallocation,
including unwinding after parent retirement. Focused custody source policy and
engineering hygiene pass. Required hermetic application test-target compilation
passes for both the Source-incarnation and closed checkpoint-loan increments.
Coverage names 159 component cases and nineteen native cases;
149 requirements remain uncovered and none qualified. These component controls
do not authenticate native receiving or supply a late helper's action Original.


Late detached-overlay helpers now receive a closed context constructed only
from the actual node's installed Source and its already entered checkpoint
Quiescence Original. The disk-seal transaction retains that same context through
materialization; every helper wait checks its original event, deadline and
current Source incarnation. It neither enters a replacement operation nor falls
back to launch Preparation. The paid helper journal retains this context before
birth and keeps it on uncertain physical return. Source/event and guard posts
are sampled independently and saved in distinct fields, preserving simultaneous
refusals. The actual Source cleanup recipient remains separately authenticated.

All fifteen focused helper controls, 53 roster controls and 71 focused
custody source-policy controls pass. The new event control cancels the actual
checkpoint Original after a real child is born, observes refusal in the actual
helper wait, and proves the operation identity and entry count remain unchanged.
It supplies no native Source or Main authority. Required hermetic application
compilation and all 62 exact hermetic supervision cases pass for this increment.
Coverage names 160 component cases and nineteen native cases; 149 requirements
remain uncovered and none qualified. Genuine native ingress, activation and
successful detached-overlay lifecycle qualification remain unfinished.


The actual Main control boundary now retains a distinct factual Native frame,
its genuine CONTROL descriptor/group, real QOM CPU reference and Source
allocation receipt/generation. Native records custody before its allocation
identity post; Source separately borrows the exact Ready handoff and canonical
module payload before its own delivery identity post. Core attempts Source
borrowing even after a born-negative Native result. Return closes actual QOM
and frame/descriptor dependencies before Source consumption and its independent
post, without resurrecting consumed debt. Stop admission remains separate.

The signed `ccb208cf` native candidate passes 187 owning scenarios, all 46
literal C lifetime/payload/Ready/Main component scenarios and eighteen
independently rebuilt causal defects at their intended assertions. Raw ABI,
signed sole-parent reconstruction and the unchanged 257-row license ledger pass.
All 3,863 native targets compile and 25 of 26 fixtures pass; the sole remaining
failure is the unchanged mandatory launched Source/Root lifecycle refusal.
The first Main candidate's fixture-directory failures remain failed attempts;
the earlier `68dd` causal run's unexplained 60-second timeout remains unresolved.
Installed publication, allocator observation, Main/BQL entry and the minimal
CPU class are modeled inputs. Main physical custody grants no CPU operation,
entered action Original, publisher membership, activation, ACK or peer return.

Standing Source publisher storage now has closed typed, action and weak
observers, each retaining the same actual Source allocation charge after its
pointer field. The publisher body and weak-retained value storage can close at
different times; neither refunds that charge before actual allocation free.
Its independent funding control also frees before releasing its original loan.
The actual constructor prices and reserves both shared allocations before birth,
rejects an undersized actual loan, and retains the physical mapping's separate
original controls. Publisher replacement drops displaced value/funding owners
outside the publication mutex. No raw strong or weak alias escapes this owner.

Seven allocation-only component controls pass, including exact allocator
observations, dead-value weak retention, erased standing observers, cloning,
concurrent close, measured recipe coverage and unwind. All 268 active resource
unit controls and their integration targets pass, with one existing ignored
case. Strict resource Clippy, the 71 focused source-policy controls, reviewed
boundary-export confinement and engineering hygiene pass. Four independently
rebuilt defects fail the intended assertions: strong credit before storage,
weak credit before storage, funding credit before its header, and pricing only
the publisher header. Required hermetic application compilation passes for
this increment. The protocol's existing narrow portability allowance and the
payload test's unsafe call now carry adjacent intent annotations; all 36
boundary-harness controls pass. Coverage names 167
component cases and nineteen native cases; 149 requirements remain uncovered
and none qualified. Allocation ownership supplies no Source/action membership,
entered operation, activation or physical peer-return evidence.

The complete callback child now first-binds a local payload-borrow pair through
the matched version-four member constructor. Its prepaid inline journal records
both original output-field addresses, a checked local generation and the actual
calling thread. A live record prevents canonical payload destruction. Return
authenticates the original fields and consumes the record before clearing both
outputs; a missing record cannot certify an unknown acquire attempt as absent.
No payload reference or operation permission crosses this local boundary.

All 1,127 plugin unit controls, its four integration cases across three targets,
36 boundary-harness controls and 71 focused custody-policy controls pass.
Thirteen new payload-borrow controls cover actual contention, poison, foreign
threads, stale generations, copied fields and physical consumption. Six
independently rebuilt defects fail at their intended checks: premature payload
retirement, copied-holder acceptance, foreign-thread acceptance, ignoring the
original serial field, retaining the record after reported return and clearing
only one output. The retained-record mutation initially failed through the
test's final return unwrap; an explicit return assertion then independently
reproduced the intended refusal. Production sources were restored afterward.
All twenty restored payload controls and five engineering-hygiene controls pass;
required hermetic compilation of all Rust application test targets also passes.
All 82 individually selected hermetic RAM-supervision cases pass.
Raw ABI conformance and all eighteen direct license-boundary controls pass.
The full hermetic license gate fails before its boundary-test phase because the
controller prerequisite rejects 901 host lint errors and an unused, shadowed
engine integration-test binding. Large returned errors account for 855 host
findings; the retained ownership/error representation and remaining strict lint
work stay unresolved. No lint allowance or packaging-gate bypass was added.
Coverage names 180 component cases and nineteen native cases; 149 requirements
remain uncovered and none qualified. Native Main custody and this module-local
record still supply no entered action Original, publisher membership, action
return, activation or physical peer-return qualification.

The matched native payload-borrow candidate is signed commit
`86918f82ecf10b631171e1383185c63d95c018be`, tree
`696aff90cd4eb6f29d70c01df2906987430c171a`. Its corrected owning identity
passes all 187 controls, including 58 native lifetime scenarios. Eight new
independently rebuilt defects fail their intended assertions. Raw ABI, signed
reconstruction and the unchanged 257-row license ledger pass. All 3,863 native
targets compile; 25 of 26 full fixtures pass, with the mandatory launched
Source/Root lifecycle still refusing. The first complete causal attempt stopped
at a stronger payload identity assertion after thirteen intended defects; its
corrected second attempt reached eight intended defects before the unchanged
60-second limit expired in the real fork/child prerequisite before the
`ready-delivery-dependency` mutation ran. Diagnostic stacks identify a child
blocked on a thread-registration lock inherited while the constructor RCU worker
was still registering. That causal diagnosis does not erase the failed attempt
or complete its qualification.

A fresh broad source-policy run reports 21 paths: the previous fourteen daemon
and six host paths, plus the delivery test's physical-lifetime retry name.
That component test preserves its first error through a second modeled physical
return; its exact source-policy custody companion remains to be added. The
broad gate remains failing, without a new baseline or scanner exemption.

The standing protocol now explicitly declares schema 4 and producer-retention
edition 1 in the former reserved word at byte 196, preserving its 1496-byte
payload, 1504-byte live file and 1520-byte seal. The actual publisher declares
that it retains every born action membership, including dirty and unprojected
rows. Its irreversible publication cut precedes the first request mutation;
only its assigned peer's authenticated physical return can settle a published
cohort. Earlier local abandonment requires actual unpublished custody. The
promise supplies no receiver subscription, entered operation or return receipt.

All 137 protocol unit controls and 95 integration controls pass. Literal
predecessor/mixed editions, absent or unknown promises, and invalid initial/live
promises refuse. The real prebirth request guard rejects a matching already
pending untyped request and an occupied real frontier; all eighteen publisher
controls pass. Seventeen matching module Setup controls, eighteen direct license
controls and five engineering-hygiene controls pass. The coverage inventory now
names 186 component cases and nineteen native cases; 149 requirements remain
uncovered and none qualified.

The matching native compatibility checkpoint is signed atomic commit
`39fa2c7e87f1a72959638d3c443e182aa204c4b7`, tree
`9b71f5ed899082b536b169ff81b3f4373da37f0e`. Its thirteen decoder groups and
two independently rebuilt rejection defects pass, as do the 187 owning tests,
raw ABI conformance, atomic reconstruction and unchanged 257-entry license
ledger. Both actual native compilation variants pass. The complete 3863-target
build still passes only 25 of 26 fixtures: the mandatory launched Source/Root
capture lifecycle still refuses. This compatibility declaration adds no callback
activation or operational issuer. Mandatory application test-target compilation
also passes for the matching host implementation.

The exact delivery lifetime body now has a focused source-policy companion;
changed custody assertions and extra reviewed-name attempts remain rejected.
Its first draft removed the function name together with its body in the generic
adversarial control; retaining the name and binding the complete body fixes that
control. All 71 focused policy controls pass. The broad gate again reports only
the previous fourteen daemon and six host paths, without a scanner exemption.
The duplicate engine `terminal` observation was removed; all fourteen affected
integration tests pass. This does not resolve the controller's retained-error
representation or its remaining strict lint prerequisite failures.

All 88 individually selected hermetic supervision cases now pass for the
schema-4 host checkpoint. The keeper also checks actual consumption of both its
canonical and failed-transfer creation fields after a zero native lifetime
return; the two new modeled negative controls preserve custody and all sixteen
local delivery controls pass. Exact source-policy companions now bind the six
host cleanup continuations to their complete retained-owner bodies and saved
lenders. The broad source-policy gate still fails on fourteen daemon paths;
these local contracts provide no allocation or launched-lifecycle qualification.
Mandatory application test-target compilation passes for this cleanup
checkpoint. The separate native fork-readiness checkpoint is signed atomic
`68ad0c4ef04202b246718a545b74455e2378eb78`, tree
`10805f2a26de206854a0e0a077a0648a8e8ae9dc`. A real RCU callback drain and
actual registry census establish zero starts in flight before the real fork;
the previously hanging unmutated foreign-process prerequisite now completes.
The complete independently rebuilt 26-defect causal sweep, 187 owning scenarios,
raw ABI, signed reconstruction and unchanged 257-entry ledger pass. One hundred
actual foreign-process repetitions, including thirty traced repetitions, pass;
an independently omitted start-completion fails the intended new inventory
assertion. Full regeneration still passes only 25 of 26 native fixtures, with
the same mandatory launched lifecycle refusal. Earlier failed causal attempts
remain failed observations; these passing component checks do not qualify them.

A fresh complete license-boundary attempt fails before its boundary phase:
the strict controller prerequisite reports 943 host test-target errors, including
the retained-error representation. The earlier direct license controls do not
replace this required gate.

Whole-node shutdown now keeps one continuation through process reap, RAM service
return and controller retirement. Physical closure, initiating failure and
independent boundary checks remain separate facts. Failed construction retains
the same issued child or completed node and its saved lender; terminal generation
replacement returns the old node before releasing its lease. Main joins the same
worker handles before restoring their borrowed Source entries, including unwind.
The controls include a real held TLS destructor, retained failure, unavailable
borrowers and restoration ordering. They do not prove that libc has released its
cached stack storage or that every native provider is joined.

Helper failure history still needs complete allocation funding and a receiving
Main lifetime independent of Native roster ownership. Current quarantine retains
funding rather than claiming cleanup completion. Neither detaching a Weak lender
nor relaxing the quarantine establishes a valid handoff. General lower initial
or steady resident peaks, native activation and zero-regression CPU/wall evidence
remain outstanding.

The native worker owner consumes the real Rust handle before polling, retains
EBUSY and unexpected status, and latches actual task/TLS return before the
independent postcheck. This does not prove libc has unmapped cached stacks or
thread-control storage. Diagnostic controls discover only descendants of their
owned process and verify cooperative error-path waits. The settlement component
uses private names for all modeled externals; genuine QOM/event/thread/lock
providers remain independently linked. Its owning check rejects an unprefixed
component symbol, stale mutant binary or unrelated failure.

Native metadata admission now publishes each actual receipt before its
independent postcheck, retains allocation custody in Source until transfer, and
authenticates native creator and BQL ownership before mutation. Five separately
compiled omission controls fail at their exact intended assertions while their
named baselines pass. All four native retirement sites now retain canonical
receipts across physical frees and settlement refusal. Cleanup records consumed
projections, physical return and debt settlement independently; retries never
repeat a started free or MR unref. The same two inventory rows and paid intrusive
dirty-header owners retain unresolved work, without completed-debt aggregation
or a fixed bound on outstanding dirty-header generations. The component controls
exercise real frees and QOM finalizers against disclosed modeled retained state;
they do not establish Source activation or positive RCU callback execution.

Exact resume now preserves phase, shutdown and factory-retirement failures
together before classification. It retains the original typed history inline,
removes the recursive boxed cleanup variant, and seals only after all outcomes
succeed. All eight outcome combinations and drive-only classifications are
covered. Those controls establish owning error transport, not a funded native
terminal receipt or completion of whole-RAM cleanup.

Native Park disposition now follows capture completion and physical return of
the request-owned block, async and RCU census. The same Source loan and writer
gate remain held; failed capture or physical return retains containment. This
does not yet place the actual fork and thread-registry transaction inside the
Park lifetime. Positive Native Park disposition and worker rearm remain
unqualified by the build and component results above.

The dirty-iterator fixture requires an ownership cutover, not successful stubs
for missing dependencies. Bare capture completion no longer acknowledges dirty
pages. Its exhaustive selection, bitmap-work and plane-isolation controls must
exercise shared private production primitives. Logging initialization, failed
reads, premature acknowledgement, rearm and Original-post failures, generation
races, abort, diagnostic retention and independent checkpoint obligations must
also run through actual launched-QEMU Root/Source/writer ownership. Keep that
mandatory lifecycle flight outside the QEMU package dependency chain. Neither
component selection nor the registered Source fixture replaces this native
qualification; the full package gate remains failing until its stale fixture
is repaired, and lifecycle qualification remains outstanding until executed.

### Historical integration notes

The following notes retain earlier source-specific results and investigation
findings. Their counts and intermediate defects are historical; the current
summary above supersedes their status claims. They do not qualify later source
changes or the complete runtime profile.

The private-feature QEMU test targets also compile independently of the
test-support feature. The complete private-feature QEMU library run now passes
all 1,143 tests, with four ignored probes, in 32.62 seconds. Capture, Pause,
PREPARE and fault-result component fixtures use a distinct host-control owner
through the same control loops. Their peer acknowledges mapped control and
sample publication independently of returning that owner's exact serial ticket;
the loops cannot finish before both facts hold. Production continues to use its
original Source action binding, and missing, revoked and foreign Source controls
still refuse. The component owner cannot wrap a live Source or construct native
authority. All 32 confinement lint controls also pass. These component results
do not qualify a live VM or replace native lifecycle evidence.

Memory-service occurrence admission now compares the reported byte rate,
operation rate and exact presence bits with the same issued action, alongside
its existing materialized-latency check. Matching payload hashes alone cannot
establish that configuration. The new control covers all four enabled/disabled
rate combinations and rejects twenty individual contradictions while preserving
the same action and APPLY identities and recomputing valid evidence and transport
hashes. This validates host event admission; native service timing and cold-page
fault qualification remain required.

Packed inventory, publication readback and canonical archive reads now borrow
one metadata cache from the existing physical-quota service. Its rows and index
use the same paired resident/metadata accounts as ordinary service work; they
retain no Source, operation authority, file descriptor or active pack pin.
Before admitting competing allocations, the service physically reclaims cached
storage and rechecks the actual accounts. In-flight fills remain charged until
their bodies close. Every read still authenticates its fresh configuration,
placement generation, file stamp, selected entry and complete object identity.
Each reader prepays an independent active manifest copy from its existing
operation budget before borrowing shared rows. Copying under the cache mutex
performs no allocation, filesystem work or caller callback. Subsequent reads
within the same pack use that copy and preserve fresh stamp and entry checks;
shared-cache eviction can close its own rows without invalidating the reader.
Small manifests use ordinary operation-owned storage when the cache's index
and control payload would cost more than their row storage. Ordinary single-tree
reads retain their existing dispatch; this is not a claim that every page read
uses shared metadata. The storage cost controls cover tiny, mixed and dense packs
and 32/512 MiB RAM traversals. Their integrity/resource results do not establish
VM performance parity or authorize new resource ceilings.

The complete volume fixture deliberately uses a quota guard without manifest
retention. Digest-ordered repack loses depth-first traversal locality, so that
fixture authenticates a manifest on almost every subsequent pack switch. The
separate cost control and production quota guard use the service-owned cache;
the measured switch count is the same, while authenticated manifests fall from
391,776 to 628 in the 512-MiB post-repack traversal. This identifies two guard
policies, not a demonstrated shared-cache eviction defect. The cache-disabled
integrity coverage remains required. Additional complete lifecycle controls now
use the same retained cache across capture, archive, repeated archive, repack,
reopen and GC. Their source and destination each keep the original 128-descriptor,
256-MiB fixture bank; the separate cost fixture keeps its 64-MiB bank. The quick
case and full 512-MiB case pass, the latter in 954.84 seconds. After repack, cold
restore authenticates 628 manifests over 393,216 rows; warm and reopened restores
authenticate none. Actual reclamation refunds the matching bank exactly once,
and both banks have zero descriptor and resident debt after final destruction.
The original cache-disabled lifecycle remains required and unchanged in scope.
These are integrity and accounting controls, not VM throughput measurements.

Execution runners now expose retirement through an existing supervised
operation. Routers visit both contained runners even when neither became the
active semantic route; one refusal does not suppress cleanup of its peer.
Returned diagnostics leave operational ownership in the actual factory. The
hot-fork runner also refuses retirement while it retains an unreconciled world.
Aggregate release readiness is observed without finishing or quarantining a
pending owner, so a launcher can finish before actual aggregate release.

Main now retains the actual worker bodies independently of their borrowing
threads. Worker storage and the fixed cleanup queue are priced before model
construction. Source construction retains its original factory, generation
storage, launcher and preallocated partial/complete lifecycle carrier across
refusal. Successful disposal returns the same carrier to its reserved cell.
An exact-cell receipt remains with the factory until actual body destruction
and containing-body lease closure; publication alone does not free a slot or
certify aggregate resource return. Hot-fork retirement returns the original
Source separately from its retained typed failure history. These operations use
the existing supervision origin and preserve failed ownership for bounded retry.

Source construction now preclaims its genuine Main role before logical World
admission. That role pays the existing Pending and construction-carrier Boxes;
World admission separately pays its launcher, generation storage and Source Loop.
The native boundary delivers a committed failed World and its exact controls to
the same preborn receiver before propagating the initiating or independent post
failure. Delivery and preparation are separate operations: refusal retains the
actual holders and both typed reports without entering preparation. No missing
callback or empty node ledger establishes that a World was never born. The
original role also supplies a nonissuing selection that verifies the actual Main
and exact empty epoch before future Service startup; it grants no Service cap.
All twelve reservation controls pass, including the unavailable-selection check.
The complete Linux resource library has 247 passes and one ignored probe.
Supervisor preparation now captures its original identity and both clock
coordinates before allocating shared controls. Publication consumes that same
value; delay cannot renew its cap. Ordinary construction uses the same path,
conservatively counting control allocation in its original interval. Four new
controls cover delayed and reversed publication, unchanged budget refusals and
exact roster identity. Both workspace/all-target checks and engineering hygiene
pass; the existing testing-standards classifier failure remains unchanged.
This lower-level seam alone supplies no Main or Service admission.

The whole-world transaction separates native resource effects from a private
component backend while preserving checkout, adoption, rollback and publication.
The component's carrier is charged to its existing fixture account before birth
and enters the shared constructor. A failed installation retains the same actual
body in its fixed slot while reporting its original typed cause; this performs
no canonical publication. Native operations provide no fixture carrier, and the
default backend still refuses a missing genuine Source issuer before child
effects. The cleanup-rejection control now requires both the initiating error
and the actual independent typed guard failure. The complete private daemon
library passes all 1,733 tests, with 43 ignored probes, in 318.12 seconds. Both
default and private workspace/all-target checks pass for this source. Engineering
hygiene has five passes; testing standards retains its existing operational-source
classifier failure. Genuine Target before-effects ownership, role handoff,
selected-member resource geometry and healthy retirement remain required. These
component results qualify neither native Target activation nor physical resource
floors or VM performance parity.

Lifecycle assembly now offers one borrowed preparation core. Input installation
checks the same pristine carrier before moving either the launcher or decoded
checkpoint; every refused installation preserves both inputs without allocation.
Preparation refuses failed, closed, reserved, poisoned or already-cleaned custody
before configuration copying or native effects. Owning constructors delegate to
that same core and perform the final move only after complete validation. Three
controls cover unusable carriers, retained validation failure and re-entry after
physical cleanup. The final private daemon library run passes all 1,736 tests,
with 43 ignored probes, in 358.60 seconds; both workspace/all-target checks pass.
The durable Main producer still needs to adopt this borrowed core before Source
startup, so these results do not qualify native activation or VM performance.

Worker and lifecycle retirement now checks its same saved Cleanup before and
after each worker/queue effect. A refused entry or post stops subsequent effects;
final physical observations still run and preserve independent work and post
causes. Controls use real retained files to prove a deadline cannot close the
next queued body and that an already closed body can still be destroyed outside
its containing mutex. Outer cancellation alone remains compatible with cleanup.

Attached, original and standalone Main retirement now use that guarded cleanup
path as the sole lifecycle drain. Their final queue checks only observe emptiness;
they cannot initiate a second cleanup after the saved Original has refused another
effect. Default and private workspace/all-target checks pass, and all 1,742
private daemon library tests pass with 43 ignored probes. Engineering hygiene
has five passes; testing standards retains one failure with 25 findings. The
removed duplicate standalone drain no longer trips its source classifier. The
independent no-Main component shutdown retains its explicit cleanup route.

Retained-source preparation now shares one borrowed engine for initial capture
and child promotion. It keeps the same Loop Box, captured continuation, returned
template tokens and current and prior disk owners before subsequent validation
can refuse. The original typed cause survives rollback and failure assembly.
A parent-park refusal retains the actual complete Source instead of forgetting
it. Two controls verify allocation identity, one-shot refusal and recovery of
that same owner. This seam still requires the durable Main capture integration.

Both workspace/all-target checks pass. The latest four-thread private daemon
run has 1,744 passes and 43 ignored probes in 373.10 seconds. An earlier
four-thread run failed the aggregate-release hot-fork control; its isolated
control and seven-test module subsequently passed, and the full run includes
an improved unexpected-disposition diagnostic. The concurrent failure remains
unexplained. A preceding invocation omitted the established four-thread limit
and exhausted the fixture's fixed SQLite capacity; its failures remain recorded.
No fixture capacity or assertion was relaxed. Engineering hygiene has five
passes; testing standards retains the same 25 classifier findings.

Session ownership now arms one inline loop slot before constructor validation
and keeps it in the actual Engine owned by the actor. Normal completion,
unpolled futures, cancellation and unwind consume that same slot through a
neutral retirement hook. Explicit extraction disarms it. Five controls retain
and return an actual file, including refusal before an Engine could be built;
no control issues native authority. Both workspace/all-target checks pass.
The full scheduler and session unit, integration and documentation suites pass
1,564 tests with one ignored probe, including 700 scheduler and 107 session
unit tests. Engineering hygiene passes; the same 25 testing-standards findings
remain. The production Loop override and its original Main destination belong
to the coordinated Source cutover and are not qualified by these component runs.

The coordinated Source, Service, capture, replay and observation cutover is now
assembled in the implementation worktree for compilation. Service startup uses
its original Main cell before effects, and capture retains the complete borrowed
preparation before template or disk work. Receiving-state retirement publishes
its actual maintenance inputs before returning the stopped native body. Review
found an unwind gap between native construction and installation in that grouped
owner; installation now occurs before the projected context is destroyed.
Discarding an authenticated, never-launched import destroys its decoded basis
and Transfer before acknowledging the ordinary alias receiver. Unwind preserves
unacknowledged debt rather than certifying destruction.

Combined compilation exposed a recursive error layout: an inline Service first
cause used the complete executor error, which could itself own terminal Service
history. Startup now stores only its five actual lower admission-error types.
This preserves the original causes without another heap allocation. Both the
default and private daemon library configurations now compile. Cleanup history
retains its complete terminal body in the same preborn receipt Box, whose
deallocation precedes terminal-role release. A synchronized inline guard keeps
raw history available without requiring a replacement error allocation. Unused
publication helpers and their unconstructed begin/callback fallback variants
are removed; the live installation and first-cause controls remain.
The independent harness ABI and license-boundary suites pass four and eighteen
controls, respectively, on this partial integration.

Managed sharing now keeps the original Main carrier and return destination
outside the existing Source Arc. Borrowed leases retain only that allocation;
an exclusive lease retains its actual return owner. Strong and Weak aliases
both prevent extraction, and poison retains the same allocation rather than
reconstructing an Arc. The Park gate stores the original nonissuing selector
instead of an allocation alias, with physical return tracked independently from
raw first and post errors. Its actual paid record survives Source rearm.
Six obsolete packaged candidate-leak paths now use this canonical destruction
path. The failed-rearm phase also delegates to the existing saved-Cleanup Source
retirement engine and transfers original typed causes and rollback diagnostics
into terminal history before its carrier is destroyed. The combined private
library compiles; native execution of these paths remains unqualified.

Thirteen native fixture endpoints use the real Source factory and transport
receiver. The operation-only Service fixture shares the production admission
and cleanup algorithms without constructing a Main key or native permission;
its original 32 assertions remain. Four comparison Target starts still need
their genuine producer and account for the remaining 27 daemon test compilation
diagnostics. Actual Target construction and simultaneous independently funded
sibling families remain unfinished. A Cargo test executable does not acquire
the installed campaign Main's authority. Native qualification must retain the
existing positive assertions under an authentic deployed issuer; missing
issuance is not a replacement passing result.

On the integrated Source/API snapshot, the API library passes 124 tests. The
Linux resource library passes 172 default tests and 247 private tests, with one
private probe ignored. All five engineering-hygiene checks pass after nineteen
content-bound responsibility reviews. The declaration contracts now bind the
actual postbody and return-destination types, retain the original same-owner
forwarding constraints, and reject added default bodies or foreign return types.
Testing standards has thirty passes and five failures in the remaining exact
operational source contracts. No matcher, inventory, capacity or existing
assertion is relaxed. The earlier green
workspace and packaged results above describe their historical snapshots, not
this uncommitted union. Full combined runtime, current packaged application
compilation and VM performance parity are still outstanding.

The subsequent Target constructor integration replaces the permit-only native
outcome with an owning Ready/Retained result and exact saved-Cleanup return.
Its QEMU host crate passes all test-target compilation and 1,147 library tests,
with four ignored probes. The current daemon library check stops at the one
remaining old Native permit-adapter call; factory/runtime consumers are not yet
cut over. The required owning consumer, independent simultaneous families and
promoted-parent integration are tracked in [Target ownership](target-ownership.md).
These current results supersede earlier source snapshots for the changed paths.

Checked checkpoint-slot operations use nonblocking access and distinguish busy,
poisoned and occupied storage. A refused restoration returns the same selected
root instead of overwriting another root or dropping the incoming owner. These
operations are ready for the durable producer; existing consuming callers still
need the coordinated cutover before the old slot operations can be removed.

Hot-fork reconciliation handles now share their expected node roster with the
actual reconciliation map. Cloning a child handle no longer copies the entire
roster, and membership validation compares ordered keys without building a
temporary set. Successful reconciliation removes both entries under the same
mutex, then destroys the completed child outside that lock. Three controls cover
shared membership, poison and missing child receipts. This removes redundant
metadata copies; complete Target heap funding, native activation and measured
VM performance parity remain unqualified. The combined private daemon library
passes all 1,742 tests, with 43 ignored probes, in 311.90 seconds. Default and
private workspace/all-target checks pass. Engineering hygiene has five passes;
testing standards has 34 passes and its unchanged operational-source classifier
failure. These local component checks do not complete the consuming cutover.

Replay preparation now selects the actual node for its installed issuer,
generation directories, child contract and failed-child retention. The same
node passes through the existing operational checks; no descriptor is cloned
to reconstruct that selection. The replay World control query measures its
actual selected generation storage and does not charge a nonexistent Source
launcher or Source Loop. Default and private workspace/all-target checks and
all seven focused replay library controls pass. This query is preparatory;
the durable replay producer and native execution remain unqualified.

If exact cell attachment refuses, the same inline factory slot retains the
pending body, its canonical never-born journal and its body lease. Physical destruction precedes the paired descriptor-table/window return
and ledger credit. Retry borrows the same cached World Cleanup; it does not
renew its origin or replace its deadline. Constructor, cleanup and independent
post-check errors remain separate typed history after physical closure. The
component executor's separate no-Main shutdown path closes any saved dispatcher
without requiring a native dispatcher to have been created.

Retained constructor finalization now separates physical closure from its
independent Cleanup postcheck. After the actual owner and Main controls close,
the same containing body is removed and destroyed outside its cell lock, even
when the postcheck expires. Initiating, work, control and post failures remain
typed reports. An open owner or control still retains the complete body. A late
report neither starts another Cleanup nor requires a retry before releasing
already-closed resources.

Normal World sweeps distinguish an outstanding containing-body lease from an
invalid return. They validate the exact epoch, member and descriptor custody,
and return arithmetic before reporting pending body custody. Pending bodies
retain their complete remaining debt and physical leases while independent
Worlds can use genuinely available capacity. Ledger assignment validates all
fallible arithmetic before publishing rows or advancing epochs. Admission
refusal clears temporary factory poison only when no assignment was published
and the independent preparation postcheck succeeded, or when the local World
directory was already full before preparation. Committed or uncertain claims
retain their existing poison and owners.

Concrete VM construction, runtime, checkpoint and cleanup ownership now live in
`crucible-daemon`. The API owns transport-neutral operational data and cleanup
operations; it no longer depends on the QEMU implementation. Handoff upcasts the
same preallocated backend body into its existing exact cleanup cell, without a
replacement allocation or owner. The cutover removes 112 obsolete QEMU boundary
allowances and preserves all 380 lifecycle and RAM unit-test declarations.
Independent default-feature library builds now include their own unit fixtures
without depending on workspace-wide feature unification. External fixtures
remain opt-in, and native permission requirements are unchanged.

Private native observations now retain the real Source factory in the paid Main
worker. The shared four-vCPU and block drivers borrow operation-only views; no
node, guard, mapping or channel owner is returned. Launch uses the ordinary
keyed constructor and saved supervision. Publication consumes the same owner and
cleanup receipt, and diagnostic loans remain held until physical closure. The
worker size query includes the new inline fields before construction; immutable
input paths and their shared body are admitted before allocation.

The default workspace/all-targets check and the separate private observation and
Parent feature checks pass. The focused private suite has 29 passes and one
ignored legacy native entry; all four original-retirement controls pass against
the actual retained thread table. The input alias control proves last strong-alias
closure and credit retention; its test-only Weak witness does not prove Arc
backing deallocation. Production keeps the body graph free of Weak/raw escapes
and drops that allocation before its decoder custody. The full private-feature
library run has 1,680 passes, 17 failures and 43 ignored tests. Its failed-name
set matches the preceding native integration failures. The membership cancellation
control now selects five actual traversal boundaries instead of calibrating raw
callback ordinals across independent SQLite reads. It checks the same operation,
typed cancellation, unchanged root, exactly one selected boundary and no
post-refusal callback. The positive traversal visits every boundary exactly once;
all seven membership controls pass. The full suite also passes the 512-MiB
packed unique-page traversal.

The supplemental service VM checks build the actual private controller into the
installed Main policy and retain the original guest/request vectors. Ordinary
deployment TOML values are unchanged. Deployment files now use the source-built
text helper so guest artifact derivation references are valid. Source/guest-only
backreferences to the old canonical gate have been replaced with direct owning
imports; the guest derivation is identical and the shared Cargo source retains
its required embedded scenario. The four-vCPU VM build reaches the unchanged
QEMU dirty-iterator fixture failure before execution. Neither service flight nor
VM performance is qualified by the compile and component results.

The API library has 119 passes. All eight Source history/saved-Cleanup controls,
four component shutdown regressions, three worker-custody controls, five exact
receipt controls and two status-ordering controls pass. These include 24 epochs through
one physical cleanup cell and actual body destruction before expired-operation
observation. Three constructor finalization controls pass with actual files,
mutex cells and worker storage, covering late expiry, combined typed reports and
an unclosed body. The complete QEMU result is recorded above. Component results
do not qualify deployed resource return or VM performance.

All 31 Rust ABI, licensing, crate-layer and scheduler-boundary checks pass, as do
26 gate-traceability checks, five engineering-hygiene controls, the two production
effect-matrix checks, the schema-registry control and all three daemon doctests.
The testing-standards suite has 30 passes and one failure: the broader source
classifier still requires review of operational paths. Six reviewed targets now
classify only effect-free cleanup declarations and eight exact same-owner
forwarders. Their mutation controls reject default bodies, changed receivers,
extra statements, waits and failed-test reruns. Mutation builders preserve raw
method token boundaries; whitespace compaction is used only for search needles.
Neither source inventory nor the escape matcher was relaxed. Admission
checks now bind both existing waits to the same original Setup. Shared Target
clauses bind saved Cleanup entry and physical return; dispatcher clauses retain
both fixed five-second bounds, all five polling loops, and same-control recovery.
All eleven actual dispatcher component tests pass. These file-backed mechanisms
establish no native Main/Source issuance. The retired plugin-worker contract and
two resolved admission-sleep exemptions are removed. Live guards, custody and
negative mutation controls remain required. The Nix scheduler boundary checks the
production adapter in the daemon; its separate raw source scan still incorrectly
includes CLI test-only delegation, while the Rust production-aware scan passes.

Packaged retirement now preserves component failures beside later pre-dispatch,
dispatcher and independent post failures. Attached retirement retains the
initiating service cause separately from each cleanup phase's first typed
failure in its existing Main. The finite inline report fields enter the actual
actor size query before structural admission; no report carrier or owner slot
is allocated on failure. All five new component controls pass, along with the
existing cleanup-cell controls. Workspace checking and source hygiene pass.
A temporary stable-compiler layout probe on the joined dispatcher, resource-begin
and World-return source measures the actor at 5,024 bytes, its inline attached
history at 1,728 bytes and a temporary report at 1,032 bytes. The initiating/rollback
report is 1,232 bytes; the concrete shared-Linux Source factory, pending construction
and launcher occupy 44,080, 1,704 and 8,720 bytes respectively. These inline
fields enter the actual sizeof-based admission queries. The probe is removed
and the exact source hashes are restored. These are Rust object extents, not
whole-stack, allocator-overhead, policy-fit or performance proofs.

Composed guards now distinguish active ownership, successful return and terminal
quarantine. Failed cleanup and explicit quarantine cannot become a successful
later finish; repeated calls perform no second host cleanup effect. Routing
refusals also update that same outer state. This prevents retained Source cleanup
from treating containment as physical closure. Guarded Main retirement preserves
its selected refusal alongside independently observed worker and lifecycle
reports, without changing native effect ordering or using another allocation.
Five real worker/file report controls and three new guard-state controls pass;
existing controls are retained. The joined full private-library run has exactly
the preceding 17 daemon and six QEMU failed names, with no new failures.

Generation ownership also separates successful return from retained quarantine.
Original launch containment keeps its initiating cause in the enclosing owner;
an absent local diagnostic cannot turn a later finish into successful release.
The allocation-free retained-cleanup observation preserves the existing HTTP,
campaign availability and terminal scheduling policies. Repeated calls neither
reenter guard cleanup nor reopen generation admission. All 32 selected generation
controls pass, and the fresh private-feature workspace/all-targets check passes.
The worker-custody source contract now binds its existing queue revisit to the
same Main, saved Cleanup and independent physical observations. Its full omission,
extra-call and failed-test-rerun mutation controls pass; the broader standards
gate still reports 27 findings across 26 unresolved operational paths. Neither
the inventory nor the escape matcher was relaxed.

The local packaged application unit/integration-target build has completed for
the earlier immutable World-return/replay snapshot, with remote builders disabled.
It predates the subsequent guard, associated-failure, policy and generation edits;
it does not qualify their packaged integration or any VM execution.

Hot-fork Target, primary-launcher and auxiliary guards now distinguish a local
successful return from retained quarantine. Terminal observations refuse before
borrowing the shared registry and cannot fabricate a released-node entry, a
finished-launcher journal or an inactive auxiliary lease. Successful local
receipts remain idempotent after an independent aggregate quarantine; they do
not attest aggregate closure. Unreaped-child transfer keeps the same child and
wait authority in the same backing guard and preserves the first shared cause.
The new static retained-cleanup observation stays terminal through existing
realization and promotion classifiers. Aggregate readiness, cleanup and physical
release ordering are unchanged.

The Guarded cause and complete returned report measure 616 and 832 bytes;
retained-constructor cleanup and retirement reports measure 1,032 and 1,200 bytes.
These are returned diagnostics, not newly stored actor fields. Main remains 5,024
bytes, and the concrete Source factory, pending construction and launcher retain
the extents above. These measurements establish neither whole-stack usage nor
budget fit. The broader generic finish adapter still needs its typed leaf
migration through the actual launcher, cleanup queue and scheduler boundary.

Retained Service factories now copy only their six immutable admission-policy
values and keep their explicit registry, actor and input custody. They no longer
clone the full executor configuration. The actual factory measures 928 bytes,
down from 2,200; its shared-Linux baked catalog factory and promotion worker
measure 1,320 and 1,360 bytes, down from 2,592 and 2,632. These extents exclude
removed deployment-map/path/string heap clones. Main and the measured Source
bodies remain unchanged. The existing real Service/watchdog control checks frozen
policy, factory clones, identity, budgets, watcher/quanta projection and four
late missing-policy refusals without losing actor capacity.

The existing neutral cleanup-owner, reservation and handoff traits now require
an associated failure type. Every current implementation explicitly retains its
existing scheduler-error type; owners, boxes, cells, receipts and cleanup effects
are unchanged. This prepares the same transport for backend-typed history; it
does not yet repair the generic guard's erased leaf. Exact declaration and
forwarder controls include missing/default/foreign-type mutations and pass. The
joined API and harness libraries have 119 and 18 passes. The daemon, QEMU,
resource, boundary, traceability and hygiene results above also pass their
previous successful controls, with exactly the previous runtime failed names
and 28 source-classifier findings. Both default and private all-target workspace
checks pass. The private workspace check exposed and fixed CLI error mapping
when dependency feature unification enables Parent variants independently of
CLI feature selection; IO/store typed routing and other error presentation stay
the same. These compilation and component results do not qualify a VM.

Dispatcher retirement now retains the first Cleanup admission result once and
authenticates that exact saved operation without initializing another one.
Terminal parents do not prevent same-owner worker joins; new work still requires
live authority. Actual panic payloads remain inline in the retained dispatcher,
while physical completion is observed independently from diagnostic history.
The shared factory reports its result and physical-closure fact under the same
mutex. Attached, original, guarded and component consumers require that fact
before returning their containing resources. Dispatcher and pool errors remain
two finite typed leaves; one cannot replace the other.

Resource-begin rollback now moves the initiating error and the actual independent
cleanup error into an inline report, without reboxing their existing allocations.
A private rollback record proves quarantine; absence of a selected checkpoint
claim alone proves nothing. Source construction and retained history preserve
that report separately from later cleanup and postchecks. The same raw host
cleanup helper owns both installed-guard cleanup and pre-guard rollback. The
public generic finish adapter still renders its raw cleanup failure into a
terminal message; preserving that leaf through the public API remains a separate
caller migration. Replay binding now uses the same inline rollback report to
keep its initiating and cleanup errors together, after its existing quarantine
effects. That narrow bind-error path still needs authentic service-lane coverage;
the seven new resource-begin component controls all pass. Checkpoint promotion
still has separate first-cause replacement paths. Replay's retained-service
fallback still allocates and leaks its containing owner on uncertain cleanup;
preserving diagnostics alone cannot repair that custody path. Promotion can carry distinct realization,
closure and restore causes plus multiple cleanup phases. Its follow-up needs a
finite nonrecursive history representation and an actual containing-body size
query for the promotion body; the ordinary semantic-worker cell query alone does
not fund a separate promotion body. Promotion construction now uses an unbuilt
plan. Its checked visible worker/vector/capture/path and shared-catalog geometry
joins the same once-only Main worker debit, and only then can the builder create
the map, exact-capacity vector and owned paths. Initial Source construction and
all promotion workers share that same immutable basis map. Clones retain the
original payment without copying the map; the last wrapper destroys both map
entries and the Arc allocation before returning payment. The B-tree query reuses
the existing audited node calculation. Finite input and duplicate-basis checks
bound construction to the admitted geometry.

The initial Main-funded map retains the actual purpose returned by that debit.
Runtime constructors require the existing decode account, and the component
composition explicitly charges its existing checkpoint metadata account. Missing
runtime authority refuses rather than manufacturing an unscoped account. Existing
captured checkpoint bodies remain existing inputs; their earlier allocations are
not newly attested by the producer query. Supplied thread payloads and names are
measured, but the standard library's private thread controls and whole-stack
capacity still need separate qualification. Resource ceilings remain unchanged.
Both default and private-feature workspace/all-target checks pass for this joined
source. Thirty-three focused daemon controls pass, including all new member
state, retained-child, shared-map, refusal-before-build and single-admission
controls. The new B-tree geometry/accounting control also passes. The fresh API
library and API ABI suite have 120 and six passes. Source hygiene has five passes;
the standards suite retains its one unresolved broad classifier gate.

The affected-library run completed with 1,701 daemon passes, 17 failures and 43
ignored tests. The daemon and QEMU failed-name sets are unchanged. All 239
resource controls pass, with one ignored probe; API, API ABI, harness, boundary,
traceability and hygiene controls pass. The broad standards gate remains open.
The original storage run has 685 passes and one checked-fence allocation-observer
failure: its process-wide roster observed three reallocations rather than zero.
Both 512-MiB workload cases pass. An isolated diagnostic invocation also passes,
which does not clear the original failed run. The unchanged six ordering/unwind
cases now run in one dedicated test child. The parent requires successful exit
and the real outer-fence measurement, so selecting no test cannot pass. The fresh focused
control, default/private workspace checks and hygiene pass. The fresh complete
four-thread storage suite now passes all 686 tests in 2,182.89 seconds, including
the fixed observer and both 512-MiB workloads. This replaces the pending full-suite
qualification without erasing the original failed run. Packaged target
compilation passes for the immutable member-state/promotion cohort, before the
subsequent test-only controls and World-loan return API. Packaged qualification
of the latest joined source remains due. These results do not qualify native
integration, physical resource floors or VM performance.

A new negative publication regression calls the actual constructor-failure
adapter twice with its canonical reservation whose queue is unavailable. It
preserves the same token, file-owning body and typed first cause, executes no
cleanup, and refuses diagnostic extraction while custody remains. The exact
release-mode control passes. Its local disposal returns no Main or World
resource; positive authenticated publication and deployed cleanup remain separate
requirements.

Prepared Service retention also needs an actual owning continuation before the
World claim: assignment/window changes can precede the before-effects callback.
Queue completion proves native-body destruction and containing-control closure,
not final World/window return. The same Service must survive outside that native
body until exact loan-backed World return, then watchdog join and discharge.
Replay still lacks Source's fixed retained-owner continuation. The existing World
queue role can support that design without a fourth cell, but these ownership
and caller-integration seams remain unimplemented; an empty node ledger is
insufficient evidence.

The genuine World cleanup loan now shares the canonical claim's physical-return
core. It authenticates the retained original and cached Cleanup, preserves
pending containing-body debt, and records descriptor/ledger consumption before
reporting either work or post-refusal. The original claim observes loan-driven
return and latches its existing boolean; its Drop uses the same nonblocking,
allocation-free fact. New loan issuance holds the ledger through the existing
pool alias clone and refuses an already returned epoch. Default and private
workspace/all-target checks pass. All 242 resource-library tests pass with one
ignored probe, including three new component controls and three additional real
kernel-limit cases. Independent source review found no concrete defect. These
controls exercise internal ledger/kernel cuts; authentic Main-to-public-loan
execution and the Source/Service handoff remain unqualified.

Ordinary prepared-Source retirement also has an unresolved ownership defect:
it empties the Source and leaks a newly boxed lifecycle/observer pair after
shutdown refusal. A replacement must preserve reachable cleanup custody and
exclude every work and reuse route once retirement starts. Keeping the lifecycle
alive until aggregate World return is insufficient: its existing cleanup cell
holds the containing-body lease, which returns only after actual body
destruction. Successful construction now moves the same World cleanup loan
from Pending into the concrete launcher, including restoration of the other
moved parts if that loan is absent. The loan remains inside the lifecycle body;
retirement must move it and the observer outside that body, use the existing preallocated
carrier/reservation for destruction, and observe exact World return before
service discharge. A historical error or cleanup receipt alone cannot establish
that return. The existing Source lifecycle Box is now included in its actual
prebirth request where it overlaps the launcher, shared controls and retained
carrier. A boxed handoff validates the original empty carrier before releasing
the Loop allocation; every refusal returns the same Box and its owners. Both
new identity/destruction controls and the existing value-transfer controls pass.
This supplies no new allocation or operational allowance and does not activate
the still-unimplemented Source retirement phase.
The actual cleanup producer now returns one opaque move-only bundle containing
its original reservation Box and the exact Weak queue, index and epoch. Pending
validates that same reserved cell before generation storage allocation and before
successful transfer; the launcher retains the same bundle inline. Validation
uses a nonblocking lock and rejects changed phase or epoch, occupied ownership,
handoff, missing controls, poison, contention and an unavailable queue. Neutral
publication consumes the original Box without another wrapper or strong queue
edge. The existing size queries include this inline storage before body birth.
Both new reservation controls and all nine existing module controls pass in
release mode. Default and private workspace/all-target checks pass, as do all
five hygiene controls and the publication mutation controls. This transports
cell identity only: the post-body World/observer continuation and pre-Service
reservation are still required, and receipt completion still proves only body
destruction and control closure.

Consuming demotion, restore-refusal and descendant-retirement callers must retain
the actual Source or its existing cleanup handoff across failure. Typed error
preservation is a prerequisite, not an implementation of these ownership seams.

Guard finish now transports its original realization error and independently
observed quarantine fact through generation ownership, the launcher, Loop,
canonical cleanup cell and completed receipt. Local member release uses a finite
status that cannot perform aggregate host cleanup. If rejected construction owns
two independent bodies, both cleanup attempts execute in their original order
and both raw failures remain owned after body destruction. The existing cell,
reservation, epoch and receipt are reused; no new cleanup allocation, clock or
resource ceiling is introduced. World aggregate state explicitly distinguishes
active, returned and retained, so an absent diagnostic cannot imply return.
Default and private workspace/all-target checks pass for this joined source.
All five new release-mode cleanup controls pass. That full daemon run finished
with 1,707 passes, the same 17 failed names and 43 ignored tests. The subsequent
boxed-transfer run exposed a provider-fixture assertion against a descriptor
number that another thread could reuse. The fixture now keeps its original inode
linked and compares device/inode identity before and after last-alias destruction,
while preserving its slot, Service-pin and exact capacity-return assertions.
The complete parallel rerun has 1,709 passes, the same 17 failed names and 43
ignored tests in 314.12 seconds. The run with 18 failures remains recorded; an
isolated passing rerun was not used to clear it. The standards suite now has 34
passes and its existing broad classifier
failure, with 26 findings after the exact publication declaration contract;
its negative and omission mutations pass. Two mutation targets were repaired:
the canonical unavailable constructor is selected explicitly, and deleting a
whole signature preserves its same unreviewed retry marker. No matcher,
inventory or operational requirement was weakened. Final layout
and native budget fit remain unqualified. The final Service/Flight diagnostic
boundary still consumes owning failures after formatting and needs its own
retained continuation.

World and node returns now verify their exact saved Cleanup, retained family,
kernel partition and ledger epoch rather than requiring a live preparation
parent. New work still needs live admission. The first Cleanup admission result
remains latched, and its actual allocation is priced once per finite World cell.
The descriptor-return journal records successful setrlimit before any readback;
a later verification refusal cannot cause a second subtraction and leaves the
partition sealed against new admission. The real-kernel helper deliberately
changes the soft limit after observing the successful write, then proves genuine
readback refusal, retained sealing and no repeated return. All 239 resource
controls pass, including six new ledger/operation controls and that helper case.

Returning an assignment is distinct from destroying its owning facade. Factory
closure still requires every canonical node and World entry to be removed. An
exact preexisting loan can observe an already-committed World through its same
pool and monotonic publication epoch, without claiming it was never born or
issuing new work. Authentic whole-factory recovery and native physical return
remain unqualified; the local ledger and kernel controls do not issue Main or
Source authority.

The retry-path review also identifies an unqualified debug-replay route: replay
loops can be dropped after shutdown refusal without a canonical cleanup handoff.
The actual Source launcher currently refuses independent replay worlds. Before
enabling that route, success and failure must retain the real replay owners
through their exact cleanup receipts; a source-classifier exemption cannot
establish that missing lifecycle.

Native Source activation, genuine Target preparation, owner-driven capture and
full qualification remain open. The normal-service VM evaluation reaches the
QEMU build, whose dirty-iterator fixture still fails; no VM lane was executed.
The required application-target build passes locally for the backend-cutover
snapshot, including every application's unit and integration target compilation,
with remote builders disabled. A new local packaged run covers the observation
and constructor-finalization code; it also passes, including all application
unit and integration target compilation. This immutable packaged snapshot
predates the dispatcher and typed resource-begin changes. A further local
application-target build now covers the joined World-return and replay source;
its result remains pending. The workspace, feature and full private-library
results are recorded above. The pending-aware World and dispatcher cohorts pass
normal all-target workspace checking and all 239 Linux resource tests, with one ignored probe. The World controls use actual
ledger transitions and physical resource leases, without claiming authenticated
Main issuance. ABI, license and scheduler boundary checks and engineering hygiene
also pass. The complete private QEMU library run has the unchanged six capture/fault
failures recorded above. Integrated qualification and VM performance parity
remain outstanding.

### 2026-10-21 retained semantic and publisher checkpoint

The v5 module child first-binds its actual semantic Enter/Current/Outcome/Return
callbacks. Its pinned payload borrower authenticates canonical output fields,
process/thread identity, checked local serials and the same pending request.
Callback first/post history remains independent of the actual worker's receipt
journal. Final immutable 48-byte action evidence precedes holder consumption;
a later negative post cannot resurrect physically returned custody. Worker
completion requires the actual material acknowledgement and physical children,
not callback success, a control token or a copied completion flag.

The standing publisher compares every one of its 187 atomic payload words
under its existing publisher lock. Identical complete facts preserve the actual
even publication epoch; any changed field still publishes a fresh checked
epoch. Notifications and cancellation observations remain required even for
identical bytes. This prevents periodic identical publications from invalidating
an ongoing native action without relaxing its captured-epoch check or renewing
any Original's interval.

Fresh fingerprint capture refuses an exhausted request/acknowledgement pair
before Source admission or mapped mutation. Sample publication separately
refuses generation exhaustion or an occupied writer before changing payload
words. The legacy coalescing sampler API does not supply a fresh operational
request; these results do not establish that every operational counter is fixed.

The semantic component checkpoint passes 1,137 plugin unit tests and four
integration tests. Independent actual rebuilds reject copied semantic holders,
omitted payload-borrow retention and missing final evidence. The standing
publisher passes 29 focused controls. The fingerprint-counter checkpoint passes
109 shared-memory unit controls and five focused host fingerprint controls.
The refreshed hermetic supervision gate passes all 113 exact cases at
`/nix/store/sfwwmkhyh9knpmdysczwasxysqjydkzb-crucible-gate-ram-supervision-0`.
These are component results, not Source activation or launched qualification.

The signed native publisher checkpoint is atomic commit
`529ca2ec448fa0120d328b3977a5a267ddf19b4d`, tree
`2899728ccc1905728e78ceabed2576bcfad50fed`, on the sole pinned parent
`1ed046750938db278a12dc55c6a7934d5fc68c14`. It retains the actual Ready
publisher subscription and a separate prepaid return writer through Main,
semantic and canonical payload closure. Local CRUCRET1 publication never clears
the Host's frontier hold or unlinks its producer rows. Full owning controls
pass all 187 scenarios, and all 34 independently rebuilt deliberate defects
reach their intended assertion failures with zero timeouts. The maximum combined
rebuild/run is 30.199 seconds within the unchanged 60-second limit. Raw ABI,
signed reconstruction and the 262-file license ledger pass. Full native
compilation completes all 3,863 targets; 25 of 26 fixtures pass. The mandatory
launched Source/Root/read/post/rearm/ACK/physical-return fixture still refuses.
The entered ActionOriginal assertion hooks are present but unexecuted.

Earlier failed candidates remain failed observations. In particular, candidate
`c798d104f9a5b8cbf767caf35633fb2658754db4` reaches sixteen intended causal
assertions before its malformed four-field mutation tuple prevents the next
compilation. Correcting that harness tuple does not qualify the failed attempt.
The missing extractor predicate references and stale fingerprint attempts also
remain recorded independently in the signed checkpoint's description.

The exact construction-custody cleanup forwarder now has its own source-policy
contract, bound to its complete cleanup and post-body companions. Foreign
receivers, added effects and erased failures remain visible to the unchanged
scanner. All 72 focused controls, five hygiene controls and mandatory application
test-target compilation pass. The broad gate still reports thirteen daemon
paths. The last full license-gate attempt fails at its strict controller
prerequisite with 943 host test-target lint errors; direct ABI and license-ledger
passes do not replace that gate. Eight known guarded-helper integrations remain
unresolved. The published inventory binds 211 component and nineteen native
cases to 243 requirements, with 149 uncovered and none fully qualified.
Activation, general low-residency progress, complete fork/rearm and performance
parity remain unqualified.

### 2026-10-21 control and scheduler publication checkpoint

Fresh control publication now checks the final unsigned generation before
calling its producer or touching mapped state. A producer is entered at most
once; an intervening generation change refuses the exact publication rather
than retrying against another boundary. The host independently rejects a
wrapped request and authenticates the unchanged acknowledgement tuple. These
changes pass 111 shared-memory tests, six host capture controls, nineteen
Source-action controls, two acknowledgement controls, and all 119 exact
hermetic supervision cases at
`/nix/store/px1v5wz4af7ax2zy4kpmy3x9miiq0m7q-crucible-gate-ram-supervision-0`.

Scheduler publication separately reserves one checked even-to-odd generation
before either inbox adapter enqueues frames. An occupied writer refuses
without waiting. Abandoning the reservation consumes its epoch while preserving
the prior tuple and wake value; it does not authorize replay of already-enqueued
frames. Restore publication uses its own boundary and grants no Quantum role.
All 116 shared-memory tests and 21 scheduler handoff integration tests pass.
Mandatory application unit/integration target compilation passes at
`/nix/store/6v4x5bk17ihhi1clx510a03k31wfxxxw-aos-test-targets-0.1.0`.
The matched 124-case hermetic supervision gate passes at
`/nix/store/kmxdx9dhs4szr2njbpbydwk2laajdafm-crucible-gate-ram-supervision-0`,
and raw ABI conformance passes at
`/nix/store/wi9cc5c8arhiiv00zqwdw3asp692wmyc-crucible-phase2-abi-conformance-0`.
These results precede the subsequent issued-owner restore changes.

The signed initial CPU checkpoint is atomic commit
`7db67fefae5063ec0b738404da06e86f1213ad34`, tree
`dd5d400b62ab0a9eb8f5fbc9f65968e8d0f34b43`. It retains actual class-0
construction receipts and QOM ownership through deferred FIFO callbacks and
independent postcuts. Selected SDK factories refuse missing allocation payers
before creating output. All 187 owning scenarios and the complete 34-defect
causal sweep pass under unchanged limits, as do signed reconstruction and the
264-file license ledger. Actual initial CPU assertion hooks remain unexecuted.
Full native compilation completes all 3,863 targets, with 25 of 26 fixtures
passing; the required launched lifecycle still fails.

The full license gate on the scheduler snapshot fails at its strict controller
prerequisite with 944 host test-target lint errors, before boundary checks.
Its direct ABI result is not a substitute for that failed gate. Published
coverage now binds 222 component and nineteen native cases; the 243 requirements
still have 149 uncovered and none fully qualified. Genuine Quantum issuance,
manifest allocation payers, activation, eight helper integrations, general
low-residency progress, full fork/rearm and performance remain unresolved.

### 2026-10-21 exact-restore and native catalogue custody checkpoint

Exact restore now retains the actual issued Node through paused priming,
deferred resume and final handoff. The existing Source recipient also owns a
fixed artifact cell for the actual prepared directory, verified target and
sealed inputs. Reserving that cell before preparation prevents process return
from publishing complete closure while files are still in flight. A failed
preparation returns the same artifacts to that recipient; it cannot create a
replacement controller or cleanup operation. The containing directory drops
after its sealed inputs. Actual file destruction runs outside the metadata
mutex, and an unwind or duplicate return leaves closure uncertain.

The completed-launch custody snapshot at `4ad082ed2a` passes all 160 focused
supervision tests, with two existing ignored cases, 72 source-policy controls,
five hygiene controls and five actual-file custody tests. Its mandatory
application unit/integration compilation passes at
`/nix/store/zlrgjrx2bvr41wjaybbwf2s1qwvl1kba-aos-test-targets-0.1.0`.
All 131 exact hermetic supervision cases pass at
`/nix/store/fgmkrza3h102z9q8bd2xxnk2i6jlj014-crucible-gate-ram-supervision-0`.
The earlier preparation extension at `b3135cd7cd` passes 160 focused supervision
tests, 73 source-policy controls and five hygiene controls. Its mandatory
application compilation passes at
`/nix/store/7vq9k815i6lzycrrxn96yxsr2q55ny4r-aos-test-targets-0.1.0`;
all 131 matched hermetic supervision cases pass at
`/nix/store/9bchr266rviajw1z19zz7n6jckdfhjdz-crucible-gate-ram-supervision-0`.
File and child-process component tests establish custody
ordering; they do not qualify a genuinely installed Source lifecycle.

The hardware catalogue and interrupt observation checkpoints retain actual
architecture/device facts in their existing fixed declarations. The interrupt
snapshot at `8e648ff0ef` is atomic commit
`3781e9719d792930a5dfdf5803224fcf6db9ae30`, tree
`12ef299e76a522b6ed58dc9d044aef244b38963a`. Its real owning-storage extractor,
187 owning scenarios, complete 34-defect causal sweep, signed reconstruction
and 267-file license ledger pass. Full native compilation completes all 3,863
targets; 25 of 26 fixtures pass. The required launched lifecycle still fails.
Raw ABI conformance passes at
`/nix/store/lmqjsv3rw6ccf3rvzfjk941238vpq5lf-crucible-phase2-abi-conformance-0`
against the byte-matched completed-launch Rust snapshot. That immutable result
excludes the subsequent preparation extension and cleanup API changes.

The full license-gate attempt for the completed-launch snapshot still fails
before boundary checks: strict controller checking reports 949 host test-target
and 907 host library errors, four control-API type-complexity errors and one
session test assertion lint. The broad source gate still reports thirteen
daemon paths. Published coverage binds 229 component and nineteen native cases
to 243 requirements, with 149 uncovered and none fully qualified. Native
initial-callback assertion hooks remain unexecuted; selected SDK factories
still refuse missing payers. Genuine Quantum issuance, allocation coverage,
activation, eight helper integrations, complete fork/rearm, general low-peak
progress and performance parity remain unresolved.

The subsequent cleanup API checkpoint at `262ba8203e` names the existing
boxed reservation, handoff and refusal types without changing allocation or
custody. Its strict library Clippy check, 73 source-policy controls, five
hygiene controls and both lifecycle integration tests pass. Mandatory
application unit/integration compilation passes at
`/nix/store/g4mzhjbcbnfwqkc5g3a697fjqdjchyaa-aos-test-targets-0.1.0`.
Strict all-target API checking then reaches nine existing integration-test
`unwrap()` findings. The full license gate remains unqualified.

### 2026-10-21 Quantum driver, refusal helpers and register count checkpoint

The driver-issued Quantum at `7f8f8eb777` now remains entered through initial
yield, publication, wait, finish and final yield. The successful report follows
its final cancellation check and actual completion. All twenty async-driver
controls pass, including five new cancellation and completion cases; 73 source
policy and five hygiene controls pass. Mandatory application compilation passes
at `/nix/store/4kp27kwc1918f5k1gdcdw6k6h9c6rzyw-aos-test-targets-0.1.0`.
All 136 matched exact hermetic supervision cases pass at
`/nix/store/l8f5xif6dk9nc0ivhs7xhh2qky2lsskv-crucible-gate-ram-supervision-0`.
This does not issue a genuine native Advance or CPU child. Published coverage
now binds 234 component and nineteen native cases to 243 requirements, with
149 uncovered and none fully qualified.

The cleanup-fixture checkpoint at `91be0c7406` propagates actual setup and
capacity-reservation errors instead of unwrapping them in integration helpers.
Strict all-target control API Clippy and both existing deallocation controls
pass. Mandatory application compilation passes at
`/nix/store/j8hacx08kxq6wl9chqx7p0bqfcy1kjpk-aos-test-targets-0.1.0`.
A fresh full license-gate attempt still fails in its strict controller
prerequisite: 910 host library and 952 host test-target errors. That attempt
reports none of the previous control API or session findings. It includes the
Quantum driver changes and precedes the static service-diagnostic change.

The ARM register count checkpoint at `cbc6055afd` is atomic commit
`2db28e26f017864cb54b04c00047ec42ee72f45e`, tree
`298644ae0d58539cbfbc7e21e333f71ba52e0365`. It counts eligible realized
registers without allocating the later sorted-description arrays. Its 187
owning scenarios, complete 34-defect independently rebuilt causal sweep,
signed reconstruction and 268-file license ledger pass. Full native
compilation remains 3,863 targets and 25/26 fixture drivers; the mandatory
launched lifecycle fails. Raw ABI conformance passes at
`/nix/store/0vmjwr6xnh7frqvl995fssdbfxlysspx-crucible-phase2-abi-conformance-0`
against immutable source
`/nix/store/sfnh5zgrr36b9vd8p33c4l85rkmqmfbd-crucible-workspace-src`.
All 5,257 tracked crate Rust/TOML files were byte-matched. That source includes
`b3135cd7cd`; the later cleanup aliases, Quantum driver and cleanup fixtures
are outside this ABI verdict. The caller-storage register-writer candidate is
being checked separately. Actual initial callback and lease assertions remain
unexecuted, and selected missing-payer refusal remains in force.

### 2026-10-21 caller-storage descriptions and static refusal diagnostics

The architecture description checkpoint at `837e0071ab` installs actual ARM
and x86 CPUClass caller-storage geometry, key-view and description hooks. It
checks complete capacities and disjoint spans before writing descriptions;
legacy allocating wrappers retain their features. Its atomic commit is
`b8af185116a394543b1741d926e18cb453df0301`, tree
`e28599baf218544f99baec0a169af96c1ae9abba`. All 187 owning scenarios,
the complete 34-defect rebuilt causal sweep, signed reconstruction and the
270-file license ledger pass. Full compilation remains 3,863 targets with
25/26 fixture drivers passing; the mandatory launched lifecycle still fails.
Raw ABI conformance passes at
`/nix/store/pzfw6zllyijf398cdj6c2h9djlf2dcxr-crucible-phase2-abi-conformance-0`
against immutable source
`/nix/store/xa49xnr9vqrqz4wb1cp3bfqcc1v6bwj2-crucible-workspace-src`.
All 5,258 tracked crate Rust/TOML files were byte-matched. This captures the
Quantum driver and fallible cleanup helpers; later static service diagnostics
and refusal-owner changes are outside that ABI result. Actual initial
callbacks, selected constructor payers and native physical return remain
unqualified.

The service-refusal checkpoint at `95245080b2` borrows fixed policy text while
preserving ownership of dynamic diagnostics. The real mismatched-capacity
refusal now observes zero allocations and zero reallocations. All 193
host-resource tests, 26 daemon history tests, 73 source-policy controls and
five hygiene controls pass. Mandatory application compilation passes at
`/nix/store/w8v9pbd01r1rlncjryq4nbipfdn36q0d-aos-test-targets-0.1.0`.
These results preserve the actual first cause, independent post and retained
custody. They do not establish complete diagnostic payload funding, passing
full strict lint, Source activation or smaller physical execution peaks.

The refusal-owner checkpoint at `e81c1724da` expresses the issuer's mutually
exclusive actual owner as one inline variant. The first cause, independent
post, delivery failure and receiving-stage failure remain separate. Moving the
actual World leaves the rest of that same report intact. All 193 host-resource
tests, 73 source-policy controls and five hygiene controls pass, including
causal omissions of World and dispatcher retention. Mandatory application
compilation passes at
`/nix/store/77r7jh0ji2aw7kd7gb6aiq8h3pq9igxf-aos-test-targets-0.1.0`.
The measured refusal layout shrinks from 384 to 248 bytes. This introduces no
failure allocation and claims neither a passing full strict gate nor complete
funding or native return qualification.

### 2026-10-21 register workspace custody checkpoint

The native workspace checkpoint at `f9faafee9a` is atomic commit
`3516a7359c20041332cc2d17777125f393006b6f`, tree
`a1fb4093e0f9d5bedfb2956675156460e4f15d24`. It derives checked typed spans
from actual register geometry, retains the stopped CPU cohort through actual
QOM/allocation dependencies, debits backing before mmap and retains uncertainty
through unmap and QOM-return cursors. The selected constructors remain refused.

All 187 owning scenarios pass with zero skips under the original limits. The
complete 34-defect independently rebuilt causal sweep passes, including five
new literal layout omission controls; positive execution is 52.482 seconds and
the slowest mutant is 30.358 seconds under the unchanged 60-second limit.
Signed sole-parent reconstruction and the 274-file license ledger pass. Full
native compilation completes 3,863 targets and 25/26 fixture drivers pass; the
mandatory launched lifecycle still fails.

Raw ABI conformance passes at
`/nix/store/sgkdscy7h3fj0acmxzar3zpc4ywkqn9v-crucible-phase2-abi-conformance-0`
against immutable source
`/nix/store/y4xzxjpxl482629pbgm7kf1rvhs2xmas-crucible-workspace-src`.
All 5,258 tracked crate Rust/TOML files byte-match the captured source at
`95245080b2` plus four frozen refusal-owner/source-policy paths. Later source
bytes, including formatting corrections and runtime diagnostics, are outside
that verdict. The actual installed map/unmap, QOM return and initial callback
paths remain unexecuted. These results do not qualify manifest acceptance,
Source activation, native operation issuance or physical peer return.

### 2026-10-21 typed runtime diagnostic checkpoint

Commit `1e86fbf04b` retains the actual typed host-supervision refusal without
formatting another diagnostic allocation. Display preserves explicitly authored
combined diagnostics, including the actual canceled Preparation and failed
Unix wake during Pause rollback. The real canceled Quantum allocation control
observes zero allocations and reallocations, and an existing owned message
moves without changing its pointer.

All 22 async-driver tests, 62 host-I/O controls, 73 source-policy controls and
five hygiene checks pass. Mandatory application test compilation passes at
`/nix/store/5pqyzldjwwph8xi06yynvd5csr7arbfr-aos-test-targets-0.1.0`.
The expanded 139 exact-case hermetic supervision gate passes at
`/nix/store/ssx9ldxj5w2dpjvibfxzpbbl47v8wz6z-crucible-gate-ram-supervision-0`,
including all three new bindings. The preceding 138-case snapshot passed too,
but predates the combined-diagnostic guard and rollback assertion; it does not
qualify those later bytes.

The inventory at this checkpoint has 256 bindings: 237 component and 19 native.
It still has 243 requirements, 149 uncovered requirements and zero qualified
requirements. Dynamic diagnostic payload funding, independent failure postcuts,
native Source activation and physical peer return remain unfinished.

### 2026-10-21 static runtime and fault registration checkpoints

Commit `3d768cb6b2` borrows static adapter diagnostics and moves owned dynamic
messages without copying their allocation. The actual unsupported metadata
method refuses with zero allocations and reallocations, before issuing a lease
or performing runtime waits. All 23 async-driver tests, 62 host-I/O controls,
73 source-policy controls and five hygiene checks pass. Final application
test-target compilation passes at
`/nix/store/hld69pr020dpw3ik49wqz0bbfm1fcpga-aos-test-targets-0.1.0`.
The 140-case hermetic supervision snapshot passes at
`/nix/store/z15sz7d0wz0carz3rzlnmcy8gypivk70-crucible-gate-ram-supervision-0`;
it precedes the test's unused-mutability cleanup and subsequent runtime-post
changes. Its verdict does not cover those later bytes. The inventory has
257 bindings: 238 component and 19 native, with 243 requirements, 149 uncovered
and zero qualified. Dynamic diagnostic funding remains unfinished.

Commit `3f106e543f` integrates nominal fault registration custody as atomic
commit `e12c9a8c00e894e9ef7c329210f77b951f6d7da6`, tree
`78e1212fd07321a08889bca0a0850d6960d5dcc5`. The actual permanent Node producer
owns canonical registration identity and construction intervals. Registration
checks process identity before inherited locks, preserves existing edges on
duplicate or sealed refusal, and retains actual Submit/VMState validation
identity, copied command, first/post and physical callback return. Selected
preallocation remains refused; no selected payer is supplied.

All 187 owning startup scenarios pass without skips under the unchanged
600-second build, 60-second execution and 6-GiB address-space bounds. Signed
reconstruction and the 277-file corresponding-source ledger pass. The complete
34-defect causal sweep passes at
`/nix/store/sxgx746f6lpxks2780pg7yzrqi1aqs6y-crucible-qemu-received-delivery-causal-11.1.1`:
the positive takes 59.057 seconds, the slowest defect takes 30.488 seconds,
and no run times out. Every retained command, source hash and intended assertion
was checked. Full compilation completes all 3,863 targets; 25/26 fixture drivers
pass and the mandatory launched lifecycle still fails. Preserve the earlier
misplaced-header compile failure and 24/26 full sweep. The corrected TCG fixture
uses actual empty producer/thread providers and aborts on an unexpected Source
selection query; it supplies no accepting owner.

Raw ABI passes at
`/nix/store/h5dc0w42pdcgjymyn9l7k64l96xbjd4z-crucible-phase2-abi-conformance-0`
against immutable source
`/nix/store/sv2gvdqbhl9c79ywlcpd6iz7lnfliwnc-crucible-workspace-src`.
All 5,258 tracked crate Rust/TOML files match the source captured at `f9faafee9a`
plus two frozen runtime diagnostic/test edits. Later static-message and
runtime-post bytes are excluded. The TCG-only repair changes none of that
gate's inputs. Genuine producer construction, duplicate registration,
callbacks, retirement, Source activation and physical peer return remain
unexecuted. The full license gate remains blocked at its controller lint
prerequisites. Pending-fault storage and later execution checkpoints are
separate work.

### 2026-10-21 runtime posts and prepaid worker journals

Commit `664c96bb16` observes the same entered operation after every actual
adapter return, including refusals. It retains the initiating typed error and
independent supervision post inline through Node and scheduler conversion.
Ordinary Source-health failures retain priority over consequential socket
transport failures. Cleanup remains live after outer cancellation; the initial
test that incorrectly expected Cleanup cancellation is retained as a failed
snapshot rather than qualification of the corrected implementation.

All 26 driver tests, five Node conversion tests, 62 host-I/O controls, three
actual Source-health tests, 73 source-policy checks and five hygiene checks
pass. Final mandatory application compilation passes at
`/nix/store/zza3ig7f4xs4s6z8wp1246c6q1hnrdyq-aos-test-targets-0.1.0`.
All 144 exact hermetic supervision cases pass at
`/nix/store/kx4b0938dv6dskv0kyx4dag084c03ngx-crucible-gate-ram-supervision-0`.
These snapshots precede the subsequent worker journal change. Target, channel
and health failure post retention, complete diagnostic funding and genuine
native issuance remain unfinished.

Commit `25bad78d7f` reserves and creates separate launch and worker failure
journals during Source preparation, before transferring the socket/backing or
starting a worker. The separate launch journal survives a failed thread spawn
destroying its closure and worker journal. Recording consumes the unpublished
owner and fills the same shared control without allocating. Published typed,
cloned and backend observers retain the original loan through control close.

All 27 Source tests pass, including success, unwind, retained-file custody,
conversion, zero-allocation recording and refusal before input transfer when
capacity covers only one of the two actual journals. All 73 focused policy and
five hygiene controls pass. Mandatory application compilation passes at
`/nix/store/wf9sq6b731z373pkf29di195ilbkwdgz-aos-test-targets-0.1.0`;
all 5,258 tracked crate Rust/TOML files byte-match immutable source
`/nix/store/j0vq3mlpmddzhwjwkdvqpisby8alm4yx-aos-workspace-src`.
All 146 exact hermetic supervision cases pass at
`/nix/store/682jkwszv61n251gjx3rmk3k20zsgbsx-crucible-gate-ram-supervision-0`.
Dynamic payloads,
thread-builder allocations and genuine selected Source execution remain
unqualified. The inventory has 263 bindings: 244 component and 19 native;
243 requirements, 149 uncovered requirements and zero qualified requirements.

### 2026-10-21 preborn helper and static channel diagnostics

Commit `e83b434377` creates its unpublished helper failure control when the
actual Main loan is reserved, before helper effects. Recording consumes that
journal without allocating; unused and final shared controls physically close
before their original paired credit returns. Three allocation/lifetime tests,
ten original-controller tests, 73 policy checks, five hygiene checks and final
mandatory application compilation pass. All 5,258 tracked crate Rust/TOML files
match immutable `vg53vvfxrqdgm796hiw708bgi3blxirv-aos-workspace-src`.
All 147 exact hermetic supervision cases pass at
`/nix/store/84cvvpk8hkb680cm61rj12b7n7vi6hka-crucible-gate-ram-supervision-0`.
Initial generic-bound and source-contract failures remain recorded. Genuine
Source/helper admission and dynamic error-payload funding remain unfinished.

Commit `6df9b6f2b0` borrows static channel diagnostics through actual constructors,
wrappers and Node conversion. Owned diagnostics keep their existing allocation,
with unchanged timeout, retry and channel coordinates. The actual unsupported
supervised Quit default refuses without allocating or calling its unsupervised
writer; the same entered Cleanup stays live. Seven focused cases, 213 Node cases
(one existing ignored), 26 driver tests, 62 host-I/O controls, 73 policy checks
and five hygiene checks pass. Final mandatory application compilation passes at
`/nix/store/iyk3b5g2csi8il2k588niw6pgylam81r-aos-test-targets-0.1.0`;
all 5,258 tracked crate Rust/TOML files match immutable
`j46f3yw6ycfiryiyj26slh3an53nj64q-aos-workspace-src`.
All 149 exact hermetic supervision cases pass at
`/nix/store/7nr3riljb0yqba519g32m9sjc8d8rghg-crucible-gate-ram-supervision-0`.
The initial conversion/wrapper
compile failure and stale reviewed hygiene digest failure remain recorded.
Dynamic payload funding and broader independent channel/target/health failure
history remain unfinished. The inventory has 266 bindings: 247 component and
19 native; 243 requirements, 149 uncovered and zero qualified requirements.

Commit `ef729ddf7f` replaces missing helper custody's boxed fixed-text I/O
error with an inline typed cause, preserving the displayed refusal. Both actual
missing-recipient checks allocate nothing and bind no recipient; their
pre-change control counted six allocations and failed. Eight receiver tests,
ten retained-controller tests, 73 policy checks and five hygiene checks pass.
The final assertion has only rustfmt paragraph changes after those local runs.
Final mandatory application compilation passes at
`/nix/store/2nlh4dxpjb5hlyqiaxn96nkngkwv45hy-aos-test-targets-0.1.0`;
all 5,258 tracked crate Rust/TOML files byte-match `ef729ddf7f` and immutable
`am0rrwdvwl19l794hlzvfwbwdkr7s83j-aos-workspace-src`.
All 150 corrected exact hermetic supervision cases pass at
`/nix/store/jmw24cvgcq9g6n81knf22f5xw1mv86xf-crucible-gate-ram-supervision-0`.
The first binding placed the
control in continuation rather than supervision, so that snapshot cannot
qualify 150 supervision cases. Other invalid-input I/O payloads, dynamic
funding and genuine selected helper admission remain unfinished.

### 2026-10-21 native pending-command custody

Commit `bba6cdc50a` integrates atomic
`465d47fe92e09345bb2e9e33ad83d3657292bf2f`, tree
`40790d5277a47d92d034d627d8d261c69c2ffee7`. Actual Node pending controls join
canonical registration before row/payload birth, retain callback output and
physical return before independent post, and survive queue unlink and physical
row/payload/control destruction. Actual command VMState owns staging and
nonwrapping issuance through construction, publication, commit, queue handoff
and cleanup. Selected preallocation ENOKEY and full registration-return ENOTSUP
remain; ordinary non-Node behavior stays intact.

All 187 owning scenarios, signed sole-parent reconstruction and the exact
278-file license ledger pass. The revised complete causal sweep passes all
34 independently rebuilt defects with exact intended assertions and no timeouts
at `/nix/store/00kkz4cdhzdchymi6rb8ibm1vc063cf4-crucible-qemu-received-delivery-causal-11.1.1`.
The positive takes 46.532 seconds of the unchanged 60-second limit; the slowest
defect takes 22.439 seconds. Per-call authenticated compile metadata is shared
between actual event-loop and QOM support selection, retaining every source,
compiler, output and complete-cohort check. Canonical output equivalence and
five provenance refusals pass. No cross-call cache or mutant-object sharing is
introduced. Preserve the preceding causal positive timeout and both diagnostic
timeouts; core suppression alone did not solve them.

Fresh raw ABI passes for immutable
`zmdc8ay16gqfswibs0v5canj40b0p9i3-crucible-workspace-src`: 5,257 of its 5,258
tracked crate Rust/TOML files match the helper checkpoint at comparison time;
the later helper declaration-clause test correction and subsequent channel
changes are outside that verdict. Full native compilation completes all 3,863
targets; 25/26 fixtures pass, with the mandatory launched Source/Root lifecycle
still failing. Genuine owned Node callbacks, restore/handoff and physical
retirement remain unexecuted at this artifact. No selected payer, activation,
ACK or physical peer return is qualified. The full license gate still fails
at controller lint prerequisites; the ledger does not replace it.

### 2026-10-21 static and typed shutdown diagnostics

Commit `905cdf8c32` borrows fixed shutdown messages and retains actual typed
supervision failures inline through Cleanup entry, budget waits and independent
postchecks. Owned messages move without another allocation. Actual refused
entry prevents work; entered work keeps its output or first refusal separately
from the same Original's failed post. No diagnostic formatting is required to
retain either cause, and typed errors expose their actual source on demand.

Eight focused controls, 216 Node tests (one existing ignored), seven shutdown
controls, 73 policy checks and five hygiene checks pass. Mandatory application
compilation passes at
`/nix/store/azp25i78kgl1rccwmhqa9hfvyffhvcvp-aos-test-targets-0.1.0`.
All 5,258 tracked crate Rust/TOML files match `905cdf8c32` and immutable
`p3xc865bcq6pa989n4h2crpsrjba1q29-aos-workspace-src`. All 153 expanded exact
hermetic supervision cases pass at
`/nix/store/hc6yr8hmcg5906km9j2mx0vppzmaij48-crucible-gate-ram-supervision-0`. The initial test that completed the actual guard
inside its counted effect exposed one deadline-report allocation and failed;
the corrected diagnostic-specific control amends the real budget after entry,
preserving the actual expired post without concealing that separate reporting
allocation. Dynamic diagnostics, complete cleanup funding and genuine selected
Source execution remain unfinished.

### 2026-10-21 inline deadline reporting and entered Cleanup completion

Commit `cd64c5ce24` keeps at most three tied deadline sources inline. Actual
status and completion preserve ordered progress/total/outer provenance without
a heap allocation. The codec reads the same bounded wire records directly into
that storage and retains existing count, tag, order and canonical-envelope
refusals. Snapshot admission includes the enlarged actual status extent and
keeps its previous conservative additional allowance.

All 194 host-resource tests, 24 operational codec tests, 73 policy checks and
five hygiene checks pass. The pre-change status control failed with one
allocation. Corrected actual status and completion allocate nothing across all
14 classes, and all deadline ties preserve their original ordering without
allocating. Initial stale codec review digest/count and incorrect review-marker
failures remain recorded; no threshold or rule changes. Mandatory application
compilation passes at
`/nix/store/lr8mn0qsjkffiq9s9q9ky7nragp54z6r-aos-test-targets-0.1.0`.
All 5,259 tracked crate Rust/TOML files match `cd64c5ce24` and immutable
`p0c0bgcb2hb2mnyhj9sb7z942w9pbb7p-aos-workspace-src`. All 155 expanded exact
supervision cases pass at
`/nix/store/b559qs3akbpm1127xdggdzpifw7q41ni-crucible-gate-ram-supervision-0`.

Commit `8fe4c8d231` returns to the actual Cleanup completion path that originally
exposed the allocation. Completing the real guard inside an entered rung now
allocates nothing; successful work retains its returned output, and refused
work retains its initiating cause separately from that same completed
Original's independent post. The prior actual deadline-expiry control remains.
Nine focused controls, 217 Node tests (one existing ignored), 73 policy checks
and five hygiene checks pass. Mandatory application compilation passes at
`/nix/store/45ck89h9bk4ndzrx3prr2vrsdq9ax512-aos-test-targets-0.1.0`;
all 5,259 tracked crate Rust/TOML files match `8fe4c8d231` and immutable
`mqda8wz5gmxirrl5q6gsa3r6h9h45649-aos-workspace-src`. All 156 expanded exact
supervision cases pass at
`/nix/store/22s309169ipnc6pfj6s3j6haib8l9534-crucible-gate-ram-supervision-0`.
The broad source-policy check still fails its same 13 daemon paths. No source mask, rename or exception is added. These
component controls issue no Source, selected operation or child-return receipt;
dynamic diagnostics and complete cleanup funding remain unfinished.

### 2026-10-21 setup memfd construction

Commit `09bd612efe` uses a static C string and the existing safe descriptor
interfaces for actual setup memfd creation, sizing and shrink sealing. It
preserves close-on-exec, write access, descriptor length and operation-specific
kernel errors. Oversized lengths still refuse before descriptor creation.
The primitive grants no Source, helper or child authority.

The pre-change real-descriptor control failed with one Rust heap allocation;
the corrected descriptor and oversized-length controls pass without allocating.
The existing spawn-resource test, all 73 policy checks and five hygiene checks
pass. Mandatory application test-target compilation passes at
`/nix/store/sbvfpx449kvjr5fh3609552gw8zvm5jh-aos-test-targets-0.1.0`.
All 5,260 tracked crate Rust/TOML files match `09bd612efe` and immutable
`p0vc3sid02ryp39y5lflfzgaxhi5dd4s-aos-workspace-src`. All 158 expanded exact
supervision cases pass at
`/nix/store/rpyxgnbfr5gnhp8njjxlsb2ycwn8m1fa-crucible-gate-ram-supervision-0`. Coverage binds 256 component and 19 native
cases across 243 requirements, with 149 uncovered and none fully qualified.
Dynamic process setup, diagnostics and complete cleanup funding remain unfinished.

### 2026-10-21 typed child RAM channel supervision

Commit `7bf34a303f` retains actual Preparation begin, wait, outer-cap and
completion refusals without formatting a diagnostic. Channel and Node
conversion preserve the typed cause, and the actual shutdown conversion
retains it through Cleanup. Scheduler conversion keeps its operational
classification and original cause in the existing shared backend carrier;
this does not establish funding for that carrier.

The pre-change actual canceled Preparation control measured three allocations.
The corrected begin, wait and completion conversions allocate nothing. A real
completed Cleanup refusal also survives channel cloning and shutdown conversion
without allocating. All 219 Node tests pass (one existing ignored), along with
73 policy checks and five hygiene checks. Mandatory application test-target
compilation passes at
`/nix/store/94d1nfxxcb88fx8mganvim0kmvp9p80s-aos-test-targets-0.1.0`.
All 5,260 tracked crate Rust/TOML files match `7bf34a303f` and immutable
`icw1s2xwmz910iqic7ra6bckd067rgzs-aos-workspace-src`. All 160 expanded
exact supervision cases pass at
`/nix/store/5jbz6964vj7rvphf90l9hn5qdr4i8n4l-crucible-gate-ram-supervision-0`. Coverage now binds 258 component and 19
native cases; 149 of 243 requirements remain uncovered and none fully qualified.
Dynamic diagnostics, independent failure histories at other channel boundaries,
complete payload funding and selected native admission remain unfinished.

### 2026-10-21 typed QMP supervision

Commit `43d18f6986` moves actual supervision causes through QMP admission,
shared and borrowed deadline checks, channel conversion and Node conversion.
Runtime adapter causes retain their actual independent post separately. QMP
display text, transport ordering and timeout behavior remain; typed channel
conversion retains the actual operation and scheduler classification.

The pre-change canceled command and four deadline checks measured two and
twelve allocations. Both corrected controls allocate nothing, and canceled
command admission writes no additional bytes. All 117 QMP unit tests,
37 integration tests, the saturated Unix backlog cancellation control and
both optional feature paths pass, together with 73 focused policy checks and
five hygiene checks. The first policy run's three stale-contract failures remain
recorded. Refreshing its exact typed-cause expression preserves every parent
Park operation, custody and physical-return predicate.

Final mandatory application test-target compilation passes at
`/nix/store/323s201w2mk9h29lhczicjx5xvhbf804-aos-test-targets-0.1.0`.
All 5,261 tracked crate Rust/TOML files match `43d18f6986` and immutable
`c8wy0i4dp4b8qmvik74z06ng2cqrn33m-aos-workspace-src`. All 162 expanded
exact supervision cases pass at
`/nix/store/0y6vnx0f7v2ix5c6s4758f9f458h7v4j-crucible-gate-ram-supervision-0`. Coverage binds 260 component and 19 native
cases across 243 requirements, with 149 uncovered and none fully qualified.
General QMP diagnostics, runtime-to-channel formatting, checkpoint error boxes,
complete payload funding and selected Source execution remain unfinished.

### 2026-10-21 borrowed canonical fingerprint hashing

Commit `9515ebefea` streams the unchanged execution-fingerprint recipe from
borrowed sample fields through the existing exact-length canonical hasher.
Both passes retain the original domain, UTF-8 byte length, word boundaries,
field order, lowercase digests and newline separators. Active finite decode
admission reserves hashing scratch before formatting and releases it before
return. Actual admission refusal remains typed through channel and Node
conversion; scheduler conversion retains the same cause through its existing
shared carrier.

Two engine streaming controls, the finite scratch-admission control and six
host fingerprint controls pass. They cover exact old hashes and material bytes
for one through eight vCPUs, numeric limits and UTF-8 boundaries, length changes
and formatter refusal in either pass, and real exhausted scratch admission.
The measured borrowed hash and already-refused channel/Node conversion have
zero allocations or reallocations. All 219 Node tests pass with one existing
ignored test, together with 73 focused policy checks and five hygiene checks.
The first retained-cause test's compile failure remains recorded and corrected
through the standard error-source chain.

Mandatory application test-target compilation passes at
`/nix/store/zrv3955dlphb8lkdxhylrm52vvjf2iv0-aos-test-targets-0.1.0`.
All 5,261 tracked crate Rust/TOML files match `9515ebefea` and immutable
`flc4dcb3piv8hfym8asjnaw9965l0wmq-aos-workspace-src`. All 167 expanded exact supervision cases pass at
`/nix/store/3w3p1whaz5lflxnk36ahwaqsm499s7dd-crucible-gate-ram-supervision-0`. Coverage binds 265 component and 19 native
cases across 243 requirements; 149 remain uncovered and none fully qualified.
The diagnostic event counter gates the existing owned recipe but supplies no
byte funding. Enabled diagnostic initialization and payloads, validation-error
formatting, initial refusal allocation, scheduler-carrier birth and complete
selected admission remain unqualified.

### 2026-10-21 streamed fingerprint component diagnostics

Commit `2db30b57a6` writes the existing diagnostic record directly from borrowed
sample fields. Hashing and diagnostics share the ordered component visitor;
only fixed ASCII labels, integers and lowercase digests use the quoted wrapper.
Authored node names retain standard debug escaping and a 160-character UTF-8
prefix. The event counter and record format remain unchanged.

The actual pre-change formatter measured 22 allocations and 13 reallocations.
All seven focused fingerprint controls pass. The new formatter control compares
24 full records against the independent old recipe for one through eight vCPUs,
numeric limits and Unicode/escaping boundaries, with zero allocations or
reallocations into already-reserved output. All 73 focused policy and five
hygiene checks pass. Mandatory application compilation passes at
`/nix/store/qwd7ldzj523jfgsr9q248sd5flsx060n-aos-test-targets-0.1.0`;
all 5,261 tracked crate Rust/TOML files match `2db30b57a6` and immutable
`65v7by54nizzamnjaw31jqsj55ljyryy-aos-workspace-src`. All 168 exact supervision cases pass at
`/nix/store/4kyg7nbziv8yxlwk6idzqkgab1zqhayk-crucible-gate-ram-supervision-0`. Coverage binds 266 component and 19 native cases;
243 requirements, 149 uncovered and none fully qualified remain unchanged.
Environment and stderr initialization, output funding and backpressure,
validation-error formatting and complete selected admission remain unqualified.

### 2026-10-21 typed fingerprint validation failures

Commit `b7a51163ba` retains the actual protocol failure or complete component
failure bitset inline through channel cloning and Node conversion. It preserves
validation precedence, original error-source links, exact diagnostics and the
existing scheduler classification. Static missing/incomplete evidence remains
borrowed. No error path constructs replacement diagnostic storage before the
caller elects to format the cause.

The pre-change oversized-sample path measured two allocations and two
reallocations. Nine actual invalid-sample cases now allocate nothing through
channel cloning and Node conversion, including competing failures, numeric
limits and each missing component. All 48 fingerprint controls, 219 Node tests
with one existing ignored test, 73 focused policy checks and five hygiene checks
pass. Mandatory application compilation passes at
`/nix/store/9b988hrvj00x4x8izw8sn1l3l91c67gw-aos-test-targets-0.1.0`.
All 5,261 tracked crate Rust/TOML files match `b7a51163ba` and immutable
`bxgb8489vi7fb4l7s5zpfr3pk7dmpsn5-aos-workspace-src`. All 169 exact supervision cases pass at
`/nix/store/k9gdn6imk7icpi75m5x6q520rysbfg3b-crucible-gate-ram-supervision-0`. Coverage binds 267 component and 19 native cases;
243 requirements, 149 uncovered and none fully qualified remain unchanged.
Final scheduler diagnostic storage, mapped-channel errors, enabled diagnostic
initialization and output funding, and selected admission remain unqualified.

### 2026-10-21 mapped quantum views and boundary refusals

Commit `6042516f7b` borrows the existing mapped channel configuration and
canonical ring topology instead of cloning node/router names and allocating
ring descriptor vectors for each temporary view. The setup allocator keeps its
owned vector interface; every supported topology retains its exact descriptor
order and indices, and overflowing cardinality refuses before allocation.
Behind/ahead fingerprint samples retain actual coordinates inline with the
same diagnostics and retry classification, without requesting another sample.

The pre-change actual mapped controls measured four allocations for a snapshot
and five for a stale sample. Both corrected controls allocate and reallocate
nothing. All 117 shared-memory tests, 80 quantum-related host tests, 73 policy
checks and five hygiene checks pass. The initial hygiene failure required a
reviewed mapped-adapter digest refresh; no size cap or rule changes. Mandatory
application test-target compilation passes at
`/nix/store/zxxrj4pqw2wd2p4vk7v96w2zxq16j8zp-aos-test-targets-0.1.0`.
All 5,261 tracked crate Rust/TOML files match immutable
`yfsjbh8flx0gjyjxgsqdvclp0mbnfvr1-aos-workspace-src`. Matched raw ABI passes at
`/nix/store/vq7digm3lxlmi6bb0qxvvsj9rd3dyafj-crucible-phase2-abi-conformance-0`;
all 5,261 files match `6042516f7b` and immutable
`x3wck103cim889vwqs642wnd3z0n0i65-crucible-workspace-src`. The expanded
172-case supervision gate passes at
`/nix/store/74zsbm9fcvn17w8vq8dpw63ff3jmakd7-crucible-gate-ram-supervision-0`. Coverage now binds 270
component and 19 native cases; 243 requirements, 149 uncovered and none fully
qualified remain. Reader supervision, broader diagnostic/payload funding,
Source activation and selected execution remain unfinished.

### 2026-10-21 typed mapped-region channel refusals

Commit `fd021c392d` retains the actual mapped-region access error through channel
cloning and Node conversion. The fixed adapter diagnostic, nonretryable status,
absence of timeout and existing scheduler rejection stay unchanged; topology
coordinates and error source links now survive without replacement formatting.
Both fingerprint mapping-error call sites use the same typed conversion.

The pre-change actual mapped refusal measured one allocation. Both invalid
topology controls now allocate and reallocate nothing, never enter the body,
and leave the actual producer slot unchanged. All 21 mapped tests, 219 Node
tests (one existing ignored), 73 policy checks and five hygiene checks pass.
Mandatory application test-target compilation passes at
`/nix/store/fv48451wa2g00gg8qphwanrw9y93dx2c-aos-test-targets-0.1.0`.
All 5,261 tracked crate Rust/TOML files match immutable
`1z9hpph4lch7rk00n3ja9sa1av6xhp07-aos-workspace-src`. The expanded 173-case
supervision gate passes at
`/nix/store/68ajwvymmvf7pvnrxz8s1cqc87ghpsj1-crucible-gate-ram-supervision-0`. Coverage now binds 271 component and 19 native
cases; 243 requirements, 149 uncovered and none fully qualified remain.
Complete carrier funding, final scheduler diagnostics, reader supervision and
selected Source admission remain unfinished.

### 2026-10-21 inline single-operation quantum observations

Commit `d40015bc99` retains the first operation inline for the mapped channel's
current-icount, logical calibration, virtual-timer witness and idle-state reads.
Each call creates a temporary adapter and records one operation. A second event
spills both events to growable storage, preserving the public operation slice
and complete quantum reports. No event is suppressed or truncated; report/frame
vectors and longer log allocation funding remain separate obligations.

The pre-change actual four-call control measured four allocations and zero
reallocations. Repeated corrected calls allocate and reallocate nothing,
preserve exact reports, and leave the producer slot unchanged. The owned
adapter control exceeds inline and vector capacity, then finishes a shared-slot
quantum with every earlier event retained and the exact eight-event report
sequence. Its first assertion incorrectly expected completion to be last;
actual inbound-consumption observation follows it. The corrected assertion
checks the entire existing sequence without changing execution behavior.
All 83 quantum-related controls, 73 policy checks and five hygiene checks pass.
Mandatory application test-target compilation passes at
`/nix/store/68nmi1vfk55brh90s3scn4nv9x4mg7an-aos-test-targets-0.1.0`.
All 175 exact supervision cases pass at
`/nix/store/12a0y0xxi6wjfxq2jsyh8h9wh4yncd0n-crucible-gate-ram-supervision-0`.
All 5,261 tracked crate Rust/TOML files match immutable application
source `4b49zz7l0hzh93aydjyw46dshrsj20ja-aos-workspace-src`.

Coverage binds 273 component and 19 native cases; 243 requirements, 149 uncovered
and none fully qualified remain. This narrow observation improvement establishes
neither complete quantum allocation funding, bounded reader supervision,
performance parity nor selected Source admission.

### 2026-10-21 independent native action-current post

Commit `36d012f83e` integrates atomic
`d042f43ee8ab8b4f2aa58f1d8b7e01807e37a375`, tree
`853238bffbeacbf65cf7767f059f911818f3c045`. Actual action-current callbacks
retain their exact serial, Main/member and publisher identity, recheck actual
rows after callback return, and always observe the retained lender's final
sequence independently of an earlier failure. First and post causes remain
separate; uncertain debt stays retained. Sequence equality grants no publisher
ownership or scheduler Advance authority.

The literal positive and all 14 independently rebuilt omission controls pass.
All 187 owning scenarios pass without skips (219.687 seconds build, 4.577
execution), and all 34 causal defects fail their intended assertions. The
causal positive takes 58.041 of 60 seconds; the slowest defect takes 18.770.
Assertions, deadlines and the 6-GiB address-space ceiling are unchanged.
The full sweep builds all 3,863 targets and passes 25/26 fixtures, failing only
the mandatory launched Source/Root lifecycle. Its complete matched cohort is
retained; all 907 patched sources match the signed tree. Later private-layout
changes require a newly matched build.

Signed sole-parent reconstruction, exact regeneration and the unchanged
289-file license ledger pass. Raw ABI passes against immutable
`f7qjixxkbcmdn8hy26nryk7is4p0yi0g-crucible-workspace-src`: all 5,261 tracked
crate Rust/TOML files match `6042516f7b` at capture. Retain manifest SHA256
`e09bf7c2cef991cfffb414d2a0236f38df11f69ce2544821a13263f695b9f191`.
Later host changes are outside this ABI verdict. Full license-boundary
qualification remains blocked by controller lint prerequisites. Activation,
genuine class-1 issuance and owned continuation/physical return remain
unqualified.

### 2026-10-21 Main cleanup waits for actual action closure

Commit `5a39df062d` integrates atomic
`8c726fa874350779b2e62eb48d6b0c514f779036`, tree
`aa9086e2fd7c15440157d342af4dc79f9d0617ff`. Actual Core, Source and Native
return paths retain payload, Ready borrowers, QOM and descriptor dependencies
until the real action-closed predicate succeeds. First and payload-post failures
remain separate across later attempts. A negative status cannot establish
physical closure.

Literal Main and RR positives and all 12 independently rebuilt omissions pass.
These use modeled journals and refusal-only dependencies, with no accepting
action provider. All 187 owning scenarios and all 34 causal controls pass.
The causal positive takes 57.679 of 60 seconds; its slowest defect takes 19.365.
All original assertions and resource limits remain. Full compilation completes
3,863 targets and passes 25/26 fixtures, with mandatory launched Source/Root
the sole failure. The complete matched build is retained; all 907 patched
sources match the signed tree.

Signed reconstruction, exact regeneration and the unchanged 289-file ledger
pass. Raw ABI passes at
`/nix/store/44lgvsff8chfiwcz0acwgyjqvgmf1v72-crucible-phase2-abi-conformance-0`,
using immutable `8bj8kdnq9bfplc69256qx0mm1wlx0sfp-crucible-workspace-src`.
All 5,261 tracked crate Rust/TOML files match before/current/immutable bytes at
capture; manifest SHA256 is
`4abdb9aaf634cd430d723c3636901d54ca006029fbe9e65585c759ff58dfa92e`.
Later codec and architecture checkpoints are outside this verdict. Genuine
provider-backed closure, selected construction, Quantum/Advance issuance,
activation and full license-boundary qualification remain unfinished.

### 2026-10-21 canonical publisher subscription byte codecs

Commit `35606a0cbe` adds independently implemented permissive Rust codecs for
canonical publisher headers, immutable commands, publications, receiver returns,
terminal records and six ticket phases. Exact geometry, zero padding, bounded
nonwrapping coordinates, typed outcomes and existing Action cohorts are checked.
Dirty partial projections retain all born debt; negative posts preserve actual
consumption facts. These copied byte records issue no Source or operation.

All 152 protocol unit tests and 95 protocol integration tests pass, including
fifteen new codec controls and independent literal public vectors. Strict protocol
Clippy, all 73 focused policy checks and all five hygiene checks pass. Every
application unit and integration target compiles at
`/nix/store/sna0cpwrxkmjw3ijkw09a3ngsyy9i7yh-aos-test-targets-0.1.0`.
All 5,265 tracked crate Rust/TOML files in immutable
`7j2gx6jlv6mp57c8jrg58vgw2nxkhsfb-aos-workspace-src` match committed Git blobs;
source manifest SHA256 is
`a1a26459f5b9e5fb7da519b827f71bd6769bf343f188f6813b401a88480779a3`.
All 190 exact hermetic supervision cases pass at
`/nix/store/dnbs90j4f4k86ic6qn4n8j66c7zldxqm-crucible-gate-ram-supervision-0`.

The inventory contains 307 bindings (288 component and 19 native), with 148
requirements uncovered and none qualified. Actual paid session construction,
mapping/doorbell custody, bounded atomic snapshots, ticket transitions, physical
returns and class-1 scheduler ownership remain unfinished. Current transport 8,
Setup 5 and the unavailable activation declaration are unchanged.

### 2026-10-21 standing construction under its original Setup

Commit `418fdb6c3e` enters the actual Setup before paid startup allocation and
standing publication construction. Physical construction runs only after the
same guard's first observation and actual inherited cancellation check; its
independent post retains either the constructed result or initiating failure.
Successful construction cannot bypass a refused post.

All seven startup and thirty standing controls pass, including real descriptor
construction/refusal and cancellation across this shared boundary. All 73
focused policy and five hygiene controls pass. Mandatory application targets
compile at
`/nix/store/62q9r03a7sg9ahanc6r9hzj39wy9b2bl-aos-test-targets-0.1.0`.
All 5,265 tracked crate Rust/TOML files in immutable
`jfv13k43pv4sq8463bdmfyilj2l96id9-aos-workspace-src` match committed Git blobs;
source manifest SHA256 is
`c3809ce92a2e455339610d25b27ca08638b29d2f4623a07929de576ba7675742`.
All 193 exact hermetic supervision cases pass at
`/nix/store/sab3vk1ijpffdhn2cc7rwzsbvbgzp7v6-crucible-gate-ram-supervision-0`.
Coverage at that checkpoint has 310
bindings (291 component and nineteen native), 148 uncovered requirements and
none qualified. Genuine Source issuance and complete physical cleanup remain
unfinished.

The separate native scheduling candidate `bacc4317d242` passes all 187 owning
scenarios, signed reconstruction, the 289-file ledger and scoped raw ABI at
`/nix/store/k68rgbzqllvj34636wcma775vzynkpbg-crucible-phase2-abi-conformance-0`.
That ABI capture precedes the final placement of standing construction after
the actual cancellation check; it does not qualify that placement. Full native
compilation finishes all 3,863 targets and passes 25/26 fixtures, with mandatory
launched Source/Root the sole refusal. The formal causal positive times out at
60.007 seconds under its unchanged 60-second limit, before defect execution.
An earlier 43.380-second diagnostic bypassed repeated provider metadata
loading and is not a formal timing pass. This candidate remains uncommitted;
matched integration and real metadata authentication efficiency are in progress.

### 2026-10-21 paired publisher purpose and plan-nine preparation

Commit `9d9a713dae` adds independently implemented permissive Rust preparation
for the sealed 224-byte `CRUCPSP1` publisher purpose and `CRUCSUP9` plan carrier.
It checks the publisher's account, process, capability and reservation against
the existing process purpose. Plan nine adds eight header bytes and a 224-byte
tail inside the unchanged aggregate cap; the existing encoder preserves exact
plan-eight bytes. Separate decoders refuse mixed editions and fallback.
Workspace-present and absent carriers retain their same original bindings.

All 160 protocol unit tests and 95 integration tests pass, including eight new
literal, truncation, geometry, identity, workspace and aggregate-limit controls.
Strict protocol Clippy, all 73 focused policy checks and five hygiene checks
pass. Mandatory application targets compile at
`/nix/store/v28d69s3wx8mszpjbriv1m5zym3qj559-aos-test-targets-0.1.0`.
The 201-case exact supervision gate passes at
`/nix/store/glzrlqw2db675q6q3im40m29a28sk4wh-crucible-gate-ram-supervision-0`.
All 5,269 tracked crate
Rust/TOML files in the application's
immutable `rlsg3b0cpsk22nv3qjqkw1fqwdq60hnb-aos-workspace-src` match committed
Git blobs; source manifest SHA256 is
`2726dcb90be4eae0b8904793ec4071b300444b28fbe32ed17950ecca0367ec53`.

The inventory contains 318 bindings (299 component and nineteen native), with
148 requirements uncovered and none qualified. These codecs create no funded
lender, queued alias, mapping, native session or operation. Genuine producer
construction, matched transport integration, physical returns, class-one
execution and activation remain unfinished.

### 2026-10-21 paired publisher setup transport preparation

Commit `28bc78d341` adds the preparation-only 125-byte Setup6 frame and exact
SCM_RIGHTS transport for eight roles without a workspace or nine with one.
The optional workspace remains sixth, before the publisher region and its two
distinct notification events. A literal vector preserves the old common
payload; strict codecs refuse mixed editions, truncation, padding, invalid
identities and roster mismatches. The activated control registry is unchanged.

All 165 protocol unit tests and 95 integration tests pass, together with strict
protocol Clippy, 73 focused policy checks and five hygiene checks. Real Unix
socket transfers verify every received alias identity and use each distinct
endpoint; malformed frames and rosters send no bytes. Mandatory application
compilation passes at `fgb5z0hh71l7y0sa5axdcvx3ar7sxjl8-aos-test-targets-0.1.0`;
all 206 exact supervision cases pass at
`xgxkghygzs95cp23d4pgjhmcswdi1x75-crucible-gate-ram-supervision-0`.
All 5,271 tracked crate Rust/TOML files in immutable
`dr7h3bbzvhkz3wa68vj1fg68rashf8nn-aos-workspace-src` match committed Git blobs;
source manifest SHA256 is
`740c0537c6cfa8ea64172d949e3314d380953089af002ea4baa7599429423dc2`.

The inventory contains 323 bindings (304 component and nineteen native), with
148 requirements uncovered and none qualified. This transport returns an I/O
receipt only: the actual paid host lender/session construction, matched queued
owner, native module transfer, class-one operation and activation remain
unfinished. It does not authenticate the physical role meanings or issue an
Original from matching bytes.

### 2026-10-21 per-alias pre-exec ownership journal

Commit `90f00965fa` fixes the actual standing descriptor duplication path.
Previously, both aliases were duplicated before either entered the paid owner's
journal; failure of the second duplication dropped the first outside that
journal. The issuer now lends each role from its retained funded publication,
and each duplicate enters its canonical slot before the next original check or
kernel effect. Existing final observation and uncertain-close retention remain
in force. No publisher session or new descriptor role is created.

Five real Unix-socket controls verify second-effect refusal, original refusal
between effects, first-effect refusal, occupied-slot refusal and ordered success.
They inspect actual alias identity and use the live socket peer. All five pass,
as do 73 focused policy controls and five hygiene controls. Mandatory application
test-target compilation passes at
`yyiy0g0z5lfdkx3x563k0sgnf1i20d1c-aos-test-targets-0.1.0`.
All 5,272 committed Rust/TOML files match immutable
`wh9blqs3azsix2b4zk69iy3jqinvk6ix-aos-workspace-src`; manifest SHA256 is
`cf081994390c99665b8e0b399d50163416faf7467115f40a7c12a842dc844ab4`.
All 211 exact supervision cases pass at `dy2jldwf5dizmsmj0icwwxnlfpf8k45a`. These component checks issue
no native Source or Original and leave activation disabled.

### 2026-10-21 complete native followup integration

Commit `83ecde0031` retains signed atomic
`9770a340c3237f1339c19447cbba078e401a86c0`, tree
`ca1face2c22f19d4b5c777fb27b2dda95c91a909`. It composes bounded resize/discard
registries, real RAM disposal exclusion, receiver/member lifetime, exact workspace
editions, the actual installing module service and fixture dependency corrections
with the prior complete provider chain. The existing four publisher action bodies
remain present in their actual Source translation unit; this does not connect the
new Setup6 atomic publisher to a genuine host producer.

All 955 changed source hashes and 7,946 retained evidence hashes match. The fresh
configured cohort rebuilds 1,917 dependent objects and relinks both system targets.
The actual configured delivery entry passes in 49.089 seconds under its unchanged
60-second and 6 GiB limits. Public component evidence passes 187 Source scenarios,
46 pre-exec omission classifiers, 47 original causal controls and four additional
cold/rearm controls. These scopes remain distinct from installed lifecycle proof.

Independent signed reconstruction passes at
`9vjfw0bfb51hcbxpajn899mi3bkjsghw-crucible-qemu-atomic-patch-repository-0`;
the exact 319-file license ledger passes at
`rwhg74ia69prwsh78awq2c71304nrya2-crucible-phase6-qemu-patch-license-ledger-0`.
The new publisher-member return control is GPL-2.0-or-later; the two existing
LGPL-2.1-or-later additions remain unchanged. The repository's owning Source check
passes at `9vn9ph79kp6fi4ilp8978abaksb1mihx-crucible-qemu-startup-source-unit-11.1.1`.
Fresh raw ABI passes at
`cd85rk6rdvcb3nk1nf53kl6qzcz1xzix-crucible-phase2-abi-conformance-0`.
All 5,272 committed Rust/TOML files match immutable
`da9c16hf8x9rqn5pg8frw5fr8msmxw5x-crucible-workspace-src`; manifest SHA256 is
`9f43bc401d8a9162375ff2725cbfd08c81ce2aaa41f86c467c5158c8da32c052`.
All twelve prior independent custody suites pass at
`pgp2mlwpcxl24k3df2ndfwyzpiyv75zr-crucible-qemu-native-custody-unit-11.1.1`,
with 247.524 seconds total, 44.860 seconds for the longest component and
449,417,216 bytes peak sampled aggregate address space. The expanded thirteen-suite run also passes at
`sdg49q1ywai7b0nij91wcs18nzlqwj59-crucible-qemu-native-custody-unit-11.1.1`.
It takes 250.603 seconds total, with a longest component of 36.455 seconds
and peak sampled aggregate address space of 449,413,120 bytes. The canonical license-boundary check fails before its assertions
because the controller dependency fails strict Clippy (1,177 host-library and
1,250 host-test errors).

The clean full package completes all 3,991 compile/link actions and passes 25 of
26 fixture drivers. All five prior dependency/extraction regressions are resolved.
Dirty iteration reaches its mandatory genuine launched capture lifecycle refusal;
no later Source/Root/read-post/rearm/ACK/physical-return obligation is thereby
qualified. All 955 signed changed files match the retained failed package source;
manifest SHA256 is
`4b34f0f7c480cd9a4f72bb28297ad9126691846587155ca8b1dc4fce799c7e88`.
The full package remains failing. Later header observation, anonymous mapping
journaling and runtime module transfer belong to separate implementation cuts.

### 2026-10-21 publisher-member return control execution

The independent native custody runner now executes the actual
`test-crucible-publisher-member-return.py` suite alongside the prior twelve
components. Its positive and twenty-one independently rebuilt omissions exercise
literal provider cleanup/span/installer bodies; they issue no Source or owner
admission. The runner reports its actual component count, preserving every
existing 180-second component and aggregate 6 GiB bound.

All thirteen suites pass at
`sdg49q1ywai7b0nij91wcs18nzlqwj59-crucible-qemu-native-custody-unit-11.1.1`.
The run takes 250.603 seconds total, with a longest component of 36.455 seconds
and peak sampled aggregate address space of 449,413,120 bytes. This evidence is
scoped to native `9770a340c3`; genuine module transfer and physical Runtime
parent return remain separate requirements.

### 2026-10-21 integrated native custody prerequisites

Commit `b69de00f81` retains signed atomic
`3376c0ee90df1af3f1091412cef914bf314b9022`, tree
`54e3dd7ffddc97492c2cfa59f92c7975e25a481c`. It preserves the reviewed
architecture, getter, APIC timer, clock row/callback, QObject retirement,
first-read, receiver storage and publisher-session prerequisites. The complete
configured cohort rebuilt 1,872 dependent objects and relinked both system
targets. All 954 changed source hashes and 7,488 retained evidence hashes match.
The real delivery entry, including complete provider authentication, passes in
50.057 seconds under its existing 60-second and 6 GiB limits. This supersedes
the earlier unsuccessful `bacc4317d242` candidate without discarding its evidence.

Independent signed reconstruction passes at
`0vgz34spf3i00hd02cp7ciq45z9h80s2`; the 318-file license ledger passes at
`8xv4wdg9cyhkl9nvvdgmnhxmg46zgpii`, preserving two LGPL-2.1-or-later additions.
All 187 owning Source scenarios pass at `6x50mgfykaaxh8q5nlnx4kgva8fl64ny`.
These component results issue no native Source, Initial or Original.

Clean hermetic qualification exposes additional fixture regressions. Delivery's
quantum execution helper changes directories while retaining build-relative
includes and cannot find `config-host.h`. The full package completes all 3,895
compile/link actions, then passes twenty of twenty-six fixtures. The same
delivery failure, stale TCG dependency extraction, changed fault-rule visitor
body, stopped-control rearm scalar-header pin and removed cold-clock extraction
delimiter account for five fixture regressions. Dirty iteration reaches the
explicit mandatory genuine launched lifecycle refusal. These first obstacles
must remain distinct from unexecuted later lifecycle obligations.
Neither the full package nor the causal gate passes. All 954 signed changed
files match the retained failed package source; manifest SHA256 is
`0da74700bd5f99c4d7b8fe6b54b2c78f99f32268e2113d2780e9c01b2b0b2ff0`.
Fresh raw ABI passes at
`xsw5495756h6a8n7gqgg504i9ndrq4qx-crucible-phase2-abi-conformance-0`.
All 5,271 committed Rust/TOML files match its immutable
`qpdw6w5hqan6xa40rbcq06m5mh780grj-crucible-workspace-src`; manifest SHA256 is
`2d946be943ce621b45d9d8e29a8d3d2259efe6b346bdfcd1a69d5e725f1cddfe`.
All twelve standalone custody components pass independently at
`s4zkwidb2r30asif31ayv3n6pqgsjrmg-crucible-qemu-native-custody-unit-11.1.1`.
Each retains its existing 180-second bound; the longest takes 32.019 seconds
and sampled aggregate address space peaks at 429,527,040 bytes under 6 GiB.
The owning Source unit remains separately bounded at 600 build/60 test seconds.
A final runner refinement preserves stdout, stderr and first status in the kept
build after failure, with a direct success/refusal diagnostic check passing;
its final hermetic replay passes all twelve components at
`wxxp873qw0khc3zykvlfhgi2f6x9ff63-crucible-qemu-native-custody-unit-11.1.1`.
The initial runner invocation rejected an
unsupported CLI argument after three components; the corrected invocation
preserves every component assertion and deadline. Only text/proof leaves the
check, and component success establishes no launched Source authority.
Later receiver module lifetime, workspace, bounded registry and RAM disposal
changes belong to a separate integration cut.

### 2026-10-21 independent native custody control execution

Commit `d025c341e4` adds
`checks.crucible.phase7.qemuNativeCustodyUnit`, which builds the actual registered
Source unit and its genuine QEMU support before running twelve standalone
custody suites. These cover Action post, APIC getter/error/timer storage,
clock callback/rows/return, FlatView, memory region/discard, provider metadata
and shared-memory callback return. Merely authenticating a Python file as a
source dependency did not execute it; this check makes that execution explicit.

The runner derives compiler flags from actual configured common/APIC commands,
rebases include paths for helper directory changes, and authenticates the real
provider/QOM/utility link closure. Components run sequentially in separate
process groups under their existing 180-second bounds, sampled aggregate 6 GiB
limit and unchanged internal subprocess limits. The prior owning Source test
retains its own 60-second bound. Complete source hashes are checked after every
component; emitted evidence includes commands, flags, generated sources and
outcomes, while executable/archive files remain in the build tree. Failed
invocations preserve their first status and diagnostics in the kept build.

The corrected runner passes all twelve components (173.874 seconds total),
with results scoped to signed native `3376c0ee90`. The final failure-evidence
refinement passes direct success/refusal checks and its final hermetic replay
passes all twelve at `wxxp873qw0khc3zykvlfhgi2f6x9ff63`. This final run takes
190.969 seconds across the twelve independently bounded components, with a longest
component of 37.476 seconds and peak sampled address space of
429,621,248 bytes. Engineering hygiene passes at
`zcvijji792yblcv5r97p578pnwrl3izi`.
No ordinary component grant substitutes for the missing actual installed
Source, producer operation, launched lifecycle or physical parent return.

### 2026-10-21 native rule and reservation storage custody

Commit `765ecc56c0` integrates atomic
`db7d16a91a1cfcd038776657939ca1a697e2f738`, tree
`ba4b0217a28aedbf6cd28ccc73253e6d202117cd`. Actual Node temporary state,
copied rules and event reservations retain storage membership through reference
return and payload destruction. Ordinary recursive operations serialize, and
prepaid retirement cursors survive unpublication, independent post refusal and
the real pending FREE_STATE receipt. Prepared reservation discard stays distinct
from release of live event credits. Selected preallocation ENOKEY and full
registration return ENOTSUP remain.

All 187 owning scenarios, signed sole-parent reconstruction and the exact
280-file license ledger pass. The complete causal sweep passes all 34
independently compiled controls with checked source hashes, compiler commands,
exact intended assertions and no timeouts at
`/nix/store/9p659dxrf1fqm8s0drq45pjk4123pjd9-crucible-qemu-received-delivery-causal-11.1.1`.
The positive takes 56.327 seconds of the unchanged 60-second limit; the slowest
defect takes 24.282 seconds. Ordinary real reservation controls and four rebuilt
storage defects pass, including retention of the actual free receipt after a
refused post, preventing repeated free and rebirth. The first TCG compile
failure from the missing genuine storage getter dependency remains recorded;
including the literal provider preserves all original assertions and limits.

Fresh raw ABI passes at
`/nix/store/nns0b3y83vlj6jzj766zkzigmf35r4hi-crucible-phase2-abi-conformance-0`,
bound to all 5,258 byte-matched crate Rust/TOML files in immutable
`3bs17ing422di8kmgg0ghgnhw7778vpi-crucible-workspace-src`. Later helper test
formatting and shutdown changes are outside that verdict. Full native
compilation completes all 3,863 targets and passes 25/26 fixtures; the mandatory
launched Source/Root lifecycle remains the sole refusal. Genuine owned Node
ARM, copied-rule consumer, aggregate restore and registration retirement remain
unexecuted at this artifact. No selected payer, activation, ACK or physical peer
return is qualified. The full license gate still fails at controller lint
prerequisites; the exact ledger does not replace it.

### 2026-10-21 ordinary initialized-system Node custody

Commit `e11db814fb` integrates atomic
`857b67d8204fb170e4faa5a0b232afe541e6857b`, tree
`c200db0a4c1cb28c82c069c310695a27f7292a90`. The ordinary fixture enters
through real `qemu_init` with the unchanged resident-RAM observer. It exercises
registration, duplicate impulse retention, Submit PREPARE_ONLY, upsert and remove,
observing actual child construction, callback histories, JSON reference return,
payload destruction and storage retirement. The three independently rebuilt
validation, pending and storage journal omissions fail their intended assertions.
Retained runtime inputs are byte-identical across the helper-only correction;
this equivalence is separate from a fresh runtime execution.

All 187 owning scenarios, signed reconstruction and the exact 283-file license
ledger pass. The complete causal sweep passes all 34 independently compiled
controls at
`/nix/store/5vcpljcqnipk8r95a2cc5kq1z5r05asp-crucible-qemu-received-delivery-causal-11.1.1`.
Its positive takes 47.338 seconds of the unchanged 60-second bound, and its
slowest defect takes 19.138 seconds. The preceding candidate timed out before
any defect, after registration completed and storage controls began; the exact
child and cause remain unresolved. Reusing a canonical output only when its
compile-record output and command operand are byte-identical preserves all
seven exact-value comparison cases and every genuine refusal. No assertion or
resource limit changes, and the measured helper savings do not explain the
whole-run timing difference.

Scoped raw ABI passes at
`/nix/store/wph1prfnasml2pn4653iamk1zgj1w38v-crucible-phase2-abi-conformance-0`.
All 5,260 tracked crate Rust/TOML files match immutable
`ysmhrfp57c3da6zzbp3flwpyfz2mdhbf-crucible-workspace-src`, including the typed
Preparation checkpoint and excluding later QMP edits. Full native compilation
completes all 3,863 targets and passes 25/26 fixtures. The mandatory launched
Source/Root lifecycle remains the sole failure. Selected construction and
activation remain unavailable; full registration return still refuses. Aggregate
restore, deferred consumers, CPU borrowers and selected physical return remain
unqualified. The full license gate remains blocked at controller lint
prerequisites.

### 2026-10-21 ordinary NODE_HANG event decoding

Commit `979a045a31` integrates atomic
`40ce1399fbf7eebdf501a0c238997d23d8431dba`, tree
`02c4798f3dd6c1e233bb8c6cd8016957f4d3b86c`. The real event decoder accepts
NODE_HANG's actual ARM model phase while preserving every envelope identity
check and the other command families' phase limits. Seven independently rebuilt
initialized-system runs pass: the positive, three physical-journal omissions
and three phase-predicate defects. The actual unconsumed codec stream contains
878 bytes with SHA-256
`bfb5e2bd7bd14e42f476c8a3ed5c4b0b968b2152d4ab09e3dbefe265f23e7cfc`.

All 187 owning scenarios, 34 independently compiled causal controls, signed
reconstruction and the exact 284-file license ledger pass. The causal positive
takes 47.593 seconds of the unchanged 60-second bound; all original resource
limits remain. Raw ABI passes at
`/nix/store/cgvgzs671vgb98in8vn1p4fv0biksjdx-crucible-phase2-abi-conformance-0`.
All 5,261 tracked crate Rust/TOML files match commit `43d18f6986` and immutable
`8sjrb9kdh4rw9lbqr146ms0sa5mibq5n-crucible-workspace-src`, excluding later
fingerprint changes. Complete native compilation finishes all 3,863 targets;
25/26 fixtures pass and the mandatory launched Source/Root lifecycle remains
the sole failure. Earlier predicate and timeout failures remain recorded.
Aggregate restore, full registration return, activation and selected CPU or
physical-return authority remain unqualified at this checkpoint.

### 2026-10-21 ordinary initialized aggregate restore

Commit `7de44a9d52` integrates atomic
`9b3c140c4ed0bbbd9513b69183684e83acf576c8`, tree
`9bff5ac7a2f2029229df744fe94471af866a4d18`. This adds seven test/documentation
paths without changing production code or private layouts. Actual initialized
RR genesis, drained control stop, unchanged complete save/load and all event
fields are exercised through real stage and pending journals. Nine independent
rebuilt runs pass, including stage return/handoff and the previous six
physical-journal and decoder defects. The actual 19,038-byte aggregate has
SHA-256 `f33f7f31c4e29805e2264aa01114c9c52d3c8779969ad01a48de0cf55e12b6cd`.
The unconsumed 630-byte save/load stream remains exact. Cross-run default RTC
epoch differences remain in the evidence; no normalized whole-stream identity
is claimed.

All 187 owning scenarios, all 34 independently compiled causal controls,
signed sole-parent reconstruction and the exact 287-file license ledger pass.
The causal positive takes 47.301 seconds of the unchanged 60-second bound;
all original resource and runtime limits remain. Raw ABI passes at
`/nix/store/fq7g16v4kkxbp1pwj8svw68czn61vd48-crucible-phase2-abi-conformance-0`.
All 5,261 tracked crate Rust/TOML files match `9515ebefea` and immutable
`c10ijqhaykpigfp71q0i5fhqrz4d1cnx-crucible-workspace-src`, excluding the later
diagnostic formatting change. Complete native compilation finishes 3,863
targets and passes 25/26 fixtures. Mandatory launched Source/Root remains the
sole failure. Selected activation, CPU borrowers, full handler retirement and
physical return remain unqualified. Subsequent CPUState layout changes require
a fresh complete native object cohort before executable validation.

### 2026-10-21 factual RR execution custody

Commit `4ae7067262` integrates atomic
`e043d35971c4c33132fbeb6699aa2c9af65d0f32`, tree
`776d6e49e5a7c9ee498ef6af04390c745d41c523`. The actual prepaid CPUState
retains its canonical same-process/thread, nonwrapping execution journal and
QOM reference before RR releases BQL. Physical executor entry/end, cleanup
revocation and actual QOM return remain distinct. Selected Source authenticates
its real allocation receipt and generation, then refuses ENOTSUP before unlock;
no accepting Quantum/Advance child is supplied. The literal predicate positive
and eight independent omissions exercise modeled local journal inputs only.

All 187 owning scenarios, 34 independently rebuilt causal defects, signed
reconstruction and the exact 289-file ledger pass. The causal positive takes
48.011 seconds of the unchanged 60-second bound; the slowest defect takes
17.888 seconds. Raw ABI passes at
`/nix/store/ifx3pbf5s7cxza91gvwglb70pip8j1ww-crucible-phase2-abi-conformance-0`.
All 5,261 tracked crate Rust/TOML files match captured immutable
`gj6mmrkb6a3kwgkpgfmqihsv2y4xmhjs-crucible-workspace-src`, including typed
fingerprint validation and excluding later mapped-view edits. The retained
manifest SHA-256 is
`1b2e6e4db3bc21d4df14b8ab37c20f9556e2351ea0bc4eaa088676302fd2d453`.

The first candidate built all 3,863 targets but passed only 24/26 fixtures:
prepark found duplicate ownership of an exact RR source pin. Removing only its
redundant supplemental entry preserves the primary pin and every assertion.
The corrected fresh full cohort builds all 3,863 targets and passes 25/26;
mandatory launched Source/Root remains the sole failure. All 907 patched source
files match the retained complete build. Later private-layout changes require
a new complete matched cohort. Genuine selected issuance, activation, owned
continuation and child/peer return remain unqualified; the license gate remains
unresolved at controller lint prerequisites.

### Canonical native observation gate cutover (required)

The supplemental service flights do not yet replace the canonical plugin gate.
Its complete result contract also owns trace framing, scheduler equations,
host-parallel recovery, diagnostic programs and mode-specific execution. The
cutover must preserve all existing predicates and perform these steps:

1. Use the direct source/guest imports already introduced, so composing the
   canonical gate from real service consumers cannot recurse through a borrowed
   source artifact. Retain every compiler-visible crate and embedded fixture.
2. Share the existing complete evidence validator and normalizer. Preserve the
   unique result and reference-summary frames, raw UART versus normalized copies,
   regular nonsymlink trace checks, positive bounded byte/row counts, raw and
   normalized digests, timer/RR relations and block-recovery ordering. Missing,
   duplicate or conflicting evidence must fail; deduplication cannot establish
   canonical provenance.
3. Orchestrate both real Main-backed plugin programs under their original shared
   1,800-second watchdog. Two independent 1,800-second checks are supplemental,
   not an equivalent combined bound. Preserve the existing six-CPU, 12-GiB outer
   policy, 6,000-second watchdog and disk envelopes. Authenticate each program's
   own cleanup and result before constructing canonical singleton metadata.
4. Migrate the actual two-node host-parallel/recovery assertions to genuine Main
   ownership under their separate 3,600-second bound. Four-vCPU round robin does
   not establish two-node parallelism; all 13 existing lifecycle/recovery markers
   and their causal checks remain required.
5. Deliver block-only and coarse/fine partition diagnostic selection to the real
   worker before startup. A parent-shell environment setting does not configure
   a systemd-owned worker. Retain the 2,100-second diagnostic bounds, malformed
   selector refusal, exact partition relation and trace summary.
6. Preserve raw result, transcript, rootfs dependency and executable-script
   contracts for fingerprint, scheduler, offload and campaign-mode consumers.
   Disabled-mode execution must still prove the production service/socket/command
   absent; enabling that service or relabeling an enabled-mode result is not a
   substitute. Supply a genuine observation owner compatible with that test's
   declared composition before changing its adapter.
7. Cut over the canonical gate and every consumer together, then remove the
   obsolete positive ignored entry and its sole model/worker route. Retain shared
   admission helpers only while live performance/write-oracle consumers need
   them, and migrate those consumers through their actual owners. No accepting
   component fallback is permitted.

These are pending implementation and runtime obligations. The new component
controls, source-closure equality and supplemental checks do not discharge them.

The existing trace/result normalization and complete evidence validator now
share one helper. Local Nix evaluation with import-from-derivation disabled
confirms identical rendered scripts, string contexts, resource specifications,
dependencies and VM derivations for the main gate and both diagnostics when
compared against the same final source snapshot. This extraction preserves the
old execution entry; its libtest completion marker cannot be fabricated by a
future service adapter. All 26 traceability and five hygiene controls pass after
the extraction. No native execution or canonical service cutover is implied.

The dependency graph below distinguishes foundations from separately enabled
capabilities. `A -> B` means B requires A's accepted contract and evidence.

```mermaid
flowchart TD
    A[Contract and writer inventory] --> B[Logical codec and Merkle core]
    A --> C[Admission and operation supervision]
    C --> D[Kernel swap qualification]
    B --> E[Incremental boundary roots]
    B --> F[Scalable page and tree storage]
    C --> G[Custom pager and lifetime service]
    E --> G
    F --> G
    G --> H[Fault-safe low-residency progress]
    G --> I[Cold-page hot forks]
    E --> J[Logical checkpoints and local lazy restore]
    F --> J
    G --> J
    F --> K[Bounded root-difference transfer]
    J --> K
    H --> L[General precise-paging qualification]
    I --> L
    J --> L
    C --> M[Runtime updates and reservation journal]
    G --> M
    M --> L
    D --> N[Coordinated release]
    K --> N
    L --> N
```

Some code may be developed in parallel, but no gate can use another unfinished
phase as assumed proof. A generic `supports_paging` bit is insufficient:
backend, mapping mode, fork, lazy restore, strict residency, and fault-safe
reclaim capabilities must be advertised independently.

The graph's node labels describe capability dependencies, not the delivery
package letters used below. Some packages combine capabilities for review:
Package I covers cold forks and local lazy restore; Package J covers live
control and bounded transfer. That grouping does not remove their independent
qualification gates or imply an atomic cross-machine operation.


## 2 Package A: contract inventory and independent oracle

Deliver a machine-profile RAM inventory with stable region IDs, alias owners,
class/mask declarations, immutable reconstruction references, and every
supported write origin. For each writer, record the actual QEMU dirty hook,
its covered geometry, caller lifetime, and consumer epochs. Identify external
kernel reads/writes through guest pointers, device pre-save mutations, bulk
reset/restore, fault injection, and cached DMA stores.

Separate the complete RAM read-resolution inventory from writable fault-target
admission. The existing mutation mapping filter excludes readonly, ROM, and
RAM-device regions; pager lookup must cover admitted cold reads of those regions
without granting mutation rights. Include retained raw/DMA borrowers and kernel
pins even with fault rules disabled. Inventory persistent retention/rowhammer
mutations, guest-RAM hardware-reporting writes, and modeled memory-service
tickets/frozen loads/deferred stores. Reconcile the host/GPL service payload
contract, including actor fields, before claiming live service coverage.
Operational copies must not exercise simulated access opportunities or timing.

Define the new fingerprint and checkpoint editions and enumerate all consumers:
production execution, exact snapshot, harness, instruction fault state,
lifecycle preconditions/source seals, trace, and persisted canonical samples.
Create an independent full-RAM Merkle oracle that does not reuse dirty bits,
cached roots, incremental code, or the production tree builder. Instrument
tests so suppressing a required dirty notification demonstrably fails.

Exit evidence is a complete inventory with no unclassified supported writer,
a precise coverage map for all named scopes, and oracle detection of deliberate
false negatives. A source audit alone does not qualify a memory backend.

## 3 Package B: canonical logical core

Implement [chapter 02](../../rfcs/0021-crucible-paged-ram/02-logical-ram-and-merkle-format.md) in the boundary-appropriate components without acquiring
QEMU dependencies in permissive crates. Portable codecs are bounded and use
checked arithmetic. Persistent trees carry immutable ownership; page-version
and dirty-epoch state remain separate from digests. Build sparse zero trees,
batch dirty updates, reuse equal-content pages, and account for dense/padded
metadata limits.

Exit evidence includes the executable positive vectors specified in [chapter 02](../../rfcs/0021-crucible-paged-ram/02-logical-ram-and-merkle-format.md),
independently produced C/Rust results, malformed and overflowing encodings,
wrong scope/topology, partial pages, reordered pages, padding proofs, and
representation-independent roots.
Retained nodes must remain valid through concurrent root users and teardown.

Build the GPL-side C hash implementation hermetically from pinned reviewed
upstream source, recording its applicable GPL-compatible license choice and
corresponding-source obligations. The Apache-side Rust implementation remains
in its separate process. Validate the official primitive vectors, the selected
unkeyed 32-byte mode, and agreement across enabled portable/SIMD paths before
enabling the logical codec. A shared algorithm MUST NOT introduce a cross-process
QEMU library dependency or conflate logical digests with CAS object identities.

## 4 Package C: resource model and granular supervision

Refactor admission around uniquely owned source pages, private child changes,
metadata, compulsory host memory, emergency buffers, disk capacity, and I/O
capacity. Maintain attempt/executor aggregate containment and account for
original cgroup ownership of COW charges. Do not convert full-RAM accounting
to a guessed working-set number before a backend has a progress proof.

Introduce operation classes and consistent monotonic start/progress/completion
coordinates. Separate modeled deadlines from host budgets. Cover QMP, quantum,
capture, publication, restore, page-in, preservation, fork barrier/rearm,
transfer, cancellation, and reaping. Ensure the outer watchdog follows the
same explicitly authorized completion contract and cannot silently defeat an
accepted latency configuration. Reconcile QEMU-internal placement waits and
host-side deadlines. Make operational controls independently responsive while
QMP and guest execution stall.

Enforce TIME-9's finite infrastructure-phase bounds at admission and on every
live update. Implement the separate outer-cap amendment transaction, shared
watcher wakeup, original-start retention, expiry precedence, durable recovery,
bounded idempotency history, and limiting-deadline status. An updated caller
duration without rebinding every affected supervisor is not complete.

Exit evidence includes nested deadlines, in-flight updates, rollback of refused
reservations, restart recovery, prolonged legitimate progress, endless paging
without guest progress, cancellation, and quarantine that remains charged.

## 5 Package D: kernel-managed swap baseline

Add explicit host prerequisites and configurable swap limits while retaining
the existing default behavior unless the operator selects the backend. Probe
usable swap and cgroup delegation. Document that cgroup swap and memory limits
apply to an aggregate owner, including file cache and emulator overhead.
There is no precise per-VM cache guarantee from `mmap`, global swappiness,
or an attempt-level cgroup alone. Package D is a labeled measurement baseline:
operator selection permits the experiment, not authenticated-backend deployment.
Advertising a supported backend requires PAGER-22's separate integrity proof;
this edition does not silently trust swap bytes or narrow TEST-7's threat model.

Measure deterministic equality and host throughput for resident, swap-enabled,
and constrained-memory runs. These measurements supply a realistic comparison
for the custom pager. Exit evidence includes actual swap activity, multiple
nodes, source/child accounting, adverse storage latency, and host failure
classification. The test must demonstrate paging occurred rather than merely
setting a sysctl or allocating a file.

## 6 Package E: incremental observation cutover

Replace all full-RAM production observers with named roots and a shared logical
edition. Preserve coherent capture ordering, request-generation publication,
and independent dirty clients. Restores install authenticated roots or force
complete reconstruction; resets establish their specified logical contents.
Do not hash mutable RAM from an asynchronous worker after guest resume.

Exit evidence is equality with the independent oracle at every tested boundary
across every writer, including write-then-revert and unchanged cold pages.
The normal fingerprint path must demonstrably avoid faulting the complete
unchanged address space into memory. Selected-range fault digests remain
separately specified where full-state identity does not answer the predicate.

## 7 Package F: scalable durable memory storage

Define page objects, portable structural records, complete root manifests,
packing, bounded index traversal, admission limits, and retained closure
ownership. Separate logical BLAKE3-256 digests from existing representation
identities, even where both use the same hash primitive.
Replace flat assumptions that cannot handle worst-case distinct 4 KiB pages.
Make tree/page verification and retrieval bounded without eagerly loading a
complete machine's page catalog into host memory.

Exit evidence includes dense distinct pages beyond former flat limits,
small-object overhead measurements, packed-object corruption, quota failure,
crash during publication, concurrent GC, and retained source/child/transfer
leases. An ordinary spill write is not accepted as durable publication.

The original packed read view retained only the most recently used authenticated
manifest. A local 32 MiB, 8192-page diagnostic performed the same 24,575 object
lookups before and after repacking. Manifest authentication increased from 769
operations over 18,438,337 encoded bytes to 23,246 operations over 3,878,963,049
bytes. This measured excess work, not an isolated throughput comparison.

The integrated retention path uses the selected physical-quota service's paired
resident/metadata accounts for shared rows and index storage. The initiating
operation separately funds its active manifest copy. Both admissions occur
before the corresponding allocation; cache eviction destroys actual shared
storage before returning its credit. Reuse binds configuration, placement
generation, immutable pack identity, inode stamp and selected entry. Every
object retains complete authentication and EOF checks. Reservation or caller
failures propagate without falling back to an uncached read.

Inventory, publication readback and canonical archive constructors use this
path. Ordinary single-tree reads keep their existing dispatch. The 32/512 MiB
controls exercise bounded traversal, reclamation and resource return, while
balanced sequential/strided read measurements cover tiny, mixed and dense
packs. Remaining lazy-checkpoint and closure-verification joins must be checked
through their actual selected owners; these component controls do not establish
complete VM performance parity.

Resource qualification must use the actual owner topology: ordinary CLI archive
transfers borrow exclusive service owners and send roots sequentially, retaining
one source session. Their Packed service's authored metadata bank is distinct
from the catalog service's SQLite heap partition. Neither a hypothetical
concurrency count nor a successful component fixture proves that the normal
configuration fits unchanged limits.

## 8 Package G: custom pager and authority lifecycle

First implement stable mappings, missing-page service, page/version state
transitions, preserved backing, immutable authenticated reads, controlled
writeback, and paused-boundary removal. Qualify the deployed userfaultfd
features, permissions, kernel-originated faults, and mapping semantics.
Retain registration authority across companion failure until QEMU can be
stopped; closing the final authority must not expose default zero faults.

The proposed GPL-side companion owns native addresses and mapping details.
Its public storage requests use bounded portable identifiers and checked
offsets. Prove its service cannot depend on a barrier held by an accessing
QEMU thread, and reserve its minimum service resources. License and ABI
review precedes adoption of this placement.

Initial acceptance includes PAGER-23's physical-access lifetime proof for
retained DMA/raw mappings, kernel pins, aliases, and observation readers.
Reserve the sound inter-boundary peak before admitting the paused-only backend;
unsupported peak reductions are refused rather than admitted with expected
runtime failure. Cold fault-transaction preparation must secure all fragments'
versions, COW rights, and commit resources before any write, under TRACK-20.

Exit evidence includes missing/short/corrupt backing, delayed and stale I/O,
companion death, kernel fault denial, mapping removal events, cleanup races,
and preservation failure before discarding the last correct resident version.

## 9 Package H: fault-safe low-residency progress

Paused-boundary eviction is a correctness baseline, not sufficient proof of
general low-residency progress. A guest can touch more pages in one quantum
than its admitted resident peak. A blocked fault cannot wait for an exact
boundary that the fault itself prevents the guest from reaching.

The [live-eviction investigation](live-eviction.md) separates stable virtual
addresses from physical pins. It identifies a candidate synchronous
write-protect/preserve/discard path using the current bounce-buffer policy,
without requiring a new lease on every software memory access. Its bounded
progress floor and actual native lifetime integration remain unqualified;
the existing full-peak admission stays in force.

Resource suspension requires a complete stop protocol that can progress while
a vCPU or device thread is blocked in a host fault, including mutex ownership,
BQL constraints, event-loop work, pager callbacks, and any dirty re-arm work.
Qualification identifies the actual discard executor and kernel primitive,
not just an independent fetch companion. A local worker needs a closed
thread/mutex plan and child reconstruction. Operational holds cannot use ordinary
host-timed CPU kicks or semantic vmstop publication without proving unchanged
interrupt checks, RR allocation, timer/device order, and partial operation state.
Concurrent removal requires a different proof: preserving every latest write,
rejecting stale I/O, preventing stale physical references or bypass of the
qualified fault path, and covering all device/DMA lifetimes. Benchmark gains
do not replace either proof.

Exit evidence includes an unmodified guest whose single quantum touches more
distinct pages than the resident peak, without extra reservation capacity,
and equivalent scenarios during device activity and runtime target reduction.
For the general backend the run must make bounded progress with correct bytes.
For the limited baseline unsupported admission must be refused; a distinct
post-admission resource-loss adversary must terminate safely. Neither case may
deadlock, substitute zeroes, or depend accidentally on extra host RAM.

## 10 Package I: cold forks and local lazy restore

Integrate fault authority into the entire hot-fork transaction before child
reconstruction. Establish child-specific mutable epochs, private preserved
versions, fault contexts, registrations, reservations, and readiness. Strict
residency requires independent child prefault/lock establishment. Shared
immutable backing stays pinned; source residency can change without changing
its logical seal. Quarantine retains all unresolved ownership.

Replace eager sealed-RAM restore with the new authenticated local closure
contract. CPU/device and continuation reconstruction remain coherent. Verify
complete local durable availability before launch, and each page before it
is exposed. Cold reads during device restore must be serviced independently.
No remote-page server is implied.

Capture establishes CHECK-13's disposition barrier for pending pager and policy
work. Restore constructs fresh controller/registration/request namespaces and
independent consumer baselines under CHECK-14. Source I/O completions cannot
be replayed into the restored owner. Existing modeled fault/service continuation
must remain intact and resume its admitted semantic effects exactly once.

Exit evidence includes mostly cold sources, fork barrier adversaries, child
reconstruction reads, failed rearm, source death, child cancellation, descendants,
promotion, dense COW writes, and lazy restore matching exact continuation.

## 11 Package J: live control and transfer

Implement generation-bound, authenticated, revisioned, idempotent policy
updates and status. Add bounded operational history and reservation amendments.
Keep accepted, applied, effective, and converged states distinct. Reductions
release capacity only after ownership is gone; increases reserve first. Restart
reconciliation must distinguish accepted-but-not-applied from applied-but-not-
reported operations. Hard update-history capacity must not consume fault-service
emergency memory.

Implement bounded root-difference traversal, paged inventories, authenticated
destination possession, source retention, cancellation between I/O chunks,
durable progress receipts, and atomic reference publication. Resume records
must bind both the transfer incarnation and selected source roots. A transfer
of VM state includes the non-RAM checkpoint closure, not just page contents.

Exit evidence includes runtime tuning during blocked faults and forks,
idempotent retry across restart, revision conflicts, quota exhaustion, dropped
transfer sessions, corrupt destination claims, partial receipts, and publication
only after complete authenticated durable possession.

Archive transfer completes with `ClosureStored` and ordinary archive selection
retention on a storage-only destination. Maintenance additionally requires
`RestoreReady`, current execution admission, and the durable ownership transition.
Test stale readiness before handoff and independently refused later restore;
neither publication nor source lease retirement implicitly grants execution.

## 12 Coordinated release and documentation


Publish canonical operational documentation for supported backends, prerequisite
checks, resource-floor calculation, runtime controls, typed failures, cleanup,
and recovery. Keep this RFC as the historical design record. Record measured
baseline and performance budgets without inventing a prior approval: the current
campaign performance gate has a blocked/unapproved baseline at the cited source
revision. Deferred remote paging or live migration receives its own design and
qualification rather than inheriting an unsupported capability flag.
