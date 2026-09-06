# Release model and cadence

## Registry, channel, partition, and environment

Four names answer four different questions:

| Layer | Question | AOS decision |
| --- | --- | --- |
| Registry | Who owns and authorizes this package universe? | `andyl/main` |
| Channel | How mature and supported is this snapshot? | `edge`, `candidate`, or `stable` |
| Partition | Which rollout cohort receives the channel's next release? | One of 256 stable buckets, `00` through `ff` |
| Hub environment | Where is the service and content being qualified or served? | `aos.staging.andyl.org` or `aos.andyl.org` |

These axes must not be collapsed. In particular, neither `andyl/staging` nor
`andyl/stable` is created.

## Keep `andyl/main`

APM resolves a package name from the highest-priority configured registry
before considering versions in lower-priority registries. Splitting the public
AOS distribution into competing registries would therefore introduce package
shadowing, independent trust rosters, cross-registry dependency policy, and
more failure modes without improving release promotion.

`andyl/main` remains the one public catalog for supported AOS software, system
roots, images, documentation, and corresponding source. A new registry is
justified only if at least one of these statements is intentionally true:

- it has a different organization or release authority;
- consumers must bootstrap a different trust root;
- its packages must form an independent dependency-resolution universe;
- legal or redistribution policy requires a separate catalog and retention
  boundary; or
- availability and incident isolation require an independently operated origin
  whose content is not promoted into `andyl/main`.

Maturity, architecture, hardware class, support lifetime, geography, cache
placement, and staging do not by themselves justify another registry. Package
metadata already carries platform and system-image variants; the Hub already
models multiple placements and routes; channels already carry stream selection.

The complete package and image target contract is defined in
[`06-platform-matrix.md`](06-platform-matrix.md). Architecture and operating
system are signed platform dimensions within one release, not registries or
channels.

## Channels

### `edge`

`edge` is for AOS developers and disposable integration systems. It receives a
release on a changed business day after the mandatory static, unit, registry,
and targeted image gates pass. It may contain prerelease packages and interface
changes. It is public so downstream integrators can test the actual distribution
protocol, but it has no production support promise.

All 256 `edge` partitions advance together. Bucketing adds no safety when the
audience has explicitly chosen the integration stream.

### `candidate`

`candidate` is the release-candidate stream. It is cut once per week when there
are eligible changes. It contains only commits intended for the next stable or
security release and must pass the complete release gate appropriate to its
artifact set.

All 256 `candidate` partitions advance after the release has passed the hosted
staging gate. A stable promotion selects an existing candidate; it never builds
a similar replacement.

### `stable`

`stable` is the supported production stream. Its normal train is monthly. A
candidate must soak for at least seven days and pass the exact-byte hardware or
hypervisor canary before it can enter stable. Security response may shorten the
soak but may not skip signature, closure, boot, recovery, license, or public
read-back gates.

Stable uses progressive partitions:

| Ring | Cumulative partitions | Approximate audience | Minimum observation |
| --- | ---: | ---: | --- |
| Internal canary | 4 | 1.6% | 24 hours |
| Early | 32 | 12.5% | 24 additional hours |
| Broad | 128 | 50% | 48 additional hours |
| General availability | 256 | 100% | Continuous |

The four initial partitions are chosen to include known Andyl canaries; they
are recorded in policy rather than assumed to be `00` through `03`. Public
fleet telemetry is not assumed. Advancement decisions use Andyl-managed
canaries, Hub delivery health, support reports, and the signed release record.

If a ring fails, advancement stops. Existing partitions are not decremented.
The correction receives a higher release version and advances affected
partitions by the normal fix-forward mechanism.

## Versions

AOS uses standard SemVer syntax without a `v` prefix, while assigning the first
three numeric fields as a calendar train:

```text
2026.9.0                         September 2026 stable train
2026.9.1                         first stable hotfix in that train
2026.10.0-rc.2                  second candidate for October 2026
2026.10.0-dev.20260902.1        first edge snapshot prepared on 2026-09-02
```

The month has no leading zero because SemVer forbids leading zeroes in numeric
identifiers. Release precedence is ordinary SemVer precedence. Build metadata
is not used to order channels because SemVer ignores it for precedence.

The registry release version identifies a complete catalog snapshot. Package
versions remain their own upstream or AOS versions. When a release contains a
new system image, `aos.system.version`, the sysroot package version, image
catalog release, recovery manifest, and public release manifest all carry the
same AOS release version. A package-only release records the most recent image
release separately and does not relabel old image bytes.

The client's monotonic floor is registry-wide, not channel-specific. A host
that consumes an `edge` or `candidate` release therefore cannot immediately
switch to an older `stable` release as if channels were priorities. It waits
for `stable` to reach or exceed its accepted version, or follows an explicit
reprovisioning or incident-recovery procedure that resets trust state. The CLI
must warn before a channel change that would strand the host above its target.

Every production version is globally unique and immutable. A failed candidate
number is never reused. A stable release is the same signed candidate commit and
artifact manifest with a later channel promotion record; it is not retagged
under a different version. Therefore the final version is selected before the
stable-eligible candidate is signed. Earlier experimental candidates use the
`-rc.N` form and are not promoted by removing the suffix.

The monthly train follows this sequence:

1. Any number of `YYYY.M.0-dev.*` edge releases.
2. Any number of `YYYY.M.0-rc.N` qualification releases.
3. A final `YYYY.M.0` candidate, signed and staged as the stable-eligible
   artifact.
4. Promotion of that exact `YYYY.M.0` release through stable partitions.

This avoids changing an immutable tag during promotion.

### Source selection and hotfixes

Normal edge and candidate plans select the current protected `master` head.
The selected commit is frozen in the plan, so later merges do not alter a
candidate already soaking. The stable channel promotes the final candidate's
existing commit; it never silently moves to a newer `master` head.

An emergency fix that must exclude newer development begins at the affected
stable source tag on a temporary `dplecki/hotfix-YYYY-M-P` branch, following the
repository branch policy. The reviewed hotfix head is preserved as a real
parent in the protected `master` history rather than squash-discarded. The
release planner may build that reviewed head only after it is reachable from
protected `origin/master` and confirms that the fix is present in the current
mainline tree. This provides a narrow stable-derived source tree without
creating a permanently divergent distribution branch.

If a hotfix cannot be made reachable from protected history without ambiguity,
publication stops. The publisher does not release an unreviewed detached
commit.

### Train branches and backports

A supported train keeps a long-lived source branch, `train/YYYY.M`, whose head
is always the train's newest reviewed stable source. The branch is a named
pointer to the same chain of hotfix heads described above, not a divergent
line: every head is merged into protected `master` as a real parent before the
planner may build it, so the reachability guarantee is unchanged. A train
without a branch is one that will receive no further releases.

A backport is a change cherry-picked onto the train branch, reviewed there,
and merged into `master`. When `master` already carries an equivalent change,
the merge records ancestry only and adds no content; git supports that
directly. Trains are independent: a fix on `train/2026.3` neither waits for
nor alters `train/2026.9`. The planner builds the train branch head exactly as
it builds a hotfix head today, with the version selected from that train.

Each train states its own support. The train branch's qualification contract
declares `support.trains."YYYY.M"` for that train alone, and `master` declares
`support.default`. Registry finalization copies the release's own train entry
into the signed registry's `[support]` table and refuses a contract naming any
other train, and only a release from the newest train may write `default`.
The registry remains one linear history with section ownership enforced by
the publisher; nothing in the registry repository branches.

Two consequences remain open and must be settled before a second train
branch exists. First, the client's monotonic floor is registry-wide today, so a
host that has accepted `2026.9.0` can never take `2026.3.7`, and a host that
stays on 2026.3 has no channel that stays with it. Per-train support therefore
implies per-train stable channels (for example `stable-2026.3`) with per-channel
floors, which the Hub's channel floors already model but the client floor rule
and CLI warnings do not. Second, `previous` delta links and any pruning inside
a package's version list must be train-aware, or a hotfix on an older train
will point delta upgrades at a newer train's predecessor.

## Cadence

Cadence is a target and a maximum exposure window, not permission to publish an
empty or unqualified artifact.

| Item | Normal cadence | Triggered cadence |
| --- | --- | --- |
| `edge` registry release | Once per changed business day | Important integration fix |
| `candidate` registry release | Weekly | Security or release-blocking fix |
| `stable` registry release | Monthly | Supported security or critical reliability fix |
| Staging system-image upload | Each image-affecting candidate, and at least one stable-eligible candidate per monthly train | Targeted edge qualification or an emergency image fix |
| Production system-image upload | Each image-bearing candidate after staging qualification | Emergency image fix; stable promotion itself uploads no rebuilt image |
| TUF timestamp refresh | At least every 12 hours, with a 48-hour expiry | Immediately after a promoted snapshot or timestamp-key rotation |
| Hub Worker deployment | On demand | Security fix or required schema/operations change |
| Restore exercise | Quarterly | Before a risky schema or storage migration |
| Key inventory and expiry review | Monthly | Before every stable release |
| Offline root and recovery ceremony | Annually | Rotation, compromise, or policy change |

There is no forced daily release when `master` is unchanged. There is no forced
image rebuild for a package-only hotfix whose closure, bootstrap trust, kernel,
initrd, root filesystem, and image tooling are unchanged. The release manifest
must make that reuse explicit.

### Image-affecting changes

A change is image-affecting when it can alter any of:

- the system toplevel or bundled runtime closure;
- kernel, modules, firmware, initrd, UKI, systemd-boot, command line, SBAT, or
  PCR policy;
- EROFS root, dm-verity tree, GPT layout, ESP, recovery UKIs, or recovery
  bundle;
- provisioning, storage, boot counting, image update, or rollback behavior;
- baked registry, configuration, Secure Boot, PKI, or operator trust anchors;
- image builders, converters, compressors, or integrity metadata; or
- the production security profile.

If classification is uncertain, the change is image-affecting.

Every image-bearing candidate builds all four supported encodings for each
Linux architecture from one signed logical disk per architecture: raw
(`.img.zst`), QCOW2, VMDK, and dynamic VHD. All are uploaded to staging. After
qualification, the exact encodings and recovery bundles are imported into
production before the production `candidate` channel moves. Monthly `stable`
rollout reuses those immutable production objects and does not upload, rebuild,
or re-sign them. A missing required architecture or format blocks a
stable-eligible release; reduced support requires an explicit versioned policy
change rather than a partial publication under an existing version.

## Hub environments and URLs

The desired public paths are:

| Use | Staging | Production |
| --- | --- | --- |
| Hub/API/Web origin | `https://aos.staging.andyl.org` | `https://aos.andyl.org` |
| Canonical registry surface | `https://aos.staging.andyl.org/andyl/main/` | `https://aos.andyl.org/andyl/main/` |
| Canonical image discovery | Staging Hub image API | Production Hub image API |

`https://cdn.aos.andyl.org/` is an existing bootstrap origin. It remains a
read-only compatibility route to byte-identical production content until a
signed image-anchor migration has reached the supported fleet. It must not
become a second publication authority. New images use the canonical production
Hub route once that route passes the RFC-0012 topology cutover and public APM
end-to-end gate.

Both Hub deployments may contain a registry row with the slug `andyl/main`.
Their database ids, storage, credentials, and mutable state remain unrelated.
The signed registry's internal name and keys bind the content identity; the Hub
slug selects its serving surface.

Disposable hosted smoke data never uses the production organization, registry
key, cache key, Secure Boot key, or release namespace. It is created under a
staging-only organization and deleted only after its evidence is retained.

## Support and retention

Supported consumers track `stable`. `candidate` and `edge` are retained for
debugging and reproducibility but carry no security response promise.

Production retains permanently:

- every stable release tag, manifest, signed metadata, provenance statement,
  source release, license artifact, recovery bundle, and image digest;
- every object needed to reproduce the current stable release and supported
  patch train;
- releases implicated in an incident, revocation, key transition, migration,
  or customer deployment; and
- the complete matching `qemu-crucible-source` output whenever the Crucible
  suite or patched QEMU binary is distributed.

Normal cache policy retains at least the current stable release, the previous
stable train, every release named by any channel partition, all rollback and
recovery roots, and twelve months of stable image artifacts. Deletion is based
on RFC-0012 provenance-bearing roots and requires a dry run. Registry history
and signed release evidence are archival records and are not garbage-collected
with cache objects.
