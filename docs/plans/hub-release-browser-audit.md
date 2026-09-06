# Release browser verification

This extends the Hub experience work in PR #240 with one release context across
Packages, Docs, Images, and Containers. Registry releases and package versions
remain distinct. Initial content URLs redirect to an exact published release;
unknown releases never fall back to HEAD. The optional committed
`registry.default_release` preference controls initial selection without changing
channel rollout policy.

## Browsing behavior

- Overview contains registry setup and complete channel bucket distributions.
  Health remains a separate utility page.
- Each release has its own page with notes, content counts, current channel
  participation, verification, and expandable publication details.
- Content links, filters, sort controls, pagers, and install commands retain the
  selected release. Images and containers support an explicit view of all
  releases, grouped in semantic-version order.
- Documentation presents one release-wide configuration tree. Any exact or
  dynamic path segment can root the view; literal dots retain their identity.
- Branches load only when expanded. Child, search, and variant responses contain
  at most 50 entries. Continuations are bound to their query and indexed release
  generation. Reopening a loaded branch reuses its existing children.
- Search stays visible while reading and defaults to the whole release, with an
  explicit subtree scope. Selecting an option reads one verified document and
  renders its type, default, example, enum choices, activation, and declaration
  information. Historical document anchors retain release and digest identity.
- Ordinary links and child pagination work without JavaScript. Session-visible
  child JSON uses private, no-store caching and the same visibility checks as
  the page.

## Publication correctness

The native seed now records measured file hashes, sizes, and strong storage
versions through the publication state machine. It uses the runtime image
snapshot store and requires a verified index before advertising a ready
publication.

The public/private fixture exposed a global artifact-snapshot ID collision for
identical releases in different registries. New IDs include the owning registry
and release. Refreshes preserve existing completed IDs after checking their
registry ownership and complete content identity. Regression coverage exercises
both identical registries and an existing legacy ID.

The first staging deployment exposed an upgrade-only issue: Worker maintenance
coalesced an unchanged publication against its completed pre-browser build ID,
bypassing the indexer's new projection-completeness checks. The Worker build
identity now uses version 3 so the normal maintenance pass rebuilds the release
catalog and documentation tree once after upgrade. A regression compares the
new identity with the previous version for identical publication inputs.

Cold rebuilds verify at most two release generations concurrently and serialize
the larger browse-projection writes. Reusable snapshots keep the eight-release
fetch window. This bounds overlapping document, SQL-parameter, and remote-request
buffers during historical rebuilds.

A read-only native diagnostic indexed staging's exact signed public surface
(`b3a53cf9f223de417805df8bbe2181d070699fd1fc2d7b56b71f7c17136189f6`):
265 packages, nine releases, and one channel. With a temporary file database,
the final implementation took 3.84 seconds and reached a process high-water
resident size of 104,216 KiB in one local sample. The diagnostic source and logs
remain local; no staging content or credentials are committed as fixtures.

## Native validation

The AOS development environment supplies the Rust tools; the browser harness uses
AOS Python and Chrome against an isolated signed development origin.

- Native library suite: 141 passed.
- Shared core suite: 812 passed; registry schema suite: 69 passed.
- Native web and seed suites: 17 passed.
- Worker library suite: 32 passed, including the completed-index upgrade case.
- Real-browser release harness: 49 passed, including a 137-child subtree,
  bounded search, no prefetch, one request per expansion, reused children,
  arbitrary-depth options, legacy links, and authenticated private expansion.
- Six desktop/mobile screenshots cover the expanded tree, focused option panel,
  and navigation with JavaScript disabled. The views fit their viewport widths;
  Chrome reported no JavaScript or content-security errors.

The repeatable browser entry point is `tests/native/hub-release-browser.py`.
Earlier settings, CLI, and VM evidence remains separately dated in
`hub-experience-audit.md` and `hub-cli-independence-audit.md`.

## Staging validation

On 2026-09-05, staging was deployed as
`staging-28cd153e93103d739d2854dce1caa86079ae54a5` from the hermetic installer
`/nix/store/ycj550lii6v6a3riyz7hrkcqjqlwrd75-aos-hub-cloudflare-0.1.0`.
The existing database instance, bindings, custom domains, and OCI pull setting
were preserved. Fresh recovery bookmarks were retained locally before and after
deployment.

The Worker successfully rebuilt all nine historical releases and acknowledged
the index job. One recorded cold run used 146.8 seconds of wall time and
6.47 seconds of CPU time. Registry status then reported a fresh index.

The public staging browser audit passed 42 checks with 16 inspected desktop and
mobile screenshots. It covered Overview, release details, Packages, Channels,
the configuration tree, paginated search, an individual option, and the original
AOS package-documentation URL. The initial documentation page contained only
27 root children and fetched no subtrees. Expanding `aos` made one request for
22 immediate children; reopening it reused the loaded result. Initial HTML was
16,059 bytes, and that child response was 4,535 bytes. Search pages remained
bounded at 50 entries and retained the selected release across continuation.

The selected option rendered one structured panel. The historical URL retained
its exact document digest and selected registry release. No JavaScript or CSP
errors were observed; narrow data tables scroll within their own regions.
Staging has no published images or containers, so populated content and private
session interactions remain covered by the isolated native fixture.
