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

## Native validation

The AOS development environment supplies the Rust tools; the browser harness uses
AOS Python and Chrome against an isolated signed development origin.

- Native library suite: 141 passed.
- Shared core suite: 812 passed; registry schema suite: 69 passed.
- Native web and seed suites: 17 passed.
- Real-browser release harness: 49 passed, including a 137-child subtree,
  bounded search, no prefetch, one request per expansion, reused children,
  arbitrary-depth options, legacy links, and authenticated private expansion.
- Six desktop/mobile screenshots cover the expanded tree, focused option panel,
  and navigation with JavaScript disabled. The views fit their viewport widths;
  Chrome reported no JavaScript or content-security errors.

The repeatable browser entry point is `tests/native/hub-release-browser.py`.
Earlier settings, CLI, and VM evidence remains separately dated in
`hub-experience-audit.md` and `hub-cli-independence-audit.md`.
