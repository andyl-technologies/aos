### UI surface map

**Consumer-facing** (anonymous, server-rendered, works with JS
disabled — the Debian ethos):

- Registry home: name, description, trust anchors with fingerprints,
  channels and their current versions, index status, committed cache
  policy, and setup snippets.
- Package index and search; package page: versions × platforms table,
  NAR/closure sizes, store paths, license/homepage/maintainer,
  dependency closure browser, sysroot image downloads (qcow2/raw),
  narinfo permalinks, per-cache availability.
- Channel page: the **256-partition grid** — which buckets point at
  which release, rollout percentage, floor history, staleness; a
  "which version will *my* host get?" calculator.
- Releases page: signed tags, signature status, pack/thin-delta
  availability, commit history.
- Registry health page: index status, committed cache policy, and delivery
  routes.
- Raw directory-listing fallback for every machine path.

**Producer-facing** (authenticated):

- Org/project dashboards: registries, members, roles, tokens, storage
  bindings, frontends, cache stores, quotas, audit feed.
- Publish pipeline view: live phase status mirroring `apr release`
  (commit → tag → packs → upload-immutable → flip-pointers),
  resumable/idempotent like `--resume`, with the optional
  validation gate before the flip.
- Channel rollout console: advance N partitions with preview, hold,
  floor guard warnings.
- Key roster management: signing-key enrollment, rotation, usage, and retirement.
- Token management mirroring `aos token` semantics.
- Configuration: draft → diff review → apply, revision history, revert.
- Git view: branches, commit log, TOML diffs; change requests
  (phase 3 minimal, fuller review flows later).

**Asset policy — strictly first-party.** Every page the hub renders and
every artifact it ships serves *all* of its assets from its own
origin: no third-party font CDNs (system-font stack by default;
any custom face is a self-hosted, subsetted, hash-named woff2), no
external JS or CSS, no analytics beacons, no third-party embeds. This
is enforced, not aspired to: a `Content-Security-Policy` of
`default-src 'self'` — plus `'wasm-unsafe-eval'` in `script-src`
(required to execute WASM on Chromium) and a nonce for the Leptos
hydration bootstrap; the exact policy is validated in the phase-1
spike — ships in every response on both runtimes, and a CI check walks
the built dist + rendered pages and fails on any absolute third-party
URL. The same policy applies to the on-CDN web
surface below — which is also a privacy property: browsing a registry
leaks nothing to anyone but the registry's own origin (and the hub,
only when explicitly configured).

### The registry web surface: a static SPA on the registry's own CDN

Every registry gets a **`web` surface**: a static, client-side-rendered
WASM app uploaded to the registry's own bucket and served by plain
S3/HTTP file serving — a polished UI with **zero hub in the serving
path**, optionally connecting to a hub for dynamic features.

**Artifact shape** — a handful of static files, not literally one
(base64-inlining the WASM adds ~33% and forfeits streaming
instantiation; there is no upload-side benefit since the pipeline
handles arbitrary file sets):

```text
/index.html               mutable    (low TTL — the pointer; see below)
/web/app-<hash>_bg.wasm   immutable  (hash-named)
/web/app-<hash>.js        immutable  (wasm-bindgen glue)
/web/style-<hash>.css     immutable
/web/config.json          mutable    (branding/theme/hub URL)
/web/index.json           mutable    (pre-rendered registry snapshot)
/web/packages/<name>.json mutable    (per-package snapshots)
/browse/<name>.html       mutable    (static no-JS package pages)
```

This maps exactly onto the existing immutable/mutable upload classes in
`static_upload.rs` — SPA upgrades are atomic by the same
immutable-first pointer-flip discipline as everything else. All assets
are first-party by construction (the asset policy above). `index.html`
and `web/`/`browse/` are origin-only files like the nix-cache surface,
never part of the committed git tree.

**Data sources:**

- **Same-origin static snapshots (primary).** Publish-time pre-rendered
  JSON (`index.json`: registry meta, channels + partition summary,
  package list; `packages/<name>.json`: versions × platforms, sizes,
  narinfo links), generated from the committed tree. Same-origin
  relative fetches → **zero CORS configuration**.
- **In-browser verification — the honest badge.** The `surface/` crate
  compiles for the browser, so the SPA lazily fetches the channel
  partition and roster same-origin and runs *real* Ed25519
  verification client-side, rendering "verified in your browser:
  partition → 1.4.2 → commit ab12…" and cross-checking the JSON
  snapshot against the verified commit. One parser — server, Worker,
  browser — which also kills the parser-divergence bug class.
- **Hub ConnectRPC (optional enhancement).** `config.json` may carry
  `hub_url`; present, the SPA lights up search (server FTS), auth,
  publish status, cross-registry navigation. The hub's CORS allowlist
  is derived from its own `Frontend` table — exact domains, not `*`.
  Absent, search degrades to client-side substring over `index.json`.

**No-JS ethos preserved, three tiers**: (1) proxied frontends — full
Leptos SSR + hydration; (2) direct frontends with JS — the CSR SPA;
(3) direct frontends without JS — `index.html` is generated as a
*real, content-bearing* Debian-style static page (trust-anchor
fingerprints, channel table, package list linking to
`/browse/<pkg>.html` static pages) that the SPA progressively takes
over. One URL, no loader shell; curl and lynx see actual content. Tier
3 is the floor and it is already strictly better than Debian's
autoindex.

**Production**: a new **`apr web generate`** subcommand, exactly
parallel to `apr cache generate` — the SPA dist is embedded in the
`apr` binary (hermetically built; the AOS build already builds
Rust→wasm toolchains from source) and the command emits the dist +
static pages + JSON snapshots + `config.json` defaults;
`apr origin upload`/`apr release` grow awareness of the web dir the
same way they handle the cache dir. The no-hub story stays complete:
an operator with only `apr` and a bucket gets the full web surface.
The hub regenerates snapshots on managed publishes; both producers emit
the identical layout, and `index.json` carries `generator` +
`surface_commit` so staleness is detectable.

Trust scoping, stated precisely: `config.json` is origin-only, unsigned
content — **not consumption-trust-relevant** (it can never change what
`apm` or Nix accept) but it *is* same-origin-integrity-trusted by the
SPA, and `hub_url` directs authenticated browser traffic. The
mitigations: `config.json` is writable only through the same
write-controlled paths as the rest of the surface, and the hub refuses
Connect calls from origins it has not registered as frontends, so a
forged `hub_url` cannot harvest a session against a legitimate hub.
The same honesty applies to the in-browser verification badge: it is
only as honest as the served SPA — an attacker with origin write could
serve a lying app. That is the same compromise that could serve any
content; the independent check is the hub-proxied page (different
origin, same verifier), and the badge UI links to it.

### Sitemap, page flows, and visual design

#### The `/-/` namespace — humans and machines share a root

The machine surface owns paths at the registry root: `HEAD`, `info/`,
`objects/`, `channels/`, `releases/`, `nix-cache-info`,
`{hash}.narinfo`, `nar/`, plus the web-surface files (`index.html`,
`web/`, `browse/`). Human sub-pages would collide — a channel page at
`…/{registry}/channels/stable` shadows the partition files
`channels/stable/<bucket>` that `apm` fetches. So **all human pages
below a registry live under `/-/`** (the GitLab convention): exact
machine paths always win, `/-/` is reserved and can never appear in
the machine layout, and the registry root itself content-negotiates
(HTML for browsers; on direct frontends the root *is* the generated
`index.html`). Org and project slugs are validated against a reserved
top-level list (`login`, `activate`, `account`, `new`, `oauth2`,
`api`, `-`, …).

```text
/                                   instance home — public registries, global search
/login  /activate  /account         auth · device-code approval · profile/sessions/passkeys/tokens
/new                                create organization
/{org}/                             org home — projects, registries, members
/{org}/-/audit                      org audit feed
/{org}/-/settings                   IAM · SSO · domains · bindings · signing keys · quotas
/{org}/{proj…}/                     project home (nested)
/{org}/{proj…}/{registry}/          registry home  ⇄  machine surface root
/{org}/{proj…}/{registry}/-/
    packages/        packages/{name}     index · package page
    channels/        channels/{name}     rollout grid · advance console
    releases/        releases/{semver}   signed tags · pack/delta detail
    health/                              index · cache policy · delivery routes
    git/log  git/diff/{a}..{b}           git views
    changes/         changes/{id}        change requests · prepared operations
    publishes/       publishes/{id}      publish pipeline runs
    settings/                            frontends · caches/stacks · mirror source · visibility · tokens
```

#### Page flows — the five journeys that matter

1. **Evaluate → adopt** (anonymous consumer): land on the registry
   home from search or a pasted URL → trust anchors, index status,
   and cache policy are above the fold (the decision
   inputs) → package page → copy the setup snippet. Zero login, zero
   JS required.
2. **Publish** (maintainer): run `apr release` in the terminal → the
   `publishes/{id}` page narrates the pipeline live (status stream:
   commit → tag → packs → upload → validation gate → flip) → channel
   page reflects the new frontier. The web never asks the maintainer
   to leave the terminal; it *narrates* what the CLI is doing.
3. **Roll out**: channel page grid → "advance to 50%" → BYO-key orgs
   get a prepared operation with a copy-paste
   `apr channel advance --from-hub <id>`; provider-custodied generations get a
   reviewed apply action → the grid updates, floor and staleness in view.
4. **Onboard an org**: create org → create registry (binding picker:
   hub bucket / BYO) → the success page *is* the
   `apr create --remote …` snippet → first publish appears live.
5. **Device login**: `apr login` prints a code → `/activate` → scope
   approval (shows exactly which paths/permissions) → the CLI
   proceeds without a copied secret.

#### Design language: Stone & ocean

The original "release-engineering paper" direction drew on two references,
both studied from their shipped HTML/CSS:

- **usgraphics.com** (U.S. Graphics / Berkeley Graphics): a
  server-rendered, table-dense "engineering document" aesthetic —
  flat, ruled, monospace-forward — whose published design philosophy
  is nearly a restatement of this RFC's ethos: *expose state and inner
  workings; dense, not sparse; explicit is better than implicit;
  verbosity over opacity; don't infantilize users; performance is
  design*. Notably it achieves the look with plain server-rendered
  HTML — proof the no-JS tier can carry the full design.
- **turbopuffer.com**: one monospace typeface for everything, and
  box-drawing ASCII diagrams as the *primary* graphic device
  (animated, where animated at all, by stepping a CSS keyframe through
  pre-rendered text frames — no canvas, no SVG).

Behind both stands the heritage this tool actually descends from:
Debian FTP listings and changelogs, man pages, IETF RFC plaintext,
`MAINTAINERS` files, BSD handbooks, release-announcement emails.
The current **Stone & ocean** direction retains the document hierarchy and
explicit state while separating readable interface text from machine data.
The shared `/_assets/style.css` owns the palette and font-family variables for
both browse pages and the management console. Workflow-specific console CSS
references those variables instead of defining a second theme.

Principles, concretely:

- **Paired typography.** Geist Sans carries headings, prose, navigation,
  and form controls. Geist Mono carries code, configuration editors,
  hashes, versions, paths, and machine identifiers. Both are self-hosted
  variable WOFF2 files under the SIL Open Font License, with bounded cache
  lifetimes. There are no font CDNs or runtime font downloads from third
  parties; upstream provenance lives beside the bundled assets.
- **Stone & ocean.** White (`#ffffff`) and near-black (`#141413`) anchor
  light mode. Warm stone surfaces (`#f2f0ed`), brown-grey secondary text
  (`#716a63`), and ocean green (`#07594f`) establish hierarchy. Dark mode
  uses `#101110`, `#f7f7f5`, `#1c1b19`, `#aaa198`, and the lighter green
  `#80bcae` for text. Solid primary actions retain deep green with white
  text. Amber and red are reserved for warning and error states; release
  categories and syntax highlighting use the green/neutral palette.
- **Appearance preference.** System is the default and works without
  JavaScript. The footer control cycles System, Light, and Dark; an explicit
  preference persists locally and applies before the stylesheet paints on
  both browse and console pages. Unavailable browser storage falls back to
  a document-local preference.
- **Tables and rules are the layout.** Sentence-case sans-serif headings,
  readable tables, and thin horizontal rules distinguish sections. Warm
  surfaces identify code and grouped controls. Small corner radii soften
  controls without turning every section into a card.
- **ASCII diagrams are the iconography.** Stack topology, mirror
  layout, and closure graphs render as box-drawing text — identical in
  the SSR page, the SPA, the static no-JS tier, and a `curl` of the
  page. Diagrams are content: selectable, copy-pasteable into a
  terminal or a doc.
- **The partition grid** is a 16×16 monospace grid where each release
  gets a glyph *and* a color (`■`/`▣`/`▢`/`▤` — colorblind-safe by
  construction); the legend is a table.
- **Raw formats shown raw.** A narinfo renders as a narinfo,
  `registry.toml` as TOML, a signature chain as indented text — with a
  permalink on everything. The page teaches the format by showing it.
- **Expose state.** Every page footer carries a state line: surface
  commit, index freshness, render time, hub version. Performance *is*
  design: SSR pages target tens of kilobytes of HTML and are complete
  without a single client-side request.
- **Accessibility.** Information is never encoded in color alone
  (glyphs and labels accompany), tables are real `<table>` semantics
  with headers, focus states are visible, both schemes hold WCAG AA
  contrast.

A flavor wireframe of the registry home (itself in the diagram
language it proposes):

```text
┌────────────────────────────────────────────────────────────────┐
│ ANDYL REGISTRY HUB        acme / infra / prod         [log in]  │
├────────────────────────────────────────────────────────────────┤
│ REGISTRY acme/infra/prod            frontier 1.4.2  ✓ verified  │
│ trust    andyl:Ed25519:AAAAC3…WKL (+1)     indexed 38s ago      │
│ caches   cdn.acme.com ✓ 100%   backup-s3 ⚠ 98.7% (3 missing)    │
├────────────────────────────────────────────────────────────────┤
│ CHANNELS                                                        │
│   stable    1.4.2      ████████████░░░░  75%     floor 1.4.0    │
│   testing   1.5.0-rc1  ████████████████ 100%                    │
├────────────────────────────────────────────────────────────────┤
│ PACKAGES (214)                        [ search ______________ ] │
│   curl      8.5.0    x86_64    3.0M / 50M     MIT               │
│   openssl   3.2.1    x86_64    7.1M / 12M     Apache-2.0        │
│   …                                                             │
├────────────────────────────────────────────────────────────────┤
│ SETUP     apr add https://hub.example.com/acme/infra/prod       │
└────────────────────────────────────────────────────────────────┘
  surface ab12cd34 · indexed 2026-06-12T16:02Z · rendered 11ms
```

Per-registry theming (`config.json`: logo, accent) selects *within*
this language, never around it — a tenant can brand a registry, not
break the system.
