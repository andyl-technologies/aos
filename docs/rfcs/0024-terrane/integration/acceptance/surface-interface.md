# T-SURF-1 interface and SDK component audit

This audit inspects the common surface interface and the compiled SDK component
at `244489fd6e6d008dd6171e3e5fa58146994d39ad`. It does not accept T-SURF-1.
The task's shared feature-matrix requirement remains unqualified. Protocol and
kernel surfaces keep their separate implementation and qualification owners
listed in the implementation plan; an unavailable surface is not a completed
implementation of its conditional obligations.

## Requirement coverage

| Requirements | Inspected implementation | Evidence and acceptance limits |
| --- | --- | --- |
| SURF-1, SURF-2, SURF-3 | [Surface and Serving][native] expose schema, repository-backed presentation, status, drain and stop. [SdkSurface][sdk] retains a repository and the exposure token. Its prepared-view input is opaque and repository-owned. | The surface-interface guest checks the public contract and configured repository composition. Neither an external trait implementation nor a parsed registration establishes a deployed surface or authorizes direct backend access. |
| SURF-4 | The [SDK registration][registry] is read-only. [Configuration][configuration] and [preparation][preparation] refuse a writer mode before starting an endpoint. | The surface-commit-path guest exercises that refusal. A durable SDK checkout preserves file modes and is not an immutable mount; it exposes no consumer mutation request or repository commit entry point. Writable protocol behavior remains with each writable surface. |
| SURF-5, SURF-6 | [Repository reads][reads] distinguish ref-selected and immutable commit-selected snapshots. Prepared SDK presentation retains the selected commit while independently rechecking current policy. SDK follow is unavailable. | The status guest advances the ref after preparation and requires the original bytes and commit. Current-authority denial is independently exercised. Follow consistency and atomic switching require T-CONS-1 and the surfaces that implement follow. |
| SURF-7 | [Repository projection][reads] rebases the selected subtree. [Checkout path checks][paths] reject escaping destinations and symlink chains; checkout preserves scoped hard-link relationships. | The surface audit must retain the repository's existing subtree controls when renewing its gates. Schema validation alone does not prove filesystem containment, and a missing subtree cannot be represented by an empty successful checkout. |
| SURF-8 | [Configuration][configuration] and [preparation][preparation] reject every named policy because the compiled policy registry is empty. | The interface guest checks both ref and commit selectors and rejects the whole list before token resolution. This is unknown-policy refusal, not implementation of registered routing or realization policies. |
| SURF-9, SURF-10, SURF-11 | The closed [registry][registry] contains only the feature-enabled SDK on its supported target, with directory endpoints. [Configuration][configuration] rejects unavailable names, invalid endpoint paths, duplicate endpoint addresses and duplicate IDs. | The interface guest exercises registry and whole-list rejection. Socket, URL and device endpoint parsers must arrive with their actual surface implementations; their absence cannot be claimed as equivalent support. |
| SURF-12 | [Preparation][preparation] resolves each exposure credential and invokes the repository's guarded schema preparation before any endpoint starts. [Prepared reads][reads] recheck authority before materializing content. | The interface guest requires second-exposure credential failure to leave both destinations absent and preserves current signed ACL denial. Instance credentials cannot replace an insufficient exposure token. Writable startup needs a separate Commit check when writable surfaces arrive. |
| SURF-13, SURF-14, SURF-15 | [Schema validation][schema] checks canonical entry metadata, root attributes and effective properties without an object reader. The SDK's empty schema agrees with its normative registry row. [Repository preparation][reads] retains authorization separately from the public metadata projection. | The schema guest checks malformed patterns, empty collections, literal existence, root attributes, types, forbidden entries and a native no-plaintext-read witness. No running follow implementation has yet demonstrated SchemaFault while retaining a last valid commit. |
| SURF-16, SURF-17, SURF-18, SURF-19 | SDK writer configuration is refused; it has no mutating consumer protocol. The repository remains the sole commit boundary. | The read-only refusal guest does not prove working-tree translation, periodic commits, durable acknowledgments, read-back authorization or native error mapping for any writable surface. Those obligations remain jointly owned by the writable surface and consistency tasks. |
| SURF-20, SURF-21, SURF-22, SURF-23 | [TokenResolver][preparation] separates credential location from repository authorization. The [configured SDK token adapter][tokens] accepts supported file references and refuses unsupported providers. SDK has no foreign protocol request credential. | This is not production foreign-credential mapping, anonymous request handling or proof of request-token attenuation. Each foreign protocol surface must exercise those checks under its exposure's authority. |
| SURF-24 | [Compiled registration][registry] is a feature-gated closed match. Configuration supplies no dynamic loader or plugin path. | The interface guest rejects uncompiled surfaces, experimental names and a shared-library pathname. A reserved name does not become available merely because it is listed in the specification. |
| SURF-25, SURF-26 | [Public lifecycle contracts][contracts] let an external implementation own its Serving handle without obtaining an SDK constructor or registered backend. | This proves the public trait boundary only. The production Distribution repository services and remote composition remain incomplete, so out-of-process parity is not established. Realizer descriptor passing has its separately owned broker requirements. |
| SURF-27, SURF-28 | [ExposureStatus][native] includes the exact served commit, surface, optional realizer, feature outcomes, effective modes, last commit outcome, schema state and lifecycle. The SDK reports a pinned completed snapshot with no writer or realizer. | The status guest checks two presentations of the same prepared commit and their actual handles. The separate presentation guest checks the completed native directory. These results do not prove status for a live kernel realizer, follow faults or writable commit outcomes. |
| SURF-29 | [TOML exposure parsing][configuration] requires the five mandatory fields, preserves surface options and validates mode choices. | SDK's normative registry row additionally requires explicit pinned mode, including for ref targets; its rejected implicit mode is not a silent change to follow semantics. Defaults for other surfaces must be implemented with those surfaces. |
| SURF-30, SURF-31 | [Credential-reference parsing][credential-reference] rejects inline credentials and malformed locators. The portable View parser validates the selector before the parsed configuration is returned. | The interface guest checks references, unavailable policies and whole-list parse failures. Syntax acceptance does not promise that the configured native adapter implements every secret provider. |
| SURF-32 | [PreparedExposures][preparation] validates the complete list before presentation and starts it in configuration order. A later physical startup failure stops previously returned handles and returns the failure. | The interface and status guests check refusal before endpoint creation and preservation of the originally prepared target. Physical startup failure may leave private incomplete checkout artifacts; it must never return a successful partial list. |
| TREE-9 | [Checkout metadata][checkout-metadata] reads only registered `uid` and `gid` attributes, validates their integer range and applies them through a retained native effect. | The presentation guest checks actual ownership and modes. There are no ownership bits or invented identity fields in the canonical tree encoding. |
| TREE-10 | The [native metadata effect][metadata-effect] sets canonical epoch access and modification times on the retained inode before restrictive final modes. | The presentation guest checks the actual timestamps. Kernel-maintained change and birth times remain local inode metadata. This result does not qualify a future property-selected timestamp presentation policy. |
| TREE-15 | [Checkout metadata][checkout-metadata] preserves raw user xattr names and values and filters security, system and trusted namespaces. | The presentation guest checks actual xattrs. No registered root policy currently grants an exception; the filter is not evidence for a future privileged-namespace presentation mode. |
| ARCH-6 | [Configuration][config] owns the parsed store expression; the configured native composition accepts its explicit supported leaf and rejects unsupported compositions. | No runtime path rewrites the expression or performs a configuration reload. Production routed/remote shape and any future logged reload remain with their owning implementation tasks. |
| CRATE-17 | [Shared configuration][config] owns store and exposure parsing. The CLI consumes that library vocabulary. | The interface guest exercises the same Config type used by native startup. A successful parse is not acknowledgment that an unavailable role or backend has run. |
| CRATE-28 | [Registration][registry] compiles SDK only with `surface-sdk` on its supported native target. | This covers the SDK component only. The shared feature matrix remains required; global conformance also requires the other feature owners listed in the implementation plan. |

## Reviewed qualification

The four owning gates at
`a9a08d2696d28d5ffb1955a72d73e3ae09d7e807` pass in 2,074.289 seconds:
surface-interface, surface-schema, surface-status and surface-commit-path.
Complete review matches 8,258 immutable source files, six retained Cargo
executables and all 27 original ordered nonignored selectors across four
UID-840 ext4 guests. The fifth guest executes the original presentation case,
including its explicit ignored-case selection, with empty capabilities and
no-new-privileges. These results qualify their recorded revision and scope.

The [owning gate definitions][gates] retain those original selector guests and
the independent presentation prerequisite. They do not replace the shared
feature matrix. The continuing matrix at `4914e8a0dc` has reported a collection
test failure; its later fixture correction still requires native qualification
and matrix renewal. No green surface component result closes that failure.

## Acceptance boundary

T-SURF-1 stays open until its shared feature-matrix obligation passes and all
applicable common/SDK evidence is reconciled with the source being accepted.
Conditional requirements above must also be exercised when their production
protocol or kernel surfaces land. The crate feature ownership table remains
the authority for those joint obligations. This audit changes no task checkbox,
accepted-task count or full RFC conformance claim.

[native]: ../../../../../crates/terrane/sdk/terrane-sdk/src/surface/native.rs
[sdk]: ../../../../../crates/terrane/sdk/terrane-sdk/src/surface/sdk.rs
[registry]: ../../../../../crates/terrane/sdk/terrane-sdk/src/surface/registry.rs
[preparation]: ../../../../../crates/terrane/sdk/terrane-sdk/src/surface/exposure.rs
[configuration]: ../../../../../crates/terrane/sdk/terrane-sdk/src/config/exposure.rs
[config]: ../../../../../crates/terrane/sdk/terrane-sdk/src/config.rs
[credential-reference]: ../../../../../crates/terrane/sdk/terrane-sdk/src/config/token.rs
[tokens]: ../../../../../crates/terrane/linux/terrane-linux/src/configured_sdk/tokens.rs
[reads]: ../../../../../crates/terrane/sdk/terrane-sdk/src/repository/read.rs
[schema]: ../../../../../crates/terrane/sdk/terrane-sdk/src/repository/schema.rs
[paths]: ../../../../../crates/terrane/sdk/terrane-sdk/src/repository/path.rs
[checkout-metadata]: ../../../../../crates/terrane/sdk/terrane-sdk/src/repository/checkout/presentation.rs
[metadata-effect]: ../../../../../crates/terrane/sdk/terrane-sdk/src/store/native_effect/checkout_metadata.rs
[contracts]: ../../../../../crates/terrane/sdk/terrane-sdk/tests/surface_lifecycle_contract.rs
[gates]: ../../../../../tests/terrane/gates/surfaces.nix
