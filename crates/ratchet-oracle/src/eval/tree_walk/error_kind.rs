//! The exhaustive `TreeWalkErrorKind` enum enumerating every evaluation failure.

use super::*;
use crate::eval::TreeWalkThunkAllocationError;

/// The category of a tree-walk evaluation failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum TreeWalkErrorKind {
    /// The evaluator was asked to read a missing IR node.
    #[error("invalid IR node id {id:?}")]
    InvalidNodeId {
        /// The missing node id.
        id: IrId,
    },
    /// The evaluator was asked to read a missing loaded IR module.
    #[error("invalid IR module id {module}")]
    InvalidModuleId {
        /// The missing module id.
        module: u32,
    },
    /// The evaluator loaded too many IR modules.
    #[error("too many loaded IR modules at node {id:?}: {modules}")]
    TooManyModules {
        /// The import node that needed another module.
        id: IrId,
        /// The number of modules already loaded.
        modules: usize,
    },
    /// The active import-cache lease stack could not grow.
    #[error("failed to reserve import-cache lease {leases} at node {id:?}")]
    ImportCacheLeaseAllocationFailed {
        /// The import argument that needed another active lease.
        id: IrId,
        /// The requested active lease count.
        leases: usize,
    },
    /// The import-cache lease generation space was exhausted.
    #[error("import-cache lease generation exhausted at node {id:?}")]
    ImportCacheLeaseGenerationExhausted {
        /// The import argument that needed another active lease.
        id: IrId,
    },
    /// The active imported-module context lease stack could not grow.
    #[error("failed to reserve imported-module context lease {leases} at node {id:?}")]
    ImportModuleLeaseAllocationFailed {
        /// The import node that needed another active context.
        id: IrId,
        /// The requested active context lease count.
        leases: usize,
    },
    /// The imported-module context lease generation space was exhausted.
    #[error("imported-module context lease generation exhausted at node {id:?}")]
    ImportModuleLeaseGenerationExhausted {
        /// The import node that needed another active context.
        id: IrId,
    },
    /// The evaluator-owned force lease stack could not grow.
    #[error("failed to reserve force lease {leases} at node {id:?}")]
    ForceLeaseAllocationFailed {
        /// The force site that needed another active lease.
        id: IrId,
        /// The requested active lease count.
        leases: usize,
    },
    /// The evaluator-owned force lease generation space was exhausted.
    #[error("force lease generation exhausted at node {id:?}")]
    ForceLeaseGenerationExhausted {
        /// The force site that needed another active lease.
        id: IrId,
    },
    /// Detached typed-work lease nesting disagreed with the active force.
    #[error("typed thunk work lease invariant failed at node {id:?}")]
    TypedThunkWorkLeaseInvariant {
        /// The force site whose detached-work lease was missing or mismatched.
        id: IrId,
    },
    /// The evaluator-owned lambda-call lease stack could not grow.
    #[error("failed to reserve lambda-call lease {leases} at node {id:?}")]
    LambdaCallLeaseAllocationFailed {
        /// The application that needed another active lease.
        id: IrId,
        /// The requested active lease count.
        leases: usize,
    },
    /// The evaluator-owned lambda-call lease generation space was exhausted.
    #[error("lambda-call lease generation exhausted at node {id:?}")]
    LambdaCallLeaseGenerationExhausted {
        /// The application that needed another active lease.
        id: IrId,
    },
    /// A content-memo CHECK-mode hit diverged from a fresh evaluation.
    ///
    /// Raised only under `AOS_NIX_MEMO_CHECK`, where every content-memo hit
    /// is shadowed by a real evaluation and asserted byte-identical; this is
    /// the diagnostic failure for a divergence, never a production path.
    #[error("content-memo hit at node {id:?} diverged from a fresh evaluation")]
    MemoCheckDivergence {
        /// The force site whose memoized payload disagreed.
        id: IrId,
    },
    /// The node kind and node payload disagreed.
    #[error("invalid payload for {kind:?} node {id:?}; expected {expected}")]
    InvalidPayload {
        /// The malformed node id.
        id: IrId,
        /// The node kind whose payload was malformed.
        kind: IrKind,
        /// The expected payload contract.
        expected: &'static str,
    },
    /// Thunk allocation planning rejected a malformed node or missing proof.
    #[error("thunk allocation planning failed at node {id:?}: {source}")]
    ThunkAllocation {
        /// The thunk allocation node being planned.
        id: IrId,
        /// The lower-level planning failure.
        source: TreeWalkThunkAllocationError,
    },
    /// A child-pool slice payload did not resolve through the IR arena.
    #[error("invalid child slice {slice:?} at node {id:?}")]
    InvalidChildSlice {
        /// The node id carrying the invalid child slice.
        id: IrId,
        /// The invalid child slice payload.
        slice: IrChildSlice,
    },
    /// An attribute-path side-table id did not resolve or carried no segments.
    #[error("invalid attribute path {path:?} at node {id:?}")]
    InvalidAttrPath {
        /// The node id carrying the invalid attribute-path id.
        id: IrId,
        /// The invalid attribute-path id payload.
        path: IrAttrPathId,
    },
    /// A binding-table slice payload did not resolve through the IR.
    #[error("invalid binding slice {slice:?} at node {id:?}")]
    InvalidBindingSlice {
        /// The node id carrying the invalid binding slice.
        id: IrId,
        /// The invalid binding slice payload.
        slice: IrBindingSlice,
    },
    /// An attrset shape id payload did not resolve through the IR.
    #[error("invalid attrset shape {shape:?} at node {id:?}")]
    InvalidShapeId {
        /// The node id carrying the invalid shape id.
        id: IrId,
        /// The invalid shape id payload.
        shape: IrShapeId,
    },
    /// A node that needs a resolver frame referenced none.
    #[error("missing frame metadata at node {id:?}")]
    MissingFrameMetadata {
        /// The malformed node id.
        id: IrId,
    },
    /// A resolver frame id did not resolve through the IR.
    #[error("invalid frame id {frame} at node {id:?}")]
    InvalidFrameId {
        /// The node id carrying the invalid frame id.
        id: IrId,
        /// The invalid frame id payload.
        frame: u32,
    },
    /// A with-chain id did not resolve through the lowered IR.
    #[error("invalid with-chain id {chain} at node {id:?}")]
    InvalidWithChain {
        /// The node id carrying the invalid with-chain id.
        id: IrId,
        /// The invalid with-chain id payload.
        chain: u32,
    },
    /// A with-chain scope did not have a matching active runtime scope.
    #[error("missing active with scope {scope:?} at node {id:?}")]
    MissingWithScope {
        /// The with-variable node id.
        id: IrId,
        /// The lowered scope node id from the with-chain.
        scope: IrId,
    },
    /// A let frame's slot count did not match its binding table.
    #[error("let frame at node {id:?} has {frame_slots} slots for {bindings} bindings")]
    LetFrameSlotMismatch {
        /// The malformed let node id.
        id: IrId,
        /// The resolver frame slot count.
        frame_slots: usize,
        /// The number of lowered bindings.
        bindings: usize,
    },
    /// A recursive attrset frame's slot count did not match its binding table.
    #[error(
        "recursive attrset frame at node {id:?} has {frame_slots} slots for {bindings} bindings"
    )]
    AttrSetFrameSlotMismatch {
        /// The malformed attrset node id.
        id: IrId,
        /// The resolver frame slot count.
        frame_slots: usize,
        /// The number of lowered bindings.
        bindings: usize,
    },
    /// A lambda frame's slot count did not match the supported pattern.
    #[error(
        "lambda frame at node {id:?} has {frame_slots} slots for {pattern_slots} pattern slots"
    )]
    LambdaFrameSlotMismatch {
        /// The malformed lambda or application node id.
        id: IrId,
        /// The resolver frame slot count.
        frame_slots: usize,
        /// The number of slots expected by the supported pattern.
        pattern_slots: usize,
    },
    /// A lambda used a parameter pattern not implemented by this evaluator slice.
    #[error("unsupported lambda pattern {pattern:?} ({kind:?}) at node {id:?}")]
    UnsupportedLambdaPattern {
        /// The application node id.
        id: IrId,
        /// The unsupported pattern node id.
        pattern: IrId,
        /// The unsupported pattern node kind.
        kind: IrKind,
    },
    /// A local variable was evaluated without an active environment frame.
    #[error("missing lexical environment at node {id:?}")]
    MissingEnvironment {
        /// The variable node id.
        id: IrId,
    },
    /// An upvalue depth did not resolve through the active environment stack.
    #[error("upvalue depth {depth} at node {id:?} exceeds {frames} active frames")]
    InvalidUpvalueDepth {
        /// The upvalue node id.
        id: IrId,
        /// The requested parent depth.
        depth: usize,
        /// The number of active frames.
        frames: usize,
    },
    /// A let binding carried an unsupported dynamic key.
    #[error("unsupported let binding key at node {id:?}")]
    UnsupportedLetBindingKey {
        /// The malformed let node id.
        id: IrId,
    },
    /// An attrset shape has a different number of keys than its binding slice.
    #[error(
        "attrset shape {shape:?} at node {id:?} has {shape_keys} keys for {binding_keys} binding keys"
    )]
    AttrSetShapeLengthMismatch {
        /// The attrset node id carrying the mismatched metadata.
        id: IrId,
        /// The shape id carrying the mismatched key table.
        shape: IrShapeId,
        /// The number of keys recorded in the shape table.
        shape_keys: usize,
        /// The number of static keys found in the binding slice.
        binding_keys: usize,
    },
    /// An attrset shape key does not match the corresponding binding key.
    #[error(
        "attrset shape {shape:?} at node {id:?} key {index} is {expected:?}, but binding key is {actual:?}"
    )]
    AttrSetShapeKeyMismatch {
        /// The attrset node id carrying the mismatched metadata.
        id: IrId,
        /// The shape id carrying the mismatched key table.
        shape: IrShapeId,
        /// The mismatched key index.
        index: usize,
        /// The symbol recorded by the shape table.
        expected: Symbol,
        /// The symbol found in the binding slice.
        actual: Symbol,
    },
    /// A symbol payload did not resolve through the IR symbol table.
    #[error("invalid symbol {symbol:?} at node {id:?}")]
    InvalidSymbol {
        /// The node id associated with the missing symbol.
        id: IrId,
        /// The unresolved symbol payload.
        symbol: Symbol,
    },
    /// A runtime-computed attribute name could not be interned.
    #[error("runtime attribute-name interning failed at node {id:?}: {source}")]
    SymbolIntern {
        /// The node id associated with the runtime attribute name.
        id: IrId,
        /// The underlying symbol-table failure.
        source: crate::syntax::AstErrorKind,
    },
    /// A byte buffer for a string literal could not be reserved.
    #[error("failed to reserve {len} string bytes at node {id:?}")]
    ByteAllocationFailed {
        /// The string node id.
        id: IrId,
        /// The requested byte length.
        len: usize,
    },
    /// A path-taking primop received a relative string.
    #[error("path at node {id:?} is not absolute: {path:?}")]
    PathNotAbsolute {
        /// The path-valued node being coerced.
        id: IrId,
        /// The rejected path bytes.
        path: Vec<u8>,
    },
    /// A pure evaluator rejected home-relative path expansion.
    #[error("{mode:?} evaluation cannot resolve home path at node {id:?}: {path:?}")]
    HomePathNotAllowed {
        /// The path-valued node being expanded.
        id: IrId,
        /// The rejected home-relative path bytes.
        path: Vec<u8>,
        /// The evaluation mode that rejected home expansion.
        mode: EvalMode,
    },
    /// A home-relative path was evaluated without a configured home directory.
    #[error("home path at node {id:?} has no configured home directory: {path:?}")]
    HomePathUnavailable {
        /// The path-valued node being expanded.
        id: IrId,
        /// The rejected home-relative path bytes.
        path: Vec<u8>,
    },
    /// An evaluation mode rejected filesystem access to a path.
    #[error("{mode:?} evaluation forbids filesystem access at node {id:?} path {path:?}")]
    PathAccessDenied {
        /// The path-valued node being accessed.
        id: IrId,
        /// The normalized or resolved path bytes.
        path: Vec<u8>,
        /// The evaluation mode that denied access.
        mode: EvalMode,
    },
    /// Pure evaluation rejected `builtins.storePath`.
    #[error("builtins.storePath is not allowed in pure evaluation mode at node {id:?}")]
    StorePathPureEval {
        /// The call node that attempted to use `builtins.storePath`.
        id: IrId,
    },
    /// A file-content primop could not read its target path.
    #[error("failed to read file at node {id:?} path {path:?}: {message}")]
    FileRead {
        /// The path-valued node being read.
        id: IrId,
        /// The file path bytes.
        path: Vec<u8>,
        /// The filesystem diagnostic.
        message: String,
    },
    /// An import recursively demanded a file already being imported.
    #[error("recursive import at node {id:?} path {path:?}")]
    RecursiveImport {
        /// The import path-valued node.
        id: IrId,
        /// The canonical imported file path.
        path: Vec<u8>,
    },
    /// Imported source bytes could not be parsed.
    #[error("failed to parse imported file at node {id:?} path {path:?}: {message}")]
    ImportParse {
        /// The import path-valued node.
        id: IrId,
        /// The canonical imported file path.
        path: Vec<u8>,
        /// The parser diagnostic.
        message: String,
    },
    /// Imported source could not be scope-resolved.
    #[error("failed to resolve imported file at node {id:?} path {path:?}: {message}")]
    ImportScope {
        /// The import path-valued node.
        id: IrId,
        /// The canonical imported file path.
        path: Vec<u8>,
        /// The resolver diagnostic.
        message: String,
    },
    /// Imported source could not be lowered to evaluator IR.
    #[error("failed to lower imported file at node {id:?} path {path:?}: {message}")]
    ImportLower {
        /// The import path-valued node.
        id: IrId,
        /// The canonical imported file path.
        path: Vec<u8>,
        /// The lowering diagnostic.
        message: String,
    },
    /// A file-content primop read bytes that cannot be represented as a Nix string.
    #[error("file at node {id:?} path {path:?} contains a NUL byte")]
    FileReadContainsNul {
        /// The path-valued node being read.
        id: IrId,
        /// The file path bytes.
        path: Vec<u8>,
    },
    /// A filesystem-stat primop could not inspect its target path.
    #[error("failed to stat path at node {id:?} path {path:?}: {message}")]
    PathStat {
        /// The path-valued node being inspected.
        id: IrId,
        /// The path bytes.
        path: Vec<u8>,
        /// The filesystem diagnostic.
        message: String,
    },
    /// A directory-listing primop could not read its target directory.
    #[error("failed to read directory at node {id:?} path {path:?}: {message}")]
    DirectoryRead {
        /// The path-valued node being listed.
        id: IrId,
        /// The directory path bytes.
        path: Vec<u8>,
        /// The filesystem diagnostic.
        message: String,
    },
    /// A source path could not be assigned a valid Nix store path name.
    #[error("failed to derive store path name at node {id:?} path {path:?}: {message}")]
    SourcePathStoreName {
        /// The path-valued node being coerced.
        id: IrId,
        /// The source path bytes.
        path: Vec<u8>,
        /// The store-name diagnostic.
        message: String,
    },
    /// A source path could not be serialized as a Nix archive.
    #[error("failed to serialize source path at node {id:?} path {path:?}: {message}")]
    SourcePathArchive {
        /// The path-valued node being coerced.
        id: IrId,
        /// The source path bytes.
        path: Vec<u8>,
        /// The archive or filesystem diagnostic.
        message: String,
    },
    /// A source path names a filesystem node kind Nix cannot copy into the store.
    #[error("unsupported source path type at node {id:?} path {path:?}")]
    UnsupportedSourcePathType {
        /// The path-valued node being coerced.
        id: IrId,
        /// The source path bytes.
        path: Vec<u8>,
    },
    /// A `builtins.path` argument set used an unsupported attribute.
    #[error("unsupported source path attribute at node {id:?}: {attr:?}")]
    UnsupportedSourcePathAttr {
        /// The `builtins.path` argument node.
        id: IrId,
        /// The unsupported attribute name bytes.
        attr: Vec<u8>,
    },
    /// A source path's actual SHA-256 digest differed from its expected digest.
    #[error(
        "source path hash mismatch at node {id:?} path {path:?}: expected {expected:?}, got {actual:?}"
    )]
    SourcePathHashMismatch {
        /// The source path node or primop id.
        id: IrId,
        /// The source path bytes.
        path: Vec<u8>,
        /// The expected SHA-256 digest bytes.
        expected: Vec<u8>,
        /// The actual SHA-256 digest bytes.
        actual: Vec<u8>,
    },
    /// `builtins.fetchurl` used an unsupported argument attribute.
    #[error("unsupported fetchurl argument at node {id:?}: {attr:?}")]
    UnsupportedFetchUrlAttr {
        /// The fetchurl argument node.
        id: IrId,
        /// The unsupported attribute name bytes.
        attr: Vec<u8>,
    },
    /// `builtins.fetchurl` could not derive or validate the output store name.
    #[error(
        "failed to derive fetchurl store name at node {id:?} url {url:?} name {name:?}: {message}"
    )]
    FetchUrlStoreName {
        /// The fetchurl argument node.
        id: IrId,
        /// The URL bytes.
        url: Vec<u8>,
        /// The rejected store name bytes.
        name: Vec<u8>,
        /// The store-name diagnostic.
        message: String,
    },
    /// `builtins.fetchurl` could not fetch or read its URL.
    #[error("failed to fetch URL at node {id:?} url {url:?}: {message}")]
    FetchUrl {
        /// The fetchurl argument node.
        id: IrId,
        /// The URL bytes.
        url: Vec<u8>,
        /// The fetch diagnostic.
        message: String,
    },
    /// An evaluation mode rejected `builtins.fetchurl` network access.
    #[error("{mode:?} evaluation forbids fetchurl network access at node {id:?} url {url:?}")]
    FetchUrlAccessDenied {
        /// The fetchurl argument node.
        id: IrId,
        /// The URL bytes.
        url: Vec<u8>,
        /// The evaluation mode that denied access.
        mode: EvalMode,
    },
    /// Pure evaluation rejected an unpinned `builtins.fetchurl` request.
    #[error("{mode:?} evaluation requires a sha256 for fetchurl at node {id:?} url {url:?}")]
    FetchUrlHashRequired {
        /// The fetchurl argument node.
        id: IrId,
        /// The URL bytes.
        url: Vec<u8>,
        /// The evaluation mode that required a hash.
        mode: EvalMode,
    },
    /// `builtins.fetchurl` downloaded bytes with a different SHA-256 digest.
    #[error(
        "fetchurl hash mismatch at node {id:?} url {url:?}: expected {expected:?}, got {actual:?}"
    )]
    FetchUrlHashMismatch {
        /// The fetchurl argument node.
        id: IrId,
        /// The URL bytes.
        url: Vec<u8>,
        /// The expected SHA-256 digest bytes.
        expected: Vec<u8>,
        /// The actual SHA-256 digest bytes.
        actual: Vec<u8>,
    },
    /// `builtins.fetchGit` used an unsupported argument attribute.
    #[error("unsupported fetchGit argument at node {id:?}: {attr:?}")]
    UnsupportedFetchGitAttr {
        /// The fetchGit argument node.
        id: IrId,
        /// The unsupported attribute name bytes.
        attr: Vec<u8>,
    },
    /// `builtins.fetchGit` could not derive or validate the output store name.
    #[error(
        "failed to derive fetchGit store name at node {id:?} url {url:?} name {name:?}: {message}"
    )]
    FetchGitStoreName {
        /// The fetchGit argument node.
        id: IrId,
        /// The URL bytes.
        url: Vec<u8>,
        /// The rejected store name bytes.
        name: Vec<u8>,
        /// The store-name diagnostic.
        message: String,
    },
    /// `builtins.fetchGit` could not fetch, check out, or materialize its repository.
    #[error("failed to fetch git repository at node {id:?} url {url:?}: {message}")]
    FetchGit {
        /// The fetchGit argument node.
        id: IrId,
        /// The URL bytes.
        url: Vec<u8>,
        /// The fetch diagnostic.
        message: String,
    },
    /// An evaluation mode rejected `builtins.fetchGit` repository access.
    #[error("{mode:?} evaluation forbids fetchGit repository access at node {id:?} url {url:?}")]
    FetchGitAccessDenied {
        /// The fetchGit argument node.
        id: IrId,
        /// The canonical git URI bytes.
        url: Vec<u8>,
        /// The evaluation mode that denied access.
        mode: EvalMode,
    },
    /// Pure evaluation rejected an unpinned `builtins.fetchGit` request.
    #[error("{mode:?} evaluation requires a rev for fetchGit at node {id:?} url {url:?}")]
    FetchGitRevRequired {
        /// The fetchGit argument node.
        id: IrId,
        /// The URL bytes.
        url: Vec<u8>,
        /// The evaluation mode that required a revision.
        mode: EvalMode,
    },
    /// `builtins.fetchGit` materialized a tree with a different recursive SHA-256 digest.
    #[error(
        "fetchGit hash mismatch at node {id:?} url {url:?}: expected {expected:?}, got {actual:?}"
    )]
    FetchGitHashMismatch {
        /// The fetchGit argument node.
        id: IrId,
        /// The URL bytes.
        url: Vec<u8>,
        /// The expected SHA-256 digest bytes.
        expected: Vec<u8>,
        /// The actual SHA-256 digest bytes.
        actual: Vec<u8>,
    },
    /// `builtins.fetchMercurial` used an unsupported argument attribute.
    #[error("unsupported fetchMercurial argument at node {id:?}: {attr:?}")]
    UnsupportedFetchMercurialAttr {
        /// The fetchMercurial argument node.
        id: IrId,
        /// The unsupported attribute name bytes.
        attr: Vec<u8>,
    },
    /// Pure evaluation rejected an unpinned `builtins.fetchMercurial` request.
    #[error("{mode:?} evaluation requires a rev for fetchMercurial at node {id:?} url {url:?}")]
    FetchMercurialRevRequired {
        /// The fetchMercurial argument node.
        id: IrId,
        /// The URL bytes.
        url: Vec<u8>,
        /// The evaluation mode that required a revision.
        mode: EvalMode,
    },
    /// `builtins.fetchTarball` used an unsupported argument attribute.
    #[error("unsupported fetchTarball argument at node {id:?}: {attr:?}")]
    UnsupportedFetchTarballAttr {
        /// The fetchTarball argument node.
        id: IrId,
        /// The unsupported attribute name bytes.
        attr: Vec<u8>,
    },
    /// `builtins.fetchTarball` could not derive or validate the output store name.
    #[error(
        "failed to derive fetchTarball store name at node {id:?} url {url:?} name {name:?}: {message}"
    )]
    FetchTarballStoreName {
        /// The fetchTarball argument node.
        id: IrId,
        /// The URL bytes.
        url: Vec<u8>,
        /// The rejected store name bytes.
        name: Vec<u8>,
        /// The store-name diagnostic.
        message: String,
    },
    /// `builtins.fetchTarball` could not fetch, unpack, or materialize its URL.
    #[error("failed to fetch tarball at node {id:?} url {url:?}: {message}")]
    FetchTarball {
        /// The fetchTarball argument node.
        id: IrId,
        /// The URL bytes.
        url: Vec<u8>,
        /// The fetch or unpack diagnostic.
        message: String,
    },
    /// An evaluation mode rejected `builtins.fetchTarball` network access.
    #[error("{mode:?} evaluation forbids fetchTarball network access at node {id:?} url {url:?}")]
    FetchTarballAccessDenied {
        /// The fetchTarball argument node.
        id: IrId,
        /// The URL bytes.
        url: Vec<u8>,
        /// The evaluation mode that denied access.
        mode: EvalMode,
    },
    /// Pure evaluation rejected an unpinned `builtins.fetchTarball` request.
    #[error("{mode:?} evaluation requires a sha256 for fetchTarball at node {id:?} url {url:?}")]
    FetchTarballHashRequired {
        /// The fetchTarball argument node.
        id: IrId,
        /// The URL bytes.
        url: Vec<u8>,
        /// The evaluation mode that required a hash.
        mode: EvalMode,
    },
    /// `builtins.fetchTarball` unpacked bytes with a different recursive SHA-256 digest.
    #[error(
        "fetchTarball hash mismatch at node {id:?} url {url:?}: expected {expected:?}, got {actual:?}"
    )]
    FetchTarballHashMismatch {
        /// The fetchTarball argument node.
        id: IrId,
        /// The URL bytes.
        url: Vec<u8>,
        /// The expected SHA-256 digest bytes.
        expected: Vec<u8>,
        /// The actual SHA-256 digest bytes.
        actual: Vec<u8>,
    },
    /// `builtins.fetchTree` used an unsupported input attribute.
    #[error("unsupported fetchTree input attribute at node {id:?}: {attr:?}")]
    UnsupportedFetchTreeAttr {
        /// The fetchTree input node.
        id: IrId,
        /// The unsupported attribute name bytes.
        attr: Vec<u8>,
    },
    /// `builtins.fetchTree` reached a feature outside the native implementation.
    #[error("fetchTree at node {id:?} does not support {feature}")]
    UnsupportedFetchTreeFeature {
        /// The fetchTree input node.
        id: IrId,
        /// The native implementation gap.
        feature: &'static str,
    },
    /// `builtins.fetchTree` could not fetch, copy, or materialize its input.
    #[error("failed to fetch tree at node {id:?} input {input:?}: {message}")]
    FetchTree {
        /// The fetchTree input node.
        id: IrId,
        /// The input path, URL, or canonical fetcher URI bytes.
        input: Vec<u8>,
        /// The fetch diagnostic.
        message: String,
    },
    /// An evaluation mode rejected `builtins.fetchTree` input access.
    #[error("{mode:?} evaluation forbids fetchTree access at node {id:?} input {input:?}")]
    FetchTreeAccessDenied {
        /// The fetchTree input node.
        id: IrId,
        /// The input path, URL, or canonical fetcher URI bytes.
        input: Vec<u8>,
        /// The evaluation mode that denied access.
        mode: EvalMode,
    },
    /// Pure evaluation rejected an unlocked `builtins.fetchTree` input.
    #[error("{mode:?} evaluation requires a locked fetchTree input at node {id:?}: {input:?}")]
    FetchTreeLockedInputRequired {
        /// The fetchTree input node.
        id: IrId,
        /// The unlocked input path, URL, or canonical fetcher URI bytes.
        input: Vec<u8>,
        /// The evaluation mode that required a locked input.
        mode: EvalMode,
    },
    /// `builtins.fetchTree` materialized a tree with a different recursive SHA-256 digest.
    #[error(
        "fetchTree hash mismatch at node {id:?} input {input:?}: expected {expected:?}, got {actual:?}"
    )]
    FetchTreeHashMismatch {
        /// The fetchTree input node.
        id: IrId,
        /// The input path, URL, or canonical fetcher URI bytes.
        input: Vec<u8>,
        /// The expected SHA-256 digest bytes.
        expected: Vec<u8>,
        /// The actual SHA-256 digest bytes.
        actual: Vec<u8>,
    },
    /// `builtins.fetchTree` observed a lastModified value different from the lock data.
    #[error(
        "fetchTree lastModified mismatch at node {id:?} input {input:?}: expected {expected}, got {actual}"
    )]
    FetchTreeLastModifiedMismatch {
        /// The fetchTree input node.
        id: IrId,
        /// The input path, URL, or canonical fetcher URI bytes.
        input: Vec<u8>,
        /// The expected lastModified Unix timestamp.
        expected: i64,
        /// The actual lastModified Unix timestamp.
        actual: i64,
    },
    /// `builtins.fetchTree` observed a revCount value different from the lock data.
    #[error(
        "fetchTree revCount mismatch at node {id:?} input {input:?}: expected {expected}, got {actual}"
    )]
    FetchTreeRevCountMismatch {
        /// The fetchTree input node.
        id: IrId,
        /// The input path, URL, or canonical fetcher URI bytes.
        input: Vec<u8>,
        /// The expected revision count.
        expected: usize,
        /// The actual revision count.
        actual: usize,
    },
    /// A flake reference could not be parsed or rendered.
    #[error("invalid flake reference at node {id:?} input {input:?}: {message}")]
    FlakeRef {
        /// The flake-reference argument node.
        id: IrId,
        /// The rejected flake reference, type, attribute, or parameter bytes.
        input: Vec<u8>,
        /// The parser or renderer diagnostic.
        message: String,
    },
    /// `builtins.flakeRefToString` used an unsupported input attribute.
    #[error("unsupported flake reference input attribute at node {id:?}: {attr:?}")]
    UnsupportedFlakeRefAttr {
        /// The flake-reference argument node.
        id: IrId,
        /// The unsupported attribute name bytes.
        attr: Vec<u8>,
    },
    /// A flake-reference attrset contained a value with an unsupported type.
    #[error(
        "flake reference input attribute {attr:?} at node {id:?} has unsupported type {actual:?}"
    )]
    FlakeRefAttrType {
        /// The flake-reference argument node.
        id: IrId,
        /// The attribute name bytes.
        attr: Vec<u8>,
        /// The unsupported value type.
        actual: ValueTag,
    },
    /// Ambient Nix search-path access was disabled by evaluator options.
    #[error("ambient Nix search path at node {id:?} does not support {feature}")]
    UnsupportedAmbientSearchPath {
        /// The search-path-sensitive node id.
        id: IrId,
        /// The rejected search-path-sensitive feature.
        feature: &'static str,
    },
    /// Unconfigured impure builtin constants were disabled by evaluator options.
    #[error("ambient builtin constant at node {id:?} does not support {feature}")]
    UnsupportedAmbientBuiltinConstant {
        /// The builtin-sensitive node id.
        id: IrId,
        /// The rejected builtin-sensitive feature.
        feature: &'static str,
    },
    /// A Nix search-path lookup found no existing candidate.
    #[error("search path lookup at node {id:?} did not find {lookup:?}")]
    SearchPathNotFound {
        /// The search-path node or primop id.
        id: IrId,
        /// The unresolved lookup bytes.
        lookup: Vec<u8>,
        /// Whether the miss came from `<...>` rather than an explicit `findFile` list.
        ambient: bool,
    },
    /// A lowered search-path literal did not retain its `<...>` delimiters.
    #[error("invalid search-path literal at node {id:?}: {literal:?}")]
    InvalidSearchPathLiteral {
        /// The malformed search-path node id.
        id: IrId,
        /// The malformed literal bytes.
        literal: Vec<u8>,
    },
    /// A list spine buffer could not be reserved.
    #[error("failed to reserve {len} list elements at node {id:?}")]
    ListAllocationFailed {
        /// The list node id.
        id: IrId,
        /// The requested list length.
        len: usize,
    },
    /// A list length could not fit in the Nix integer type.
    #[error("list length {len} at node {id:?} does not fit in i64")]
    ListLengthOverflow {
        /// The list-valued node whose length overflowed.
        id: IrId,
        /// The overflowing list length.
        len: usize,
    },
    /// A builtin list length argument was negative.
    #[error("negative list length {length} at node {id:?}")]
    NegativeListLength {
        /// The length-valued node whose signed value was invalid.
        id: IrId,
        /// The negative length.
        length: i64,
    },
    /// `replaceStrings` received pattern and replacement lists of different lengths.
    #[error("replaceStrings at node {id:?} received {from_len} patterns but {to_len} replacements")]
    ReplaceStringsLengthMismatch {
        /// The primop node id.
        id: IrId,
        /// The number of pattern strings.
        from_len: usize,
        /// The number of replacement strings.
        to_len: usize,
    },
    /// A list primop received an empty list where it requires an element.
    #[error("{op} received an empty list at node {id:?}")]
    EmptyListPrimOp {
        /// The list-valued node that was empty.
        id: IrId,
        /// The primop that rejected the empty list.
        op: &'static str,
    },
    /// A list primop index was outside the list spine.
    #[error("list index {index} out of bounds for length {len} at node {id:?}")]
    ListIndexOutOfBounds {
        /// The index-valued node that was outside the list.
        id: IrId,
        /// The requested signed index.
        index: i64,
        /// The list spine length.
        len: usize,
    },
    /// A substring start offset was negative or overflowed the builtin offset type.
    #[error("negative substring start {start} at node {id:?}")]
    NegativeSubstringStart {
        /// The start-valued node whose offset was invalid.
        id: IrId,
        /// The effective signed 32-bit start offset.
        start: i64,
    },
    /// The active with-scope stack could not reserve another entry.
    #[error("failed to reserve {scopes} active with scopes at node {id:?}")]
    WithScopeAllocationFailed {
        /// The with-expression node id.
        id: IrId,
        /// The requested number of active with scopes.
        scopes: usize,
    },
    /// The active safepoint-root stack length overflowed.
    #[error("active safepoint root stack overflow at node {id:?}")]
    SafepointRootStackLengthOverflow {
        /// The node id that attempted to register another safepoint root.
        id: IrId,
    },
    /// The active safepoint-root stack could not reserve another entry.
    #[error("failed to reserve {roots} active safepoint roots at node {id:?}")]
    SafepointRootStackAllocationFailed {
        /// The node id that attempted to register another safepoint root.
        id: IrId,
        /// The requested number of active safepoint roots.
        roots: usize,
    },
    /// A heap-backed value was produced by the non-owning convenience API.
    #[error("heap-backed {tag:?} value at node {id:?} requires an owning evaluation result")]
    HeapValueRequiresOwner {
        /// The root node id that produced the heap value.
        id: IrId,
        /// The heap-backed value tag.
        tag: ValueTag,
    },
    /// A GC-stress boundary scan failed after evaluation produced a value.
    #[error("GC-stress boundary scan failed at node {id:?}: {source}")]
    GcStressBoundaryScan {
        /// The root node id whose completed evaluation triggered the scan.
        id: IrId,
        /// The lower-level safepoint scanner failure.
        source: TreeWalkSafepointScanError,
    },
    /// A GC-stress allocation safepoint failed while publishing a just-allocated value.
    #[error("GC-stress allocation safepoint failed at node {id:?}: {source}")]
    GcStressAllocationSafepoint {
        /// The heap-allocation node whose allocation triggered the safepoint.
        id: IrId,
        /// The lower-level tree-walk writeback failure.
        source: TreeWalkSafepointRootWritebackError,
    },
    /// A Tier-B quiescent sweep failed.
    ///
    /// Sweep failures are evaluator bugs (a stale root, a non-quiescent
    /// caller, or storage exhaustion), never user errors.
    #[error("Tier-B quiescent sweep failed: {source}")]
    GcQuiescentSweep {
        /// The lower-level root-collection or heap-sweep failure.
        source: TreeWalkGcSweepError,
    },
    /// Default-off terminal permanent publication failed.
    ///
    /// This is an evaluator invariant failure rather than a user expression
    /// error. The stage identifies the last source-untouched or roll-forward
    /// boundary reached by the transaction.
    #[error("terminal permanent publication failed at node {id:?} during {stage}: {reason}")]
    TerminalPermanentPublication {
        /// The completed root node whose heap was being compacted.
        id: IrId,
        /// The publication transaction stage that rejected the heap.
        stage: &'static str,
        /// The lower-level invariant or allocation failure.
        reason: String,
    },
    /// Automatic post-evaluation Tier-B admission failed.
    #[error("Tier-B transition admission failed at node {id:?}: {source}")]
    TierBTransitionAdmission {
        /// The root node whose completed evaluation triggered admission.
        id: IrId,
        /// The lower-level admission failure.
        source: EvalTierBTransitionAdmissionApplyError,
    },
    /// The evaluator heap failed while allocating or retrieving a value.
    #[error("heap operation failed at node {id:?}: {source}")]
    Heap {
        /// The node id associated with the heap operation.
        id: IrId,
        /// The underlying heap failure.
        source: EvalHeapError,
    },
    /// Lexical environment access failed.
    #[error("environment operation failed at node {id:?}: {source}")]
    Env {
        /// The node id associated with the environment operation.
        id: IrId,
        /// The underlying environment failure.
        source: EvalEnvError,
    },
    /// Thunk forcing failed.
    #[error("thunk force failed at node {id:?}: {source}")]
    Force {
        /// The node id associated with the force operation.
        id: IrId,
        /// The underlying force failure.
        source: ForceError,
    },
    /// Parallel thunk payload forcing failed.
    #[error("parallel thunk payload failed at node {id:?}: {source}")]
    ParallelThunkPayload {
        /// The node id associated with the parallel thunk operation.
        id: IrId,
        /// The underlying parallel payload failure.
        source: ParallelThunkPayloadError,
    },
    /// A parallel thunk claim was dropped before publishing a terminal payload.
    #[error("parallel thunk claim was dropped at node {id:?}")]
    ParallelThunkClaimDropped {
        /// The thunk allocation node whose parallel claim was abandoned.
        id: IrId,
    },
    /// A nested function call exceeded the configured evaluator call-depth limit.
    #[error("stack overflow; max-call-depth exceeded")]
    MaxCallDepthExceeded {
        /// The application node id being entered.
        id: IrId,
        /// The active call depth when the limit rejected the call.
        depth: usize,
        /// The configured `max-call-depth` value.
        max: usize,
    },
    /// Evaluation exceeded the configured deterministic IR-node step budget.
    #[error("evaluation step budget exceeded ({steps} of {max})")]
    MaxEvalStepsExceeded {
        /// The node rejected after exhausting the budget.
        id: IrId,
        /// Steps already consumed.
        steps: u64,
        /// Configured step ceiling.
        max: u64,
    },
    /// Evaluation exceeded its configured in-engine wall-clock deadline.
    #[error("evaluation time budget exceeded ({max:?})")]
    MaxEvalDurationExceeded {
        /// The node active when the deadline expired.
        id: IrId,
        /// Configured duration ceiling.
        max: std::time::Duration,
    },
    /// Evaluation crossed the configured hard resident-memory ceiling.
    #[error("evaluation heap memory budget exceeded ({resident_bytes} > {max_bytes} bytes)")]
    HeapMemoryBudgetExceeded {
        /// The node active when memory pressure was observed.
        id: IrId,
        /// Observed resident bytes.
        resident_bytes: usize,
        /// Configured hard ceiling.
        max_bytes: usize,
    },
    /// A Nix string operation failed.
    #[error("string operation failed at node {id:?}: {source}")]
    String {
        /// The node id associated with the string operation.
        id: IrId,
        /// The underlying string failure.
        source: NixStringError,
    },
    /// A primop received a context-bearing string where C++ Nix forbids one.
    #[error("{op} does not allow string context at node {id:?}")]
    StringContextNotAllowed {
        /// The node id associated with the rejected string.
        id: IrId,
        /// The primop rejecting the string context.
        op: &'static str,
    },
    /// A filesystem-reading builtin reached IFD without a realizer callback.
    #[error("{op} at node {id:?} requires import-from-derivation: {detail}")]
    UnsupportedImportFromDerivation {
        /// The argument node whose path triggered IFD.
        id: IrId,
        /// The filesystem-reading builtin that triggered the demand.
        op: &'static str,
        /// The IFD path and derivation context.
        detail: Box<IfdErrorDetail>,
    },
    /// A configured IFD realizer failed.
    #[error("{op} IFD realization failed at node {id:?}: {detail}")]
    ImportFromDerivation {
        /// The argument node whose path triggered IFD.
        id: IrId,
        /// The filesystem-reading builtin that triggered the demand.
        op: &'static str,
        /// The IFD path, derivation context, and realizer diagnostic.
        detail: Box<IfdErrorDetail>,
    },
    /// A context-transforming primop required exactly one string-context element.
    #[error("string context at node {id:?} must have exactly one element, but has {len}")]
    StringContextElementCount {
        /// The string-valued node whose context had the wrong cardinality.
        id: IrId,
        /// The observed context element count.
        len: usize,
    },
    /// A reflected string-context attrset key was not a valid store path.
    #[error("string context key at node {id:?} is not a store path: {path:?}")]
    StringContextKeyNotStorePath {
        /// The reflected context attrset node.
        id: IrId,
        /// The rejected context key bytes.
        path: Vec<u8>,
    },
    /// `builtins.storePath` received a path outside the configured store.
    #[error("path at node {id:?} is not in the Nix store: {path:?}")]
    StorePathNotInStore {
        /// The argument node whose normalized path was rejected.
        id: IrId,
        /// The rejected normalized path bytes.
        path: Vec<u8>,
    },
    /// `derivationStrict` needed UTF-8 for a field stored in nix-compat.
    #[error("derivationStrict {field} at node {id:?} is not UTF-8: {bytes:?}: {message}")]
    DerivationStringUtf8 {
        /// The derivation boundary node id.
        id: IrId,
        /// The derivation field being converted.
        field: &'static str,
        /// The rejected bytes.
        bytes: Vec<u8>,
        /// The UTF-8 diagnostic.
        message: String,
    },
    /// `derivationStrict` could not parse or construct a store path.
    #[error("derivationStrict path at node {id:?} is invalid: {path:?}: {message}")]
    DerivationPath {
        /// The derivation boundary node id.
        id: IrId,
        /// The rejected or malformed path.
        path: Vec<u8>,
        /// The path diagnostic.
        message: String,
    },
    /// `derivationStrict` failed while constructing the derivation model.
    #[error("derivationStrict failed at node {id:?}: {message}")]
    DerivationStrict {
        /// The derivation boundary node id.
        id: IrId,
        /// The derivation diagnostic.
        message: String,
    },
    /// A context-transforming primop required a derivation path context.
    #[error("string context path at node {id:?} is not a derivation: {path:?}")]
    StringContextPathNotDerivation {
        /// The string-valued node whose context path was rejected.
        id: IrId,
        /// The rejected context path bytes.
        path: Vec<u8>,
    },
    /// A context-transforming primop rejected a single derivation output context.
    #[error("string context at node {id:?} names derivation output {output:?}")]
    StringContextDerivationOutput {
        /// The string-valued node whose context output was rejected.
        id: IrId,
        /// The rejected output name bytes.
        output: Vec<u8>,
    },
    /// `builtins.toFile` received contents that reference a derivation output.
    #[error(
        "toFile contents at node {id:?} for {name:?} may not reference derivation context {reference:?} ({kind:?}, output {output:?})"
    )]
    ToFileDerivationReference {
        /// The string-valued contents node whose context was rejected.
        id: IrId,
        /// The requested store path name.
        name: Vec<u8>,
        /// The derivation path referenced by the contents context.
        reference: Vec<u8>,
        /// The rejected context kind.
        kind: ContextKind,
        /// The rejected output name, when the context names a single output.
        output: Option<Vec<u8>>,
    },
    /// `builtins.toFile` could not construct a text store path.
    #[error("toFile path at node {id:?} for {name:?} is invalid: {message}")]
    ToFilePath {
        /// The `toFile` call node id.
        id: IrId,
        /// The requested store path name.
        name: Vec<u8>,
        /// The path construction diagnostic.
        message: String,
    },
    /// A JSON string failed to parse.
    #[error("JSON parse failed at node {id:?}: {message}")]
    JsonParse {
        /// The string-valued node that was parsed as JSON.
        id: IrId,
        /// The parser diagnostic.
        message: String,
    },
    /// A parsed JSON number did not fit any supported evaluator number shape.
    #[error("unsupported JSON number at node {id:?}")]
    JsonNumberUnsupported {
        /// The string-valued node that produced the unsupported number.
        id: IrId,
    },
    /// A value cannot be represented as JSON.
    #[error("cannot convert {actual:?} at node {id:?} to JSON")]
    JsonUnsupportedValue {
        /// The value node that could not be converted.
        id: IrId,
        /// The unsupported runtime tag.
        actual: ValueTag,
    },
    /// A Nix string cannot be represented as JSON UTF-8.
    #[error("cannot convert non-UTF-8 string at node {id:?} to JSON: {bytes:?}: {message}")]
    JsonInvalidUtf8 {
        /// The string-valued node that could not be converted.
        id: IrId,
        /// The rejected raw bytes.
        bytes: Vec<u8>,
        /// The UTF-8 diagnostic.
        message: String,
    },
    /// A TOML string failed to parse.
    #[error("TOML parse failed at node {id:?}: {message}")]
    TomlParse {
        /// The string-valued node that was parsed as TOML.
        id: IrId,
        /// The parser diagnostic.
        message: String,
    },
    /// A parsed TOML value has no C++ Nix `fromTOML` representation.
    #[error("unsupported TOML {kind} at node {id:?}")]
    TomlUnsupportedValue {
        /// The string-valued node that produced the unsupported value.
        id: IrId,
        /// The unsupported TOML value category.
        kind: &'static str,
    },
    /// A regular expression failed to compile.
    #[error("regular expression at node {id:?} failed to compile: {message}")]
    RegexCompile {
        /// The string-valued node that was parsed as a regular expression.
        id: IrId,
        /// The rejected regular expression bytes.
        pattern: Vec<u8>,
        /// The parser diagnostic.
        message: String,
    },
    /// A hash primop received an unsupported algorithm name.
    #[error("unknown hash algorithm at node {id:?}: {algorithm:?}")]
    UnknownHashAlgorithm {
        /// The algorithm string node.
        id: IrId,
        /// The unsupported algorithm bytes.
        algorithm: Vec<u8>,
    },
    /// `builtins.convertHash` received an unsupported output format.
    #[error("unknown hash format at node {id:?}: {format:?}")]
    UnknownHashFormat {
        /// The format string node.
        id: IrId,
        /// The unsupported output format bytes.
        format: Vec<u8>,
    },
    /// `builtins.convertHash` received an untyped hash without `hashAlgo`.
    #[error("hash at node {id:?} does not include an algorithm: {hash:?}")]
    HashAlgorithmRequired {
        /// The convertHash argument node.
        id: IrId,
        /// The hash bytes that need an explicit algorithm.
        hash: Vec<u8>,
    },
    /// `builtins.convertHash` received a typed hash that disagreed with `hashAlgo`.
    #[error("hash at node {id:?} does not match expected algorithm {expected:?}: {hash:?}")]
    HashAlgorithmMismatch {
        /// The convertHash argument node.
        id: IrId,
        /// The typed hash bytes.
        hash: Vec<u8>,
        /// The expected algorithm bytes.
        expected: Vec<u8>,
    },
    /// `builtins.convertHash` received a hash with the wrong digest length.
    #[error("hash at node {id:?} has the wrong length for {algorithm:?}: {hash:?}")]
    HashWrongLength {
        /// The convertHash argument node.
        id: IrId,
        /// The hash bytes with the wrong length.
        hash: Vec<u8>,
        /// The algorithm whose digest length was expected.
        algorithm: Vec<u8>,
    },
    /// `builtins.convertHash` received an invalid base16 hash.
    #[error("invalid base16 hash at node {id:?}: {hash:?}")]
    InvalidBase16Hash {
        /// The convertHash argument node.
        id: IrId,
        /// The rejected hash bytes.
        hash: Vec<u8>,
    },
    /// `builtins.convertHash` received an invalid Nix base32 hash.
    #[error("invalid nix32 hash at node {id:?}: {hash:?}")]
    InvalidNix32Hash {
        /// The convertHash argument node.
        id: IrId,
        /// The rejected hash bytes.
        hash: Vec<u8>,
    },
    /// `builtins.convertHash` received an invalid base64 hash.
    #[error("invalid base64 hash at node {id:?}: {hash:?}")]
    InvalidBase64Hash {
        /// The convertHash argument node.
        id: IrId,
        /// The rejected hash bytes.
        hash: Vec<u8>,
    },
    /// `builtins.convertHash` received an invalid SRI hash.
    #[error("invalid SRI hash at node {id:?}: {hash:?}")]
    InvalidSriHash {
        /// The convertHash argument node.
        id: IrId,
        /// The rejected hash bytes.
        hash: Vec<u8>,
    },
    /// An internal string-context element violated its shape invariant.
    #[error("invalid string context at node {id:?}")]
    InvalidStringContext {
        /// The node id associated with the malformed context.
        id: IrId,
    },
    /// A Nix list operation failed.
    #[error("list operation failed at node {id:?}: {source}")]
    List {
        /// The node id associated with the list operation.
        id: IrId,
        /// The underlying list failure.
        source: NixListError,
    },
    /// A flat attribute-set operation failed.
    #[error("attribute-set operation failed at node {id:?}: {source}")]
    Attr {
        /// The node id associated with the attrset operation.
        id: IrId,
        /// The underlying attrset failure.
        source: AttrError,
    },
    /// A representation-dispatching attribute selection failed.
    #[error("attribute select_slow failed at node {id:?}: {source}")]
    AttrSelect {
        /// The select node id.
        id: IrId,
        /// The underlying representation-dispatch failure.
        source: AttrSelectError,
    },
    /// A flat select-cache operation failed.
    #[error("flat select cache failed at node {id:?}: {source}")]
    FlatSelectCache {
        /// The select node id.
        id: IrId,
        /// The underlying flat select-cache failure.
        source: FlatSelectError,
    },
    /// A hidden-class shape operation failed.
    #[error("shape operation failed at node {id:?}: {source}")]
    Shape {
        /// The node id associated with the shape operation.
        id: IrId,
        /// The underlying shape failure.
        source: ShapeError,
    },
    /// A shaped attribute-set operation failed.
    #[error("shaped attribute-set operation failed at node {id:?}: {source}")]
    ShapedAttr {
        /// The node id associated with the shaped attrset operation.
        id: IrId,
        /// The underlying shaped attrset failure.
        source: ShapedAttrsError,
    },
    /// A shaped select-cache operation failed.
    #[error("shaped select cache failed at node {id:?}: {source}")]
    ShapedSelectCache {
        /// The select node id.
        id: IrId,
        /// The underlying shaped select-cache failure.
        source: ShapedSelectError,
    },
    /// A record select-cache operation failed.
    #[error("record select cache failed at node {id:?}: {source}")]
    RecordSelectCache {
        /// The select node id.
        id: IrId,
        /// The underlying record select-cache failure.
        source: RecordSelectError,
    },
    /// A HAMT attribute-set operation failed.
    #[error("HAMT attribute-set operation failed at node {id:?}: {source}")]
    HamtAttr {
        /// The node id associated with the HAMT attrset operation.
        id: IrId,
        /// The underlying HAMT failure.
        source: HamtError,
    },
    /// A HAMT select-cache operation failed.
    #[error("HAMT select cache failed at node {id:?}: {source}")]
    HamtSelectCache {
        /// The select node id.
        id: IrId,
        /// The underlying HAMT select-cache failure.
        source: HamtSelectError,
    },
    /// A scalar operation received a value of the wrong Nix type.
    #[error("type error at node {id:?}: expected {expected}, got {actual:?}")]
    Type {
        /// The node id associated with the type check.
        id: IrId,
        /// The expected evaluator value category.
        expected: &'static str,
        /// The actual runtime value tag.
        actual: ValueTag,
    },
    /// An attribute selection found no binding and had no default.
    #[error("missing attribute {symbol:?} at node {id:?}")]
    MissingAttribute {
        /// The select node id.
        id: IrId,
        /// The missing static attribute symbol.
        symbol: Symbol,
    },
    /// A formal-set lambda argument missed a required attribute.
    #[error("missing required formal attribute {symbol:?} at node {id:?}")]
    MissingFormalAttribute {
        /// The application node id.
        id: IrId,
        /// The missing formal attribute symbol.
        symbol: Symbol,
    },
    /// A formal-set lambda argument carried an unexpected attribute.
    #[error("unexpected formal attribute {symbol:?} at node {id:?}")]
    UnexpectedFormalAttribute {
        /// The application node id.
        id: IrId,
        /// The unexpected argument attribute symbol.
        symbol: Symbol,
    },
    /// A dynamic with lookup found no attribute and no supported global fallback.
    #[error("unresolved with variable {symbol:?} at node {id:?}")]
    UnresolvedWithVar {
        /// The with-variable node id.
        id: IrId,
        /// The missing symbol.
        symbol: Symbol,
    },
    /// A bare global lookup found no supported top-level binding.
    #[error("unresolved global variable {symbol:?} at node {id:?}")]
    UnresolvedGlobalVar {
        /// The global-variable node id.
        id: IrId,
        /// The missing symbol.
        symbol: Symbol,
    },
    /// A boolean-tagged value had an invalid payload.
    ///
    /// Current safe constructors cannot create this state; the check is a
    /// defensive guard for later runtime fast paths and heap-backed values.
    #[error("invalid boolean payload {payload} at node {id:?}")]
    InvalidBoolPayload {
        /// The node id associated with the invalid payload.
        id: IrId,
        /// The invalid boolean payload.
        payload: u64,
    },
    /// A primitive operation exists in IR but is outside this evaluator slice.
    #[error("unsupported tree-walk primop symbol {symbol:?} at {id:?}")]
    UnsupportedPrimOp {
        /// The primop node id.
        id: IrId,
        /// The unsupported primop symbol.
        symbol: Symbol,
    },
    /// A dialect operation exists in IR but is outside this evaluator slice.
    #[error("unsupported tree-walk dialect operation {op:?} at {id:?}")]
    UnsupportedDialectOp {
        /// The primop node id.
        id: IrId,
        /// The unsupported dialect operation key.
        op: IrDialectOp,
    },
    /// A `builtins` attribute exists but is outside this evaluator slice.
    #[error("unsupported builtins attribute {symbol:?} at node {id:?}")]
    UnsupportedBuiltinAttr {
        /// The select node id.
        id: IrId,
        /// The unsupported builtin attribute symbol.
        symbol: Symbol,
    },
    /// A primitive operation carries the wrong number of lowered arguments.
    #[error("invalid primop arity at {id:?}: expected {expected}, got {actual}")]
    InvalidPrimOpArity {
        /// The primop node id.
        id: IrId,
        /// The primop symbol whose argument list is malformed.
        symbol: Symbol,
        /// The expected number of arguments.
        expected: usize,
        /// The actual number of arguments in the IR child slice.
        actual: usize,
    },
    /// Structural equality for this runtime value type is outside this evaluator slice.
    #[error("unsupported tree-walk equality between {left:?} and {right:?} at {id:?}")]
    UnsupportedEqualityType {
        /// The equality operator node id.
        id: IrId,
        /// The left operand's runtime value tag.
        left: ValueTag,
        /// The right operand's runtime value tag.
        right: ValueTag,
    },
    /// A checked integer arithmetic operation overflowed.
    #[error("arithmetic overflow for {op:?} at node {id:?}")]
    ArithmeticOverflow {
        /// The node id of the overflowing operator.
        id: IrId,
        /// The overflowing arithmetic operator.
        op: ArithmeticOp,
    },
    /// A numeric division operation used a zero divisor.
    #[error("division by zero at node {id:?}")]
    DivisionByZero {
        /// The division node id.
        id: IrId,
    },
    /// An `assert` condition evaluated to `false`.
    #[error("assertion failed at node {id:?}")]
    AssertionFailed {
        /// The failed assertion node id.
        id: IrId,
    },
    /// `builtins.throw` raised a catchable evaluation error.
    #[error("thrown error at node {id:?}: {message:?}")]
    Thrown {
        /// The message argument node.
        id: IrId,
        /// The coerced message bytes.
        message: Vec<u8>,
    },
    /// `builtins.abort` raised a fatal evaluation error.
    #[error("evaluation aborted at node {id:?}: {message:?}")]
    Aborted {
        /// The message argument node.
        id: IrId,
        /// The coerced message bytes.
        message: Vec<u8>,
    },
    /// `builtins.warn` aborted after emitting a warning.
    #[error("warning aborted evaluation at node {id:?}: {message:?}")]
    WarningAborted {
        /// The warning message argument node.
        id: IrId,
        /// The warning message bytes.
        message: Vec<u8>,
    },
    /// The node kind is not directly evaluable.
    #[error("invalid tree-walk node {kind:?} at {id:?}: node kind is not directly evaluable")]
    InvalidNodeKind {
        /// The invalid node id.
        id: IrId,
        /// The invalid node kind.
        kind: IrKind,
    },
}
