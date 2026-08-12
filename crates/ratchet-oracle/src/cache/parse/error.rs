//! The [`ParseCacheError`] type covering parse-cache and file-memoization failures.

use super::*;

/// A parse-cache or file-memoization failure.
#[derive(Debug, Error)]
pub enum ParseCacheError {
    /// Source bytes could not be parsed.
    #[error("failed to parse source for parse cache")]
    Parse {
        /// The parser failure.
        source: ParseError,
    },
    /// A parsed AST could not be scope-resolved.
    #[error("failed to resolve source for parse cache")]
    Scope {
        /// The scope-resolution failure.
        source: ScopeError,
    },
    /// A scope-resolved artifact could not be lowered to IR.
    #[error("failed to lower source for parse cache")]
    LowerIr {
        /// The IR lowering failure.
        source: IrError,
    },
    /// A lowered IR artifact could not be simplified.
    #[error("failed to simplify lowered IR for parse cache")]
    Simplify {
        /// The simplifier failure.
        source: SimplifyError,
    },
    /// A source path could not be canonicalized for file memoization.
    #[error("failed to canonicalize source path {path:?}")]
    CanonicalizeSource {
        /// The requested source path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// A canonicalized source file could not be read for file memoization.
    #[error("failed to read source file {path:?}")]
    ReadSource {
        /// The canonical source path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The cache entry directory could not be created.
    #[error("failed to create parse-cache directory {path:?}")]
    CreateDir {
        /// The directory path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The diagnostic metadata file could not be written.
    #[error("failed to write parse-cache metadata {path:?}")]
    WriteMeta {
        /// The metadata file path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// A binary cache artifact could not be written.
    #[error("failed to write parse-cache artifact {path:?}")]
    WriteArtifact {
        /// The artifact file path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// A binary cache artifact could not be read.
    #[error("failed to read parse-cache artifact {path:?}")]
    ReadArtifact {
        /// The artifact file path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// A binary cache artifact could not be decoded.
    #[error("failed to decode parse-cache artifact {path:?}: {message}")]
    DecodeArtifact {
        /// The artifact file path.
        path: PathBuf,
        /// The decode failure.
        message: String,
    },
    /// A refreshed analysis fact sidecar does not match its cache entry.
    #[error("invalid parse-cache fact sidecar update {path:?}: {message}")]
    InvalidFactSidecarUpdate {
        /// The fact sidecar path.
        path: PathBuf,
        /// The validation failure.
        message: String,
    },
    /// A raw parse-cache artifact bundle could not be decoded.
    #[error("failed to decode parse-cache artifact bundle: {message}")]
    DecodeArtifactBundle {
        /// The decode failure.
        message: String,
    },
    /// Parse-cache diagnostic metadata could not be decoded.
    #[error("failed to decode parse-cache metadata: {message}")]
    DecodeMeta {
        /// The decode failure.
        message: String,
    },
    /// A resolved artifact could not be encoded.
    #[error("failed to encode parse-cache artifact: {0}")]
    EncodeArtifact(String),
}

/// A failure while refreshing parse-cache analysis facts.
#[derive(Debug, Error)]
pub enum ParseFactRefreshError {
    /// The analysis pipeline rejected the lowered IR.
    #[error("failed to refresh parse-cache IR facts")]
    Analyze {
        /// The analysis failure.
        source: IrAnalysisError,
    },
    /// A parse-cache operation failed before or during fact refresh.
    #[error(transparent)]
    Cache(#[from] ParseCacheError),
}
