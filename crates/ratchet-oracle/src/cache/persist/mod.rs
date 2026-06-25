//! Versioned persistent-cache layout.
//!
//! The full Phase-2 storage engine will fill `nodes/`, `values/`, and `files/`
//! with verifying traces and content-addressed artifacts. This module owns the
//! on-disk layout contract and schema-version guard those stores share.

use std::fs::{self, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use thiserror::Error;

use super::parse::{
    PARSE_CACHE_SCHEMA_VERSION, ParseArtifactBundle, ParseCacheEntry, ParseCacheError,
    ParseCacheKey, ParseFileKey,
};
use super::{
    DurableBlake3Hash, MaterializationDecision, MaterializationReuse, MaterializationSignals,
};

/// The persistent eval-cache schema format marker.
pub const PERSIST_CACHE_FORMAT: &str = "aos-nix-eval-cache";
/// The persistent eval-cache schema version.
pub const PERSIST_CACHE_SCHEMA_VERSION: u32 = 1;
/// The fixed magic bytes at the start of every immutable blob packfile.
pub const PERSIST_BLOB_PACK_MAGIC: [u8; 16] = *b"AOS-NIX-BLOBPACK";
/// The immutable blob packfile format version.
pub const PERSIST_BLOB_PACK_VERSION: u32 = 1;
/// The encoded length of an immutable blob packfile header.
pub const PERSIST_BLOB_PACK_HEADER_LEN: usize = 24;
/// The encoded length of an immutable blob record header.
pub const PERSIST_BLOB_RECORD_HEADER_LEN: usize = 40;
/// The encoded length of a hash-to-offset index key.
pub const PERSIST_BLOB_INDEX_KEY_LEN: usize = 33;
/// The encoded length of a hash-to-offset index value.
pub const PERSIST_BLOB_INDEX_VALUE_LEN: usize = 16;
/// The encoded length of a complete hash-to-offset index entry.
pub const PERSIST_BLOB_INDEX_ENTRY_LEN: usize =
    PERSIST_BLOB_INDEX_KEY_LEN + PERSIST_BLOB_INDEX_VALUE_LEN;
/// The encoded length of a file-artifact index key.
pub const PERSIST_FILE_ARTIFACT_INDEX_KEY_LEN: usize = 33;
/// The encoded length of a file-artifact index value.
pub const PERSIST_FILE_ARTIFACT_INDEX_VALUE_LEN: usize =
    PERSIST_BLOB_INDEX_KEY_LEN + PERSIST_BLOB_INDEX_VALUE_LEN;
/// The encoded length of a complete file-artifact index entry.
pub const PERSIST_FILE_ARTIFACT_INDEX_ENTRY_LEN: usize =
    PERSIST_FILE_ARTIFACT_INDEX_KEY_LEN + PERSIST_FILE_ARTIFACT_INDEX_VALUE_LEN;
/// The encoded length of durable materialization reuse metadata.
pub const PERSIST_MATERIALIZATION_REUSE_LEN: usize = 16;

static SCHEMA_WRITE_ID: AtomicU64 = AtomicU64::new(0);
const PERSIST_FILE_ARTIFACT_INDEX_TAG: u8 = 3;
const PERSIST_FILE_ARTIFACT_KEY_PERSONALIZATION: &[u8] = b"aos-nix-persist-file-artifact-key-v1";

mod cache;
mod disk;
mod error;
mod format;
mod layout;
mod materialization;
mod pack;

pub use cache::PersistCache;
pub use error::{
    PersistBlobIndexError, PersistBlobIndexedReadError, PersistBlobIndexedWriteError,
    PersistBlobPackError, PersistError, PersistFileArtifactHydrationError,
    PersistFileArtifactIndexError, PersistFileArtifactIndexedHydrationError,
    PersistFileArtifactIndexedWriteError, PersistPackFormatError,
    PersistParseArtifactMaterializationError,
};
pub use format::{
    PersistBlobIndex, PersistBlobIndexEntry, PersistBlobKey, PersistBlobLocation,
    PersistBlobPackHeader, PersistBlobRecordHeader, PersistBlobStore, PersistFileArtifactIndex,
    PersistFileArtifactIndexEntry, PersistFileArtifactIndexValue, PersistFileArtifactKey,
};
pub use layout::PersistLayout;
pub use materialization::{PersistFileArtifactMaterialization, PersistMaterialization};
pub use pack::PersistBlobPack;

// The `io` helpers are `persist`-internal; re-import them here so this module
// and sibling modules can name them through `use super::*`.
use disk::*;

#[cfg(test)]
mod tests;
