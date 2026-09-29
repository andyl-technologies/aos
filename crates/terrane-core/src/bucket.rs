//! Owns registered bucket keys and canonical durable bucket records.
//!
//! Filesystem and object-store backends share these relative keys and formats.
//! Backend-private exclusion and temporary files are never authoritative keys.

mod keys;
mod records;

pub use keys::{BucketKey, KeyError, Mutability};
pub use records::{
    BucketCapabilities, GenerationManifest, GenerationShard, PackInventoryEntry, RecordError,
    StoreProfile, Tombstone,
};
