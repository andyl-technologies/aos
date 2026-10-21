//! Owns fresh-bucket evidence for administrative host enrollment.
//!
//! Native creation, activation and retained exclusion must precede enrollment.
//! Existing files or decoded metadata do not establish an original creator event.
//! The fresh-only factory returns a single-use physical observation, not a
//! writable bucket. Administrative claim persistence, project assignment and
//! final host custody remain the consuming native helper's responsibilities.

#[cfg(unix)]
pub use crate::store::native_publication_effects::initialization_inputs::fresh::enrollment::{
    NativeInitialBucketEnrollment, NativeInitialDirectory, NativeInitialFile,
};

#[cfg(unix)]
use super::{BucketBinding, FileBucketConfig, files, publication};
#[cfg(unix)]
use crate::store::{
    Clock, LocalFs, NativePublicationInitializationOutcome, StoreErrorKind, StoreFailure,
};

/// Creates and validates a fresh bucket for first administrative enrollment.
///
/// Only the actual successful native absent-root creator can return this
/// receipt. Activation, capability probes and final exact genesis checks retain
/// that creator's original exclusion; no second flock or writer is opened.
/// Existing roots, portable copies and interrupted prior creation refuse.
///
/// The returned noncloneable receipt retains original directories, coordination
/// and all final regular-file descriptors/preimages. A native administrative
/// consumer takes it by value and independently rechecks its observations before
/// first durable global claims or setters. This function performs no host quota,
/// enrollment ledger, custody change or general Original-authority opening.
///
/// # Errors
/// Refuses unsupported configuration, existing roots, unavailable native creation,
/// changed creator inputs, extra or unsafe namespace entries, incomplete genesis,
/// failed native probes and actual I/O or durability failures. Tokio builds also
/// require an active runtime for the final owned physical inspection worker.
/// Non-Linux targets return unsupported before any creator effect.
#[cfg(unix)]
pub async fn create_initial_bucket<F, C>(
    config: FileBucketConfig,
    fs: &F,
    clock: &C,
) -> Result<NativeInitialBucketEnrollment, StoreFailure>
where
    F: LocalFs + BucketBinding,
    C: Clock + BucketBinding,
{
    use terrane_format::{bucket::StoreProfile, chunking::ChunkProfile};

    // Final retained-inode reopening uses Linux O_PATH and genuine procfs.
    // Refuse other targets before creating a root or protected registration.
    if !cfg!(target_os = "linux") {
        return Err(StoreFailure::new(StoreErrorKind::Unsupported));
    }
    if config.chunk_profile_name != "cdc-1m"
        || config.chunk_profile != ChunkProfile::cdc_1m(config.chunk_profile.seed())
    {
        return Err(files::malformed());
    }
    let protected = config
        .publication_control
        .as_ref()
        .ok_or_else(files::malformed)?;
    let (owner, control) = publication::configured_location(&config.root, protected)?;
    let profile = StoreProfile {
        identity: "terrane-v1".into(),
        algorithm: "blake3".into(),
        chunk: config.chunk_profile_name,
        seed: config.chunk_profile.seed(),
    };
    let timestamp = clock
        .now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map_err(|_| files::malformed())?
        .as_secs();
    let request = || {
        crate::store::native_initialization_request(
            &config.root,
            &control,
            owner,
            profile.clone(),
            timestamp,
        )
    };
    let expected = request()?;
    match fs.initialize_publication(request()?).await? {
        NativePublicationInitializationOutcome::Fresh(receipt) => {
            crate::store::native_publication_effects::initialization_inputs::fresh::enrollment::activate(
                fs, *receipt, expected,
            ).await
        }
        NativePublicationInitializationOutcome::Existing => Err(StoreFailure::new(StoreErrorKind::Unsupported)),
    }
}
