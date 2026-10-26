//! Reopens a read-only native repository using public trust and an explicit Read.
//!
//! Signing seeds and the instance token are never loaded. The existing protected
//! registration, publication and Original records remain necessary, and the
//! caller's startup capability must independently authorize the selected head.

use std::collections::BTreeSet;

use terrane_format::{auth::IssuerKey, chunking::ChunkProfile};

use super::{local_coordinator, validate_bucket_owner, validate_local_reference, validate_policy};
use crate::{
    bucket::{BucketBinding, FileBucket, FileBucketConfig, FileBucketPublicationConfig},
    repository::{
        Error, LocalRepositoryLocation, LocalRepositoryPolicy, MetadataValidator, Repository,
    },
    store::{Clock, LocalFs},
};

/// Supplies independently configured public trust for native read-only reopening.
pub struct LocalReaderIdentity {
    /// Trusted issuer rotation keys, including configured retirement bounds.
    ///
    /// The nonempty keyring must contain distinct issuer/key identifiers and
    /// match the installed protected Guard configuration.
    pub issuer_keys: Vec<IssuerKey>,
    /// Expected owner of the original bucket and protected authority records.
    pub owner_uid: u32,
}

impl<F, C> Repository<FileBucket<F, C, MetadataValidator>, C, F>
where
    F: LocalFs + BucketBinding + Clone + Sync + 'static,
    C: Clock + BucketBinding + Clone + Sync + 'static,
    FileBucket<F, C, MetadataValidator>: Sync,
{
    /// Reopens original read-only storage with public keys and a startup Read.
    ///
    /// The explicit token must authorize the configured reference's whole root
    /// through the ordinary current Guard. It is used for that startup check;
    /// each subsequent operation must supply its own current capability.
    /// This returns no signing authority, authoring retention, audit binding or
    /// collection binding. Mutable operations remain refused even on writable
    /// backing. No missing state is initialized, probed with writes or repaired.
    ///
    /// Avoiding signing-file reads does not establish process confinement. The
    /// launcher must independently deny the serving role access to those files.
    ///
    /// # Errors
    /// Rejects empty or ambiguous public trust, unsafe paths or ownership,
    /// invalid policy or references, incompatible publication state, failed
    /// Original checks and a denied, expired or invalid startup capability.
    pub async fn open_local_reader(
        location: &LocalRepositoryLocation,
        identity: &LocalReaderIdentity,
        policy: LocalRepositoryPolicy,
        reference: &str,
        token: &[u8],
        fs: F,
        clock: C,
    ) -> Result<Self, Error> {
        if identity.issuer_keys.is_empty() || identity.owner_uid == u32::MAX {
            return Err(Error::Denied);
        }
        let mut names = BTreeSet::new();
        for key in &identity.issuer_keys {
            if key.issuer.is_empty()
                || key.key_id.is_empty()
                || !names.insert((key.issuer.as_str(), key.key_id.as_str()))
            {
                return Err(Error::Denied);
            }
        }
        validate_policy(&policy)?;
        validate_local_reference(reference)?;
        crate::repository::local_authority::validate_maintenance_location(
            &fs,
            &location.bucket,
            &location.authority,
            identity.owner_uid,
        )
        .await?;
        validate_bucket_owner(&fs, &location.bucket, identity.owner_uid).await?;

        let control = FileBucketPublicationConfig {
            operator_uid: identity.owner_uid,
            control: None,
        };
        let registered =
            crate::bucket::publication::registered_profile(&fs, &location.bucket, &control).await?;
        let profile = ChunkProfile::cdc_1m(registered.seed);
        let bucket = FileBucket::open_existing_read_only(
            FileBucketConfig {
                root: location.bucket.clone(),
                chunk_profile_name: "cdc-1m".to_owned(),
                chunk_profile: profile.clone(),
                locality: policy.locality.clone(),
                publication_control: Some(control),
            },
            fs.clone(),
            clock.clone(),
            MetadataValidator::new(profile.clone()),
        )
        .await?;
        let (coordinator, namespace) = local_coordinator(
            location,
            &identity.issuer_keys,
            policy,
            profile,
            fs,
            clock,
            bucket,
        );
        let repository = Self::reopen_native_retention(
            coordinator,
            &namespace,
            &location.authority,
            identity.owner_uid,
        )
        .await?;
        repository
            .coordinator
            .guard()
            .read_snapshot(reference, token, b"/", "sdk")
            .await?;
        Ok(repository)
    }
}
