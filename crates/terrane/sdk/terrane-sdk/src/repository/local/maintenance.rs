//! Reopens original native maintenance bindings with public verification inputs.
//!
//! Protected registration, immutable genesis and retained original history still
//! select the actual backend. No issuer seed, terminal seed or capability token
//! is read, returned or synthesized. A collector must subsequently acquire its
//! genuine singleton lease and authenticate the complete current root inventory.

use super::{
    ChunkProfile, Clock, Error, FileBucket, FileBucketPublicationConfig, LocalFs,
    LocalRepositoryLocation, LocalRepositoryPolicy, MetadataValidator, Repository,
    open_local_parts, validate_bucket_owner, validate_policy,
};
use crate::bucket::BucketBinding;
use terrane_format::auth::IssuerKey;

/// Supplies public trust and expected ownership for native maintenance reopening.
pub struct LocalMaintenanceIdentity {
    /// Trusted verification key, including its configured retirement bound.
    pub issuer: IssuerKey,
    /// Expected Unix owner of the original bucket and retained authority records.
    pub owner_uid: u32,
}

impl<F, C> Repository<FileBucket<F, C, MetadataValidator>, C, F>
where
    F: LocalFs + BucketBinding + Clone + Sync + 'static,
    C: Clock + BucketBinding + Clone + Sync + 'static,
    FileBucket<F, C, MetadataValidator>: Sync,
{
    /// Reopens protected native maintenance state without loading credentials.
    ///
    /// The caller supplies trusted public issuer configuration independently of
    /// stored token claims. Existing registration, immutable genesis, physical
    /// association and retained historical configuration receive the ordinary
    /// native reopen checks. No missing state is initialized or repaired.
    ///
    /// This grants neither a repository Read nor collector ownership. Collection
    /// separately authenticates all selected roots under its actual whole lease;
    /// ordinary repository operations still require their own fresh capability.
    /// The process launcher must also deny filesystem access to signing files:
    /// avoiding their use here does not establish role confinement.
    ///
    /// # Errors
    /// Rejects missing issuer identity, unsafe paths or ownership, invalid policy,
    /// absent or incompatible registered genesis, malformed original controls,
    /// conflicting retained history and actual backend failures.
    pub async fn open_local_maintenance(
        location: &LocalRepositoryLocation,
        identity: &LocalMaintenanceIdentity,
        policy: LocalRepositoryPolicy,
        fs: F,
        clock: C,
    ) -> Result<Self, Error> {
        if identity.issuer.issuer.is_empty()
            || identity.issuer.key_id.is_empty()
            || identity.owner_uid == u32::MAX
        {
            return Err(Error::Denied);
        }
        validate_policy(&policy)?;
        crate::repository::local_authority::validate_maintenance_location(
            &fs,
            &location.bucket,
            &location.authority,
            identity.owner_uid,
        )
        .await?;
        validate_bucket_owner(&fs, &location.bucket, identity.owner_uid).await?;

        // Mutable content capabilities cannot choose a replacement CDC seed.
        let registered = crate::bucket::publication::registered_profile(
            &fs,
            &location.bucket,
            &FileBucketPublicationConfig {
                operator_uid: identity.owner_uid,
                control: None,
            },
        )
        .await?;
        let (coordinator, namespace) = open_local_parts(
            location,
            &identity.issuer,
            policy,
            ChunkProfile::cdc_1m(registered.seed),
            fs,
            clock,
            identity.owner_uid,
        )
        .await?;
        Self::reopen_native_retention(
            coordinator,
            &namespace,
            &location.authority,
            identity.owner_uid,
        )
        .await
    }
}
