//! Reopens existing native authority for configured read-only Serve composition.

use super::*;

#[cfg(all(test, feature = "tokio"))]
#[allow(
    clippy::unwrap_used,
    reason = "native regressions require valid fixtures"
)]
mod tests;

impl<F, C> Repository<FileBucket<F, C, MetadataValidator>, C, F>
where
    F: LocalFs + BucketBinding + Clone + Sync + 'static,
    C: Clock + BucketBinding + Clone + Sync + 'static,
    FileBucket<F, C, MetadataValidator>: Sync,
{
    /// Reopens original selected history without granting authoring or maintenance.
    ///
    /// A selected Guard and signed current snapshot must already exist. Missing
    /// controls or history never trigger initialization, repair or key creation.
    /// The original filesystem remains available for disjoint snapshot output.
    ///
    /// # Errors
    /// Refuses invalid configuration, missing or unsafe native authority,
    /// incompatible registration and failed existing signed-snapshot checks.
    pub(crate) async fn open_local_read_only(
        location: &LocalRepositoryLocation,
        identity: &LocalAuthorityIdentity,
        policy: LocalRepositoryPolicy,
        reference: &str,
        fs: F,
        clock: C,
    ) -> Result<(Self, LocalAuthority), Error> {
        validate_policy(&policy)?;
        validate_local_reference(reference)?;
        let now = clock
            .now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| Error::Denied)?
            .as_secs();
        let authority =
            LocalAuthority::open(&fs, &location.bucket, &location.authority, identity, now).await?;
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
            std::slice::from_ref(authority.issuer_key()),
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
            .read_snapshot(reference, authority.token(), b"/", "sdk")
            .await?;
        Ok((repository, authority))
    }
}
