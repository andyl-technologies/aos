//! Recovers a pending local disclosure only through its genuine current pair.
//!
//! PROV-26 through PROV-31 and AUTH-26, AUTH-28 through AUTH-30 require retained
//! original controls independently of current publication rights. DOM-24 also
//! requires the same authenticated principal at both repositories. The private
//! coordinator below carries no selected setup receipt and never escapes. Its
//! only operation repeats source Read and destination Commit under the actual
//! held pair, checks exact expected import bindings and role additions, and
//! retains both control owners through the final selected publication. Ordinary
//! opening continues to require complete selected configuration equality.

use super::{
    ChunkProfile, Clock, Error, FileBucket, FileBucketPublicationConfig, LocalAuthority,
    LocalAuthorityIdentity, LocalFs, LocalRepositoryLocation, LocalRepositoryPolicy,
    MetadataValidator, Repository, SystemTime, open_local_parts, validate_bucket_owner,
    validate_local_reference, validate_policy,
};
use crate::bucket::BucketBinding;
use crate::ref_advance::DisclosureCommitRequest;
use crate::repository::local_authority::{NativeRetention, retention};

impl<F, C> Repository<FileBucket<F, C, MetadataValidator>, C, F>
where
    F: LocalFs + BucketBinding + Clone + Sync + 'static,
    C: Clock + BucketBinding + Clone + Sync + 'static,
    FileBucket<F, C, MetadataValidator>: Sync,
{
    /// Recovers only the exact pending imports justified by a fresh paired publication.
    ///
    /// Credentials, owner and immutable registered profile receive the same
    /// checks as ordinary local reopening. Deferred setup never supplies an
    /// ordinary repository, a missing original context, or a publication receipt.
    /// The final ordinary factory checks the newly selected complete snapshot.
    ///
    /// # Errors
    /// Rejects unsafe local state, absent original controls, unrelated pending
    /// roles or changed expected imports, different principals, denied current
    /// source or destination authority, incomplete provenance, expired timing
    /// and uncertain durable publication. Failure returns no repository.
    pub async fn recover_local_disclosure<D>(
        location: &LocalRepositoryLocation,
        identity: &LocalAuthorityIdentity,
        policy: LocalRepositoryPolicy,
        reference: &str,
        source: &Repository<FileBucket<F, C, MetadataValidator>, D, F>,
        request: DisclosureCommitRequest,
        runtime: (F, C),
    ) -> Result<(Self, LocalAuthority, terrane_format::refs::RefRecord), Error>
    where
        D: Clock + Sync,
    {
        let (fs, clock) = runtime;
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
        let registered = crate::bucket::publication::registered_profile(
            &fs,
            &location.bucket,
            &FileBucketPublicationConfig {
                operator_uid: identity.owner_uid,
                control: None,
            },
        )
        .await?;
        let profile = ChunkProfile::cdc_1m(registered.seed);
        let (pending, namespace) = open_local_parts(
            location,
            &authority,
            policy,
            profile,
            fs,
            clock,
            identity.owner_uid,
        )
        .await?;

        // Raw registration fields establish no authority until the concrete
        // backend independently checks their physical and protected bindings.
        let registration: retention::RegistrationRecord = retention::read(
            pending.fs(),
            &location.authority,
            identity.owner_uid,
            "registration.cbor",
        )
        .await?;
        let original = pending
            .guard()
            .bind_original_authority(&namespace, &location.authority, registration.view())
            .await?;
        pending
            .guard()
            .prepare_paired_original_verifier(&original)
            .await?;
        let retention = NativeRetention {
            authority: original.clone(),
            owner_uid: identity.owner_uid,
            authoring_acl: pending.guard().config().initial_acl.clone(),
        };
        retention.load(pending.guard()).await?;

        // Neither begin nor preparation selects setup state. The producer's
        // fresh held checks alone may select the exact source-derived transition.
        let mut session = {
            let holder = crate::bucket::held::HeldBuckets::acquire(
                source.coordinator().store(),
                pending.store(),
            )
            .await?;
            let guard = pending
                .guard()
                .held_guard(holder.destination(), pending.guard().clock().clone())?;
            let destination = crate::ref_advance::Coordinator::new(
                guard,
                pending.timing(),
                crate::ref_advance::FsRef(pending.fs()),
            );
            let observed = destination.store().observe_publication().await?;
            destination
                .begin_held(
                    reference,
                    authority.token(),
                    &request.proposal.surface,
                    observed.identity(),
                )
                .await?
        };
        let record = pending
            .advance_disclosure(source.coordinator().guard(), &mut session, request)
            .await?;
        let repository = Self::from_native_authority(pending, original, identity.owner_uid).await?;
        Ok((repository, authority, record))
    }
}
