//! Adopts pinned reconstruction metadata under the original recovery barrier.
//!
//! The native publisher proves current directory-relative canonical custody.
//! The response supplies both the verified file and its lifecycle observation;
//! an inventory candidate supplies only its expected key, never a prior inode.
//! The physical recovery executor retains accepted resources before correlation;
//! these exchanges grant no Running publisher or serving authority.

use std::{fs::File, io, os::fd::AsFd, sync::Arc};

use rustix::fs::{FileType, Mode, OFlags, ResolveFlags};
use terrane_sdk::host::{
    cache::HostDomainLocation,
    publication::{PublicationClaim, PublicationRecipe},
};

use super::{
    BodyIncarnationObservation, Client, Error, PeerPublishedObject, PublisherRecoveryContext,
    RequestPayload, invalidate, receipt,
};
use crate::{
    host_cache::{
        AcceptedRecoveryManifestEffect, NativeRecoveryCandidate, RecoveryManifestBodyFailure,
        RecoveryManifestBodyRetention, RecoveryManifestEffect, RecoveryManifestEffectFailure,
        RecoveryRetainedManifest,
    },
    host_quota::NativeProject,
    publisher_local::wire::{BodyKey, BodyKind, Claim, Operation},
};

/// Retains the registered body/pin pair and its actual same-response observation.
///
/// No serving, consumer-pin, prior scanned-inode or completed-recovery authority
/// is added. The physical executor already retains the resource pair. Borrowing
/// its body or metadata performs no embedded-state lookup.
pub(crate) struct RecoveryManifestBody {
    retained: RecoveryManifestBodyRetention,
    observation: BodyIncarnationObservation<HostDomainLocation>,
}

impl RecoveryManifestBody {
    /// Borrows the actual native body and durable metadata resources together.
    pub(crate) fn retained(&self) -> &RecoveryManifestBodyRetention {
        &self.retained
    }

    /// Borrows the original-barrier lifecycle observation from that same response.
    pub(crate) fn observation(&self) -> &BodyIncarnationObservation<HostDomainLocation> {
        &self.observation
    }
}

/// Pairs a failed native resource owner with its original response observation.
type BodyFailureResources = (
    RecoveryManifestBodyFailure,
    BodyIncarnationObservation<HostDomainLocation>,
);

/// Preserves typed resource custody on every stage of a failed recovery exchange.
///
/// Slots are allocated before submission and filled before returning an effect
/// error. An empty slot cannot supply resource or recovery-completion authority.
pub(crate) enum RecoveryManifestError {
    /// The receipt could not arm an effect; its physical source registry remains.
    BeforeEffect(io::Error),
    /// No verified response body was accepted; durable metadata custody remains.
    Metadata(Box<Option<RecoveryManifestEffectFailure>>),
    /// The registered body, metadata and genuine lifecycle observation remain owned.
    Body(Box<Option<BodyFailureResources>>),
}

impl Client<HostDomainLocation> {
    /// Rechecks a genuine manifest body against the Inspector's original barrier.
    ///
    /// The caller supplies the retained original opaque context, never a fresh
    /// capture. This borrows the actual body/pin pair without transferring or
    /// releasing resources, including on failure. Native inode, seal and charge
    /// owner checks take no embedded-state lock. Current durable policy/holds
    /// remain the physical owner's separate checks before entering this method.
    /// No prior scanned-inode equality or completed recovery is asserted.
    ///
    /// # Errors
    /// Rejects a different body/metadata claim, session, original epoch, root,
    /// key, token or native project; stale inode, access or seal custody; a
    /// poisoned mutex; and a non-recovery or uncertain client. Failed checks
    /// invalidate this client's phase while leaving all retained resources owned.
    pub(crate) fn check_recovery_manifest_body(
        &self,
        body: &RecoveryManifestBody,
        original: &PublisherRecoveryContext<HostDomainLocation>,
    ) -> Result<(), Error> {
        self.correlate_manifest_body(
            original,
            body.observation(),
            body.retained().body(),
            Some(body.retained()),
        )
    }

    /// Adopts pinned manifest content within its genuine original recovery phase.
    ///
    /// Native adoption can persist bindings or quarantine conflicting content.
    /// The actual effect guard retains holds and resource ownership through
    /// synchronization and fresh quota reconciliation, including failed replies.
    /// No ordinary publication or completed recovery is enabled here.
    ///
    /// # Errors
    /// Retains typed custody for stale source/phase/candidate/session data,
    /// transport or verification failures, failed lifecycle/project correlation
    /// and failed synchronization or fresh quota reconciliation.
    pub(crate) fn adopt_manifest_recovery(
        &self,
        retained: RecoveryRetainedManifest<'_, '_>,
        expected: &NativeRecoveryCandidate,
    ) -> Result<RecoveryManifestBody, RecoveryManifestError> {
        self.recovery_manifest_exchange(Operation::Adopt, retained, expected)
    }

    fn recovery_manifest_exchange(
        &self,
        operation: Operation,
        retained: RecoveryRetainedManifest<'_, '_>,
        expected: &NativeRecoveryCandidate,
    ) -> Result<RecoveryManifestBody, RecoveryManifestError> {
        // Reserve both possible failure carriers before any publisher exchange.
        // Filling an owned slot never allocates after the native effect or drops
        // its original metadata/body custody to manufacture a smaller error.
        let mut metadata_failure = Box::new(None);
        let mut body_failure = Box::new(None);
        let effect = retained
            .begin_effect()
            .map_err(RecoveryManifestError::BeforeEffect)?;
        // Every guard transition occurs outside the Client mutex. This helper
        // releases its mutex before returning any response or failure.
        let response = self.recovery_manifest_response(operation, &effect, expected);
        let (body, observation) = match response {
            Ok(response) => response,
            Err(error) => {
                *metadata_failure = Some(effect.fail(io::Error::other(error)));
                return Err(RecoveryManifestError::Metadata(metadata_failure));
            }
        };
        // Capacity was reserved before submission. Register the actual owned
        // verified file before any later fallible correlation or completion.
        let accepted = effect.accept_body(body);
        if let Err(error) = self.correlate_recovery_manifest(&accepted, &observation) {
            *body_failure = Some((accepted.fail(io::Error::other(error)), observation));
            return Err(RecoveryManifestError::Body(body_failure));
        }
        match accepted.complete() {
            Ok(retained) => Ok(RecoveryManifestBody {
                retained,
                observation,
            }),
            Err(failure) => {
                *body_failure = Some((failure, observation));
                Err(RecoveryManifestError::Body(body_failure))
            }
        }
    }

    fn recovery_manifest_response(
        &self,
        operation: Operation,
        effect: &RecoveryManifestEffect<'_, '_>,
        expected: &NativeRecoveryCandidate,
    ) -> Result<
        (
            PeerPublishedObject<HostDomainLocation>,
            BodyIncarnationObservation<HostDomainLocation>,
        ),
        Error,
    > {
        // These genuine producer checks may take embedded state and must run
        // before the Client mutex. No fresh drain context is captured here.
        effect.check_current()?;
        let live = effect.live_context();
        if !std::ptr::eq(self, live.publisher_session().as_ref())
            || !Arc::ptr_eq(&self.layout, effect.layout())
            || &self.cache_incarnation != effect.cache_incarnation()
        {
            return Err(Error::Invalid("recovery manifest session or root"));
        }
        let claim = self.recovery_manifest_claim(effect)?;
        let key = BodyKey {
            kind: BodyKind::Sealed as i32,
            descriptor: claim.descriptor().encode(),
            ..Default::default()
        };
        require_candidate_key(expected.key(), &key)?;
        let range = effect.manifest_range();
        let payload = RequestPayload {
            claim: Some(Claim {
                descriptor: key.descriptor.clone(),
                chunk_profile: self.config.chunk_profile_name.clone(),
                plaintext_size: claim.plaintext_size(),
                manifest_offset: range.start,
                manifest_length: range.length,
                retention_id: effect.retention_id().to_vec(),
            }),
            body: Some(key.clone()),
            ..Default::default()
        };

        let mut state = self.lock()?;
        self.require_recovery_context(&state, live.publisher_context())?;
        let result = (|| {
            let received = self.exchange_payload_files(
                &mut state,
                operation,
                payload,
                &[effect.metadata_file().as_fd()],
            )?;
            // Both brands originate in this one correlated response. Capture
            // the genuine token before the native verifier consumes its file.
            let observation = self.observation(&state, key, &received.packet.body_incarnation)?;
            let body = receipt::published(
                received,
                Arc::clone(&self.layout),
                self.config.identities.publish_uid,
                claim,
            )?;
            Ok((body, observation))
        })();
        if result.is_err() {
            invalidate(&mut state);
        }
        result
    }

    fn recovery_manifest_claim(
        &self,
        effect: &RecoveryManifestEffect<'_, '_>,
    ) -> Result<PublicationClaim, Error> {
        let original = effect.claim();
        let canonical = original
            .canonical_manifest()
            .ok_or(Error::Invalid("recovery claim is not a manifest"))?;
        let range = effect.manifest_range();
        let metadata = effect.metadata_file().metadata()?;
        if original.domain() != self.layout.layout().domain()
            || range.length != original.descriptor().size()
            || u64::try_from(canonical.len()).ok() != Some(range.length)
            || range
                .start
                .checked_add(range.length)
                .is_none_or(|end| end > metadata.len())
        {
            return Err(Error::Invalid("recovery manifest claim or metadata range"));
        }
        Ok(PublicationClaim::new(
            original.domain().to_owned(),
            PublicationRecipe::Manifest {
                object: original.descriptor().clone(),
                canonical_manifest: canonical.to_vec(),
            },
            self.layout.layout().chunk_profile(),
        )?)
    }

    fn correlate_recovery_manifest(
        &self,
        accepted: &AcceptedRecoveryManifestEffect<'_, '_>,
        observation: &BodyIncarnationObservation<HostDomainLocation>,
    ) -> Result<(), Error> {
        self.correlate_manifest_body(
            accepted.live_context().publisher_context(),
            observation,
            accepted.body(),
            None,
        )
    }

    fn correlate_manifest_body(
        &self,
        original: &PublisherRecoveryContext<HostDomainLocation>,
        observation: &BodyIncarnationObservation<HostDomainLocation>,
        body: &PeerPublishedObject<HostDomainLocation>,
        retained: Option<&RecoveryManifestBodyRetention>,
    ) -> Result<(), Error> {
        let mut state = self.lock()?;
        let result = (|| {
            self.correlate_sealed_response(&state, original, observation, body)?;
            if let Some(retained) = retained {
                // These getters borrow immutable genuine resource custody;
                // they never consult the embedded owner or release pins.
                let backing = retained.backing();
                require_same_claim(body.claim(), backing.claim())?;
                if !Arc::ptr_eq(body.layout(), backing.layout())
                    || &self.cache_incarnation != backing.cache_incarnation()
                    || backing.synchronized_source_and_body_bytes().is_none()
                    || backing.charged_reserved_bytes().is_none()
                {
                    return Err(Error::Invalid("manifest body metadata custody differs"));
                }
            }
            self.check_manifest_native_body(body)
        })();
        if result.is_err() {
            invalidate(&mut state);
        }
        result
    }

    fn check_manifest_native_body(
        &self,
        body: &PeerPublishedObject<HostDomainLocation>,
    ) -> Result<(), Error> {
        self.layout.recheck()?;
        let root = File::from(rustix::fs::openat2(
            rustix::fs::CWD,
            self.layout.layout().root(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS,
        )?);
        let root_project = NativeProject::inspect(&root)?;
        let body_project = NativeProject::inspect(body.handle())?;
        let root_stat = rustix::fs::fstat(&root)?;
        let body_stat = rustix::fs::fstat(body.handle())?;
        let flags = rustix::fs::fcntl_getfl(body.handle())?;
        if (root_stat.st_dev, root_stat.st_ino) != self.layout.directory_binding("layout-root")?
            || (body_project.device, body_project.inode) != (body_stat.st_dev, body_stat.st_ino)
            || body_project.device != root_project.device
            || body_project.project_id != root_project.project_id
            || flags.intersects(OFlags::WRONLY | OFlags::RDWR | OFlags::PATH)
            || FileType::from_raw_mode(body_stat.st_mode) != FileType::RegularFile
            || body_stat.st_uid != self.config.identities.publish_uid
            || body_stat.st_nlink == 0
            || u64::try_from(body_stat.st_size).ok() != Some(body.claim().plaintext_size())
            || &crate::verity::measure(body.handle())? != body.binding()
        {
            return Err(Error::Invalid(
                "canonical response native inode or seal custody",
            ));
        }
        self.layout.recheck()?;
        Ok(())
    }
}

fn require_same_claim(body: &PublicationClaim, metadata: &PublicationClaim) -> Result<(), Error> {
    if body.domain() != metadata.domain()
        || body.descriptor() != metadata.descriptor()
        || body.plaintext_size() != metadata.plaintext_size()
        || body.canonical_manifest() != metadata.canonical_manifest()
    {
        return Err(Error::Invalid(
            "manifest body differs from retained metadata claim",
        ));
    }
    Ok(())
}

fn require_candidate_key(expected: &BodyKey, requested: &BodyKey) -> Result<(), Error> {
    if expected != requested {
        return Err(Error::Invalid(
            "recovery candidate differs from pinned manifest",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn candidate_comparison_requires_the_complete_registered_key() {
        // These are only key comparisons, never native receipts or authority.
        let requested = BodyKey {
            kind: BodyKind::Sealed as i32,
            descriptor: vec![1, 2, 3],
            ..Default::default()
        };
        assert!(require_candidate_key(&requested, &requested).is_ok());
        for changed in [
            BodyKey {
                codec: 1,
                ..requested.clone()
            },
            BodyKey {
                pack_id: vec![0; 16],
                ..requested.clone()
            },
            BodyKey {
                kind: BodyKind::Chunk as i32,
                ..requested.clone()
            },
            BodyKey {
                descriptor: vec![1, 2, 4],
                ..requested.clone()
            },
        ] {
            assert!(require_candidate_key(&changed, &requested).is_err());
        }
    }

    #[test]
    fn retained_claim_comparison_rejects_other_domains_and_content() {
        use terrane_format::{
            chunking::ChunkProfile,
            identity::{Descriptor, IdentityKind, TERRANE_V1},
        };

        // Real claim parsing exercises only the equality policy; this creates
        // no root, peer response, native receipt, pin or recovery context.
        let claim = |domain: &str, bytes: &[u8]| {
            let identity = TERRANE_V1.calculate(IdentityKind::Chunk, bytes).unwrap();
            let descriptor = Descriptor::from_identity(&TERRANE_V1, &identity, bytes).unwrap();
            PublicationClaim::new(
                domain.to_owned(),
                PublicationRecipe::Inline { chunk: descriptor },
                &ChunkProfile::cdc_1m([0; 32]),
            )
            .unwrap()
        };
        let original = claim("public", b"same bytes");
        assert!(require_same_claim(&original, &original).is_ok());
        assert!(require_same_claim(&original, &claim("private:other", b"same bytes")).is_err());
        assert!(require_same_claim(&original, &claim("public", b"other bytes")).is_err());
    }
}
