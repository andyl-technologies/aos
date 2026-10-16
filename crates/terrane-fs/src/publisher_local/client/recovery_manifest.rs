//! Adopts pinned reconstruction metadata under the original recovery barrier.
//!
//! The native publisher proves current directory-relative canonical custody.
//! The response supplies both the verified file and its lifecycle observation;
//! an inventory candidate supplies only its expected key, never a prior inode.
//! These methods remain outside owner dispatch until full recovery integration.

use std::{fs::File, io, os::fd::AsFd, sync::Arc};

use rustix::fs::{Mode, OFlags, ResolveFlags};
use terrane::host::{
    cache::HostDomainLocation,
    publication::{PublicationClaim, PublicationRecipe},
};

use super::{
    BodyIncarnationObservation, Client, Error, PeerPublishedObject, RequestPayload, invalidate,
    receipt,
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

/// Preserves typed resource custody on every stage of a failed recovery exchange.
pub(crate) enum RecoveryManifestError {
    /// The receipt could not arm an effect; its physical source registry remains.
    BeforeEffect(io::Error),
    /// No verified response body was accepted; durable metadata custody remains.
    Metadata(RecoveryManifestEffectFailure),
    /// The registered body, metadata and genuine lifecycle observation remain owned.
    Body {
        /// The actual failed native resource pair and original error.
        failure: RecoveryManifestBodyFailure,
        /// The lifecycle name extracted from the same verified response.
        observation: BodyIncarnationObservation<HostDomainLocation>,
    },
}

impl Client<HostDomainLocation> {
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

    /// Inspects and adopts pinned manifest content under its original barrier.
    ///
    /// Sealed InspectBody performs the same effectful native adoption as Adopt.
    /// Its same-response observation grants no permission for new retirement.
    ///
    /// # Errors
    /// Preserves typed source/body custody on changed candidate, original phase,
    /// transport, verification, correlation, durability or quota failures.
    pub(crate) fn inspect_manifest_recovery(
        &self,
        retained: RecoveryRetainedManifest<'_, '_>,
        expected: &NativeRecoveryCandidate,
    ) -> Result<RecoveryManifestBody, RecoveryManifestError> {
        self.recovery_manifest_exchange(Operation::InspectBody, retained, expected)
    }

    fn recovery_manifest_exchange(
        &self,
        operation: Operation,
        retained: RecoveryRetainedManifest<'_, '_>,
        expected: &NativeRecoveryCandidate,
    ) -> Result<RecoveryManifestBody, RecoveryManifestError> {
        let effect = retained
            .begin_effect()
            .map_err(RecoveryManifestError::BeforeEffect)?;
        // Every guard transition occurs outside the Client mutex. This helper
        // releases its mutex before returning any response or failure.
        let response = self.recovery_manifest_response(operation, &effect, expected);
        let (body, observation) = match response {
            Ok(response) => response,
            Err(error) => {
                return Err(RecoveryManifestError::Metadata(
                    effect.fail(io::Error::other(error)),
                ));
            }
        };
        // Capacity was reserved before submission. Register the actual owned
        // verified file before any later fallible correlation or completion.
        let accepted = effect.accept_body(body);
        if let Err(error) = self.correlate_recovery_manifest(&accepted, &observation) {
            return Err(RecoveryManifestError::Body {
                failure: accepted.fail(io::Error::other(error)),
                observation,
            });
        }
        match accepted.complete() {
            Ok(retained) => Ok(RecoveryManifestBody {
                retained,
                observation,
            }),
            Err(failure) => Err(RecoveryManifestError::Body {
                failure,
                observation,
            }),
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
        let mut state = self.lock()?;
        let result = (|| {
            self.correlate_sealed_response(
                &state,
                accepted.live_context().publisher_context(),
                observation,
                accepted.body(),
            )?;
            self.layout.recheck()?;
            let root = File::from(rustix::fs::openat2(
                rustix::fs::CWD,
                self.layout.layout().root(),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::NO_SYMLINKS,
            )?);
            let root_project = NativeProject::inspect(&root)?;
            let body = NativeProject::inspect(accepted.body().handle())?;
            let root_stat = rustix::fs::fstat(&root)?;
            let body_stat = rustix::fs::fstat(accepted.body().handle())?;
            if (root_stat.st_dev, root_stat.st_ino)
                != self.layout.directory_binding("layout-root")?
                || (body.device, body.inode) != (body_stat.st_dev, body_stat.st_ino)
                || body.device != root_project.device
                || body.project_id != root_project.project_id
            {
                return Err(Error::Invalid("canonical response native project or inode"));
            }
            self.layout.recheck()?;
            Ok(())
        })();
        if result.is_err() {
            invalidate(&mut state);
        }
        result
    }
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
}
