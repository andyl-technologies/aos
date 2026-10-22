//! Selects complete sealed files from original publication and recovery custody.
//!
//! This source consumes a whole inline or assembled object. It never interprets
//! a Manifest metadata grant as permission to expose the assembled file, nor
//! treats a chunk's range within another object as a standalone backing file.

use super::{PublicationJob, eviction, residence};
mod recovery;

use crate::{
    host_cache::owner::{
        corruption::{Failure, Signal},
        retention::{Custody, NativeOwnerExecutor},
    },
    publisher_local::client::PeerPublishedObject,
};
use recovery::RecoveredOrigin;
use std::{
    io,
    os::fd::{AsFd, OwnedFd},
    sync::{Arc, Mutex},
};
use terrane_format::identity::{Descriptor, Identity, IdentityKind, TERRANE_V1};
use terrane_sdk::host::cache::HostDomainLocation;

/// Retains an exact whole file without exporting a raw-file constructor.
pub(in crate::host_cache::owner) struct SealedObjectSource {
    identity: Identity,
    body: Arc<PeerPublishedObject<HostDomainLocation>>,
    origin: Origin,
    activity: Arc<eviction::ReadActivity>,
    corruption: Arc<Signal>,
    project: u32,
    publisher_uid: u32,
}

enum Origin {
    Publication(Arc<Mutex<PublicationJob>>),
    Recovery(RecoveredOrigin),
}

impl SealedObjectSource {
    /// Selects original completed publication custody on the physical worker.
    ///
    /// Cold files require the actual executor's verified recovery registry and
    /// acknowledged Resume. Ledger rows and encoded bodies cannot substitute.
    /// A selected publication failure never falls back to recovered backing or
    /// another representation of the same identity.
    ///
    /// # Errors
    /// Refuses absent Running custody, unsupported identities, incomplete or
    /// foreign publications, failed restoration and native integrity errors.
    pub(in crate::host_cache::owner) async fn prepare(
        executor: &mut NativeOwnerExecutor,
        identity: Identity,
    ) -> io::Result<Self> {
        executor.check_physical_worker()?;
        if identity.profile() != TERRANE_V1.name()
            || !matches!(
                identity.kind(),
                IdentityKind::Chunk | IdentityKind::Manifest
            )
        {
            return Err(invalid(
                "sealed object requires a registered content identity",
            ));
        }
        let running = executor.admission_context()?;
        running.check_current().map_err(io::Error::other)?;
        let mut selected = None;
        for resource in executor.publication_jobs() {
            let job = resource
                .lock()
                .map_err(|_| invalid("sealed object publication poisoned"))?;
            let descriptor = job.claim.descriptor();
            if matches_identity(descriptor, &identity)? {
                if !Arc::ptr_eq(&job.custody, executor.custody()) {
                    return Err(invalid("sealed object belongs to another physical owner"));
                }
                selected = Some((Arc::clone(resource), descriptor.clone()));
                break;
            }
        }
        if let Some((_, descriptor)) = &selected {
            eviction::restore_publication(executor, descriptor).await?;
        }

        let source = {
            let owner = executor
                .custody()
                .lock()
                .map_err(|_| invalid("sealed object custody poisoned"))?;
            if owner.faulted || owner.recovery_required {
                return Err(invalid("sealed object requires writable Running custody"));
            }
            let (body, origin) = match selected {
                Some((publication, _)) => {
                    let body = {
                        let job = publication
                            .lock()
                            .map_err(|_| invalid("sealed object publication poisoned"))?;
                        Arc::clone(residence::registered_body(&owner, &job)?)
                    };
                    (body, Origin::Publication(publication))
                }
                None => {
                    let recovered =
                        RecoveredOrigin::select(executor, &owner, &identity, Arc::clone(&running))?;
                    (Arc::clone(recovered.body()), Origin::Recovery(recovered))
                }
            };
            Self {
                identity,
                activity: executor.body_read_activity(&owner, &body)?,
                corruption: executor.sealed_corruption_signal(&owner, &body)?,
                project: owner.preparation.config.project_id,
                publisher_uid: owner.preparation.config.publisher.identities.publish_uid,
                body,
                origin,
            }
        };
        source.check_native()?;
        running.check_current().map_err(io::Error::other)?;
        Ok(source)
    }

    /// Borrows the exact original whole-object identity.
    pub(in crate::host_cache::owner) fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Checks original publication or recovery custody before the consumer pin.
    ///
    /// # Errors
    /// Refuses poisoned publication state, lost funding or changed backing.
    pub(in crate::host_cache::owner) fn check_protected(&self, owner: &Custody) -> io::Result<()> {
        match &self.origin {
            Origin::Publication(publication) => {
                let job = publication
                    .lock()
                    .map_err(|_| invalid("sealed object publication poisoned"))?;
                if !Arc::ptr_eq(&self.body, residence::registered_body(owner, &job)?) {
                    return Err(invalid(
                        "sealed object changed original publication backing",
                    ));
                }
                Ok(())
            }
            Origin::Recovery(recovered) => {
                if !Arc::ptr_eq(&self.body, recovered.body()) {
                    return Err(invalid("sealed object changed original recovery backing"));
                }
                recovered.check_registration(owner)
            }
        }
    }

    /// Checks immutable backing independently of a former producer's funding.
    ///
    /// The caller must additionally check its own original durable consumer pin.
    ///
    /// # Errors
    /// Refuses stale snapshot custody, a foreign layout or failed native checks.
    pub(in crate::host_cache::owner) fn check_consumer_backing(
        &self,
        owner: &Custody,
    ) -> io::Result<()> {
        residence::check_snapshot(owner)?;
        if !Arc::ptr_eq(self.body.layout(), owner.preparation.layout()) {
            return Err(invalid("sealed object changed original layout"));
        }
        self.check_native()
    }

    /// Synchronizes and measures the exact complete sealed inode.
    ///
    /// # Errors
    /// Refuses changed native backing or failed inode and filesystem synchronization.
    pub(in crate::host_cache::owner) fn synchronize_pin_backing(&self) -> io::Result<u64> {
        self.check_native()?;
        residence::synchronize_body(&self.body, self.project, self.publisher_uid)
    }

    /// Duplicates only this retained read-only file after fresh native checks.
    ///
    /// Its consumer retains the original source through the duplicate's complete
    /// delegated lifetime. No pathname is opened and no file body is allocated.
    ///
    /// # Errors
    /// Refuses changed or rejected backing, failed descriptor duplication or
    /// unavailable read-activity bookkeeping.
    pub(in crate::host_cache::owner) fn duplicate_backing(&self) -> io::Result<OwnedFd> {
        self.check_native()?;
        let file = self.body.handle().as_fd().try_clone_to_owned()?;
        self.check_native()?;
        self.activity.record()?;
        Ok(file)
    }

    /// Bounds owned header and identity storage without duplicating the body.
    pub(in crate::host_cache::owner) fn storage_bytes() -> usize {
        std::mem::size_of::<Self>() + TERRANE_V1.digest_len()
    }

    fn check_native(&self) -> io::Result<()> {
        self.corruption.check_readable()?;
        residence::check_native_body(&self.body, self.project, self.publisher_uid)
            .inspect_err(|_| self.corruption.reject(&self.body, Failure::Custody))
    }
}

fn matches_identity(descriptor: &Descriptor, identity: &Identity) -> io::Result<bool> {
    Ok(descriptor.algorithm() == TERRANE_V1.algorithm()
        && descriptor.domain()
            == TERRANE_V1
                .domain(identity.kind())
                .map_err(io::Error::other)?
        && descriptor.digest() == identity.digest())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
