//! Retains the actual admitted standalone inode through sealed residence transfer.
//!
//! Selection comes only from this physical executor's completed admissions.
//! Publisher inspection must return that same read-only inode, and retirement
//! keeps its original descriptors and durable holds until genuine cleanup.

use super::{Input, backing::AdmissionJob, io as native, state};
use crate::{
    host_cache::owner::retention::{Custody, NativeOwnerExecutor},
    publisher_local::wire::{BodyKey, BodyKind},
};
use std::{
    fs::File,
    io,
    os::unix::fs::MetadataExt,
    sync::{Arc, Mutex},
};
use terrane_core::identity::{Descriptor, Identity, IdentityKind, TERRANE_V1};

/// Keeps one original registered admission rather than accepting a source claim.
#[derive(Clone)]
pub(in crate::host_cache::owner) struct TransferSource {
    job: Arc<Mutex<AdmissionJob>>,
    key: BodyKey,
    source: (u64, u64, u64),
}

/// Retains original admission funding only after genuine final removal and closure.
pub(in crate::host_cache::owner) struct TransferredFunding {
    job: Arc<Mutex<AdmissionJob>>,
    token: String,
    hold: u64,
    hashes: Vec<String>,
    cached: Option<super::handoff::CachedAdmission>,
}

impl TransferredFunding {
    /// Removes only the original checked operation's exact durable protection.
    ///
    /// # Errors
    /// Refuses changed original registration or a policy copy missing its records.
    pub(in crate::host_cache::owner) fn remove_from(
        &self,
        owner: &Custody,
        next: &mut terrane::host::cache::CacheState,
    ) -> io::Result<()> {
        let job = self
            .job
            .lock()
            .map_err(|_| invalid("transferred admission poisoned"))?;
        state::check_registration(owner, &job)?;
        if job.token != self.token || job.hold != self.hold || job.hashes != self.hashes {
            return Err(invalid("transferred admission funding changed"));
        }
        if let Some(cached) = &self.cached {
            return cached.remove_transferred(owner, &job, next);
        }
        let name = format!("admission:{}", self.token);
        if next.pins.iter().filter(|row| row.owner == name).count() != self.hashes.len() {
            return Err(invalid(
                "transferred admission has unexpected dependency pins",
            ));
        }
        next.pins.retain(|row| row.owner != name);
        next.leases.retain(|row| row.owner != name);
        next.reservations.retain(|row| row.id != self.token);
        Ok(())
    }

    /// Relinquishes obsolete native and input resources after synchronized funding removal.
    ///
    /// # Errors
    /// Refuses a changed owner, uncertain snapshot, retained funding or live descriptors.
    pub(in crate::host_cache::owner) fn release(
        &self,
        executor: &NativeOwnerExecutor,
    ) -> io::Result<()> {
        executor.check_physical_worker()?;
        let mut job = self
            .job
            .lock()
            .map_err(|_| invalid("transferred admission poisoned"))?;
        {
            let custody = executor
                .custody()
                .lock()
                .map_err(|_| invalid("transfer custody poisoned"))?;
            super::super::publication::residence::check_snapshot(&custody)?;
            let name = format!("admission:{}", self.token);
            if custody
                .state
                .reservations
                .iter()
                .any(|row| row.id == self.token)
                || custody.state.leases.iter().any(|row| row.owner == name)
                || custody.state.pins.iter().any(|row| row.owner == name)
            {
                return Err(invalid("transferred admission funding still present"));
            }
            if let Some(cached) = &self.cached {
                cached.check_released(&custody, &job)?;
            }
        }
        if !Arc::ptr_eq(&job.custody, executor.custody())
            || job.token != self.token
            || job.hold != self.hold
            || job.hashes != self.hashes
            || job.files.len() != 1
        {
            return Err(invalid("transferred admission changed original ownership"));
        }
        job.files[0].check_transferred_closed()?;
        let Input::Chunk { encoded, .. } = &mut job.input else {
            return Err(invalid("transferred admission changed input class"));
        };
        *encoded = Arc::new(Vec::new());
        job.files.clear();
        job.directory_progress.clear();
        job.dependencies.clear();
        job.cached = None;
        Ok(())
    }

    /// Recognizes the original resource for registry removal after completed release.
    pub(in crate::host_cache::owner) fn belongs_to(&self, job: &Arc<Mutex<AdmissionJob>>) -> bool {
        Arc::ptr_eq(&self.job, job)
    }
}

impl TransferSource {
    /// Retains funding only under the actual original final-removal acknowledgment.
    ///
    /// # Errors
    /// Refuses another physical worker, absent registration, changed input or
    /// incomplete native closure. No caller-selected key creates this scope.
    pub(in crate::host_cache::owner) fn closed_funding(
        &self,
        executor: &NativeOwnerExecutor,
        owner: &Custody,
        acknowledged: &super::super::publication::retirement::AcknowledgedSource<'_>,
    ) -> io::Result<TransferredFunding> {
        acknowledged.check(executor, self)?;
        if !executor
            .admission_jobs()
            .iter()
            .any(|job| Arc::ptr_eq(job, &self.job))
        {
            return Err(invalid("transferred admission registry absent"));
        }
        let job = self
            .job
            .lock()
            .map_err(|_| invalid("transferred admission poisoned"))?;
        if !job.complete || job.files.len() != 1 || !Arc::ptr_eq(&job.custody, executor.custody()) {
            return Err(invalid(
                "transferred admission is not original completed work",
            ));
        }
        state::check_registration(owner, &job)?;
        job.files[0].check_transferred_closed()?;
        let Input::Chunk {
            descriptor,
            encoded,
            ..
        } = &job.input
        else {
            return Err(invalid("transferred admission changed input class"));
        };
        if descriptor.encode() != self.key.descriptor
            || encoded.first().map(|codec| u32::from(*codec)) != Some(self.key.codec)
        {
            return Err(invalid("transferred admission differs from original input"));
        }
        Ok(TransferredFunding {
            job: Arc::clone(&self.job),
            token: job.token.clone(),
            hold: job.hold,
            hashes: job.hashes.clone(),
            cached: job.cached.clone(),
        })
    }

    /// Closes only this actual acknowledged source's original native descriptors.
    ///
    /// # Errors
    /// Refuses foreign physical custody, a missing original registration,
    /// incomplete work, another encoded input, or changed native handles/bytes.
    pub(in crate::host_cache::owner) fn close_finished_source(
        &self,
        executor: &NativeOwnerExecutor,
        owner: &Custody,
        acknowledged: &super::super::publication::retirement::AcknowledgedSource<'_>,
        inspected: &mut Vec<File>,
    ) -> io::Result<()> {
        acknowledged.check(executor, self)?;
        if !executor
            .admission_jobs()
            .iter()
            .any(|job| Arc::ptr_eq(job, &self.job))
        {
            return Err(invalid("source closure lost original admission registry"));
        }
        let mut guard = self
            .job
            .lock()
            .map_err(|_| invalid("source admission poisoned"))?;
        let job = &mut *guard;
        if !job.complete || job.files.len() != 1 || !Arc::ptr_eq(&job.custody, executor.custody()) {
            return Err(invalid("source closure differs from completed admission"));
        }
        state::check_registration(owner, job)?;
        let Input::Chunk {
            descriptor,
            encoded,
            ..
        } = &job.input
        else {
            return Err(invalid("source closure changed input class"));
        };
        if descriptor.encode() != self.key.descriptor
            || encoded.first().map(|codec| u32::from(*codec)) != Some(self.key.codec)
        {
            return Err(invalid("source closure changed original encoded input"));
        }
        job.files[0].close_finished_source(owner, self.source, encoded, inspected)
    }

    /// Selects the exact completed admission from the actual physical registry.
    ///
    /// # Errors
    /// Refuses foreign, absent, incomplete, altered or unpinned canonical input.
    pub(in crate::host_cache::owner) fn select(
        executor: &NativeOwnerExecutor,
        owner: &Custody,
        descriptor: &Descriptor,
    ) -> io::Result<Self> {
        Self::select_matching(executor, owner, |actual| actual == descriptor)
    }

    /// Selects a manifest chunk only from this worker's completed actual inputs.
    ///
    /// # Errors
    /// Refuses another identity profile or kind, absent admission, changed
    /// descriptor length, physical bytes, pins or native inode custody.
    pub(in crate::host_cache::owner) fn select_chunk(
        executor: &NativeOwnerExecutor,
        owner: &Custody,
        identity: &Identity,
        length: u64,
    ) -> io::Result<Self> {
        if identity.kind() != IdentityKind::Chunk || identity.profile() != TERRANE_V1.name() {
            return Err(invalid(
                "manifest transfer requires a registered chunk identity",
            ));
        }
        Self::select_matching(executor, owner, |actual| {
            actual.digest() == identity.digest() && actual.size() == length
        })
    }

    fn select_matching(
        executor: &NativeOwnerExecutor,
        owner: &Custody,
        matches: impl Fn(&Descriptor) -> bool,
    ) -> io::Result<Self> {
        executor.check_physical_worker()?;
        for candidate in executor.admission_jobs() {
            let job = candidate
                .lock()
                .map_err(|_| invalid("transfer admission poisoned"))?;
            let Input::Chunk {
                descriptor: actual,
                encoded,
                ..
            } = &job.input
            else {
                continue;
            };
            if !matches(actual) || !job.complete {
                continue;
            }
            if !Arc::ptr_eq(&job.custody, executor.custody()) || job.files.len() != 1 {
                return Err(invalid("transfer source belongs to another actual owner"));
            }
            state::check_registration(owner, &job)?;
            native::check_current(owner, &job.files[0], encoded)?;
            let file = job.files[0]
                .readonly
                .as_ref()
                .ok_or_else(|| invalid("transfer source descriptor absent"))?;
            let metadata = file.metadata()?;
            let codec = *encoded
                .first()
                .ok_or_else(|| invalid("transfer encoding absent"))?;
            return Ok(Self {
                job: Arc::clone(candidate),
                key: BodyKey {
                    kind: BodyKind::Chunk as i32,
                    descriptor: actual.encode(),
                    codec: u32::from(codec),
                    ..Default::default()
                },
                source: (metadata.dev(), metadata.ino(), metadata.len()),
            });
        }
        Err(invalid(
            "standalone body lacks actual completed admission custody",
        ))
    }

    /// Borrows the registered key derived from this actual source's encoding.
    pub(in crate::host_cache::owner) fn key(&self) -> &BodyKey {
        &self.key
    }

    /// Rechecks the original canonical inode and its durable registration.
    ///
    /// # Errors
    /// Refuses changed physical bytes, missing pins, replacement or lost custody.
    pub(in crate::host_cache::owner) fn check_current(&self, owner: &Custody) -> io::Result<()> {
        let job = self
            .job
            .lock()
            .map_err(|_| invalid("transfer admission poisoned"))?;
        let Input::Chunk {
            descriptor,
            encoded,
            ..
        } = &job.input
        else {
            return Err(invalid("transfer admission changed input class"));
        };
        self.check_job(owner, &job, descriptor, encoded)?;
        native::check_current(owner, &job.files[0], encoded)
    }

    /// Checks an actual publisher inspection descriptor against the retained inode.
    ///
    /// # Errors
    /// Refuses another inode, writable descriptor, project, ownership or bytes.
    pub(in crate::host_cache::owner) fn check_received(
        &self,
        owner: &Custody,
        file: &File,
    ) -> io::Result<()> {
        let job = self
            .job
            .lock()
            .map_err(|_| invalid("transfer admission poisoned"))?;
        let Input::Chunk {
            descriptor,
            encoded,
            ..
        } = &job.input
        else {
            return Err(invalid("transfer admission changed input class"));
        };
        self.check_job(owner, &job, descriptor, encoded)?;
        let metadata = file.metadata()?;
        let flags = rustix::fs::fcntl_getfl(file)?;
        if (metadata.dev(), metadata.ino(), metadata.len()) != self.source
            || flags.intersects(
                rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::RDWR | rustix::fs::OFlags::PATH,
            )
        {
            return Err(invalid(
                "publisher transfer inspection has another inode or access mode",
            ));
        }
        native::verify_custodied_bytes(owner, file, encoded)
    }

    /// Rechecks retained source bytes after the genuine retirement acknowledgment.
    ///
    /// The rename may change ctime. The actual inode, bytes, project, ownership,
    /// durable admission pin and charged open description must still agree.
    ///
    /// # Errors
    /// Refuses changed or missing source custody; this never authorizes unlink.
    pub(in crate::host_cache::owner) fn check_retired(&self, owner: &Custody) -> io::Result<()> {
        let job = self
            .job
            .lock()
            .map_err(|_| invalid("transfer admission poisoned"))?;
        let Input::Chunk {
            descriptor,
            encoded,
            ..
        } = &job.input
        else {
            return Err(invalid("transfer admission changed input class"));
        };
        self.check_job(owner, &job, descriptor, encoded)?;
        let file = job.files[0]
            .readonly
            .as_ref()
            .ok_or_else(|| invalid("retired transfer source descriptor absent"))?;
        native::verify_custodied_bytes(owner, file, encoded)
    }

    fn check_job(
        &self,
        owner: &Custody,
        job: &AdmissionJob,
        descriptor: &Descriptor,
        encoded: &[u8],
    ) -> io::Result<()> {
        if !job.complete
            || job.files.len() != 1
            || descriptor.encode() != self.key.descriptor
            || encoded.first().map(|codec| u32::from(*codec)) != Some(self.key.codec)
        {
            return Err(invalid(
                "transfer source differs from its original registration",
            ));
        }
        state::check_registration(owner, job)?;
        let file = job.files[0]
            .readonly
            .as_ref()
            .ok_or_else(|| invalid("transfer source descriptor absent"))?;
        let metadata = file.metadata()?;
        if (metadata.dev(), metadata.ino(), metadata.len()) != self.source {
            return Err(invalid("transfer source lost its original inode"));
        }
        Ok(())
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::other(message)
}
