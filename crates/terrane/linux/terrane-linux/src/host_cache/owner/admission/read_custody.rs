//! Retains exact encoded publisher observations before reads and after failures.
//!
//! The physical turn borrows the actual executor throughout each RPC. Cache
//! handoff captures healthy original custody before releasing funding. Later
//! corruption processing uses that same observation and retains every original
//! admission, consumer promise and allocation after revocation.

use super::{AdmissionJob, backing, eviction, reconcile};
use crate::{
    host_cache::owner::{
        consumer::state as policy, publication::residence::check_snapshot,
        retention::NativeOwnerExecutor,
    },
    publisher_local::{
        client::{EncodedReadObservation, PublisherRunningContext},
        wire::{BodyKey, Operation},
    },
};
use std::{
    fs::File,
    io,
    os::unix::fs::MetadataExt,
    sync::{Arc, Mutex, atomic::AtomicBool},
};

/// Retains the original physical executor across observation or quarantine RPC.
pub(crate) struct PublisherEncodedReadTurn<'turn> {
    executor: &'turn mut NativeOwnerExecutor,
    resource: Arc<Mutex<AdmissionJob>>,
    running: Arc<PublisherRunningContext>,
    original: Option<Arc<EncodedReadObservation>>,
}

impl PublisherEncodedReadTurn<'_> {
    /// Checks the original registration and phase before returning a fixed key.
    ///
    /// # Errors
    /// Refuses another worker, actual resource, synchronized snapshot or phase.
    pub(crate) fn key(
        &self,
        operation: Operation,
    ) -> io::Result<(Arc<PublisherRunningContext>, BodyKey)> {
        self.executor.check_physical_worker()?;
        if !self
            .executor
            .admission_jobs()
            .iter()
            .any(|resource| Arc::ptr_eq(resource, &self.resource))
        {
            return Err(invalid("encoded read turn lost original admission"));
        }
        let job = backing::lock(&self.resource)?;
        let owner = self
            .executor
            .custody()
            .lock()
            .map_err(|_| invalid("encoded read custody poisoned"))?;
        check_snapshot(&owner)?;
        policy::check_bootstrap(&owner, &self.running)?;
        if !job.complete || !Arc::ptr_eq(&job.custody, self.executor.custody()) {
            return Err(invalid(
                "encoded read turn requires original completed custody",
            ));
        }
        let key = eviction::key_for_input(&job.input)?;
        match (&self.original, operation) {
            (None, Operation::InspectBody) => {
                policy::check_ready(self.executor, &owner)?;
                reconcile::verify(&owner, &job)?;
            }
            (Some(original), Operation::Quarantine) if owner.faulted => {
                super::state::check_registration(&owner, &job)?;
                if !job
                    .read_observation
                    .as_ref()
                    .is_some_and(|actual| Arc::ptr_eq(actual, original))
                {
                    return Err(invalid("encoded failure changed original observation"));
                }
                original.check_original(&self.running, &key)?;
            }
            _ => return Err(invalid("encoded read turn changed physical phase")),
        }
        Ok((Arc::clone(&self.running), key))
    }

    /// Checks the returned primary descriptor against both healthy original members.
    ///
    /// # Errors
    /// Refuses changed original payload/custody, missing or foreign descriptors.
    pub(crate) fn check_received(&self, received: &[File]) -> io::Result<()> {
        self.key(Operation::InspectBody)?;
        let [file] = received else {
            return Err(invalid(
                "encoded read inspection requires one primary descriptor",
            ));
        };
        let job = backing::lock(&self.resource)?;
        let original = job
            .files
            .last()
            .and_then(|member| member.readonly.as_ref())
            .ok_or_else(|| invalid("original encoded primary descriptor absent"))?;
        let actual = file.metadata()?;
        let expected = original.metadata()?;
        if (actual.dev(), actual.ino(), actual.len())
            != (expected.dev(), expected.ino(), expected.len())
            || rustix::fs::fcntl_getfl(file)?.intersects(
                rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::RDWR | rustix::fs::OFlags::PATH,
            )
        {
            return Err(invalid("encoded read inspection returned another original"));
        }
        Ok(())
    }

    /// Shares only the original physical owner's bounded failure notifier.
    pub(crate) fn notifier(&self) -> Arc<AtomicBool> {
        self.executor.encoded_failure_notifier()
    }

    /// Checks the exact original observation retained before any failed read.
    ///
    /// # Errors
    /// Refuses an observation from another source or native phase.
    pub(crate) fn check_original(&self, original: &Arc<EncodedReadObservation>) -> io::Result<()> {
        if !self
            .original
            .as_ref()
            .is_some_and(|actual| Arc::ptr_eq(actual, original))
        {
            return Err(invalid(
                "encoded quarantine substituted original observation",
            ));
        }
        self.key(Operation::Quarantine).map(|_| ())
    }
}

/// Captures authenticated original custody before any producer funding release.
///
/// # Errors
/// Refuses stale physical custody, changed original bytes or failed inspection.
pub(super) fn observe(
    executor: &mut NativeOwnerExecutor,
    resource: &Arc<Mutex<AdmissionJob>>,
) -> io::Result<Arc<EncodedReadObservation>> {
    if let Some(original) = backing::lock(resource)?.read_observation.as_ref() {
        original.check_readable()?;
        return Ok(Arc::clone(original));
    }
    let running = executor.admission_context()?;
    running.check_current().map_err(io::Error::other)?;
    let session = Arc::clone(running.publisher_session());
    let mut turn = PublisherEncodedReadTurn {
        executor,
        resource: Arc::clone(resource),
        running,
        original: None,
    };
    let original = session
        .observe_encoded_read(&mut turn)
        .map_err(io::Error::other)?;
    backing::lock(resource)?.read_observation = Some(Arc::clone(&original));
    Ok(original)
}

/// Captures each actual dictionary dependency before exposing a pack read.
///
/// # Errors
/// Refuses exhausted bounds, changed original jobs or failed publisher inspection.
pub(super) fn observe_dependencies(
    executor: &mut NativeOwnerExecutor,
    resource: &Arc<Mutex<AdmissionJob>>,
) -> io::Result<()> {
    let limit = executor
        .custody()
        .lock()
        .map_err(|_| invalid("dependency observation custody poisoned"))?
        .preparation
        .config
        .state
        .records;
    let mut sources = backing::lock(resource)?.dependencies.clone();
    let mut position = 0;
    while position < sources.len() {
        if sources.len() > limit {
            return Err(invalid(
                "dependency observations exceed the original record bound",
            ));
        }
        let source = backing::lock(&sources[position])?;
        let dependencies = source.dependencies.clone();
        drop(source);
        for dependency in dependencies {
            if Arc::ptr_eq(&dependency, resource) {
                return Err(invalid("pack observation dependency cycle"));
            }
            if !sources.iter().any(|seen| Arc::ptr_eq(seen, &dependency)) {
                sources.try_reserve_exact(1).map_err(io::Error::other)?;
                sources.push(dependency);
            }
        }
        position += 1;
    }
    for source in sources.into_iter().rev() {
        observe(executor, &source)?;
    }
    Ok(())
}

/// Processes actual read reports while retaining every original funding promise.
///
/// # Errors
/// Refuses changed original policy/custody and uncertain publisher exchanges.
pub(in crate::host_cache::owner) fn quarantine(
    executor: &mut NativeOwnerExecutor,
    running: Arc<PublisherRunningContext>,
) -> io::Result<()> {
    executor.check_physical_worker()?;
    running.check_current().map_err(io::Error::other)?;
    let mut resources = Vec::new();
    resources
        .try_reserve_exact(executor.admission_jobs().len())
        .map_err(io::Error::other)?;
    resources.extend(executor.admission_jobs().iter().cloned());
    for resource in resources {
        let pending = {
            let job = backing::lock(&resource)?;
            job.read_observation.as_ref().and_then(|original| {
                original
                    .take_failed()
                    .map(|stage| (Arc::clone(original), stage))
            })
        };
        let Some((original, stage)) = pending else {
            continue;
        };
        running.check_current().map_err(io::Error::other)?;
        {
            let mut owner = executor
                .custody()
                .lock()
                .map_err(|_| invalid("failed encoded custody poisoned"))?;
            check_snapshot(&owner)?;
            owner.faulted = true;
        }
        eprintln!(
            "terrane: rejecting original encoded incarnation after native read failure stage={stage}"
        );
        let session = Arc::clone(running.publisher_session());
        let mut turn = PublisherEncodedReadTurn {
            executor,
            resource,
            running: Arc::clone(&running),
            original: Some(Arc::clone(&original)),
        };
        session
            .quarantine_encoded_read(&mut turn, &original)
            .map_err(io::Error::other)?;
    }
    Ok(())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::other(message)
}
