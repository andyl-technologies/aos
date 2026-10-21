//! Reads actual policy-selected native object backing before completing cache handoff.
//!
//! The repository independently authorizes and verifies content before invoking
//! this provider and compares its actual output afterward. This provider retains
//! the original native owner, circuit and lower store; it never manufactures
//! readiness, consumer grants, kernel handles or producer funding.

use super::{NativePreparedObject, NativeReadDriver, native_failure};
use std::{io, os::unix::fs::FileExt, time::Duration};
use terrane_format::{
    identity::{Identity, IdentityKind},
    manifest::Manifest,
};
use terrane_sdk::{
    bucket::BucketBinding,
    host::cache::ReassemblyMode,
    repository::ObjectPresentation,
    store::{Clock, ContentStore, StoreErrorKind, StoreFailure, TokioClock},
};

/// Retains actual native custody for the configured object presentation policy.
///
/// Sealing conservatively waits for recently released consumer grace before a
/// genuine sweep and source selection. A grace wait above 300 seconds is refused;
/// elapsed time alone neither releases native resources nor permits transfer.
pub struct NativeObjectPresentation<S> {
    driver: NativeReadDriver<S>,
    mode: ReassemblyMode,
}

impl<S> NativeReadDriver<S> {
    /// Shares the original running owner and lower circuit with object presentation.
    ///
    /// This creates no object, lease, producer job or readiness receipt. Actual
    /// preparation and cleanup occur only during an authorized repository read.
    pub fn presentation(&self, mode: ReassemblyMode) -> NativeObjectPresentation<S> {
        NativeObjectPresentation {
            driver: self.clone(),
            mode,
        }
    }
}

#[async_trait::async_trait]
impl<S: ContentStore + BucketBinding> ObjectPresentation for NativeObjectPresentation<S> {
    async fn read(&self, identity: &Identity, size: usize) -> Result<Vec<u8>, StoreFailure> {
        // The preceding guarded read warms dependencies first. A manifest's
        // first admission may have lacked them; repeat its genuine admission
        // now rather than interpreting lower metadata as native residence.
        let canonical = self.driver.get(identity, None).await?;
        let needs_sealed = if identity.kind() == IdentityKind::Chunk {
            true
        } else {
            let manifest = Manifest::decode_verified(
                &canonical,
                self.driver.native().ready.layout().layout().chunk_profile(),
                identity,
            )
            .map_err(|error| {
                native_failure(io::Error::new(io::ErrorKind::InvalidData, error), identity)
            })?;
            self.mode == ReassemblyMode::Always || manifest.chunks.len() < 2
        };
        if needs_sealed {
            // Guard reads have just released real consumer grants. Their
            // original grace still protects source inodes against transfer.
            // Time only schedules a sweep; actual native removal must confirm
            // quiescence before publication can select any retiring source.
            let delay = self
                .driver
                .native()
                .ready
                .consumer_release_grace()
                .checked_add(Duration::from_secs(1))
                .filter(|delay| *delay <= Duration::from_secs(300))
                .ok_or_else(|| StoreFailure::new(StoreErrorKind::Capacity))?;
            TokioClock
                .sleep(delay)
                .await
                .map_err(|error| native_failure(error, identity))?;
            self.driver
                .native()
                .ready
                .owner()
                .sweep_consumer_leases()
                .await
                .map_err(|error| native_failure(error, identity))?;
        }
        let object = self
            .driver
            .native()
            .prepare_object(identity, self.mode)
            .await?;
        match object {
            NativePreparedObject::Chunked(object) => {
                let bytes = {
                    let mut reader = object.reader();
                    read_exact_object(&mut reader, size)
                        .map_err(|error| native_failure(error, identity))
                };
                let release = object.close().await;
                let bytes = bytes?;
                release?;
                Ok(bytes)
            }
            NativePreparedObject::Sealed(object) => {
                let bytes = read_sealed(object.handle(), size)
                    .map_err(|error| native_failure(error, identity));
                // Cleanup is attempted after failed reads too. Every accepted
                // physical effect remains with the original owner on failure.
                let release = object.into_cache().await;
                let bytes = bytes?;
                release?;
                Ok(bytes)
            }
        }
    }
}

fn allocation(size: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(size).map_err(io::Error::other)?;
    bytes.resize(size, 0);
    Ok(bytes)
}

fn read_exact_object(reader: &mut impl io::Read, size: usize) -> io::Result<Vec<u8>> {
    let mut bytes = allocation(size)?;
    reader.read_exact(&mut bytes)?;
    let mut extra = [0];
    if reader.read(&mut extra)? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "native object size differs",
        ));
    }
    Ok(bytes)
}

fn read_sealed(file: &std::fs::File, size: usize) -> io::Result<Vec<u8>> {
    if file.metadata()?.len() != size as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "native sealed size differs",
        ));
    }
    let mut bytes = allocation(size)?;
    let mut offset = 0;
    while offset < size {
        let end = size.min(offset.saturating_add(65536));
        let count = file.read_at(&mut bytes[offset..end], offset as u64)?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "native sealed object ended",
            ));
        }
        offset += count;
    }
    Ok(bytes)
}
