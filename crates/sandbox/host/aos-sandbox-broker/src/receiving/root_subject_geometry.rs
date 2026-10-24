//! Shares the existing pure strict-Root receiving geometry.
//!
//! These lexical recipes contain no native effect, callback or role admission.
//! Actual native and legacy owners bind their concrete sample/readiness layouts
//! and retain their original error boundary without a new runtime adapter.

/// Expands the full existing native subject/readiness peak DATA law.
#[doc(hidden)]
#[macro_export]
macro_rules! root_subject_receiving_demand_v1 {
    (sample: $sample:ident, readiness: $readiness:ident, error: $error:expr $(,)?) => {{
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
        let invalid = || $error;
        let geometry =
            $sample::receive_geometry_v1().map_err(|_| invalid())?;
        let (native_bytes, native_files) = geometry.receive_obligations_v1();
        let cell = 4096_u64
            + 256
            + std::mem::size_of::<aos_linux_descriptors::Error>() as u64
            + std::mem::size_of::<aos_linux_descriptors::pidfd::PidFdInfo>() as u64;
        let native = 512_u64
            .checked_mul(cell)
            .ok_or_else(invalid)?
            .max(u64::try_from(native_bytes).map_err(|_| invalid())?);
        let membership = aos_sandbox_linux::cgroup::ExactCgroupMembershipReadbackV1::
            dominant_requested_bytes_v1().ok_or_else(invalid)?;
        let memory = native
            .checked_add(u64::try_from(membership).map_err(|_| invalid())?)
            .and_then(|bytes| bytes.checked_add(8 * 4096))
            .and_then(|bytes| {
                bytes.checked_add($readiness::receiving_construction_bytes_v1()?)
            })
            .and_then(|bytes| {
                bytes.checked_add(u64::try_from(
                    $sample::receiving_construction_bytes_v1()?,
                ).ok()?)
            })
            .ok_or_else(invalid)?;
        let files = u64::try_from(native_files)
            .map_err(|_| invalid())?
            .checked_add(10)
            .ok_or_else(invalid)?;
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, memory)
            .with(
                D::MetadataEntries,
                512 + $readiness::receiving_metadata_cells_v1(),
            )
            .with(D::OpenFiles, files))
        }};
}

/// Expands the original fixed Ready DATA law with its concrete owner layout.
#[doc(hidden)]
#[macro_export]
macro_rules! root_ready_fixed_demand_v1 {
    (native: $native:expr, owner: $owner:ty, clock: $clock:expr, error: $error:expr $(,)?) => {{
        use ::aos_sandbox_model::{ResourceDimension as D, ResourceVector};

        let invalid = || $error;
        let native = $native?;
        let frames = ::aos_sandbox_protocol::domain_ledger::create_storage_history::transport::FRAME_HEADER_BYTES + ::aos_sandbox_protocol::domain_ledger::create_storage_history::transport::INDEX_BYTES
            + ::aos_sandbox_protocol::domain_ledger::create_storage_history::transport::FRAME_HEADER_BYTES + ::aos_sandbox_protocol::domain_ledger::create_storage_history::transport::CHUNK_HEADER_BYTES + ::aos_sandbox_protocol::domain_ledger::create_q04_history::CLAIM_CHUNK_BYTES;
        let memory = native.get(D::MemoryBytes)
            .checked_add(frames as u64)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<$owner>() as u64))
            .ok_or_else(invalid)?;
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, memory)
            .with(D::MetadataEntries, native.get(D::MetadataEntries))
            .with(D::OpenFiles, native.get(D::OpenFiles))
            .with(D::NetworkBytes, (::aos_sandbox_protocol::domain_ledger::create_storage_history::transport::FRAME_HEADER_BYTES + ::aos_sandbox_protocol::domain_ledger::create_storage_history::transport::INDEX_BYTES) as u64)
            .with(D::OutputBytes, memory)
            .with(D::LogBytes, 64 * 1024)
            .checked_add($clock?)
            .map_err(|_| invalid())?)
        }};
}

/// Expands the original actual encoded Ready extent and traffic DATA law.
#[doc(hidden)]
#[macro_export]
macro_rules! root_ready_encoded_demand_v1 {
    (index: $index:ident, error: $error:expr $(,)?) => {{
        use ::aos_sandbox_model::{ResourceDimension as D, ResourceVector};

        let invalid = || $error;
        let _ = usize::try_from($index.total()).map_err(|_| invalid())?;
        let memory = $index.total().checked_mul(2).ok_or_else(invalid)?;
        let overhead = u64::from($index.count())
            .checked_mul((::aos_sandbox_protocol::domain_ledger::create_storage_history::transport::FRAME_HEADER_BYTES + ::aos_sandbox_protocol::domain_ledger::create_storage_history::transport::CHUNK_HEADER_BYTES) as u64).ok_or_else(invalid)?;
        let traffic = $index.total().checked_add(overhead).ok_or_else(invalid)?;
        // Only inert encoded storage/copy is admitted here. No typed B decoder,
        // model graph, signing, U or prospective compiler allocation enters.
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, memory)
            .with(D::OutputBytes, memory)
            .with(D::NetworkBytes, traffic))
        }};
}
