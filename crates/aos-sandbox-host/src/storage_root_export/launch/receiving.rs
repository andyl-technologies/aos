//! Prices whole root-export custody and restricts the same native label walk.
//!
//! Arithmetic uses the actual compiled suppliers and matching original Launch
//! capacity. Every result is passive DATA; only the genuine parent borrower
//! admits it before construction, growth or native entry. No refund is offered.

use super::*;

impl HostRootMountExportOriginalV2 {
    pub(super) fn fixed_demand() -> Result<ResourceVector> {
        let (admission_bytes, admission_files) =
            DescriptorSubjectSocket::retaining_raw_admission_obligations_v2()
                .ok_or(HostError::ResourceExhausted)?;
        let (reply_bytes, reply_files) = DescriptorSubjectSocket::root_mount_reply_obligations_v2(
            STORAGE_ROOT_EXPORT_RESPONSE_BYTES_V1,
        )
        .ok_or(HostError::ResourceExhausted)?;
        let (active_bytes, active_files, active_names) =
            RuntimeScopeMembershipOriginalV1::active_receiving_demand_v1()
                .ok_or(HostError::ResourceExhausted)?;
        let membership_bytes = ExactCgroupMembershipReadbackV1::dominant_requested_bytes_v1()
            .ok_or(HostError::ResourceExhausted)?;
        let bytes = size_of::<Self>()
            .checked_mul(2)
            .and_then(|bytes| {
                bytes.checked_add(WorkerCgroupOpeningV1::dominant_requested_bytes_v1()?)
            })
            .and_then(|bytes| bytes.checked_add(reply_bytes))
            .and_then(|bytes| bytes.checked_add(admission_bytes))
            .and_then(|bytes| bytes.checked_add(active_bytes))
            .and_then(|bytes| bytes.checked_add(membership_bytes.checked_mul(3)?))
            // Fixed connect/admission, errno/formatting, canonical request and
            // transport stack backing; no dynamically sized model parser here.
            .and_then(|bytes| bytes.checked_add(64 * 1024))
            .ok_or(HostError::ResourceExhausted)?;
        let files = WorkerCgroupOpeningV1::MAXIMUM_RETAINED_FILES_V1
            .checked_add(reply_files)
            .and_then(|n| n.checked_add(active_files))
            .and_then(|n| {
                n.checked_add(3 * ExactCgroupMembershipReadbackV1::MAXIMUM_RETAINED_FILES_V1)
            })
            .and_then(|n| n.checked_add(admission_files))
            .and_then(|n| n.checked_add(2))
            .ok_or(HostError::ResourceExhausted)?;
        Ok(ResourceVector::ZERO
            .with(
                D::MemoryBytes,
                u64::try_from(bytes).map_err(|_| HostError::ResourceExhausted)?,
            )
            .with(
                D::OpenFiles,
                u64::try_from(files).map_err(|_| HostError::ResourceExhausted)?,
            )
            .with(
                D::MetadataEntries,
                u64::try_from(active_names + 8).map_err(|_| HostError::ResourceExhausted)?,
            )
            .with(D::Mounts, 1)
            .with(D::OutputBytes, STORAGE_ROOT_EXPORT_RESPONSE_BYTES_V1 as u64)
            .with(
                D::NetworkBytes,
                STORAGE_ROOT_EXPORT_RESPONSE_BYTES_V1 as u64,
            ))
    }
}

pub(super) fn label_receiving_limits(
    remaining: ResourceVector,
) -> Result<(usize, usize, ResourceVector)> {
    let entries = remaining
        .get(D::MetadataEntries)
        .checked_sub(74)
        .map(|n| (n / 10).min(250_000))
        .ok_or(HostError::ResourceExhausted)?;
    let entries = usize::try_from(entries).map_err(|_| HostError::ResourceExhausted)?;
    let fixed = GuestRootLabelReadOriginalV1::fixed_receiving_footprint_v1()
        .ok_or(HostError::ResourceExhausted)?;
    // Every candidate is pure bounded arithmetic. The enforced owner permits
    // no native scope deeper or wider than this already admitted footprint.
    for depth in (0..=2048).rev() {
        let Some(walk) =
            GuestRootLabelReadOriginalV1::receiving_footprint_with_limits_v2(depth, entries)
        else {
            continue;
        };
        let Some(bytes) = walk.memory_bytes.checked_add(fixed.memory_bytes) else {
            continue;
        };
        let Some(files) = walk.open_files.checked_add(fixed.open_files) else {
            continue;
        };
        let demand = ResourceVector::ZERO
            .with(
                D::MemoryBytes,
                u64::try_from(bytes).map_err(|_| HostError::ResourceExhausted)?,
            )
            .with(
                D::OpenFiles,
                u64::try_from(files).map_err(|_| HostError::ResourceExhausted)?,
            )
            .with(
                D::MetadataEntries,
                u64::try_from(walk.metadata_entries).map_err(|_| HostError::ResourceExhausted)?,
            );
        if remaining.checked_sub(demand).is_ok() {
            return Ok((depth, entries, demand));
        }
    }
    Err(HostError::ResourceExhausted)
}
