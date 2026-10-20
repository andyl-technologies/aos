//! Prices the concrete two-sample peer reservoir without authorizing its work.
//!
//! Counts describe dominant requested carriers with actual kernel/process hard
//! backstops. They are not a transitive allocator census or a reusable grant.

use std::mem::size_of;

use aos_sandbox_core::ResourceDimension as D;
use aos_sandbox_linux::cgroup::{ExactCgroupMembershipReadbackV1, RootInitialCgroupReadbackV1};
use aos_sandbox_linux::unix_stream::UnixStreamOriginalCurrentnessV1;
use aos_systemd::{FixedPid1PropertyArchiveV1, FixedPid1PropertyGeometryV1};

use super::{CreateStorageEndpointRevalidationShapeDataV1, CreateStorageRootPeerReceivingOriginalsV1,
    MATERIALIZED_BYTES, ProductionControllerNormalRootProfileV1, StableRootPeerV1};
use super::sample::PeerSampleV1;

// Preserve the existing diagnostic/control scratch byte allowance. These
// Rust carriers do not nominate namespace entries.
const SAMPLE_CONTROL_CELLS: usize = 50 + 4 + 7;

impl CreateStorageRootPeerReceivingOriginalsV1 {
    /// Supplies the SAME fixed PID1 row's complete passive native geometry.
    pub(crate) fn property_geometry_v1() -> Option<FixedPid1PropertyGeometryV1> {
        FixedPid1PropertyArchiveV1::fixed_property_geometry_v1(MATERIALIZED_BYTES).ok()
    }

    /// Bounds cumulative PID1 wire and diagnostic traffic for a finite caller.
    ///
    /// The caller supplies its actual closed program's maximum number of peer
    /// observations before IO. Each observation has exactly two row attempts.
    pub(crate) fn query_traffic_v1(observations: usize) -> Option<(u64, u64)> {
        let rows = u64::try_from(observations.checked_mul(Self::property_rows_per_observation_v1())?).ok()?;
        let row = Self::property_geometry_v1()?;
        Some((row.wire_io_bytes.checked_mul(rows)?, row.maximum_log_bytes.checked_mul(rows)?))
    }

    pub(in crate::normal_root::client) fn delete_native_peak_v1(
        actual: &ProductionControllerNormalRootProfileV1,
    ) -> Option<aos_sandbox_core::ResourceVector> {
        let (bytes, files, _) = sample_receiving_shape(actual)?;
        // The held first sample can coexist with a failed strict-chunk sample
        // and the separately owed after. These are three real native owners.
        let (stable_bytes, stable_files, _) = stable_receiving_shape_v1()?;
        let memory = bytes.checked_mul(3)?.checked_add(stable_bytes)?;
        Some(aos_sandbox_core::ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(memory).ok()?)
            .with(D::OpenFiles, u64::try_from(files.checked_mul(3)?.checked_add(stable_files)?).ok()?))
    }

    pub(in crate::normal_root::client) fn environment_native_peak_v1(
        actual: &ProductionControllerNormalRootProfileV1,
    ) -> Option<aos_sandbox_core::ResourceVector> {
        let (bytes, files, namespaces) = sample_receiving_shape(actual)?;
        let (stable_bytes, stable_files, stable_namespaces) = stable_receiving_shape_v1()?;
        Some(aos_sandbox_core::ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes.checked_mul(2)?.checked_add(stable_bytes)?).ok()?)
            .with(D::OpenFiles, u64::try_from(files.checked_mul(2)?.checked_add(stable_files)?).ok()?)
            .with(D::MetadataEntries, u64::try_from(namespaces.checked_mul(2)?.checked_add(stable_namespaces)?).ok()?))
    }

    // Five real intervals retain ten independent bookends. At most one failed
    // strict chunk coexists: a refusal prevents entry to every later phase.
    pub(in crate::normal_root::client) fn execution_no_apply_native_peak_v2(
        actual: &ProductionControllerNormalRootProfileV1,
    ) -> Option<aos_sandbox_core::ResourceVector> {
        provisioning_peer_peak_v1(actual, 11, PeerResidenceV1::WithStable)
    }

    // The caller's compiled before/owed array plus one retained failed chunk
    // coexist with the same stable native Root binding. No role or fit is made.
    pub(in crate::normal_root::client) fn retained_bookends_native_peak_v1(
        actual: &ProductionControllerNormalRootProfileV1,
        bookends: usize,
    ) -> Option<aos_sandbox_core::ResourceVector> {
        provisioning_peer_peak_v1(actual, bookends.checked_add(1)?, PeerResidenceV1::WithStable)
    }

    // Opening retains first, failed strict chunk and separately owed after.
    pub(in crate::normal_root::client) fn provisioning_native_peak_v1(
        actual: &ProductionControllerNormalRootProfileV1,
    ) -> Option<aos_sandbox_core::ResourceVector> {
        provisioning_peer_peak_v1(actual, 3, PeerResidenceV1::WithStable)
    }

    // A later phase has two distinct before/after native destinations. Its
    // prepaid entry refusal runs only if that new phase was never allocated.
    pub(in crate::normal_root::client) fn provisioning_turn_native_peak_v1(
        actual: &ProductionControllerNormalRootProfileV1,
    ) -> Option<aos_sandbox_core::ResourceVector> {
        provisioning_peer_peak_v1(actual, 2, PeerResidenceV1::WithStable)
    }

    // The one-shot metadata exchange keeps before, failed chunk and after.
    // It never constructs a future stable-binding owner or another phase.
    pub(in crate::normal_root::client) fn finality_recover_native_peak_v1(
        actual: &ProductionControllerNormalRootProfileV1,
    ) -> Option<aos_sandbox_core::ResourceVector> {
        provisioning_peer_peak_v1(actual, 3, PeerResidenceV1::SamplesOnly)
    }

    pub(crate) fn receiving_shape_v1(
        actual: &ProductionControllerNormalRootProfileV1,
    ) -> Option<CreateStorageEndpointRevalidationShapeDataV1> {
        let (sample_bytes, sample_files, sample_cells) = sample_receiving_shape(actual)?;
        let (stable_bytes, stable_files, stable_cells) = stable_receiving_shape_v1()?;

        Some(CreateStorageEndpointRevalidationShapeDataV1 {
            // The two resident sample allocations are in heap_bytes; one
            // actual constructor can coexist with both once-only destinations.
            inline_bytes: size_of::<Self>().checked_mul(2)?.checked_add(size_of::<PeerSampleV1>())?,
            heap_bytes: sample_bytes.checked_mul(2)?
                .checked_add(stable_bytes)?,
            // Two genuinely simultaneous failed/owed samples plus the stable
            // original hierarchy/child and fragment; no future-drop credit.
            file_descriptors: sample_files.checked_mul(2)?.checked_add(stable_files)?,
            // The stable original keeps only the hierarchy/role and unit
            // fragment names beside the two independent sample destinations.
            metadata_cells: sample_cells.checked_mul(2)?.checked_add(stable_cells)?,
        })
    }
}

// One actual stable hierarchy/role/unit-fragment owner. Every caller uses
// this same retained geometry after the native first anchor transfers.
fn stable_receiving_shape_v1() -> Option<(usize, usize, usize)> {
    Some((size_of::<StableRootPeerV1>().checked_add(64 * 1024 + 4 * 4096)?, 3, 3))
}

enum PeerResidenceV1 { WithStable, SamplesOnly }

fn provisioning_peer_peak_v1(actual: &ProductionControllerNormalRootProfileV1,
    samples: usize, residence: PeerResidenceV1,
) -> Option<aos_sandbox_core::ResourceVector> {
    let (bytes, files, namespaces) = sample_receiving_shape(actual)?;
    let (stable_bytes, stable_files, stable_names) = match residence {
        PeerResidenceV1::WithStable => stable_receiving_shape_v1()?,
        PeerResidenceV1::SamplesOnly => (0, 0, 0),
    };
    Some(aos_sandbox_core::ResourceVector::ZERO
        .with(D::MemoryBytes, u64::try_from(bytes.checked_mul(samples)?
            .checked_add(stable_bytes)?).ok()?)
        .with(D::OpenFiles, u64::try_from(files.checked_mul(samples)?
            .checked_add(stable_files)?).ok()?)
        .with(D::MetadataEntries, u64::try_from(namespaces.checked_mul(samples)?
            .checked_add(stable_names)?).ok()?))
}

// Both financial purposes use the same actual native sample roster. The old
// J namespace allowance remains on its old caller; D uses only bytes/files.
fn sample_receiving_shape(actual: &ProductionControllerNormalRootProfileV1)
    -> Option<(usize, usize, usize)>
{
        let local = actual.local_currentness_receiving_demand_v1()?;
        let row = CreateStorageRootPeerReceivingOriginalsV1::property_geometry_v1()?;
        let (stream_bytes, stream_files, stream_cells) = UnixStreamOriginalCurrentnessV1::receiving_demand_v1()?;
        let membership_bytes = ExactCgroupMembershipReadbackV1::dominant_requested_bytes_v1()?;
        let member_cells = ExactCgroupMembershipReadbackV1::receiving_metadata_cells_v1();

        // Each actual sample retains two complete local destinations, two
        // no-duplicate stream comparisons and two membership owners (socket
        // creator and actual received subject). The two actual archives each
        // have one row. Each actual sample layout below is its distinct lazy
        // Box backing, admitted before allocation. These bytes supply no
        // unassigned metadata or FD credit.
        // Resident queued-clock owners are in PeerSample. Two actual row
        // samples and comparator temporaries coexist with those destinations.
        let sample_bytes = size_of::<PeerSampleV1>()
            .checked_add(size_of::<rustix::time::Timespec>().checked_mul(4)?)?
            .checked_add(usize::try_from(local.get(D::MemoryBytes)).ok()?.checked_mul(2)?)?
            .checked_add(stream_bytes.checked_mul(2)?)?
            .checked_add(membership_bytes.checked_mul(2)?)?
            .checked_add(usize::try_from(row.memory_bytes).ok()?.checked_mul(2)?)?
            .checked_add(FixedPid1PropertyArchiveV1::entry_bytes_v1().checked_mul(4)?)?
            // Six property/canonical/decoded extents and eight bounded unit
            // extents cover retained bytes, normalization and growth overlap.
            .checked_add(MATERIALIZED_BYTES.checked_mul(6 + 8)?)?
            // Actual fixed cgroup/name paths, current errors and formatting
            // scratch remain bounded independently of a received byte count.
            .checked_add(32 * 4096)?
            .checked_add(SAMPLE_CONTROL_CELLS.checked_mul(256)?)?;
        let sample_files = usize::try_from(local.get(D::OpenFiles)).ok()?.checked_mul(2)?
            .checked_add(stream_files.checked_mul(2)?)?
            .checked_add(ExactCgroupMembershipReadbackV1::MAXIMUM_RETAINED_FILES_V1.checked_mul(2)?)?
            .checked_add(6 + 1)?
            .checked_add(usize::try_from(row.open_files).ok()?.checked_mul(2)?)?;
        // The fixed Root hierarchy/role/procs roster and one measured unit
        // fragment are actual native names. Keep the local credential/pin,
        // membership and fixed PID1 row suppliers; no Result, Arc, identity
        // snapshot or once-control field adds a namespace entry.
        let sample_cells = RootInitialCgroupReadbackV1::receiving_namespace_entries_v1()
            .checked_add(1)?
            .checked_add(usize::try_from(local.get(D::MetadataEntries)).ok()?.checked_mul(2)?)?
            .checked_add(stream_cells.checked_mul(2)?)?
            .checked_add(member_cells.checked_mul(2)?)?
            .checked_add(usize::try_from(row.metadata_entries).ok()?.checked_mul(2)?)?;

    Some((sample_bytes, sample_files, sample_cells))
}
