//! Dormant fallback-only session ownership and fixture-gated backing handoff.
//!
//! There is no production entry point. The private session machinery preserves
//! the registration owner and exact prepared connection through synchronous C
//! dispatch. A future production owner must supply independently authenticated
//! consumer backing and connected-FD custody, not a raw reader implementation.

use std::os::fd::{AsRawFd, BorrowedFd};

use aos_filesystem_view::{
    DataPlane, DataReadScratch, DurableStateLimits, ExtendedAttributeLimits, MetadataConnection,
    RegistrationLimits, ReplyScratch, RequestBudget, TeardownSummary, VerifiedObjectReader,
};

use crate::dormant_libfuse::{DormantLibfuseOperationsAdapterV2, ProtectedFuseRegistrationOwnerV2};
use crate::operations::ImmutableOperationLimits;
use crate::{RunError, TransportLimits, abi, callbacks};

mod resident;

pub(crate) struct FallbackState<'owner> {
    pub adapter: DormantLibfuseOperationsAdapterV2,
    pub data: DataPlane,
    pub scratch: DataReadScratch,
    pub durable: DurableStateLimits,
    pub owner: &'owner mut ProtectedFuseRegistrationOwnerV2,
    pub reader: &'owner mut dyn VerifiedObjectReader,
}

/// Runs a repository-owned fallback fixture over genuine sealed backing FDs.
///
/// This function is absent from default builds. It bypasses no backing seal,
/// object digest, registration-journal, callback or FD-role checks. Its fixture
/// connection grants no production consumer disclosure or Mount handoff authority.
/// Each backing is limited to 64 MiB, at most 32 distinct objects and two retained
/// FDs per object; verification retains one 64 KiB buffer. No fetch is performed.
/// Sparse bytes may be tested by the data planner, but allocation and SEEK_HOLE
/// capabilities remain unqualified and disabled.
///
/// # Errors
///
/// Returns an error for invalid profile/bounds, unsafe registration storage,
/// backing admission or integrity failure, cancellation or terminal transport
/// failure. The caller retains borrowed transport descriptors on every path.
#[cfg(any(test, feature = "test-fixtures"))]
#[allow(clippy::too_many_arguments)]
pub fn run_fallback_test_fixture(
    connection: MetadataConnection<'_, '_, '_, '_>,
    data: DataPlane,
    scratch: &mut ReplyScratch,
    owner: &mut ProtectedFuseRegistrationOwnerV2,
    backings: Vec<(
        aos_sandbox_core::ObjectDescriptor,
        aos_sandbox_linux::immutable_file::FsVerityBacking,
    )>,
    connected: BorrowedFd<'_>,
    cancellation: BorrowedFd<'_>,
    limits: TransportLimits,
    budget: RequestBudget,
) -> Result<TeardownSummary, RunError> {
    let mut reader =
        resident::ResidentVerifiedReader::for_fixture(backings, cancellation.as_raw_fd())
            .map_err(|_| RunError::Integrity)?;
    run(
        connection,
        data,
        scratch,
        owner,
        &mut reader,
        connected,
        cancellation,
        limits,
        budget,
    )
}

#[allow(clippy::too_many_arguments)]
fn run(
    mut connection: MetadataConnection<'_, '_, '_, '_>,
    data: DataPlane,
    scratch: &mut ReplyScratch,
    owner: &mut ProtectedFuseRegistrationOwnerV2,
    reader: &mut dyn VerifiedObjectReader,
    connected: BorrowedFd<'_>,
    cancellation: BorrowedFd<'_>,
    limits: TransportLimits,
    budget: RequestBudget,
) -> Result<TeardownSummary, RunError> {
    let encoded = abi::FallbackLimitsV2 {
        abi_major: 2,
        abi_minor: 0,
        struct_size: size_of::<abi::FallbackLimitsV2>() as u32,
        profile: 1,
        reserved: 0,
        metadata: limits.encode()?,
    };
    if !connection.fallback_only_transport_admitted() {
        return Err(RunError::InvalidLimits);
    }
    crate::initialize_metadata(&mut connection, cancellation, limits, budget)?;
    let mut context = callbacks::Context::new(
        connection,
        scratch,
        cancellation.as_raw_fd(),
        limits,
        budget,
    );
    let durable = DurableStateLimits {
        maximum_bytes: 65_536,
        maximum_registration_records: 1,
    };
    let operations = ImmutableOperationLimits {
        maximum_file_handles: 128,
        maximum_read_bytes: limits.maximum_write_bytes as usize,
        extended_attributes: ExtendedAttributeLimits {
            maximum_name_bytes: 255,
            maximum_value_bytes: 4096,
            maximum_list_bytes: 4096,
            maximum_attributes_per_inode: 1,
            maximum_scratch_heap_bytes: 4096,
        },
    };
    let adapter = context
        .prepare_dormant_operations(
            owner,
            durable,
            RegistrationLimits {
                maximum_registrations: 1,
                maximum_open_references: 128,
            },
            operations,
        )
        .map_err(|_| RunError::Integrity)?;
    let read_scratch = DataReadScratch::allocate(
        u64::from(limits.maximum_write_bytes),
        limits.maximum_write_bytes as usize,
    )
    .map_err(|_| RunError::InvalidLimits)?;
    context.fallback = Some(FallbackState {
        adapter,
        data,
        scratch: read_scratch,
        durable,
        owner,
        reader,
    });

    // SAFETY: This private V2 table embeds the exact V1 metadata table and adds
    // only serialized synchronous file callbacks. Context, all borrowed owners,
    // and C reply buffers remain live until the runner returns. No pointer escapes.
    let result = unsafe {
        abi::aos_fuse_transport_run_fallback_v2(
            connected.as_raw_fd(),
            cancellation.as_raw_fd(),
            &callbacks::FALLBACK_OPERATIONS_V2,
            (&mut context as *mut callbacks::Context<'_, '_, '_, '_, '_>).cast(),
            &encoded,
        )
    };
    crate::finish_context(context, result)
}
