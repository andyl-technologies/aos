//! Shares the actual fixed055 helper's role-free native runtime representation.
//!
//! These are the existing Controller helper code/TCTI/crypto/scratch and actual
//! finite inherited stack terms. They grant no Source, Controller, PID1, process,
//! transport, TPM, writer or physical success permission. The real service
//! cgroup backs residual native allocator bookkeeping under RFC-0006.

pub(super) use aos_sandbox_broker::fixed_tpm_helper_runtime::helper_runtime_bytes_v1;

/// Quotes the actual normal helper runtime and four retained zero-rights replies.
pub(in crate::tpm_nv_custody) fn boot_transport_demand_v1(
    stack: rustix::process::Rlimit,
    helper: &std::path::Path,
) -> Option<aos_sandbox_model::ResourceVector> {
    use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
    use aos_sandbox_linux::seqpacket::{RecordSubjectSeqpacketPairOriginalV2, SeqpacketSocket};

    let (pair_bytes, pair_files) = RecordSubjectSeqpacketPairOriginalV2::receiving_obligations_v2()?;
    let (receive_bytes, receive_files) = SeqpacketSocket::closed_zero_rights_receive_obligations_v1(
        crate::recovery::RESPONSE_BYTES,
    )?;
    // One ACK and the three fixed Read/Extend/Read replies remain resident.
    // The shared lower suppliers own their native/parser control geometry.
    let bytes = pair_bytes.checked_mul(2)?
        .checked_add(receive_bytes.checked_mul(4)?)?
        .checked_add(aos_sandbox_linux::pidfd::PidFdProcOriginalsV1::receiving_bytes_v1()?.checked_mul(2)?)?
        .checked_add(std::mem::size_of::<std::process::Command>().checked_mul(2)?)?
        .checked_add(helper.as_os_str().as_encoded_bytes().len().checked_add(1)?.checked_mul(4)?)?;
    let memory = u64::try_from(bytes).ok()?.checked_add(helper_runtime_bytes_v1(stack)?)?;
    // The original fixed helper inventory is the same as Controller: channel,
    // pidfd, held stat/context, both lock loans, stdio/loader/device/config,
    // record subjects and spawn/exec overlap. Pair/receive suppliers add their
    // actual partial acquisition and retained zero-rights overlap separately.
    let files = 19usize.checked_add(pair_files)?.checked_add(receive_files.checked_mul(4)?)?;
    // Initial stat/context capture occurs once after spawn. Its two retained
    // native carriers are priced above; pay the same bounded readers' actual
    // requested traffic here, before the initial native capture can enter.
    let reads = aos_sandbox_linux::pidfd::PidFdProcOriginalsV1::stat_maximum_requested_read_bytes_v1()?
        .checked_add(aos_sandbox_linux::pidfd::PidFdProcOriginalsV1::context_maximum_requested_read_bytes_v1()?)?;
    Some(ResourceVector::ZERO.with(D::MemoryBytes, memory)
        .with(D::OpenFiles, u64::try_from(files).ok()?)
        .with(D::OutputBytes, u64::try_from(reads).ok()?)
        .with(D::ConcurrentOperations, 1))
}
