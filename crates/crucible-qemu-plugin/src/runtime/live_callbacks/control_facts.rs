//! Copies bounded control-request facts without entering the control handler.
//!
//! The Native ready observer consumes this process-private C record. Its copied
//! ordinal and generations confer no producing operation, deadline, RAM writer
//! fence, Root read, or acknowledgement authority.
// SPDX-License-Identifier: GPL-2.0-only

use crucible_shmem::{FingerprintSampleSlot, NodeSlot};

mod protected_read;
pub(super) use protected_read::{ProtectedReader, ReadOutcome};

/// Matches the factual callback record in the selected Native plugin interface.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::runtime) struct ControlIntentFacts {
    /// The actual paired pending token, including a wrapped even zero.
    pub(in crate::runtime) control_sequence: u64,
    /// The copied command ordinal, which supplies no immutable frontier loan.
    pub(in crate::runtime) command_producer_ordinal: u64,
    /// The actual optional request generation when `sample_present` is set.
    pub(in crate::runtime) sample_generation: u64,
    /// The independent configured slot generation when `sampler_configured` is set.
    pub(in crate::runtime) installed_sample_generation: u64,
    /// Whether this actual callback child owns a configured sampler.
    pub(in crate::runtime) sampler_configured: u32,
    /// Whether the actual pending control tuple requests a sample.
    pub(in crate::runtime) sample_present: u32,
}

/// Reports factual metadata through Native's paid observation output.
///
/// The creating enrollment supplies this actual retained callback child; the
/// Native ready observer independently validates its owning frame and output.
pub(super) extern "C" fn factual_snapshot(
    output: *mut ControlIntentFacts,
    userdata: *mut std::ffi::c_void,
) -> i32 {
    let Some(state) = std::ptr::NonNull::new(userdata.cast::<super::LiveVcpuTimeCallbackState>())
    else {
        return -libc::EINVAL;
    };
    if output.is_null() {
        return -libc::EINVAL;
    }
    // SAFETY: genuine enrollment retains this independently pinned child and
    // its mapping through Native's actual snapshot/return lifetime. This read
    // calls no semantic callback and takes only its inline bounded reader lock.
    let received = unsafe { state.as_ref() }.control_intent_facts();
    if let Some(facts) = received.facts {
        // SAFETY: the matched Native observer supplies its live, aligned,
        // writable factual record. The checked nonnull output is distinct
        // from the retained child and is not a shared-memory wire object.
        // Actual captured fields precede signed post refusal; they grant no
        // continuation and remain retained by the observer on that negative.
        unsafe { output.write(facts) };
    }
    received.status()
}

/// Copies one unchanged pending request and independent configured sample state.
///
/// # Errors
/// Returns `-ENOENT` for an acknowledged request and `-EAGAIN` when the request
/// changes during collection. No request or sample field is acknowledged.
#[cfg(test)]
fn snapshot(
    slot: &NodeSlot,
    sampler: Option<&FingerprintSampleSlot>,
) -> Result<ControlIntentFacts, i32> {
    snapshot_with_interleave(slot, sampler, || {})
}

fn snapshot_with_interleave(
    slot: &NodeSlot,
    sampler: Option<&FingerprintSampleSlot>,
    interleave: impl FnOnce(),
) -> Result<ControlIntentFacts, i32> {
    let control_sequence = slot.control_boundary_token();
    if control_sequence & 1 != 0 {
        return Err(-libc::ENOENT);
    }

    let command_producer_ordinal = slot.control_boundary_fault_command_frontier();
    let sample = slot.control_boundary_capture_request();
    let installed_sample_generation =
        sampler.map(FingerprintSampleSlot::capture_request_generation);
    interleave();
    if slot.control_boundary_token() != control_sequence {
        return Err(-libc::EAGAIN);
    }

    // Pending request fields are immutable under this even sequence. Installed
    // sampler state is an independent observation; a mismatch is preserved.
    Ok(ControlIntentFacts {
        control_sequence: u64::from(control_sequence),
        command_producer_ordinal,
        sample_generation: u64::from(sample.unwrap_or(0)),
        installed_sample_generation: u64::from(installed_sample_generation.unwrap_or(0)),
        sampler_configured: u32::from(sampler.is_some()),
        sample_present: u32::from(sample.is_some()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_request_refuses_without_manufacturing_a_sample() {
        let slot = NodeSlot::new(crucible_shmem::KIND_VM);

        assert_eq!(snapshot(&slot, None), Err(-libc::ENOENT));
        assert_eq!(slot.control_boundary_token(), 1);
    }

    #[test]
    fn request_facts_preserve_configured_sample_mismatch_without_acknowledging() {
        let slot = NodeSlot::new(crucible_shmem::KIND_VM);
        let sampler = FingerprintSampleSlot::new();
        let installed = sampler.request_capture_v1();
        let requested = installed.wrapping_add(2);
        let token = slot
            .request_control_boundary(73, Some(requested))
            .unwrap_or_else(|error| panic!("request should publish: {error}"));

        let observed = snapshot(&slot, Some(&sampler))
            .unwrap_or_else(|status| panic!("pending request should be observable: {status}"));

        assert_eq!(observed.control_sequence, u64::from(token));
        assert_eq!(observed.command_producer_ordinal, 73);
        assert_eq!(observed.sample_generation, u64::from(requested));
        assert_eq!(observed.installed_sample_generation, u64::from(installed));
        assert_eq!(observed.sampler_configured, 1);
        assert_eq!(observed.sample_present, 1);
        assert_eq!(slot.control_boundary_token(), token);
        assert_eq!(sampler.capture_request_generation(), installed);
    }

    #[test]
    fn resident_without_sampler_preserves_actual_paired_request() {
        let slot = NodeSlot::new(crucible_shmem::KIND_VM);
        let token = slot
            .request_control_boundary(0, Some(9))
            .unwrap_or_else(|error| panic!("request should publish: {error}"));

        let observed = snapshot(&slot, None)
            .unwrap_or_else(|status| panic!("pending request should be observable: {status}"));

        assert_eq!(observed.control_sequence, u64::from(token));
        assert_eq!(observed.command_producer_ordinal, 0);
        assert_eq!(observed.sample_generation, 9);
        assert_eq!(observed.sample_present, 1);
        assert_eq!(observed.sampler_configured, 0);
        assert_eq!(observed.installed_sample_generation, 0);
    }

    #[test]
    fn changed_real_publication_refuses_instead_of_combining_requests() {
        let slot = NodeSlot::new(crucible_shmem::KIND_VM);
        slot.request_control_boundary(73, Some(3))
            .unwrap_or_else(|error| panic!("first request should publish: {error}"));

        let observed = snapshot_with_interleave(&slot, None, || {
            slot.acknowledge_control_boundary();
            slot.request_control_boundary(74, Some(5))
                .unwrap_or_else(|error| panic!("next request should publish: {error}"));
        });

        assert_eq!(observed, Err(-libc::EAGAIN));
        assert_eq!(slot.control_boundary_fault_command_frontier(), 74);
        assert_eq!(slot.control_boundary_capture_request(), Some(5));
        assert!(slot.control_boundary_is_requested());
    }
}
