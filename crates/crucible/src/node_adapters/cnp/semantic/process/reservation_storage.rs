//! Observes the exact unattempted reservation before original Child effects.
//!
//! An attempted reservation cannot masquerade as empty prebirth backing. The
//! caller separately accounts this fixed traversal bank before entering; actual
//! slot callbacks use the typed data-only contract and keep unknown owners open.

use super::*;
use crate::node_adapters::cnp::semantic::retained_storage::{
    CnpRetainedStorageReport, preparation::PreparationCounter,
};
use crate::node_contract::RuntimeError;
use std::mem::{align_of, size_of, size_of_val};

// Match PreparationCounter's shared-layout bound, including its conservative
// trailing padding. An exact sized Rc layout can underquote that observer.
fn quote_shared_storage<T>(maximum: usize) -> Result<usize, RuntimeError> {
    let header = crate::node_contract::NodeRuntime::capture_protocol_shared_header_storage(
        1,
        align_of::<T>(),
        maximum,
    )?;

    size_of::<T>()
        .checked_add(header)
        .filter(|bytes| *bytes <= maximum)
        .ok_or(RuntimeError::ResourceLimit)
}

impl CnpSemanticLaunchReservation {
    /// Returns the fixed nested observer bank required before this data walk.
    pub const fn unlaunched_storage_counter_scratch_data() -> usize {
        size_of::<PreparationCounter>() + Self::unlaunched_descriptor_counter_scratch_data()
    }

    pub(in crate::node_adapters::cnp::semantic::process) const fn unlaunched_descriptor_counter_scratch_data()
    -> usize {
        use super::super::super::packet_complete_source::OriginalCompletedCanonicalAckWorldAdmission;
        use crucible_node_provider::connection::OriginalProtocolSupervisor;
        use std::cell::{BorrowError, Ref};

        type SupervisorLoan = Ref<'static, Option<OriginalProtocolSupervisor>>;
        type AdmissionLoan = Ref<'static, Option<OriginalCompletedCanonicalAckWorldAdmission>>;

        size_of::<&Self>()
            + size_of::<&CnpSemanticProcessCustody>()
            + size_of::<Result<&CnpSemanticProcessCustody, RuntimeError>>()
            + size_of::<Option<&Box<CnpSemanticProcessCustody>>>()
            + size_of::<Result<&Box<CnpSemanticProcessCustody>, RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<Result<Option<usize>, RuntimeError>>()
            + size_of::<Option<usize>>()
            + size_of::<Option<&Box<dyn CnpSemanticProcessSlot>>>()
            + size_of::<Result<&Box<dyn CnpSemanticProcessSlot>, RuntimeError>>()
            + size_of::<&dyn CnpSemanticProcessSlot>()
            // The terminal phase check reborrows both same immutable cells
            // while the descriptor walk retains its original loan pair.
            + 2 * size_of::<SupervisorLoan>()
            + 2 * size_of::<AdmissionLoan>()
            + 2 * size_of::<Result<SupervisorLoan, BorrowError>>()
            + 2 * size_of::<Result<AdmissionLoan, BorrowError>>()
    }

    /// Observes the original unattempted reservation and actual supervisor slot.
    ///
    /// The containing holder counts this owner's inline layout once. This walk
    /// counts its boxed process capsule, independent directory/reference heaps,
    /// actual read-owner Rc and concrete slot backing. It invokes no kernel,
    /// executable, formatter or legacy authority callback. A slot without a
    /// typed observer remains explicitly unknown rather than empty.
    ///
    /// # Errors
    /// Refuses a foreign process, attempted/transferred/populated reservation,
    /// busy backing loan or checked capacity/traversal overrun.
    pub fn unlaunched_retained_requested_storage_precredit_data(
        &self,
        maximum: usize,
    ) -> Result<CnpRetainedStorageReport, RuntimeError> {
        let native = self.unlaunched_storage_origin_precredit_data()?;
        // Preserve these immutable loans across the typed slot observer.
        let _supervisor = native
            .protocol_supervisor
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let _completed = native
            .completed_ack_admission
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let mut counter = PreparationCounter::new(maximum);
        counter.add(size_of::<CnpSemanticProcessCustody>())?;
        counter.path(&native.directory)?;
        counter.content_reference(&native.expected_executable)?;
        counter.rc(&native.read_owner)?;
        let slot = self
            .guard
            .slot
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        counter.add(size_of_val(slot.as_ref()))?;
        match slot.retained_requested_storage_precredit_data(counter.remaining())? {
            Some(bytes) => counter.add(bytes)?,
            None => counter.unknowns.supervisor_slot = true,
        }
        native.read_owner.storage_precredit_data()?;
        Ok(counter.finish())
    }
}

impl CnpSemanticLaunchReservation {
    // This phase is fixed by the genuine reservation, never inferred from a
    // missing executable or a claimed descriptor count. Revocation removes read
    // rights but does not erase retained data; busy owner loans still refuse.
    fn unlaunched_storage_origin_precredit_data(
        &self,
    ) -> Result<&CnpSemanticProcessCustody, RuntimeError> {
        if self.guard.creator_process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.attempted || self.authenticated {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let native = self
            .guard
            .custody
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if native.creator_process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        let supervisor = native
            .protocol_supervisor
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let completed = native
            .completed_ack_admission
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if native.child.is_some()
            || native.original_child.is_some()
            || native.provider_pid != 0
            || native.controller.is_some()
            || supervisor.is_some()
            || native.handshake.is_some()
            || native.extension_handshake.is_some()
            || native.installation_kind.is_some()
            || native.registration.is_some()
            || native.installed_identity.is_some()
            || native.source.is_some()
            || native.acceptance.is_some()
            || native.conformance.is_some()
            || native.collection_plan.is_some()
            || native.runtime.is_some()
            || native.completed_ack_protocol_started
            || completed.is_some()
            || native.rejected_control.is_some()
            || native.group.is_some()
            || native.killed
            || native.reaped.is_some()
            || native.kernel_identity.is_some()
            || native.executable_guard.is_some()
        {
            return Err(RuntimeError::UnsupportedFacet);
        }
        native.read_owner.storage_precredit_data()?;
        Ok(native)
    }

    pub(in crate::node_adapters::cnp::semantic::process) fn unlaunched_descriptor_views_precredit_data(
        &self,
    ) -> Result<usize, RuntimeError> {
        let native = self.unlaunched_storage_origin_precredit_data()?;
        let _supervisor = native
            .protocol_supervisor
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let _completed = native
            .completed_ack_admission
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let count = self
            .guard
            .slot
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .retained_descriptor_views_precredit_data()?
            .ok_or(RuntimeError::UnsupportedFacet)?;
        self.unlaunched_storage_origin_precredit_data()?;
        Ok(count)
    }

    /// Quotes the new unattempted custody from the original borrowed inputs.
    ///
    /// The containing holder counts its reservation inline. Directory and full
    /// reference clones, the complete custody Box, original ReadOwner Rc and
    /// independently boxed slot are included. The caller precredits the fixed
    /// observer bank before the trusted slot's typed data callback.
    ///
    /// # Errors
    /// Refuses a relative/oversized path, unsupported slot, or checked overrun.
    pub fn quote_unlaunched_retained_storage_precredit_data(
        directory: &std::path::Path,
        executable: &ContentRef,
        slot: &dyn CnpSemanticProcessSlot,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        let length = directory.as_os_str().as_encoded_bytes().len();
        if !directory.is_absolute() || length > 4096 {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let mut counter = PreparationCounter::new(maximum);
        counter.add(size_of::<CnpSemanticProcessCustody>())?;
        counter.add(length)?;
        counter.content_reference(executable)?;
        counter.add(quote_shared_storage::<current::ReadOwner>(
            counter.remaining(),
        )?)?;
        counter.add(size_of_val(slot))?;
        counter.add(
            slot.retained_requested_storage_precredit_data(counter.remaining())?
                .ok_or(RuntimeError::UnsupportedFacet)?,
        )?;
        counter.finish().complete_requested_bytes_precredit_data()
    }

    /// Quotes bounded selected acquisition and later original-material checks.
    ///
    /// Returns future retained executable owners, the complete simultaneous
    /// transient bank, and named fixed counter/validation scratch respectively.
    /// The selected constructor uses fixed procfs/namespace/streamed hash banks;
    /// it cannot reserve a changed on-disk executable's full length. Requested
    /// Rust layouts are counted here; kernel resources, compiler frames and
    /// allocator physical overhead remain separate policy obligations.
    ///
    /// # Errors
    /// Refuses an unsupported full reference or checked policy overrun.
    pub fn quote_original_native_startup_acquisition_storage_data(
        executable: &ContentRef,
        maximum: usize,
    ) -> Result<(usize, usize, usize), RuntimeError> {
        use super::super::executable_guard::{FreshCurrentScratch, OriginalExecutable};
        use crate::node_contract::NodeRuntime;
        if executable.hash.algorithm != "blake3-256"
            || executable.hash.domain != "cnp.blob.v1"
            || executable.hash.digest.len() != 64
            || !executable
                .hash
                .digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || executable.media_type != "application/octet-stream"
            || executable.length.get() == 0
            || executable.length.get() > 256 * 1024 * 1024
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        let link = OriginalExecutable::original_native_startup_link_bytes();
        let reference = NodeRuntime::capture_reference_storage(executable)?;
        let retained = quote_shared_storage::<OriginalExecutable>(maximum)?
            .checked_add(quote_shared_storage::<std::fs::File>(maximum)?)
            .and_then(|bytes| bytes.checked_add(32))
            .and_then(|bytes| bytes.checked_add(link))
            .and_then(|bytes| bytes.checked_add(reference))
            .filter(|bytes| *bytes <= maximum)
            .ok_or(RuntimeError::ResourceLimit)?;
        // Initial acquisition retains its scratch while terminal process/pidfd
        // validation opens a second sequential bank. Both exact link banks are
        // simultaneously live; later material checks are conservatively added.
        let transient = link
            .checked_mul(2)
            .filter(|bytes| *bytes <= maximum)
            .ok_or(RuntimeError::ResourceLimit)?;
        let scratch = FreshCurrentScratch::declared_scratch_data()
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(Self::unlaunched_storage_counter_scratch_data()))
            // Pinned AOS std's File::open path conversion uses this fixed bank
            // for the selected /proc/pid/exe spelling, which is under 32 bytes.
            .and_then(|bytes| bytes.checked_add(384))
            .and_then(|bytes| {
                bytes.checked_add(
                super::super::super::packet_complete_source::PacketCompleteAckPeerBootMaterial::
                    original_native_startup_authentication_scratch_data())
            })
            .filter(|bytes| *bytes <= maximum)
            .ok_or(RuntimeError::ResourceLimit)?;
        retained
            .checked_add(transient)
            .and_then(|bytes| bytes.checked_add(scratch))
            .filter(|bytes| *bytes <= maximum)
            .ok_or(RuntimeError::ResourceLimit)?;
        Ok((retained, transient, scratch))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_contract::{U64, canonical};

    struct FlatSlot;
    impl CnpSemanticProcessSlot for FlatSlot {
        fn identity(&self) -> U64 {
            U64::new(913)
        }
        fn retain(&mut self, _original: CnpSemanticProcessCustody) {
            panic!("unlaunched data control must never transfer native custody")
        }
        fn retained_requested_storage_precredit_data(
            &self,
            _maximum: usize,
        ) -> Result<Option<usize>, RuntimeError> {
            Ok(Some(0))
        }
    }

    #[test]
    fn attempted_reservation_cannot_reenter_unlaunched_descriptor_census() {
        let mut reservation = CnpSemanticLaunchReservation::reserve_original_native_startup(
            std::path::PathBuf::from("/tmp/aos-unlaunched-descriptor-data-only"),
            canonical::content_ref(b"fixture executable", "application/octet-stream").unwrap(),
            Box::new(FlatSlot),
        );
        reservation.attempted = true;

        assert_eq!(
            reservation.retained_descriptor_views_precredit_data(),
            Err(RuntimeError::OwnerUnavailable)
        );
        assert_eq!(
            reservation.unlaunched_descriptor_views_precredit_data(),
            Err(RuntimeError::UnsupportedFacet)
        );
        assert!(
            reservation
                .guard
                .custody
                .as_ref()
                .unwrap()
                .original_child
                .is_none()
        );
    }

    #[test]
    fn actual_unlaunched_custody_fits_quote_and_one_short_refuses_unchanged() {
        let directory = std::path::Path::new("/tmp/aos-unlaunched-native-data-only");
        let executable =
            canonical::content_ref(b"fixture executable", "application/octet-stream").unwrap();
        let quoted =
            CnpSemanticLaunchReservation::quote_unlaunched_retained_storage_precredit_data(
                directory,
                &executable,
                &FlatSlot,
                usize::MAX,
            )
            .unwrap();
        let reservation = CnpSemanticLaunchReservation::reserve_original_native_startup(
            directory.to_path_buf(),
            executable.clone(),
            Box::new(FlatSlot),
        );
        let observed = reservation
            .unlaunched_retained_requested_storage_precredit_data(quoted)
            .unwrap()
            .complete_requested_bytes_precredit_data()
            .unwrap();
        assert!(observed <= quoted);
        assert_eq!(
            reservation
                .unlaunched_retained_requested_storage_precredit_data(observed - 1)
                .unwrap_err(),
            RuntimeError::ResourceLimit
        );
        assert_eq!(
            reservation
                .unlaunched_retained_requested_storage_precredit_data(observed)
                .unwrap()
                .complete_requested_bytes_precredit_data()
                .unwrap(),
            observed
        );
        assert!(!reservation.attempted && !reservation.authenticated);
        let custody = reservation.guard.custody.as_ref().unwrap();
        assert!(custody.child.is_none() && custody.original_child.is_none());
    }

    #[test]
    fn selected_acquisition_quote_cannot_shrink_with_measured_elf_length() {
        let small = canonical::content_ref(b"x", "application/octet-stream").unwrap();
        let mut large = small.clone();
        large.length = U64::new(256 * 1024 * 1024);
        let first =
            CnpSemanticLaunchReservation::quote_original_native_startup_acquisition_storage_data(
                &small,
                usize::MAX,
            )
            .unwrap();
        let second =
            CnpSemanticLaunchReservation::quote_original_native_startup_acquisition_storage_data(
                &large,
                usize::MAX,
            )
            .unwrap();
        assert_eq!(first, second);
        let total = first.0 + first.1 + first.2;
        assert_eq!(
            CnpSemanticLaunchReservation::quote_original_native_startup_acquisition_storage_data(
                &small,
                total - 1
            ),
            Err(RuntimeError::ResourceLimit)
        );
        let birth_scratch = crate::node_adapters::cnp::PacketCompleteAckPeerBootMaterial::
            original_native_startup_authentication_scratch_data();
        assert!(total >= birth_scratch);
        assert!(total - birth_scratch < 256 * 1024);
    }
}
