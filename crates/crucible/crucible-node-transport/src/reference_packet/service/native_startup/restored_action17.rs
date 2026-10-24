//! Retains raw custody before selecting the closed native17 action family.
//!
//! One actual preChild17 bank owns this wrapper before receive. Numeric rows,
//! decoded features and syntax select no native right. The private Boot/index,
//! current Connection/Control/World and a separately debited action remain the
//! mandatory consumer boundary for both variants.

use super::{
    NativeRestoredInputReactive17Attempt, NativeRestoredSettledCaptureAttempt,
    NativeRestoredSettledCaptureUploadAttempt, PacketNativeStartupAllocationRow,
    original_restored_input_reactive17_ingress_row_data,
    original_restored_settled_capture_ingress_counter_scratch_data,
    original_restored_settled_capture_ingress_row_data,
    original_restored_settled_capture_upload_ingress_counter_scratch_data,
    original_restored_settled_capture_upload_ingress_row_data,
};
use crate::reference_packet::service::restored_input_reactive17::RESTORED_INPUT_REACTIVE17_FEATURE;
use crate::reference_packet::service::{
    restored_settled_capture::{
        RESTORED_SETTLED_CAPTURE_FEATURE, upload::RESTORED_SETTLED_CAPTURE_UPLOAD_FEATURE,
    },
    restored_settled_confirmation::PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_FEATURE,
};
use crate::retained_metadata::MetadataObserver;
use crate::{
    ProviderError,
    envelope::{Envelope, Method},
};
use std::{cell::RefCell, mem::size_of};

/// Selects DATA routing only after one actual raw original chose its family.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum NativeRestoredSettledActionFamily17 {
    /// Selects the actual final Capture/confirmation child.
    Capture,
    /// Selects the distinct Source-signed grant-free ordinary Blob child.
    CaptureUpload17,
    /// Selects the actual staged Input or Reactive lifecycle child.
    InputReactive,
}

#[derive(serde::Serialize)]
#[serde(tag = "family", content = "data", rename_all = "snake_case")]
enum Selected {
    Capture(NativeRestoredSettledCaptureAttempt),
    CaptureUpload17(NativeRestoredSettledCaptureUploadAttempt),
    InputReactive(NativeRestoredInputReactive17Attempt),
}

/// Retains each raw/typed partial in the single actual nonrenewing native bank.
/// No public constructor, decoder or row creates a private installed Boot owner.
#[derive(serde::Serialize)]
pub(crate) struct NativeRestoredSettledActionAttempt {
    ordinal: u64,
    original: Option<Envelope>,
    selected: Option<Selected>,
    decoded: bool,
    failed: bool,
}

impl NativeRestoredSettledActionAttempt {
    pub(crate) fn new_data(ordinal: u64) -> Self {
        Self {
            ordinal,
            original: None,
            selected: None,
            decoded: false,
            failed: false,
        }
    }

    /// Moves raw custody into this bank before inspecting any family fields.
    /// A selected child is installed before its fallible syntax checks run.
    pub(crate) fn retain_original_data(&mut self, original: Envelope) -> Result<(), ProviderError> {
        let failed = self.failed;
        self.failed = true;
        if self.original.is_some() || self.selected.is_some() {
            return Err(refused());
        }
        self.original = Some(original);
        // Even a poisoned, never-dispatched vacant slot keeps the newly read
        // original before its eligibility can fail. The receive scope allows
        // exactly one transfer into this slot.
        if failed || self.ordinal == 0 || self.decoded {
            return Err(refused());
        }
        let original = self.original.as_ref().ok_or_else(refused)?;
        let capture = if original.capture_owner_id.0.is_some() {
            if original.execution_owner_id.0.is_some() || original.extensions.len() != 1 {
                return Err(refused());
            }
            let feature = match original.method {
                Method::Begin => RESTORED_SETTLED_CAPTURE_FEATURE,
                Method::BlobBegin | Method::BlobChunk | Method::BlobFinish => {
                    RESTORED_SETTLED_CAPTURE_UPLOAD_FEATURE
                }
                Method::Poll => PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_FEATURE,
                _ => return Err(refused()),
            };
            if !original.extensions.contains_key(feature) {
                return Err(refused());
            }
            true
        } else {
            if original.execution_owner_id.0.is_none() {
                return Err(refused());
            }
            if !matches!(
                original.method,
                Method::Input
                    | Method::Begin
                    | Method::Poll
                    | Method::Retire
                    | Method::Observe
                    | Method::BlobBegin
                    | Method::BlobChunk
                    | Method::BlobFinish
            ) || original.extensions.len() != 1
                || !original
                    .extensions
                    .contains_key(RESTORED_INPUT_REACTIVE17_FEATURE)
            {
                return Err(refused());
            }
            false
        };
        self.selected = Some(
            if capture
                && matches!(
                    original.method,
                    Method::BlobBegin | Method::BlobChunk | Method::BlobFinish
                )
            {
                Selected::CaptureUpload17(NativeRestoredSettledCaptureUploadAttempt::new_data(
                    self.ordinal,
                ))
            } else if capture {
                Selected::Capture(NativeRestoredSettledCaptureAttempt::new_data(self.ordinal))
            } else {
                Selected::InputReactive(NativeRestoredInputReactive17Attempt::new_data(
                    self.ordinal,
                ))
            },
        );
        // No parser, allocation, callback or validation occurs between taking
        // this raw field and installing it in the already retained child.
        let raw = self.original.take().ok_or_else(refused)?;
        match self.selected.as_mut().ok_or_else(refused)? {
            Selected::Capture(child) => child.retain_original_data(raw)?,
            Selected::CaptureUpload17(child) => child.retain_original_data(raw)?,
            Selected::InputReactive(child) => child.retain_original_data(raw)?,
        }
        self.failed = false;
        Ok(())
    }

    pub(crate) fn decode_body_data(&mut self, frame: usize) -> Result<(), ProviderError> {
        let failed = self.failed;
        self.failed = true;
        if failed || self.decoded || self.original.is_some() {
            return Err(refused());
        }
        match self.selected.as_mut().ok_or_else(refused)? {
            Selected::Capture(child) => child.decode_body_data(frame)?,
            Selected::CaptureUpload17(child) => child.decode_body_data(frame)?,
            Selected::InputReactive(child) => child.decode_body_data(frame)?,
        }
        self.decoded = true;
        self.failed = false;
        Ok(())
    }

    /// Borrows raw custody without promoting a failed or merely typed attempt.
    pub(crate) fn original_data(&self) -> Result<&Envelope, ProviderError> {
        if let Some(original) = &self.original {
            return Ok(original);
        }
        match self.selected.as_ref().ok_or_else(refused)? {
            Selected::Capture(child) => child.original_data(),
            Selected::CaptureUpload17(child) => child.original_data(),
            Selected::InputReactive(child) => child.original_data(),
        }
    }

    pub(crate) fn family_data(&self) -> Result<NativeRestoredSettledActionFamily17, ProviderError> {
        if self.failed || !self.decoded {
            return Err(refused());
        }
        match self.selected.as_ref().ok_or_else(refused)? {
            Selected::Capture(_) => Ok(NativeRestoredSettledActionFamily17::Capture),
            Selected::CaptureUpload17(_) => {
                Ok(NativeRestoredSettledActionFamily17::CaptureUpload17)
            }
            Selected::InputReactive(_) => Ok(NativeRestoredSettledActionFamily17::InputReactive),
        }
    }

    /// Borrows only the selected typed Capture child beneath its actual bank.
    pub(crate) fn capture_data_mut(
        &mut self,
    ) -> Result<&mut NativeRestoredSettledCaptureAttempt, ProviderError> {
        if self.failed || !self.decoded {
            return Err(refused());
        }
        match self.selected.as_mut() {
            Some(Selected::Capture(child)) => Ok(child),
            _ => Err(refused()),
        }
    }

    /// Borrows the selected typed Capture child without dispatch permission.
    ///
    /// # Errors
    /// Refuses an incomplete/failed wrapper or another actual selected family.
    pub(crate) fn capture_data(
        &self,
    ) -> Result<&NativeRestoredSettledCaptureAttempt, ProviderError> {
        if self.failed || !self.decoded {
            return Err(refused());
        }
        match self.selected.as_ref() {
            Some(Selected::Capture(child)) => Ok(child),
            _ => Err(refused()),
        }
    }

    /// Borrows only the distinct typed upload child of this actual occurrence.
    ///
    /// # Errors
    /// Refuses raw/failed/undecoded custody or either other selected family.
    pub(crate) fn capture_upload17_data(
        &self,
    ) -> Result<&NativeRestoredSettledCaptureUploadAttempt, ProviderError> {
        if self.failed || !self.decoded {
            return Err(refused());
        }
        match self.selected.as_ref() {
            Some(Selected::CaptureUpload17(child)) => Ok(child),
            _ => Err(refused()),
        }
    }

    /// Borrows the same actual upload destination without issuing a live action.
    ///
    /// # Errors
    /// Refuses raw/failed/undecoded custody or either other selected family.
    pub(crate) fn capture_upload17_data_mut(
        &mut self,
    ) -> Result<&mut NativeRestoredSettledCaptureUploadAttempt, ProviderError> {
        if self.failed || !self.decoded {
            return Err(refused());
        }
        match self.selected.as_mut() {
            Some(Selected::CaptureUpload17(child)) => Ok(child),
            _ => Err(refused()),
        }
    }

    /// Borrows the same typed child without permitting mutation or dispatch.
    pub(crate) fn input_reactive_data(
        &self,
    ) -> Result<&NativeRestoredInputReactive17Attempt, ProviderError> {
        if self.failed || !self.decoded {
            return Err(refused());
        }
        match self.selected.as_ref() {
            Some(Selected::InputReactive(child)) => Ok(child),
            _ => Err(refused()),
        }
    }

    /// Borrows only the selected typed Input/Reactive child beneath that bank.
    pub(crate) fn input_reactive_data_mut(
        &mut self,
    ) -> Result<&mut NativeRestoredInputReactive17Attempt, ProviderError> {
        if self.failed || !self.decoded {
            return Err(refused());
        }
        match self.selected.as_mut() {
            Some(Selected::InputReactive(child)) => Ok(child),
            _ => Err(refused()),
        }
    }

    pub(crate) fn interrupt_data(&mut self) {
        self.failed = true;
        if let Some(child) = self.selected.as_mut() {
            match child {
                Selected::Capture(child) => child.interrupt_data(),
                Selected::CaptureUpload17(child) => child.interrupt_data(),
                Selected::InputReactive(child) => child.interrupt_data(),
            }
        }
    }

    /// Appends actual failed/raw/typed fields without resetting aggregate banks.
    pub(crate) fn observe_settled_history_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        observer.observe(&self.ordinal)?;
        observer.observe(&self.original)?;
        observer.observe(&self.decoded)?;
        observer.observe(&self.failed)?;
        if let Some(selected) = &self.selected {
            match selected {
                Selected::Capture(child) => {
                    child.observe_settled_history_metadata_data(observer)?
                }
                Selected::CaptureUpload17(child) => {
                    child.observe_settled_history_metadata_data(observer)?
                }
                Selected::InputReactive(child) => child.observe_retained_data(observer)?,
            }
        }
        Ok(())
    }
}

/// Quotes each independent receive axis over the exact mutually exclusive union.
/// The actual owner separately funds every lifetime slot and all persistent
/// action/Control/output owners. This MAX discounts no earlier spent original.
pub(crate) fn original_restored_settled_action_ingress_row_data(
    frame: usize,
) -> Result<PacketNativeStartupAllocationRow, ProviderError> {
    let capture = original_restored_settled_capture_ingress_row_data(frame)?;
    let input = original_restored_input_reactive17_ingress_row_data(frame)?;
    let upload = original_restored_settled_capture_upload_ingress_row_data(frame)?;
    let wrapper = size_of::<NativeRestoredSettledActionAttempt>()
        .checked_mul(2)
        .and_then(|n| n.checked_add(size_of::<RefCell<NativeRestoredSettledActionAttempt>>()))
        .and_then(|n| {
            n.checked_add(size_of::<
                std::rc::Rc<RefCell<NativeRestoredSettledActionAttempt>>,
            >())
        })
        .and_then(|n| {
            n.checked_add(
                crate::retained_metadata::requested_storage::shared_header_storage_data(
                    1,
                    std::mem::align_of::<RefCell<NativeRestoredSettledActionAttempt>>(),
                )
                .ok()?,
            )
        })
        .ok_or_else(refused)?;
    let retained = capture
        .retained_requested_bytes
        .get()
        .max(input.retained_requested_bytes.get())
        .max(upload.retained_requested_bytes.get())
        .checked_add(u64::try_from(wrapper).map_err(|_| refused())?)
        .ok_or_else(refused)?;
    let transient = capture
        .maximum_simultaneous_transient_bytes
        .get()
        .max(input.maximum_simultaneous_transient_bytes.get())
        .max(upload.maximum_simultaneous_transient_bytes.get());
    let scratch = capture
        .declared_counter_scratch_bytes
        .get()
        .checked_add(input.declared_counter_scratch_bytes.get())
        .and_then(|n| n.checked_add(upload.declared_counter_scratch_bytes.get()))
        .and_then(|n| {
            n.checked_add(
                u64::try_from(original_restored_settled_action_counter_scratch_data()).ok()?,
            )
        })
        .ok_or_else(refused)?;
    Ok(PacketNativeStartupAllocationRow {
        retained_requested_bytes: crucible_node_format::U64::new(retained),
        maximum_simultaneous_transient_bytes: crucible_node_format::U64::new(transient),
        declared_counter_scratch_bytes: crucible_node_format::U64::new(scratch),
    })
}

pub(crate) fn original_restored_settled_action_counter_scratch_data() -> usize {
    size_of::<NativeRestoredSettledActionCurrent17<'static>>()
        + size_of::<ActionCurrentWithOutput17<'static>>()
        + size_of::<NativeRestoredSettledActionAttempt>()
        + size_of::<Option<NativeRestoredSettledActionAttempt>>()
        + size_of::<Selected>()
        + size_of::<Option<Selected>>()
        + size_of::<NativeRestoredSettledActionFamily17>()
        + size_of::<Result<NativeRestoredSettledActionFamily17, ProviderError>>()
        + size_of::<&Selected>()
        + size_of::<Option<&Selected>>()
        + size_of::<Result<&Selected, ProviderError>>()
        + size_of::<&NativeRestoredSettledActionAttempt>()
        + size_of::<&mut NativeRestoredSettledActionAttempt>()
        + size_of::<&Envelope>()
        + size_of::<Envelope>()
        + size_of::<Option<Envelope>>()
        + size_of::<Option<&Envelope>>()
        + size_of::<Result<&Envelope, ProviderError>>()
        + size_of::<&str>()
        + size_of::<Method>()
        + size_of::<bool>() * 3
        + size_of::<&mut Selected>()
        + size_of::<Option<&mut Selected>>()
        + size_of::<Result<&mut Selected, ProviderError>>()
        + size_of::<Result<&mut NativeRestoredSettledCaptureAttempt, ProviderError>>()
        + size_of::<Result<&mut NativeRestoredSettledCaptureUploadAttempt, ProviderError>>()
        + size_of::<Result<&NativeRestoredSettledCaptureUploadAttempt, ProviderError>>()
        + size_of::<Result<&mut NativeRestoredInputReactive17Attempt, ProviderError>>()
        + size_of::<MetadataObserver<'static>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<PacketNativeStartupAllocationRow>() * 4
        + size_of::<Result<PacketNativeStartupAllocationRow, ProviderError>>()
        + size_of::<Option<usize>>()
        + size_of::<Option<u64>>()
        + size_of::<Result<u64, std::num::TryFromIntError>>()
        + original_restored_settled_capture_ingress_counter_scratch_data()
        + original_restored_settled_capture_upload_ingress_counter_scratch_data()
}

fn refused() -> ProviderError {
    ProviderError::Correlation("closed native17 action bank differs")
}

// crucible-lint: allow panic-shortcut -- raw-bank retention is the observation.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::Nullable;
    use crucible_node_format::Id;

    #[test]
    fn poisoned_vacant_slot_retains_received_raw_without_selecting_a_family() {
        let original = crate::envelope::tests::request();
        let mut attempt = NativeRestoredSettledActionAttempt::new_data(1);
        attempt.interrupt_data();

        assert!(attempt.retain_original_data(original.clone()).is_err());

        assert_eq!(attempt.original_data().unwrap(), &original);
        assert!(attempt.selected.is_none());
        assert!(attempt.family_data().is_err());
        assert!(attempt.decode_body_data(65_536).is_err());
        let mut observer = MetadataObserver::new();
        attempt
            .observe_settled_history_metadata_data(&mut observer)
            .unwrap();
        assert!(observer.finish().string_capacity_bytes > 0);
    }

    #[test]
    fn foreign_family_keeps_raw_original_before_refusing() {
        let mut original = crate::envelope::tests::request();
        original.method = Method::Input;
        original.execution_owner_id = Nullable(None);
        original.capture_owner_id = Nullable(Some(Id::new("foreign-capture-role").unwrap()));
        let mut attempt = NativeRestoredSettledActionAttempt::new_data(1);

        assert!(attempt.retain_original_data(original.clone()).is_err());
        assert_eq!(attempt.original.as_ref(), Some(&original));
        assert!(attempt.selected.is_none());
        assert!(attempt.failed);
        assert!(attempt.decode_body_data(65_536).is_err());
        assert!(attempt.retain_original_data(original).is_err());
        let mut observer = MetadataObserver::new();
        attempt
            .observe_settled_history_metadata_data(&mut observer)
            .unwrap();
        assert!(observer.finish().string_capacity_bytes > 0);
    }
}

/// Borrows one actual Capture union occurrence while its outputs are mutable.
///
/// The occurrence loan is DATA only. Its exact source Rc/index must be checked
/// by every enclosing Boot walker; it supplies no native row or dispatch right.
pub(crate) struct NativeRestoredSettledActionCurrent17<'a> {
    owner: &'a std::rc::Rc<RefCell<NativeRestoredSettledActionAttempt>>,
    index: usize,
    ordinal: &'a u64,
    original: &'a Option<Envelope>,
    selected: super::restored_settled_capture_ingress::NativeCaptureAttemptCurrent17<'a>,
    decoded: &'a bool,
    failed: &'a bool,
}

impl NativeRestoredSettledActionAttempt {
    /// Splits only the exact selected Capture payload of this real shared cell.
    ///
    /// # Errors
    /// Refuses another Rc payload, failed/raw/incomplete union, another selected
    /// family or absent output custody. No scalar index creates a permission.
    pub(crate) fn split_capture_current17_data<'a>(
        &'a mut self,
        owner: &'a std::rc::Rc<RefCell<Self>>,
        index: usize,
    ) -> Result<
        (
            NativeRestoredSettledActionCurrent17<'a>,
            &'a mut super::restored_settled_capture_output::NativeRestoredSettledCaptureOutputs,
        ),
        ProviderError,
    > {
        if !std::ptr::eq(self, owner.as_ref().as_ptr().cast_const()) {
            return Err(refused());
        }
        let Self {
            ordinal,
            original,
            selected,
            decoded,
            failed,
        } = self;
        if *failed || !*decoded || original.is_some() {
            return Err(refused());
        }
        let Some(Selected::Capture(capture)) = selected else {
            return Err(refused());
        };
        let (selected, outputs) = capture.split_outputs_current17_data()?;
        Ok((
            NativeRestoredSettledActionCurrent17 {
                owner,
                index,
                ordinal,
                original,
                selected,
                decoded,
                failed,
            },
            outputs,
        ))
    }
}

impl NativeRestoredSettledActionCurrent17<'_> {
    /// Authenticates the exact enclosing vector occurrence without reborrowing it.
    ///
    /// # Errors
    /// Refuses another ordinal/index or a distinct equal-content Rc allocation.
    pub(crate) fn authenticate_occurrence_data(
        &self,
        index: usize,
        owner: &std::rc::Rc<RefCell<NativeRestoredSettledActionAttempt>>,
    ) -> Result<(), ProviderError> {
        if index != self.index || !std::rc::Rc::ptr_eq(self.owner, owner) {
            return Err(refused());
        }
        Ok(())
    }

    /// Observes the same full union fields and its exact active-recorder cut.
    ///
    /// # Errors
    /// Refuses metadata capacity or checked native-layout overflow.
    pub(crate) fn observe_with_output_cut_metadata_data(
        &self,
        output: &super::restored_settled_capture_output::NativeCaptureOutputCut17<'_>,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        observer.observe(self.ordinal)?;
        observer.observe(self.original)?;
        observer.observe(self.decoded)?;
        observer.observe(self.failed)?;
        self.selected
            .observe_with_output_cut_metadata_data(output, observer)
    }

    /// Borrows its full source serializer with the separately loaned output cut.
    pub(crate) fn borrowed_with_output_cut_data<'a>(
        &'a self,
        output: &'a super::restored_settled_capture_output::NativeCaptureOutputCut17<'a>,
    ) -> impl serde::Serialize + 'a {
        ActionCurrentWithOutput17 {
            source: self,
            output,
        }
    }
}

struct ActionCurrentWithOutput17<'a> {
    source: &'a NativeRestoredSettledActionCurrent17<'a>,
    output: &'a super::restored_settled_capture_output::NativeCaptureOutputCut17<'a>,
}

impl serde::Serialize for ActionCurrentWithOutput17<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        #[derive(serde::Serialize)]
        struct SelectedCapture17<T> {
            family: &'static str,
            data: T,
        }
        let capture = self
            .source
            .selected
            .borrowed_with_output_cut_data(self.output);
        let mut fields = serializer.serialize_struct("NativeRestoredSettledActionCurrent17", 5)?;
        fields.serialize_field("ordinal", self.source.ordinal)?;
        fields.serialize_field("original", self.source.original)?;
        fields.serialize_field(
            "selected",
            &SelectedCapture17 {
                family: "capture",
                data: capture,
            },
        )?;
        fields.serialize_field("decoded", self.source.decoded)?;
        fields.serialize_field("failed", self.source.failed)?;
        fields.end()
    }
}

impl NativeRestoredSettledActionCurrent17<'_> {
    /// Borrows the closed typed current request from this exact shared-cell loan.
    ///
    /// The enclosing Boot still authenticates the actual Rc and vector index.
    /// This method grants no dispatch, debit or native admission permission.
    ///
    /// # Errors
    /// Refuses an incomplete/failed wrapper or another typed action family.
    pub(crate) fn current_capture_cut_original17_data(&self) -> Result<&Envelope, ProviderError> {
        if !*self.decoded || *self.failed || self.original.is_some() {
            return Err(refused());
        }
        self.selected.current_capture_cut_original17_data()
    }
}

impl NativeRestoredSettledActionAttempt {
    /// Lends only a genuine completely published signed Observe17 child.
    ///
    /// Other families and partially published actions remain unsupported here.
    /// The borrowed private child is custody, not permission for another action.
    ///
    /// # Errors
    /// Refuses failed/raw/undecoded wrappers, another family, incomplete
    /// publication or a refusal from the borrowed callback.
    pub(crate) fn with_published_observation_checkpoint17_data<R>(
        &self,
        inspect: impl FnOnce(&Envelope, &Envelope, usize) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        if self.failed || !self.decoded || self.original.is_some() {
            return Err(ProviderError::Correlation(
                "native17 completed observation owner absent",
            ));
        }
        let Some(Selected::InputReactive(child)) = &self.selected else {
            return Err(ProviderError::Correlation(
                "native17 preceding action is not a published observation",
            ));
        };
        let completed = child.published_checkpoint17_data()?;
        inspect(
            completed.original_data(),
            completed.terminal_data(),
            completed.publication_record_data(),
        )
    }
}

#[cfg(test)]
#[path = "restored_action17/upload_tests.rs"]
mod upload_tests;
