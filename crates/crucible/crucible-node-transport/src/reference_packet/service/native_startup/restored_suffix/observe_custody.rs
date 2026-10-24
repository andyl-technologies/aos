//! Retains raw and typed recurring-Observe ingress before later model effects.
//!
//! This is a closed receive owner, not a dispatcher or execution permit. Its
//! caller must hold the genuine startup16 post-observation witness and debit
//! the independently admitted ingress row before reserving its retained slot.
//! Only the owning dispatcher may close publication after current proof and ACK
//! checks; an inert stage value cannot reopen native reservation custody.

use super::*;
use crate::retained_metadata::serialization_storage::{
    OriginalSerializationStorageData, OriginalSerializationStorageProjection,
    original_json_value_storage_extent_data, original_serialization_tree_node_requested_bytes_data,
};
use crate::retained_metadata::{MetadataObserver, RetainedProtocolMetadataFacts};
use crate::{
    bodies::ObserveRequest,
    envelope::{Envelope, MessageKind, Method},
};
use crucible_node_format::Validate;
use std::mem::size_of;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stage {
    Receiving,
    Raw,
    Typed,
    Dispatched,
    Published,
    Failed,
}

/// Owns one spent original and its independently decoded Observe body.
///
/// This private owner never converts a request or numeric row into permission.
/// Every partial remains observable after rejection, including a decoded body
/// whose generation or binding is subsequently rejected by the actual witness.
pub(crate) struct NativeRestoredSuffixObserveAttempt {
    ordinal: u64,
    original: Option<Envelope>,
    body: Option<ObserveRequest>,
    terminal: Option<Envelope>,
    stage: Stage,
}

impl NativeRestoredSuffixObserveAttempt {
    /// Initializes fixed custody only; no live claim or native permission is created.
    pub(crate) fn new_data(ordinal: u64) -> Self {
        Self {
            ordinal,
            original: None,
            body: None,
            terminal: None,
            stage: Stage::Receiving,
        }
    }

    /// Retains a raw original before any fallible shape checks.
    ///
    /// # Errors
    /// Refuses an occupied or interrupted slot and any unsupported raw shape.
    pub(crate) fn retain_original_data(&mut self, original: Envelope) -> Result<(), ProviderError> {
        let previous = self.stage;
        self.stage = Stage::Failed;
        if previous != Stage::Receiving || self.original.is_some() {
            return Err(invalid());
        }
        self.original = Some(original);
        let original = self.original.as_ref().ok_or_else(invalid)?;
        original.validate()?;
        authenticate_raw_observe_data(original)?;
        self.stage = Stage::Raw;
        Ok(())
    }

    /// Borrows the same retained raw or typed original.
    ///
    /// # Errors
    /// Refuses a missing, interrupted or not-yet-received original.
    pub(crate) fn original_data(&self) -> Result<&Envelope, ProviderError> {
        if !matches!(
            self.stage,
            Stage::Raw | Stage::Typed | Stage::Dispatched | Stage::Published
        ) {
            return Err(invalid());
        }
        self.original.as_ref().ok_or_else(invalid)
    }

    /// Retains the independent typed body before validation can refuse.
    ///
    /// # Errors
    /// Refuses a nonraw slot, short encoded extent or invalid closed Observe body.
    pub(crate) fn decode_body_data(&mut self, frame: usize) -> Result<(), ProviderError> {
        let previous = self.stage;
        self.stage = Stage::Failed;
        if previous != Stage::Raw || self.body.is_some() {
            return Err(invalid());
        }
        let original = self.original.as_ref().ok_or_else(invalid)?;
        let maximum = usize::try_from(
            original_restored_suffix_observe_ingress_row_data(frame)?.requested_peak_data()?,
        )
        .map_err(|_| invalid())?;
        let mut projection = OriginalSerializationStorageProjection::new(maximum)?;
        projection.add_value(&original.body)?;
        let actual = projection.finish(maximum)?;
        if actual.maximum_encoded_bytes > frame {
            return Err(invalid());
        }
        // The pre-read quote separately funds this actual DOM copy, the typed
        // strings and the decoder's transient/error owners. Raw bytes are not
        // treated as a substitute for those allocations.
        self.body = Some(
            serde_json::from_value(serde_json::Value::Object(original.body.clone()))
                .map_err(crucible_node_format::ContractError::from)?,
        );
        let body = self.body.as_ref().ok_or_else(invalid)?;
        body.validate()?;
        if body.after_observation_sequence != U64::new(0)
            || body.maximum_items != U64::new(1)
            || !body.extensions.is_empty()
        {
            return Err(invalid());
        }
        self.stage = Stage::Typed;
        Ok(())
    }

    /// Borrows the independently decoded closed body of the same original.
    ///
    /// # Errors
    /// Refuses a missing body or an interrupted/nondecoded attempt.
    pub(crate) fn body_data(&self) -> Result<&ObserveRequest, ProviderError> {
        if !matches!(
            self.stage,
            Stage::Typed | Stage::Dispatched | Stage::Published
        ) {
            return Err(invalid());
        }
        self.body.as_ref().ok_or_else(invalid)
    }

    /// Checks the private dispatched milestone without issuing a native permit.
    ///
    /// # Errors
    /// Refuses every stage except the once dispatched attempt.
    pub(crate) fn authenticate_dispatched_data(&self) -> Result<(), ProviderError> {
        if self.stage != Stage::Dispatched {
            return Err(invalid());
        }
        Ok(())
    }

    /// Marks dispatch once before the owning current-model proof callback.
    ///
    /// # Errors
    /// Refuses another dispatch or a body that did not pass closed validation.
    pub(crate) fn begin_dispatch_data(&mut self) -> Result<(), ProviderError> {
        let previous = self.stage;
        self.stage = Stage::Failed;
        if previous != Stage::Typed {
            return Err(invalid());
        }
        self.stage = Stage::Dispatched;
        Ok(())
    }

    /// Retains the actual emitted terminal before semantic validation.
    ///
    /// # Errors
    /// Refuses repeated, undispatched or mismatched terminals, retaining partials.
    pub(crate) fn retain_terminal_data(
        &mut self,
        terminal: &Envelope,
    ) -> Result<(), ProviderError> {
        let previous = self.stage;
        self.stage = Stage::Failed;
        if previous != Stage::Dispatched || self.terminal.is_some() {
            return Err(invalid());
        }
        self.terminal = Some(terminal.clone());
        let original = self.original.as_ref().ok_or_else(invalid)?;
        if terminal.message != MessageKind::Response
            || terminal.method != Method::Observe
            || terminal.request_id != original.request_id
            || terminal.session_id != original.session_id
            || terminal.incarnation_id != original.incarnation_id
        {
            return Err(invalid());
        }
        self.stage = Stage::Dispatched;
        Ok(())
    }

    /// Closes only the data milestone after the owning live publication check.
    ///
    /// # Errors
    /// Refuses repeated completion or a missing dispatch/terminal milestone.
    pub(crate) fn complete_publication_data(&mut self) -> Result<(), ProviderError> {
        let previous = self.stage;
        self.stage = Stage::Failed;
        if previous != Stage::Dispatched || self.terminal.is_none() {
            return Err(invalid());
        }
        self.stage = Stage::Published;
        Ok(())
    }

    /// Keeps an interrupted owner permanently unavailable without dropping partials.
    pub(crate) fn interrupt_data(&mut self) {
        self.stage = Stage::Failed;
    }

    /// Visits every actual partial capacity without requiring readiness.
    ///
    /// # Errors
    /// Refuses metadata traversal exhaustion or checked extent overflow.
    pub(crate) fn observe_retained_data(
        &self,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        let Self {
            ordinal,
            original,
            body,
            terminal,
            stage: _,
        } = self;
        observer.observe(ordinal)?;
        observer.observe(original)?;
        observer.observe(terminal)?;
        if let Some(body) = body {
            let ObserveRequest {
                binding_hash,
                owner_generation,
                after_observation_sequence,
                maximum_items,
                extensions,
            } = body;
            observer.observe(binding_hash)?;
            observer.observe(owner_generation)?;
            observer.observe(after_observation_sequence)?;
            observer.observe(maximum_items)?;
            observer.observe(extensions)?;
        }
        Ok(())
    }
}

fn authenticate_raw_observe_data(original: &Envelope) -> Result<(), ProviderError> {
    if original.message != MessageKind::Request
        || original.method != Method::Observe
        || original.operation_id.0.is_some()
        || original.capture_owner_id.0.is_some()
        || !original.extensions.is_empty()
        || original.body.len() != 5
        || original
            .body
            .get("after_observation_sequence")
            .and_then(serde_json::Value::as_str)
            != Some("0")
        || original
            .body
            .get("maximum_items")
            .and_then(serde_json::Value::as_str)
            != Some("1")
        || original
            .body
            .get("extensions")
            .and_then(serde_json::Value::as_object)
            .is_none_or(|v| !v.is_empty())
        || original
            .body
            .get("owner_generation")
            .and_then(serde_json::Value::as_str)
            .is_none()
    {
        return Err(invalid());
    }
    let binding = original
        .body
        .get("binding_hash")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(invalid)?;
    if binding.len() != 3
        || binding.get("algorithm").and_then(serde_json::Value::as_str) != Some("blake3-256")
        || !matches!(
            binding.get("domain").and_then(serde_json::Value::as_str),
            Some("cnp.node-binding.v1" | "cnp.owner-binding.v1")
        )
    {
        return Err(invalid());
    }
    let digest = binding
        .get("digest")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(invalid)?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid());
    }
    let generation = original
        .body
        .get("owner_generation")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(invalid)?;
    if generation.is_empty()
        || generation.len() > 20
        || generation.starts_with('0')
        || !generation.bytes().all(|byte| byte.is_ascii_digit())
        || generation
            .parse::<u64>()
            .ok()
            .filter(|value| *value > 0)
            .is_none()
    {
        return Err(invalid());
    }
    Ok(())
}

/// Quotes one complete raw ingress and its closed typed Observe decoder.
///
/// The retained bound includes both old raw owners and independent typed
/// backing/slot growth. The DOM copy and decoder/error phases remain separate
/// transient terms. This row grants no current-model callback or publication.
///
/// # Errors
/// Refuses an empty frame, a defining projection failure or checked overflow.
pub(crate) fn original_restored_suffix_observe_ingress_row_data(
    frame: usize,
) -> Result<PacketNativeStartupAllocationRow, ProviderError> {
    if frame == 0 {
        return Err(invalid());
    }
    let raw = original_json_value_storage_extent_data(frame)?;
    let growth = frame.checked_mul(2).ok_or_else(invalid)?;
    let slots = size_of::<NativeRestoredSuffixObserveAttempt>()
        .checked_mul(2)
        .ok_or_else(invalid)?;
    let typed_extensions =
        original_serialization_tree_node_requested_bytes_data::<String, serde_json::Value>()?;
    // Raw eligibility fixes all three hash strings before typed allocation.
    // Extensions are an empty tree; U64 decoding has no owned string backing.
    // No arbitrary arrays/maps or unbounded error rendering reach this decoder.
    let typed_strings = "blake3-256".len() + "cnp.owner-binding.v1".len() + 64;
    let retained = sum(&[
        raw.value_dom_requested_bytes
            .checked_mul(3)
            .ok_or_else(invalid)?,
        growth,
        size_of::<Envelope>().checked_mul(9).ok_or_else(invalid)?,
        size_of::<crate::connection::ConnectionIncident>(),
        size_of::<Option<Envelope>>(),
        size_of::<Option<crate::connection::ConnectionIncident>>(),
        slots,
        size_of::<std::cell::RefCell<NativeRestoredSuffixObserveAttempt>>(),
        size_of::<std::rc::Rc<std::cell::RefCell<NativeRestoredSuffixObserveAttempt>>>(),
        crate::retained_metadata::requested_storage::shared_header_storage_data(
            1,
            std::mem::align_of::<std::cell::RefCell<NativeRestoredSuffixObserveAttempt>>(),
        )?,
        size_of::<ObserveRequest>(),
        typed_strings,
        typed_extensions,
        raw.value_dom_requested_bytes,
        size_of::<Envelope>(),
    ])?;
    let transient = sum(&[
        raw.canonical_pass_requested_bytes()?,
        raw.value_dom_requested_bytes,
        growth,
        raw.canonical_pass_requested_bytes()?,
        size_of::<ObserveRequest>(),
        typed_strings,
        20,
    ])?;
    Ok(PacketNativeStartupAllocationRow {
        retained_requested_bytes: quantity(retained)?,
        maximum_simultaneous_transient_bytes: quantity(transient)?,
        declared_counter_scratch_bytes: quantity(
            original_restored_suffix_observe_custody_counter_scratch_data(),
        )?,
    })
}

/// Names the full fixed receive, typed, parser and returned result views.
pub(crate) fn original_restored_suffix_observe_custody_counter_scratch_data() -> usize {
    size_of::<std::rc::Rc<std::cell::RefCell<NativeRestoredSuffixObserveAttempt>>>()
        + size_of::<std::cell::RefCell<NativeRestoredSuffixObserveAttempt>>()
        + size_of::<std::cell::Ref<'static, NativeRestoredSuffixObserveAttempt>>()
        + size_of::<std::cell::RefMut<'static, NativeRestoredSuffixObserveAttempt>>()
        + size_of::<Result<std::cell::Ref<'static, NativeRestoredSuffixObserveAttempt>, std::cell::BorrowError>>()
        + size_of::<Result<std::cell::RefMut<'static, NativeRestoredSuffixObserveAttempt>, std::cell::BorrowMutError>>()
        + size_of::<Result<std::cell::Ref<'static, NativeRestoredSuffixObserveAttempt>, ProviderError>>()
        + size_of::<Result<std::cell::RefMut<'static, NativeRestoredSuffixObserveAttempt>, ProviderError>>()
        + size_of::<NativeRestoredSuffixObserveAttempt>()
        + size_of::<Option<NativeRestoredSuffixObserveAttempt>>()
        + size_of::<&NativeRestoredSuffixObserveAttempt>()
        + size_of::<&mut NativeRestoredSuffixObserveAttempt>()

        + size_of::<Stage>() * 2
        + size_of::<(&Envelope, &serde_json::Map<String, serde_json::Value>, &str, &str)>()
        + size_of::<std::str::Bytes<'static>>()
        + size_of::<std::ops::RangeInclusive<u8>>()
        + size_of::<Result<u64, std::num::ParseIntError>>()
        + size_of::<Option<u64>>()
        + size_of::<ObserveRequest>()
        + size_of::<Option<ObserveRequest>>()
        + size_of::<Option<&ObserveRequest>>()
        + size_of::<Result<ObserveRequest, serde_json::Error>>()
        + size_of::<Result<ObserveRequest, crucible_node_format::ContractError>>()
        + size_of::<Result<(), crucible_node_format::ContractError>>()

        + size_of::<serde_json::Value>()
        + size_of::<serde_json::Map<String, serde_json::Value>>()
        + size_of::<Option<&serde_json::Map<String, serde_json::Value>>>()
        + size_of::<Result<&serde_json::Map<String, serde_json::Value>, ProviderError>>()
        + size_of::<Option<&serde_json::Value>>()
        + size_of::<Option<&str>>()
        + size_of::<Result<&str, ProviderError>>()
        + size_of::<u8>()
        + size_of::<&u8>()
        + size_of::<&mut MetadataObserver<'static>>()
        + size_of::<Result<&ObserveRequest, ProviderError>>()
        + size_of::<Option<Envelope>>()
        + size_of::<Option<&Envelope>>()
        + size_of::<Result<&Envelope, ProviderError>>()

        + size_of::<MetadataObserver<'static>>()
        + size_of::<RetainedProtocolMetadataFacts>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<Result<PacketNativeStartupAllocationRow, ProviderError>>()
        + size_of::<Result<U64, ProviderError>>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<Option<usize>>()
        + size_of::<OriginalSerializationStorageProjection>()
        + size_of::<Result<OriginalSerializationStorageProjection, ProviderError>>()
        + size_of::<OriginalSerializationStorageData>()
        + size_of::<Result<OriginalSerializationStorageData, ProviderError>>()
        + crate::retained_metadata::serialization_storage::original_serialization_counter_scratch_data()
        + crate::retained_metadata::serialization_storage::original_serialization_tree_node_counter_scratch_data()
        + size_of::<Result<u64, std::num::TryFromIntError>>()
        + size_of::<(&u64, &Option<Envelope>, &Option<ObserveRequest>, &Option<Envelope>, &Stage)>()
        + size_of::<(&crucible_node_format::HashRef, &U64, &U64, &U64, &crucible_node_format::Extensions)>()

        + size_of::<[usize; 15]>() + size_of::<[usize; 7]>()
        + size_of::<&[usize]>() + size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<&usize>()
        + crate::retained_metadata::serialization_storage::original_json_value_storage_extent_counter_scratch_data()
}

fn sum(values: &[usize]) -> Result<usize, ProviderError> {
    values.iter().try_fold(0usize, |total, value| {
        total.checked_add(*value).ok_or_else(invalid)
    })
}

fn quantity(value: usize) -> Result<U64, ProviderError> {
    Ok(U64::new(u64::try_from(value).map_err(|_| invalid())?))
}

fn invalid() -> ProviderError {
    ProviderError::Correlation("restored suffix Observe ingress changed or incomplete")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::Nullable;
    use crucible_node_format::canonical;

    fn original() -> Envelope {
        let mut original = crate::envelope::tests::request();
        original.method = Method::Observe;
        original.operation_id = Nullable(None);
        original.capture_owner_id = Nullable(None);
        original.extensions.clear();
        let mut binding = canonical::content_ref(b"binding", "application/json")
            .unwrap()
            .hash;
        binding.domain = "cnp.owner-binding.v1".into();
        let body = ObserveRequest {
            binding_hash: binding,
            owner_generation: U64::new(1),
            after_observation_sequence: U64::new(0),
            maximum_items: U64::new(1),
            extensions: Default::default(),
        };
        original.body = serde_json::to_value(body)
            .unwrap()
            .as_object()
            .unwrap()
            .clone();
        original
    }

    #[test]
    fn actual_observe_decode_keeps_raw_and_typed_backing_after_interruption() {
        let mut owner = NativeRestoredSuffixObserveAttempt::new_data(1);
        owner.retain_original_data(original()).unwrap();
        owner.decode_body_data(4096).unwrap();
        let mut observer = MetadataObserver::new();
        owner.observe_retained_data(&mut observer).unwrap();
        let before = observer.finish();
        assert!(before.string_capacity_bytes > 0);
        assert!(before.tree_containers > 0);

        owner.interrupt_data();
        let mut observer = MetadataObserver::new();
        owner.observe_retained_data(&mut observer).unwrap();
        assert_eq!(observer.finish(), before);
        assert!(owner.original_data().is_err());
        assert!(owner.decode_body_data(4096).is_err());
        assert!(owner.body.is_some());
        assert!(owner.original.is_some());
    }

    #[test]
    fn actual_raw_refusal_precedes_typed_decode_and_keeps_rejected_original() {
        let mut owner = NativeRestoredSuffixObserveAttempt::new_data(1);
        let mut request = original();
        request
            .body
            .insert("maximum_items".into(), serde_json::json!("2"));
        assert!(owner.retain_original_data(request).is_err());
        assert!(owner.body.is_none());
        assert!(owner.original.is_some());
        assert!(owner.decode_body_data(4096).is_err());

        let mut owner = NativeRestoredSuffixObserveAttempt::new_data(2);
        let mut request = original();
        request
            .body
            .insert("owner_generation".into(), serde_json::json!("0"));
        assert!(owner.retain_original_data(request).is_err());
        assert!(owner.decode_body_data(4096).is_err());
        assert!(owner.body.is_none());
        assert_eq!(owner.stage, Stage::Failed);
    }

    #[test]
    fn terminal_failure_retains_actual_original_body_and_mismatched_terminal() {
        let request = original();
        let mut owner = NativeRestoredSuffixObserveAttempt::new_data(1);
        owner.retain_original_data(request.clone()).unwrap();
        owner.decode_body_data(4096).unwrap();
        owner.begin_dispatch_data().unwrap();
        let mut terminal = request.clone();
        terminal.message = MessageKind::Response;
        terminal.request_id = Nullable(Some(
            crucible_node_format::Id::new("foreign-reply").unwrap(),
        ));
        assert!(owner.retain_terminal_data(&terminal).is_err());
        assert_eq!(owner.original.as_ref(), Some(&request));
        assert_eq!(owner.terminal.as_ref(), Some(&terminal));
        assert!(owner.body.is_some());
        assert_eq!(owner.stage, Stage::Failed);
        assert!(owner.complete_publication_data().is_err());
        assert!(owner.begin_dispatch_data().is_err());
        let mut observer = MetadataObserver::new();
        owner.observe_retained_data(&mut observer).unwrap();
        assert!(observer.finish().string_capacity_bytes > 0);
    }

    #[test]
    fn publication_milestone_requires_dispatch_and_terminal_and_never_reopens_attempt() {
        let request = original();
        let mut owner = NativeRestoredSuffixObserveAttempt::new_data(1);
        owner.retain_original_data(request.clone()).unwrap();
        owner.decode_body_data(4096).unwrap();
        assert!(owner.complete_publication_data().is_err());
        assert_eq!(owner.stage, Stage::Failed);

        let mut owner = NativeRestoredSuffixObserveAttempt::new_data(2);
        owner.retain_original_data(request.clone()).unwrap();
        owner.decode_body_data(4096).unwrap();
        owner.begin_dispatch_data().unwrap();
        let mut terminal = request;
        terminal.message = MessageKind::Response;
        owner.retain_terminal_data(&terminal).unwrap();
        // This only checks the inert custody milestone. No boot, proof,
        // currentness witness or sent ACK is manufactured by this control.
        owner.complete_publication_data().unwrap();
        assert_eq!(owner.stage, Stage::Published);
        assert!(owner.complete_publication_data().is_err());
        assert!(owner.begin_dispatch_data().is_err());
        assert!(owner.terminal.is_some() && owner.original.is_some() && owner.body.is_some());
    }
}

#[path = "observe_custody/settled.rs"]
mod settled;
