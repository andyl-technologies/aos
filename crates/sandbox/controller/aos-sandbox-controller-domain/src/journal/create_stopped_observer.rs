//! Fences cold public Create success without an authenticated recovery owner.
//!
//! A protected row is historical DATA. Restart does not recreate the old live
//! C23, its monotone liabilities, Root socket or prepaid terminal destinations.
//! This fixed-size observer therefore denies a cold version-six Succeeded
//! Create while that actual native recovery provider is unavailable. It never
//! parses another Source graph without payment or supplies a positive adopter.

use std::error::Error;

use aos_sandbox_model::OperationId;
use aos_sandbox_protocol::domain_ledger::operation::{OperationRecord, decode_operation, decode_operation_key};
use aos_sandbox_protocol::domain_ledger::public_operation::{OperationState, PublicOperationDataError};
use aos_sandbox_protocol::public_api::PublicOperationMethodV1;

use super::{Journal, JournalError, RecordNamespace};
use crate::source_domain::ProtectedSourceDomainJournalOwnerV1;

/// Reports a fenced cold observer without replacing its retained original cause.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("cold Create success lacks authenticated native recovery custody")]
#[doc(hidden)]
pub struct CreateStoppedColdObserverClosedV1;

#[derive(Debug, thiserror::Error)]
enum ObserverFailureV1 {
    #[error("cold Create has conflicting or malformed parent Effect identity")]
    Shape,
    #[error("cold Create {0} has no authenticated native recovery original")]
    NativeRecoveryUnavailable(OperationId),
}

#[derive(Clone, Copy)]
enum FirstV1 { Entry, Shape, Key, Operation, Source, NativeRecovery }

/// Retains the actual fixed-size cold ingress check and its first refusal.
///
/// It grants no recovery, Source mutation, deadline or capacity. Its concrete
/// inline storage is paid through the same compiled Runtime custody header.
#[doc(hidden)]
pub struct CreateStoppedColdObserverOriginalV1 {
    entered: bool,
    no_completed_create: bool,
    entry: Option<Result<(), JournalError>>,
    selected_key: Option<[u8; 20]>,
    key: Option<Result<OperationId, PublicOperationDataError>>,
    operation: Option<Result<OperationRecord, PublicOperationDataError>>,
    source: Option<Result<(), JournalError>>,
    refusal: Option<ObserverFailureV1>,
    first: Option<FirstV1>,
}

impl CreateStoppedColdObserverOriginalV1 {
    /// Creates inert fixed storage for a cold startup observation.
    #[must_use]
    pub const fn new() -> Self {
        Self { entered: false, no_completed_create: false, entry: None,
            selected_key: None, key: None, operation: None, source: None,
            refusal: None, first: None }
    }

    /// Checks actual cold Controller state beside the retained protected Source.
    ///
    /// No native Source IO or semantic graph allocation is entered. Genuine
    /// Source health is checked, but it cannot manufacture the missing prior
    /// Root/native/financial recovery owner. Source/C full semantic replay and
    /// fresh native bookends remain prerequisites for any positive recovery.
    ///
    /// # Errors
    /// Poisons the SAME Controller and refuses missing provenance, malformed
    /// state or a cold Succeeded Create without authenticated recovery custody.
    pub fn observe_once_v1(&mut self, controller: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), CreateStoppedColdObserverClosedV1> {
        self.observe_v1(controller, Some(source))
    }

    pub(crate) fn observe_without_source_once_v1(&mut self, controller: &mut Journal)
        -> Result<(), CreateStoppedColdObserverClosedV1> {
        self.observe_v1(controller, None)
    }

    fn observe_v1(&mut self, controller: &mut Journal,
        source: Option<&ProtectedSourceDomainJournalOwnerV1>,
    ) -> Result<(), CreateStoppedColdObserverClosedV1> {
        if self.entered {
            // The startup caller may retry unrelated discovery before Ready.
            // This cached no-Create result is not a reusable admission grant.
            return if self.no_completed_create && controller.ensure_healthy().is_ok() {
                Ok(())
            } else { Err(CreateStoppedColdObserverClosedV1) };
        }
        self.entered = true;
        self.entry = Some(controller.ensure_protected_authority());
        if !matches!(self.entry, Some(Ok(()))) {
            self.first = Some(FirstV1::Entry);
        } else if let Err(first) = self.inspect_controller_v1(controller) {
            self.first = Some(first);
        } else if self.no_completed_create {
            return Ok(());
        } else {
            if let Some(source) = source {
                self.source = Some(source.journal_ref_v1().ensure_protected_authority());
                if !matches!(self.source, Some(Ok(()))) { self.first = Some(FirstV1::Source); }
            }
            if self.first.is_none() {
                let operation = self.key.as_ref().and_then(|v| v.as_ref().ok()).copied();
                self.refusal = Some(match operation {
                    Some(operation) => ObserverFailureV1::NativeRecoveryUnavailable(operation),
                    None => ObserverFailureV1::Shape,
                });
                self.first = Some(FirstV1::NativeRecovery);
            }
        }
        // Diagnostic Journal.get remains available. Authority/public observers
        // must honor this original intrinsic poison; restoring bytes cannot
        // turn an unavailable recovery owner into a live financial grant.
        controller.native.poison();
        Err(CreateStoppedColdObserverClosedV1)
    }

    fn inspect_controller_v1(&mut self, controller: &Journal) -> Result<(), FirstV1> {
        let mut rows = controller.records(RecordNamespace::Effect)
            .filter(|(_, value)| value.first() == Some(&6));
        let Some((key, _)) = rows.next() else {
            self.no_completed_create = true;
            return Ok(());
        };
        if rows.next().is_some() || key.len() != 20 || key[16..] != [0; 4] {
            self.refusal = Some(ObserverFailureV1::Shape);
            return Err(FirstV1::Shape);
        }
        self.selected_key = key.try_into().ok();
        self.key = Some(decode_operation_key(&key[..16]));
        let operation = self.key.as_ref().and_then(|v| v.as_ref().ok()).copied()
            .ok_or(FirstV1::Key)?;
        let Some(raw) = controller.get(RecordNamespace::Operation, operation.as_bytes()) else {
            self.refusal = Some(ObserverFailureV1::Shape);
            return Err(FirstV1::Shape);
        };
        self.operation = Some(decode_operation(raw));
        let parent = self.operation.as_ref().and_then(|v| v.as_ref().ok()).ok_or(FirstV1::Operation)?;
        if parent.state() != OperationState::Succeeded {
            self.no_completed_create = true;
            return Ok(());
        }
        if parent.effect_count() != 1 || parent.public_operation().is_none_or(|public|
            public.method() != PublicOperationMethodV1::CreateSandbox) {
            self.refusal = Some(ObserverFailureV1::Shape);
            return Err(FirstV1::Shape);
        }
        Ok(())
    }

    /// Borrows the retained actual entry, decoder or unavailable-owner cause.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            FirstV1::Entry => cause(&self.entry),
            FirstV1::Key => cause(&self.key),
            FirstV1::Operation => cause(&self.operation),
            FirstV1::Source => cause(&self.source),
            FirstV1::Shape | FirstV1::NativeRecovery => self.refusal.as_ref().map(|cause| cause as _),
        }
    }
}

impl Default for CreateStoppedColdObserverOriginalV1 {
    fn default() -> Self { Self::new() }
}

fn cause<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}
