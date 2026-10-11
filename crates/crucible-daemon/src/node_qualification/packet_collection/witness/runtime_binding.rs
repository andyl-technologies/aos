//! Retains source-verified local operation identity from the original runner hook.
//!
//! Only the packet native oracle inserts a binding, after inspecting an opaque
//! original completion witness against its independent native/socket evidence.
//! Bytes, labels and persisted records cannot construct this process-local seal.

use std::cell::{Cell, RefCell};

use crucible::node_contract::{OperationToken, OriginalCompletedOperation, WorldActivation};
use crucible_node_contract::ContentRef;

use super::{QualificationError, scope};

const MAXIMUM_BINDING_BYTES: usize = 64 * 1024;
// One selected owner, bounded128-byte IDs/printable media, fixed hash domains and
// decimal U64 coordinates fit this complete two-copy slot. Reserve every future
// slot before Child; actual original fields are counted again before copying.
const MAXIMUM_ENTRY_BYTES: usize = 8192;

pub(super) struct OriginalBindings {
    entries: RefCell<Vec<Option<Binding>>>,
    bytes: Cell<usize>,
}

struct Binding {
    token: OperationToken,
    activation: WorldActivation,
    report: ContentRef,
}

impl OriginalBindings {
    pub(super) fn reserve(cases: usize) -> Result<Self, QualificationError> {
        if cases == 0
            || cases
                .checked_mul(MAXIMUM_ENTRY_BYTES)
                .is_none_or(|size| size > MAXIMUM_BINDING_BYTES)
        {
            return Err(QualificationError::Refused("packet original binding count"));
        }
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(cases)
            .map_err(|_| QualificationError::Refused("packet original binding allocation"))?;
        entries.resize_with(cases, || None);
        Ok(Self {
            entries: RefCell::new(entries),
            bytes: Cell::new(0),
        })
    }

    pub(super) fn retain(
        &self,
        index: usize,
        original: &OriginalCompletedOperation<'_>,
        report: &ContentRef,
    ) -> Result<(), QualificationError> {
        let mut entries = self
            .entries
            .try_borrow_mut()
            .map_err(|_| QualificationError::Refused("packet original bindings busy"))?;
        if index >= entries.len() {
            return Err(QualificationError::Refused("packet original binding index"));
        }
        if let Some(binding) = &entries[index] {
            return binding.authenticate(original, report);
        }
        let admission = original.admission();
        // Before/after ACK cases for one grant must share the same actual local
        // token and activation; another runtime with equal labels is foreign.
        for binding in entries.iter().flatten() {
            if binding.token.operation() == admission.token().operation()
                && (!binding.token.same_authority(admission.token())
                    || !binding.activation.same_authority(admission.activation()))
            {
                return Err(QualificationError::Refused(
                    "foreign packet original operation",
                ));
            }
        }
        let view = scope::activation_view(admission.activation().record());
        // Charge every owned ID/route/activation/ref before cloning handles.
        // Shared native preparation Rc bodies are retained, never expanded.
        let entry_bytes = scope::encoded_size(
            &(
                admission.token().operation(),
                admission.token().route(),
                &view,
                report,
            ),
            MAXIMUM_ENTRY_BYTES / 2,
        )?
        .checked_mul(2)
        .filter(|size| *size <= MAXIMUM_ENTRY_BYTES)
        .ok_or(QualificationError::Refused("packet original entry bytes"))?;
        let credit = self
            .bytes
            .get()
            .checked_add(entry_bytes)
            .filter(|size| *size <= MAXIMUM_BINDING_BYTES)
            .ok_or(QualificationError::Refused("packet original binding bytes"))?;
        entries[index] = Some(Binding {
            token: admission.token().clone(),
            activation: admission.activation().clone(),
            report: report.clone(),
        });
        self.bytes.set(credit);
        Ok(())
    }

    pub(super) fn authenticate(
        &self,
        index: usize,
        original: &OriginalCompletedOperation<'_>,
        report: &ContentRef,
    ) -> Result<(), QualificationError> {
        let entries = self
            .entries
            .try_borrow()
            .map_err(|_| QualificationError::Refused("packet original bindings busy"))?;
        entries
            .get(index)
            .and_then(Option::as_ref)
            .ok_or(QualificationError::Refused(
                "packet original result was not witnessed",
            ))?
            .authenticate(original, report)
    }
}

impl Binding {
    fn authenticate(
        &self,
        original: &OriginalCompletedOperation<'_>,
        report: &ContentRef,
    ) -> Result<(), QualificationError> {
        let admission = original.admission();
        if !self.token.same_authority(admission.token())
            || !self.activation.same_authority(admission.activation())
            || &self.report != report
        {
            return Err(QualificationError::Refused(
                "foreign packet original result identity",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
