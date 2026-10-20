//! Binds the separately selected input-prepare and commit dialect to native policy.

use super::super::complete_restore::{transfer::*, *};
use super::*;

const PHASE_KEYS: [&str; 6] = [
    PACKET_COMPLETE_RESTORE_PREPARE_EXTENSION,
    PACKET_COMPLETE_RESTORE_PREPARE_PROOF_EXTENSION,
    PACKET_COMPLETE_RESTORE_PREPARE_RECEIPT_EXTENSION,
    PACKET_COMPLETE_RESTORE_COMMIT_EXTENSION,
    PACKET_COMPLETE_RESTORE_COMMIT_PROOF_EXTENSION,
    PACKET_COMPLETE_RESTORE_COMMIT_RECEIPT_EXTENSION,
];

impl Native5Policy {
    pub(crate) fn complete_restore_transfer_schemas() -> Result<[SchemaRef; 7], ProviderError> {
        use PacketCompleteRestoreTransferPhase::{Commit, Prepare};
        use PacketCompleteRestoreTransferSchema::{Proof, Receipt, Request};
        Ok([
            complete_restore_transfer_schema(Prepare, Request)?,
            complete_restore_transfer_schema(Prepare, Proof)?,
            complete_restore_transfer_schema(Prepare, Receipt)?,
            complete_restore_transfer_schema(Commit, Request)?,
            complete_restore_transfer_schema(Commit, Proof)?,
            complete_restore_transfer_schema(Commit, Receipt)?,
            native_restored_record_schema()?,
        ])
    }

    pub(super) fn bind_complete_restore_transfer_definitions(
        &mut self,
    ) -> Result<(), ProviderError> {
        if self.complete_restore_selection
            == Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
        {
            self.complete_restore_transfer_definitions =
                Some(Self::complete_restore_transfer_schemas()?.map(|schema| schema.definition));
        }
        Ok(())
    }

    pub(crate) fn complete_restore_transfer_definitions(&self) -> Option<&[ContentRef; 7]> {
        self.complete_restore_transfer_definitions.as_ref()
    }

    pub(super) fn validate_complete_restore_transfer_content(&self) -> Result<(), ProviderError> {
        self.validate_restore_input_emitter_content()?;
        if self.complete_restore_selection
            != Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
        {
            return if self.complete_restore_transfer_definitions.is_none() {
                Ok(())
            } else {
                Err(ProviderError::Correlation(
                    "native unselected restore transfer definitions",
                ))
            };
        }
        let schemas = Self::complete_restore_transfer_schemas()?;
        if self
            .complete_restore_transfer_definitions
            .as_ref()
            .is_none_or(|actual| {
                actual
                    .iter()
                    .zip(&schemas)
                    .any(|(reference, schema)| reference != &schema.definition)
            })
            || schemas.iter().any(|schema| {
                !self
                    .selection
                    .provider
                    .implementation
                    .formats
                    .contains(schema)
            })
        {
            return Err(ProviderError::Correlation(
                "native restore transfer full definitions differ",
            ));
        }
        Ok(())
    }

    pub(super) fn validate_complete_restore_transfer_negotiation(
        &self,
        authority: &ConnectionAuthority,
    ) -> Result<(), ProviderError> {
        self.validate_restore_input_emitter_negotiation(authority)?;
        if self.complete_restore_selection
            != Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
        {
            return Ok(());
        }
        if PHASE_KEYS.iter().any(|key| {
            !authority
                .selected_features()
                .iter()
                .any(|feature| feature.as_str() == *key)
                || !authority.envelope_extensions().contains(*key)
        }) || [
            PACKET_COMPLETE_RESTORE_TRANSFER_FEATURE,
            PACKET_NATIVE_RESTORED_RECORD_FEATURE,
        ]
        .iter()
        .any(|key| {
            !authority
                .selected_features()
                .iter()
                .any(|feature| feature.as_str() == *key)
        }) {
            return Err(ProviderError::Correlation(
                "native restore transfer negotiated roster differs",
            ));
        }
        authority.ensure_live()
    }

    pub(super) fn verify_complete_restore_transfer_envelope(
        &self,
        authority: &ConnectionAuthority,
        envelope: &Envelope,
        received: &ReceivedBody,
    ) -> Result<bool, ProviderError> {
        if !envelope
            .extensions
            .keys()
            .any(|key| PHASE_KEYS.contains(&key.as_str()))
        {
            return Ok(false);
        }
        if self.complete_restore_selection
            != Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
            || self.complete_restore_transfer_definitions.is_none()
            || envelope.node_id.0.as_ref()
                != Some(&self.selection.realization.bindings[0].compatibility.node_id)
        {
            return Err(ProviderError::Correlation(
                "native selected restore transfer absent",
            ));
        }
        self.validate_complete_restore_transfer_negotiation(authority)?;
        let _projection = if self.fresh_restore_allocation_selection.is_some()
            && envelope.extensions.contains_key(super::super::fresh_restore_allocation::PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING)
        {
            crate::connection::CompleteRestoreTransferProjection::from_envelope_with_fresh_binding_data(envelope)?
        } else {
            crate::connection::CompleteRestoreTransferProjection::from_envelope(envelope)?
        };
        match (envelope.message, received) {
            (MessageKind::Request, ReceivedBody::Request(request))
                if matches!(request.as_ref(), RequestBody::Begin(begin)
                if begin.kind == crate::bodies::BeginKind::PrepareRestore) => {}
            (MessageKind::Response, ReceivedBody::Response(response))
                if matches!(
                    response.shape,
                    crate::bodies::ResponseShape::Completed {
                        operation_state: crate::bodies::OperationState::Completed,
                        ..
                    }
                ) && matches!(
                    response.result,
                    Some(crate::bodies::MethodResult::PrepareRestore(_))
                ) => {}
            _ => {
                return Err(ProviderError::Correlation(
                    "native restore transfer baseline body differs",
                ));
            }
        }
        Ok(true)
    }
}

pub(super) struct TransferPolicyView<'a>(pub(super) &'a Native5Policy);
impl Serialize for TransferPolicyView<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if self.0.complete_restore_selection
            == Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
        {
            (
                "source-private.native5-policy-restore-transfer/15",
                &self.0.complete_restore_transfer_definitions,
                super::restore_policy::CompleteRestorePolicyView(self.0),
            )
                .serialize(serializer)
        } else {
            super::restore_policy::CompleteRestorePolicyView(self.0).serialize(serializer)
        }
    }
}

pub(super) struct TransferCompactPolicyView<'a>(pub(super) &'a Native5Policy);
impl Serialize for TransferCompactPolicyView<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if self.0.complete_restore_selection
            == Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
        {
            (
                "source-private.native5-policy-compact-restore-transfer/15",
                &self.0.complete_restore_transfer_definitions,
                super::restore_policy::CompleteRestoreCompactPolicyView(self.0),
            )
                .serialize(serializer)
        } else {
            super::restore_policy::CompleteRestoreCompactPolicyView(self.0).serialize(serializer)
        }
    }
}

pub(super) struct TransferOwnedPolicyView<'a>(pub(super) &'a Native5Policy);
impl Serialize for TransferOwnedPolicyView<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if self.0.complete_restore_selection
            == Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
        {
            (
                "source-private.native5-policy-owned-restore-transfer/15",
                &self.0.complete_restore_transfer_definitions,
                super::restore_policy::CompleteRestoreOwnedPolicyView(self.0),
            )
                .serialize(serializer)
        } else {
            super::restore_policy::CompleteRestoreOwnedPolicyView(self.0).serialize(serializer)
        }
    }
}

impl Native5Policy {
    pub(crate) fn authenticate_prepare_startup_header_data(
        &self,
        original: &Envelope,
    ) -> Result<(), ProviderError> {
        if self.complete_restore_selection
            != Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
        {
            return Err(ProviderError::Correlation(
                "native Prepare startup selection",
            ));
        }
        crate::connection::authenticate_original_native_prepare_header_data(
            &self.selection,
            self.fresh_restore_allocation_selection().is_some(),
            original,
        )
    }
}
