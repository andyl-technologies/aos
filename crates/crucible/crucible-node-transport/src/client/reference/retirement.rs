//! Writes the owning controller's complete private originals after terminal audit.

use std::io::Write;

use crate::{
    ProviderError,
    bodies::{EffectCertainty, OperationState, ResponseShape, decode_request, decode_response},
    envelope::RequestOrigin,
};

use super::ReferenceController;

impl ReferenceController {
    /// Bounds the complete borrowed private history before owning copies.
    ///
    /// The bound includes both request namespaces, original content transfers,
    /// profiles, credentials and the same inert observer. Raw byte credit uses
    /// maximal decimal arrays to conservatively cover base64 expansion without
    /// copying the archive or encoding its byte leaves.
    ///
    /// # Errors
    /// Refuses zero or larger-than64MiB allowances, unsupported probe archives,
    /// incomplete transfers or observations, poisoned custody and exhausted
    /// complete serialization credit. No native or release effect is performed.
    pub fn private_original_history_credit(
        &self,
        maximum_bytes: usize,
    ) -> Result<usize, ProviderError> {
        use crate::client::history_credit::{BootstrapCredit, ByteCredit, Count, Sequence};

        if maximum_bytes == 0 || maximum_bytes > 64 * 1024 * 1024 {
            return Err(ProviderError::ResourceExhausted(
                "original history credit geometry",
            ));
        }
        if self.transmissions.is_some() {
            return Err(ProviderError::Correlation(
                "original probe archives need their own resolver",
            ));
        }
        let observation = self
            .observer
            .as_ref()
            .map(|observer| {
                observer
                    .private_original_credit(maximum_bytes)
                    .map(ByteCredit)
            })
            .transpose()?;
        let conflicts = self
            .conflicts
            .as_ref()
            .map(|recorder| recorder.private_original_history())
            .transpose()?;
        let objects = self.custody.content().retirement_object_credit()?;
        let body = (
            "crucible.private-reference-controller-history.v1",
            BootstrapCredit(&self.bootstrap),
            Sequence(|| {
                self.profile
                    .content_objects()
                    .iter()
                    .map(|object| (&object.reference, &object.bytes))
            }),
            &self.qualifications,
            Sequence(|| self.custody.originals_by_origin(RequestOrigin::Controller)),
            Sequence(|| self.custody.originals_by_origin(RequestOrigin::Provider)),
            objects,
            observation,
        );
        let mut credit = Count::new(maximum_bytes);
        if let Some(conflicts) = conflicts {
            serde_json::to_writer(
                &mut credit,
                &(
                    "crucible.private-reference-controller-conflict-history.v1",
                    &body,
                    conflicts,
                ),
            )
            .map_err(crucible_node_format::ContractError::from)?;
        } else {
            serde_json::to_writer(&mut credit, &body)
                .map_err(crucible_node_format::ContractError::from)?;
        }
        Ok(credit.used())
    }

    /// Writes the actual controller's private original history as data only.
    ///
    /// The body retains bootstrap secrets, both original request namespaces,
    /// content and the same owned inert observation archive. It belongs only
    /// in a private operational sink and grants no cleanup or release authority.
    ///
    /// # Errors
    /// Refuses unsupported probe archives, incomplete transfers or observations,
    /// poisoned original storage, serialization failures and sink failures.
    pub fn write_private_original_history(
        &self,
        output: &mut impl Write,
    ) -> Result<(), ProviderError> {
        if self.transmissions.is_some() {
            return Err(ProviderError::Correlation(
                "original probe archives need their own resolver",
            ));
        }
        let conflicts = self
            .conflicts
            .as_ref()
            .map(|recorder| recorder.private_original_history())
            .transpose()?;
        let observation = self
            .observer
            .as_ref()
            .map(|observer| observer.private_original_snapshot())
            .transpose()?;
        if observation
            .as_ref()
            .is_some_and(|original| !original.recording_complete)
        {
            return Err(ProviderError::Correlation(
                "original observation archive remains incomplete",
            ));
        }
        let objects = self.custody.content().retirement_objects()?;
        let body = (
            "crucible.private-reference-controller-history.v1",
            &self.bootstrap,
            self.profile
                .content_objects()
                .iter()
                .map(|object| (&object.reference, &object.bytes))
                .collect::<Vec<_>>(),
            &self.qualifications,
            self.custody
                .originals_by_origin(RequestOrigin::Controller)
                .collect::<Vec<_>>(),
            self.custody
                .originals_by_origin(RequestOrigin::Provider)
                .collect::<Vec<_>>(),
            objects,
            observation,
        );
        if let Some(conflicts) = conflicts {
            serde_json::to_writer(
                output,
                &(
                    "crucible.private-reference-controller-conflict-history.v1",
                    &body,
                    conflicts,
                ),
            )
            .map_err(crucible_node_format::ContractError::from)?;
        } else {
            serde_json::to_writer(output, &body)
                .map_err(crucible_node_format::ContractError::from)?;
        }
        Ok(())
    }

    /// Exports completed native originals together with their owned observations.
    ///
    /// Completion is checked against the actual controller journal. An inert
    /// observer never issues semantic retirement; the retaining native actor
    /// must additionally authenticate Shutdown, Release and kernel reclamation.
    ///
    /// # Errors
    /// Refuses uncertain or nonterminal original controls, unsupported archives,
    /// incomplete original observations or transfers, and serialization failures.
    pub fn write_owned_completed_originals(
        &self,
        output: &mut impl Write,
    ) -> Result<(), ProviderError> {
        self.validate_completed_originals()?;
        self.write_private_original_history(output)
    }

    /// Exports terminal originals including definitive source-owned refusals.
    ///
    /// This data export preserves each original refusal unchanged. Only a known
    /// baseline error with not-started effects and operation state, no retry,
    /// and no response extensions is terminal here. Actual semantic release and
    /// native reclamation remain separate obligations of the same owning actor.
    /// The completed-only exporter retains its stricter behavior.
    ///
    /// # Errors
    /// Refuses missing, accepted, uncertain, partial, retryable or unknown-code
    /// responses, unsupported probe archives and incomplete private transfers.
    pub fn write_owned_terminal_originals(
        &self,
        output: &mut impl Write,
    ) -> Result<(), ProviderError> {
        for original in self.custody.originals() {
            let response = original
                .response
                .as_ref()
                .ok_or(ProviderError::Correlation(
                    "original terminal control response remains uncertain",
                ))?;
            let request = decode_request(original.request.method, &original.request.body)?;
            let response = decode_response(&request, &response.body)?;
            if !terminal_original(&response.shape) {
                return Err(ProviderError::Correlation(
                    "original terminal control effect remains unresolved",
                ));
            }
        }
        self.write_private_original_history(output)
    }

    fn validate_completed_originals(&self) -> Result<(), ProviderError> {
        for original in self.custody.originals() {
            let response = original
                .response
                .as_ref()
                .ok_or(ProviderError::Correlation(
                    "original control response remains uncertain",
                ))?;
            let request = decode_request(original.request.method, &original.request.body)?;
            let response = decode_response(&request, &response.body)?;
            if !matches!(response.shape, ResponseShape::Completed { .. }) {
                return Err(ProviderError::Correlation(
                    "original control effect remains unresolved",
                ));
            }
        }
        Ok(())
    }

    /// Writes complete private original journals without conferring release authority.
    ///
    /// This data includes bootstrap secrets and must only enter a private
    /// operational custody sink. Any accepted or uncertain original remains
    /// under its existing owner and refuses this completed-control export.
    ///
    /// # Errors
    /// Refuses incomplete, uncertain, foreign or nonterminal originals and
    /// unfinished content transfers. Propagates serialization and sink failures.
    pub fn write_retirement_originals(&self, output: &mut impl Write) -> Result<(), ProviderError> {
        if self.observer.is_some() || self.transmissions.is_some() || self.conflicts.is_some() {
            return Err(ProviderError::Correlation(
                "qualification journals require their owning resolver",
            ));
        }
        for original in self.custody.originals() {
            let response = original
                .response
                .as_ref()
                .ok_or(ProviderError::Correlation(
                    "original control response remains uncertain",
                ))?;
            let request = decode_request(original.request.method, &original.request.body)?;
            let response = decode_response(&request, &response.body)?;
            let terminal = matches!(response.shape, ResponseShape::Completed { .. });
            if !terminal {
                return Err(ProviderError::Correlation(
                    "original control effect remains unresolved",
                ));
            }
        }
        let objects = self.custody.content().retirement_objects()?;
        serde_json::to_writer(
            output,
            &(
                &self.bootstrap,
                self.profile
                    .content_objects()
                    .iter()
                    .map(|object| (&object.reference, &object.bytes))
                    .collect::<Vec<_>>(),
                &self.qualifications,
                self.custody
                    .originals_by_origin(RequestOrigin::Controller)
                    .collect::<Vec<_>>(),
                self.custody
                    .originals_by_origin(RequestOrigin::Provider)
                    .collect::<Vec<_>>(),
                objects,
            ),
        )
        .map_err(crucible_node_format::ContractError::from)?;
        Ok(())
    }
}

// Refusal records are retained data, never native release authority.
fn terminal_original(shape: &ResponseShape) -> bool {
    match shape {
        ResponseShape::Completed {
            operation_state: OperationState::Completed,
            ..
        } => true,
        ResponseShape::Error {
            operation_state: OperationState::NotStarted,
            error,
            extensions,
        } => {
            !error.retryable
                && extensions.is_empty()
                && error.effect == EffectCertainty::NotStarted
                && error.baseline_handling().1 == EffectCertainty::NotStarted
        }
        _ => false,
    }
}

#[cfg(test)]
mod terminal_tests {
    use super::*;
    use crate::bodies::ErrorRecord;
    use crucible_node_format::Extensions;

    fn refusal() -> ResponseShape {
        ResponseShape::Error {
            operation_state: OperationState::NotStarted,
            error: ErrorRecord {
                code: "CONFLICT".into(),
                message: "original refusal".into(),
                effect: EffectCertainty::NotStarted,
                retryable: false,
                details: Default::default(),
            },
            extensions: Extensions::new(),
        }
    }

    #[test]
    fn only_definitive_original_refusals_are_terminal() {
        let source = refusal();
        assert!(terminal_original(&source));
        for state in [
            OperationState::Running,
            OperationState::Unknown,
            OperationState::Completed,
        ] {
            let mut changed = source.clone();
            if let ResponseShape::Error {
                operation_state, ..
            } = &mut changed
            {
                *operation_state = state;
            }
            assert!(!terminal_original(&changed));
        }
        for effect in [
            EffectCertainty::Unknown,
            EffectCertainty::InProgress,
            EffectCertainty::Completed,
        ] {
            let mut changed = source.clone();
            if let ResponseShape::Error { error, .. } = &mut changed {
                error.effect = effect;
            }
            assert!(!terminal_original(&changed));
        }
        let mut changed = source.clone();
        if let ResponseShape::Error { error, .. } = &mut changed {
            error.retryable = true;
        }
        assert!(!terminal_original(&changed));
        changed = source.clone();
        if let ResponseShape::Error { error, .. } = &mut changed {
            error.code = "unqualified-extension-error".into();
        }
        assert!(!terminal_original(&changed));
        changed = source;
        if let ResponseShape::Error { extensions, .. } = &mut changed {
            extensions.insert("foreign".into(), serde_json::Value::Bool(true));
        }
        assert!(!terminal_original(&changed));
    }
}
