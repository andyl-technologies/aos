//! Retains genuine Observe17 comparison, production and publication custody.
//!
//! The containing actual spent ingress owns this eleventh field before funded
//! current comparison or proof production. Historical readers reconstruct only
//! inert counterparts. This owner supplies no Source MAC, row or action grant.

use super::*;
use crate::reference_packet::control::{
    NativeObservation17CheckpointAttempt, NativeObservation17ProductionAttempt,
    NativeObservation17PublishedProductionData,
};

/// Keeps every comparison/producer partial and the actual publication ordinal.
#[derive(serde::Serialize)]
pub(crate) struct NativeObservation17ActionAttempt {
    checkpoint: Option<NativeObservation17CheckpointAttempt>,
    production: Option<NativeObservation17ProductionAttempt>,
    publication_record: Option<usize>,
}

/// Borrows proof banks owned by one genuinely published actual ingress.
pub(crate) struct NativePublishedInputReactive17CheckpointData<'a> {
    original: &'a Envelope,
    terminal: &'a Envelope,
    model: (&'a ContentRef, &'a [u8]),
    restored: (&'a ContentRef, &'a [u8]),
    publication_record: usize,
}

impl<'a> NativePublishedInputReactive17CheckpointData<'a> {
    /// Borrows the same original retained by this published attempt.
    pub(crate) fn original_data(&self) -> &'a Envelope {
        self.original
    }

    /// Borrows its actual retained terminal.
    pub(crate) fn terminal_data(&self) -> &'a Envelope {
        self.terminal
    }

    /// Borrows its complete native model reference and immutable bank.
    pub(crate) fn model_data(&self) -> (&'a ContentRef, &'a [u8]) {
        self.model
    }

    /// Borrows its complete restored proof reference and immutable bank.
    pub(crate) fn restored_data(&self) -> (&'a ContentRef, &'a [u8]) {
        self.restored
    }

    /// Returns the actual publication record saved by the private native scope.
    pub(crate) fn publication_record_data(&self) -> usize {
        self.publication_record
    }
}

impl NativeObservation17ActionAttempt {
    fn new_data() -> Self {
        Self {
            checkpoint: None,
            production: None,
            publication_record: None,
        }
    }

    /// Lends the same retained destination for the funded stopped-model check.
    pub(crate) fn checkpoint_destination_data(
        &mut self,
    ) -> &mut Option<NativeObservation17CheckpointAttempt> {
        &mut self.checkpoint
    }

    /// Lends the same retained destination for the separately funded producer.
    pub(crate) fn production_destination_data(
        &mut self,
    ) -> &mut Option<NativeObservation17ProductionAttempt> {
        &mut self.production
    }

    /// Returns existing publication custody without creating completion.
    pub(crate) fn publication_record_data(&self) -> Option<usize> {
        self.publication_record
    }

    /// Checks the real retained completed comparison before publication.
    ///
    /// # Errors
    /// Refuses absent or partial comparison custody.
    pub(crate) fn authenticate_validated_checkpoint_data(&self) -> Result<(), ProviderError> {
        self.checkpoint
            .as_ref()
            .ok_or_else(invalid)?
            .authenticate_validated_data()
    }

    /// Walks every retained partial without clearing failed custody.
    ///
    /// # Errors
    /// Refuses exhausted metadata banks or checked layout overflow.
    pub(super) fn observe_retained_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self {
            checkpoint,
            production,
            publication_record,
        } = self;
        if let Some(checkpoint) = checkpoint {
            checkpoint.observe_retained_data(observer)?;
        }
        if let Some(production) = production {
            production.observe_retained_data(observer)?;
        }
        observer.observe(publication_record)
    }
}

impl NativeRestoredInputReactive17Attempt {
    /// Lends actual authenticated fields for a nonallocating prospective quote.
    ///
    /// # Errors
    /// Refuses another stage/method, mixed old checkpoint/arguments, missing
    /// authenticated context or a previously initialized observation owner.
    pub(crate) fn observation17_quote_parts_data(
        &self,
    ) -> Result<
        (
            &Envelope,
            &ObserveRequest,
            &PacketRestoredInputReactive17Request,
        ),
        ProviderError,
    > {
        if self.stage != Stage::Authenticated || self.observation.is_some() {
            return Err(invalid());
        }
        self.observation17_fields_data()
    }

    fn observation17_fields_data(
        &self,
    ) -> Result<
        (
            &Envelope,
            &ObserveRequest,
            &PacketRestoredInputReactive17Request,
        ),
        ProviderError,
    > {
        let original = self.original.as_ref().ok_or_else(invalid)?;
        let Some(Body::Observe(body)) = &self.body else {
            return Err(invalid());
        };
        let request = &self.artifact.as_ref().ok_or_else(invalid)?.request;
        if original.method != Method::Observe
            || request.command != crate::reference_packet::service::restored_input_reactive17::PacketRestoredInputReactive17Command::Observe
            || self.context.as_ref().ok_or_else(invalid)?.request != *request
            || self.arguments.is_some() || self.checkpoint.is_some()
        {
            return Err(invalid());
        }
        Ok((original, body, request))
    }

    /// Retains the actual action header and splits its disjoint funded banks.
    ///
    /// The private native scope calls this after its real debit and Dispatched
    /// transition. The destinations retain every later failed partial; this
    /// custody split does not grant a current comparison or producer effect.
    ///
    /// # Errors
    /// Refuses another stage/method, missing authenticated fields, mixed old
    /// action custody or an attempt whose publication already completed.
    pub(crate) fn observation17_parts_data(
        &mut self,
    ) -> Result<
        (
            &Envelope,
            &ObserveRequest,
            &PacketRestoredInputReactive17Request,
            &mut NativeObservation17ActionAttempt,
        ),
        ProviderError,
    > {
        if self.stage != Stage::Dispatched {
            return Err(invalid());
        }
        self.observation17_fields_data()?;
        if self.observation.is_none() {
            self.observation = Some(NativeObservation17ActionAttempt::new_data());
        }
        let observation = self.observation.as_mut().ok_or_else(invalid)?;
        if observation.publication_record.is_some() {
            return Err(invalid());
        }
        let original = self.original.as_ref().ok_or_else(invalid)?;
        let Some(Body::Observe(body)) = &self.body else {
            return Err(invalid());
        };
        let request = &self.artifact.as_ref().ok_or_else(invalid)?.request;
        Ok((original, body, request, observation))
    }

    /// Borrows real produced proof/body custody before terminal publication.
    ///
    /// This read-only split initializes no destination and supplies no Published
    /// or current-checkpoint claim. The private scope independently joins these
    /// banks to the same Control cache and actual all-ACK publication.
    ///
    /// # Errors
    /// Refuses another stage/method, absent or incomplete comparison/producer,
    /// inconsistent publication custody or changed retained reply/terminal.
    pub(crate) fn observation17_produced_parts_data(
        &self,
    ) -> Result<(&Envelope, NativeObservation17PublishedProductionData<'_>), ProviderError> {
        if !matches!(self.stage, Stage::Dispatched | Stage::Published) {
            return Err(invalid());
        }
        let (original, _, _) = self.observation17_fields_data()?;
        let observation = self.observation.as_ref().ok_or_else(invalid)?;
        if (self.stage == Stage::Published) != observation.publication_record.is_some() {
            return Err(invalid());
        }
        observation.authenticate_validated_checkpoint_data()?;
        let production = observation
            .production
            .as_ref()
            .ok_or_else(invalid)?
            .published_data(original)?;
        if self
            .prepared_reply
            .as_ref()
            .is_some_and(|body| body != production.body_data())
        {
            return Err(invalid());
        }
        if let Some(terminal) = &self.terminal {
            original.matches_response(terminal)?;
            if &terminal.body != production.body_data() {
                return Err(invalid());
            }
        }
        Ok((original, production))
    }

    /// Marks only an already produced observation after genuine publication.
    ///
    /// The sole private native scope calls this after real all-ACK publication,
    /// exact cached output correspondence and its retained exchange checks.
    /// Numeric record DATA alone supplies none of that permission.
    ///
    /// # Errors
    /// Refuses reentry, wrong stage/method, missing comparison/production,
    /// changed terminal/prepared body or an already retained record.
    pub(crate) fn complete_publication_observation17_data(
        &mut self,
        record: usize,
    ) -> Result<(), ProviderError> {
        let previous = self.stage;
        self.stage = Stage::Failed;
        if previous != Stage::Dispatched {
            return Err(invalid());
        }
        let (original, _, _) = self.observation17_fields_data()?;
        let terminal = self.terminal.as_ref().ok_or_else(invalid)?;
        original.matches_response(terminal)?;
        if self.prepared_reply.as_ref() != Some(&terminal.body) {
            return Err(invalid());
        }
        let observation = self.observation.as_ref().ok_or_else(invalid)?;
        if observation.publication_record.is_some() {
            return Err(invalid());
        }
        observation.authenticate_validated_checkpoint_data()?;
        let production = observation
            .production
            .as_ref()
            .ok_or_else(invalid)?
            .published_data(original)?;
        if production.body_data() != &terminal.body {
            return Err(invalid());
        }
        self.observation
            .as_mut()
            .ok_or_else(invalid)?
            .publication_record = Some(record);
        self.stage = Stage::Published;
        Ok(())
    }

    /// Borrows actual completed publication without hashing or decoding DTOs.
    ///
    /// The native Boot lender separately supplies same-actor/Rc/index/current
    /// provenance; this getter cannot promote an inert historical record.
    ///
    /// # Errors
    /// Refuses nonpublished/failed custody, another method, absent or partial
    /// proof owners, changed terminal/body or a missing publication occurrence.
    pub(crate) fn published_checkpoint17_data(
        &self,
    ) -> Result<NativePublishedInputReactive17CheckpointData<'_>, ProviderError> {
        if self.stage != Stage::Published {
            return Err(invalid());
        }
        let (original, _, _) = self.observation17_fields_data()?;
        let terminal = self.terminal.as_ref().ok_or_else(invalid)?;
        original.matches_response(terminal)?;
        if self.prepared_reply.as_ref() != Some(&terminal.body) {
            return Err(invalid());
        }
        let observation = self.observation.as_ref().ok_or_else(invalid)?;
        observation.authenticate_validated_checkpoint_data()?;
        let publication_record = observation.publication_record.ok_or_else(invalid)?;
        let production = observation
            .production
            .as_ref()
            .ok_or_else(invalid)?
            .published_data(original)?;
        if production.body_data() != &terminal.body {
            return Err(invalid());
        }
        Ok(NativePublishedInputReactive17CheckpointData {
            original,
            terminal,
            model: production.model_data(),
            restored: production.restored_data(),
            publication_record,
        })
    }
}

/// Names concrete retained-owner/getter views before an actual borrowed walk.
pub(crate) fn original_native_observation17_retained_counter_scratch_data() -> usize {
    size_of::<NativeObservation17ActionAttempt>()
        + size_of::<NativePublishedInputReactive17CheckpointData<'static>>()
        + size_of::<(
            &Envelope,
            &ObserveRequest,
            &PacketRestoredInputReactive17Request,
        )>()
        + size_of::<(
            &Envelope,
            &ObserveRequest,
            &PacketRestoredInputReactive17Request,
            &mut NativeObservation17ActionAttempt,
        )>()
        + size_of::<Result<NativePublishedInputReactive17CheckpointData<'static>, ProviderError>>()
        + size_of::<Result<(), ProviderError>>() * 3
        + NativeObservation17ProductionAttempt::retained_counter_scratch_data()
        + NativeObservation17CheckpointAttempt::retained_counter_scratch_data()
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- These inert grammar/stage controls deliberately panic on invalid setup.
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::protocol_snapshot::owned11::{json_value::HistoricalJsonLimits, typed::Ledger};
    use crate::protocol_snapshot::restored_settled17::{
        current_actions::CurrentInputAttempt17, current_suffix::CurrentAttemptStage17,
    };
    use crate::retained_metadata::records::ValidatedMetadataRecords;

    fn limits() -> HistoricalJsonLimits {
        HistoricalJsonLimits {
            maximum_input_bytes: 65_536,
            maximum_nodes: 4096,
            maximum_depth: 32,
            maximum_owned_backing_bytes: 65_536,
            maximum_tree_entries: 1024,
        }
    }

    #[test]
    fn actual_unused_and_failed_ingress_use_the_required_eleven_field_grammar() {
        // The constructor retains DATA only; no Boot, ledger, signed scope or
        // native action/publication permission is fabricated by this control.
        let mut actual = NativeRestoredInputReactive17Attempt::new_data(7);
        assert!(actual.observation17_quote_parts_data().is_err());
        assert!(actual.observation17_parts_data().is_err());
        assert!(actual.published_checkpoint17_data().is_err());
        assert!(actual.observation17_produced_parts_data().is_err());
        let rows = ValidatedMetadataRecords::validate(b"[]", 1, 65_536).unwrap();
        for failed in [false, true] {
            if failed {
                actual.interrupt_data();
            }
            // Historical structs retain defining source order. Passing through
            // Value would sort these keys and stop exercising the actual writer.
            let input = serde_json::to_vec(&actual).unwrap();
            let value: Value = serde_json::from_slice(&input).unwrap();
            assert_eq!(value.as_object().unwrap().len(), 11);
            assert!(value.get("observation").unwrap().is_null());
            let mut ledger = Ledger::new(rows.rows(), limits());
            assert!(
                ledger
                    .read::<CurrentInputAttempt17>(&input, false)
                    .unwrap()
                    .is_none()
            );
            assert!(ledger.rows.next().is_none());

            let mut ledger = Ledger::new(rows.rows(), limits());
            let historical = ledger
                .read::<CurrentInputAttempt17>(&input, true)
                .unwrap()
                .unwrap();
            assert_eq!(historical.ordinal, 7);
            assert!(historical.observation.is_none());
            assert!(match historical.stage {
                CurrentAttemptStage17::Receiving => !failed,
                CurrentAttemptStage17::Failed => failed,
                _ => false,
            });
            assert!(ledger.rows.next().is_none());

            // Preserve every other byte/order so these controls specifically
            // exercise the missing and unknown field checks.
            let suffix = br#","observation":null}"#;
            let preceding = input.strip_suffix(suffix).unwrap();
            let mut missing = preceding.to_vec();
            missing.push(b'}');
            let mut ledger = Ledger::new(rows.rows(), limits());
            assert!(
                ledger
                    .read::<CurrentInputAttempt17>(&missing, false)
                    .is_err()
            );

            let mut unknown = input[..input.len() - 1].to_vec();
            unknown.extend_from_slice(br#","unsupported":true}"#);
            let mut ledger = Ledger::new(rows.rows(), limits());
            assert!(
                ledger
                    .read::<CurrentInputAttempt17>(&unknown, false)
                    .is_err()
            );
        }
    }
}
