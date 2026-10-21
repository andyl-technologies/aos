//! Retains the actual SDK request envelope decoded from its original strict tree.
//!
//! Original claims and the typed extension offer establish the closed initial
//! grammar before this decoder runs. Complete output is retained before exact
//! original correspondence, envelope validation or any terminal admission.

use crate::ProviderError;
use crate::envelope::{Envelope, MessageKind, Method};
use crate::operational_time::OperationalDeadline;
use crate::protocol_snapshot::ProtocolCaptureOwner;
use crate::retained_metadata::{MetadataObserver, requested_metadata_backing_storage_data};
use serde::Deserialize;
use serde_json::Value;
use std::mem::size_of;

/// Retains actual envelope output and scalar decoder-failure coordinates.
pub(in super::super) struct Attempt {
    owner: ProtocolCaptureOwner,
    stage: Stage,
    cut: Option<OperationalDeadline>,
    row: Option<[usize; 3]>,
    envelope: Option<Envelope>,
    failure: Option<Failure>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Stage {
    Empty,
    Inspecting,
    Quoted,
    Decoded,
    Complete,
    Failed,
}

struct Failure {
    category: serde_json::error::Category,
    line: usize,
    column: usize,
}

const _: fn(&Attempt) = |value| {
    let Attempt {
        owner: _,
        stage: _,
        cut: _,
        row: _,
        envelope: _,
        failure: _,
    } = value;
};

impl Attempt {
    /// Initializes empty physical slots without parsing or allocation.
    pub(in super::super) fn empty_data() -> Self {
        Self {
            owner: ProtocolCaptureOwner::new(),
            stage: Stage::Empty,
            cut: None,
            row: None,
            envelope: None,
            failure: None,
        }
    }

    /// Spends the occurrence before any enclosing guard or admission callback.
    ///
    /// # Errors
    /// Refuses foreign creator custody or a previously spent attempt.
    pub(super) fn start_data(&mut self, cut: OperationalDeadline) -> Result<(), ProviderError> {
        self.owner.ensure_current()?;
        if self.stage != Stage::Empty {
            return Err(refused());
        }
        self.stage = Stage::Inspecting;
        self.cut = Some(cut);
        Ok(())
    }

    /// Stores the independently admitted row before envelope allocation.
    ///
    /// # Errors
    /// Refuses foreign custody, another stage or an occupied quote slot.
    pub(super) fn quote_data(&mut self, row: [usize; 3]) -> Result<(), ProviderError> {
        self.owner.ensure_current()?;
        if self.stage != Stage::Inspecting || self.row.is_some() {
            return Err(refused());
        }
        self.row = Some(row);
        self.stage = Stage::Quoted;
        Ok(())
    }

    /// Decodes the real envelope directly from its checked original Value.
    ///
    /// The caller holds the complete initial claims/offer and original custody
    /// guards. No canonical copy, second JSON parse or live authority is used.
    /// Temporary serde diagnostics are funded by the admitted transient row.
    ///
    /// # Errors
    /// Refuses stale/substituted custody, occupied slots, decoding, changed
    /// original correlation/body or envelope validation.
    pub(super) fn construct_data(
        &mut self,
        value: &Value,
        cut: OperationalDeadline,
    ) -> Result<(), ProviderError> {
        let outcome = self.construct_current_data(value, cut);
        let terminal = self.guard(cut);
        if let Err(error) = outcome.and(terminal) {
            self.stage = Stage::Failed;
            return Err(error);
        }
        Ok(())
    }

    fn construct_current_data(
        &mut self,
        value: &Value,
        cut: OperationalDeadline,
    ) -> Result<(), ProviderError> {
        self.guard(cut)?;
        if self.stage != Stage::Quoted
            || self.row.is_none()
            || self.envelope.is_some()
            || self.failure.is_some()
        {
            return Err(refused());
        }
        match Envelope::deserialize(value) {
            Ok(envelope) => self.envelope = Some(envelope),
            Err(error) => {
                self.failure = Some(Failure {
                    category: error.classify(),
                    line: error.line(),
                    column: error.column(),
                });
                return Err(refused());
            }
        }
        self.stage = Stage::Decoded;
        self.authenticate_data(value, cut)?;
        self.envelope.as_ref().ok_or_else(refused)?.validate()
    }

    /// Checks every actual envelope field against the same original strict tree.
    ///
    /// # Errors
    /// Refuses stale/substituted custody, missing output or changed initial
    /// header, request ID, body or envelope extensions.
    pub(super) fn authenticate_data(
        &self,
        value: &Value,
        cut: OperationalDeadline,
    ) -> Result<(), ProviderError> {
        self.guard(cut)?;
        let envelope = self.envelope.as_ref().ok_or_else(refused)?;
        let root = value.as_object().ok_or_else(refused)?;
        let extensions = root
            .get("extensions")
            .and_then(Value::as_object)
            .ok_or_else(refused)?;
        if self.failure.is_some()
            || root.len() != 13
            || envelope.protocol != "CNP/1"
            || root.get("protocol").and_then(Value::as_str) != Some(envelope.protocol.as_str())
            || envelope.message != MessageKind::Request
            || root.get("message").and_then(Value::as_str) != Some("request")
            || envelope.method != Method::Hello
            || root.get("method").and_then(Value::as_str) != Some("hello")
            || envelope.sequence.get() != 1
            || root.get("sequence").and_then(Value::as_str) != Some("1")
            || envelope.session_id.0.is_some()
            || envelope.incarnation_id.0.is_some()
            || envelope.node_id.0.is_some()
            || envelope.execution_owner_id.0.is_some()
            || envelope.capture_owner_id.0.is_some()
            || envelope.operation_id.0.is_some()
            || envelope.request_id.0.as_ref().map(|id| id.as_str())
                != root.get("request_id").and_then(Value::as_str)
            || envelope.request_id.0.is_none()
            || root.get("body").and_then(Value::as_object) != Some(&envelope.body)
            || extensions.len() != envelope.extensions.len()
            || !extensions.iter().zip(&envelope.extensions).all(
                |((actual_key, actual_value), (owned_key, owned_value))| {
                    actual_key == owned_key && actual_value == owned_value
                },
            )
        {
            return Err(refused());
        }
        for field in NULL_FIELDS {
            if !root.get(field).is_some_and(Value::is_null) {
                return Err(refused());
            }
        }
        self.guard(cut)
    }

    /// Completes after original terminal admission and correspondence checks.
    ///
    /// # Errors
    /// Refuses stale custody or incomplete/refused physical construction.
    pub(super) fn complete_data(&mut self) -> Result<(), ProviderError> {
        self.guard(self.cut.ok_or_else(refused)?)?;
        if self.stage != Stage::Decoded || self.envelope.is_none() || self.failure.is_some() {
            return Err(refused());
        }
        self.stage = Stage::Complete;
        Ok(())
    }

    /// Closes the occurrence without releasing initialized output ownership.
    pub(super) fn refuse_data(&mut self) {
        self.stage = Stage::Failed;
    }

    /// Lends only the same completed envelope under its unchanged original cut.
    ///
    /// # Errors
    /// Refuses stale/substituted custody or incomplete/refused construction.
    pub(super) fn data(&self, cut: OperationalDeadline) -> Result<&Envelope, ProviderError> {
        self.guard(cut)?;
        if self.stage != Stage::Complete || self.failure.is_some() {
            return Err(refused());
        }
        self.envelope.as_ref().ok_or_else(refused)
    }

    /// Counts all surviving actual envelope allocations without formatting secrets.
    ///
    /// # Errors
    /// Refuses foreign custody, a noninitial branch or metadata overflow.
    pub(in super::super) fn retained_backing_data(&self) -> Result<usize, ProviderError> {
        self.owner.ensure_current()?;
        let mut observer = MetadataObserver::new();
        if let Some(envelope) = &self.envelope {
            let Envelope {
                protocol,
                message,
                session_id,
                incarnation_id,
                node_id,
                execution_owner_id,
                capture_owner_id,
                request_id,
                operation_id,
                sequence,
                method,
                body,
                extensions,
            } = envelope;
            if *message != MessageKind::Request
                || *method != Method::Hello
                || session_id.0.is_some()
                || incarnation_id.0.is_some()
                || node_id.0.is_some()
                || execution_owner_id.0.is_some()
                || capture_owner_id.0.is_some()
                || operation_id.0.is_some()
            {
                return Err(refused());
            }
            observer.observe(protocol)?;
            observer.observe(request_id)?;
            observer.observe(sequence)?;
            observer.observe(body)?;
            observer.observe(extensions)?;
        }
        requested_metadata_backing_storage_data(&observer.finish())
    }

    fn guard(&self, cut: OperationalDeadline) -> Result<(), ProviderError> {
        self.owner.ensure_current()?;
        if self.cut != Some(cut) || cut.is_expired() {
            return Err(refused());
        }
        Ok(())
    }

    #[cfg(test)]
    pub(in super::super) fn row_fixture_data(&self) -> Option<[usize; 3]> {
        self.row
    }

    #[cfg(test)]
    pub(in super::super) fn envelope_fixture_data(&self) -> Option<&Envelope> {
        self.envelope.as_ref()
    }

    /// Names actual output, guard, comparison and retained-census controls.
    pub(super) fn counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<&mut Self>()
            + size_of::<&Value>()
            + size_of::<&Envelope>()
            + size_of::<OperationalDeadline>()
            + size_of::<Option<OperationalDeadline>>()
            + size_of::<Failure>()
            + size_of::<Option<Failure>>()
            + size_of::<Result<Envelope, serde_json::Error>>()
            + size_of::<MetadataObserver<'static>>()
            + size_of::<crate::retained_metadata::RetainedProtocolMetadataFacts>()
            + size_of::<Result<(), ProviderError>>() * 4
            + size_of::<Result<usize, ProviderError>>() * 2
            + size_of::<[&str; NULL_FIELDS.len()]>()
            + size_of::<std::array::IntoIter<&'static str, { NULL_FIELDS.len() }>>()
            + comparison_counter_scratch_data()
    }
}

const NULL_FIELDS: [&str; 6] = [
    "session_id",
    "incarnation_id",
    "node_id",
    "execution_owner_id",
    "capture_owner_id",
    "operation_id",
];

fn comparison_counter_scratch_data() -> usize {
    // Checked initial body/offer fields have at most six nested JSON containers.
    // Map equality and extension comparison visit the same bounded original
    // arrays, Strings and Value leaves without formatting or re-encoding.
    7 * (size_of::<&Value>() * 2
        + size_of::<&String>() * 2
        + size_of::<serde_json::map::Iter<'static>>() * 2
        + size_of::<std::slice::Iter<'static, Value>>() * 2
        + size_of::<Option<(&'static String, &'static Value)>>() * 2
        + size_of::<(&Value, &Value)>()
        + size_of::<Option<(&Value, &Value)>>()
        + size_of::<bool>() * 2
        + size_of::<usize>() * 2)
        + size_of::<std::collections::btree_map::Iter<'static, String, Value>>()
        + size_of::<
            std::iter::Zip<
                serde_json::map::Iter<'static>,
                std::collections::btree_map::Iter<'static, String, Value>,
            >,
        >()
        + size_of::<Option<((&String, &Value), (&String, &Value))>>()
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original import18 SDK Hello envelope refused")
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
