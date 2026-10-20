//! Pairs expanded SDK18 metadata with its actual Controller and custody rows.
//!
//! The ordinary Controller observer remains unchanged. This explicit adapter
//! admits only profiles from the same retained capsule and exact literal pairs;
//! unrelated rows keep the ordinary work/depth budget. Neither a profile nor a
//! matching cached body grants a protocol phase, Source or native permission.

use super::*;
use crate::connection::OriginalRetainedSupervisor;
use crate::retained_metadata::aliases::MetadataSharedKind;
use std::mem::size_of;

impl OriginalNativeImport18Assignment {
    /// Borrows only a genuine retained pair's constructor profile as DATA.
    ///
    /// # Errors
    /// Refuses a foreign actor, invalid profile or exhausted bounded comparison.
    pub(crate) fn metadata_profile_for_envelope_data(
        &self,
        envelope: &Envelope,
    ) -> Result<Option<NativeImport18JsonMetadataProfileData>, ProviderError> {
        self.controller.ensure_current()?;
        if let Some(profile) = matched_metadata_profile_data(
            self.prepare.json_profile,
            self.prepare.original.as_ref(),
            self.prepare.response.as_ref(),
            envelope,
        )? {
            return Ok(Some(profile));
        }
        self.uploads.metadata_profile_for_envelope_data(envelope)
    }
}

/// Selects only a real retained literal pair; it never accepts a caller profile.
pub(super) fn matched_metadata_profile_data(
    profile: NativeImport18JsonMetadataProfileData,
    original: Option<&Envelope>,
    terminal: Option<&Envelope>,
    candidate: &Envelope,
) -> Result<Option<NativeImport18JsonMetadataProfileData>, ProviderError> {
    let Some(original) = original else {
        return Ok(None);
    };
    if original.request_id.0.is_none() || original.request_id != candidate.request_id {
        return Ok(None);
    }
    let expected = match candidate.message {
        MessageKind::Request => original,
        MessageKind::Response => match terminal {
            Some(terminal) => terminal,
            None => return Ok(None),
        },
        _ => return Ok(None),
    };
    let mut comparison = LiteralComparison {
        work: 0,
        maximum_work: profile.maximum_work_data()?,
        maximum_depth: profile.maximum_depth_data(),
    };
    if !comparison.envelope_data(expected, candidate)? {
        return Ok(None);
    }
    Ok(Some(profile))
}

impl CnpController {
    /// Names this explicit adapter's actual fixed lookup/borrow controls.
    ///
    /// Admit this before the scalar-only dynamic counter getter. It does not
    /// allocate, serialize, inspect a Value or grant a larger ordinary budget.
    pub fn native_import18_settled_metadata_counter_scratch_data() -> usize {
        Self::settled_history_counter_scratch_data()
            + Self::original_native_import18_assignment_counter_scratch_data()
            + size_of::<&OriginalNativeImport18Assignment>()
            + size_of::<Option<NativeImport18JsonMetadataProfileData>>()
            + size_of::<Result<Option<NativeImport18JsonMetadataProfileData>, ProviderError>>()
            + input_upload::retained_counter_scratch_data()
            + size_of::<std::collections::btree_map::Iter<'static, Id, crate::client::ClientOriginal>>(
            )
            + size_of::<(&Id, &crate::client::ClientOriginal)>()
            + size_of::<LiteralComparison>()
            + size_of::<Result<bool, ProviderError>>()
            + size_of::<[usize; 3]>()
            + size_of::<&[usize]>()
            + size_of::<&usize>()
            + size_of::<std::slice::Iter<'static, usize>>()
            + size_of::<Option<usize>>()
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<(&Envelope, &Envelope)>()
            + size_of::<LiteralHeaderLoans<'static>>()
            + size_of::<Option<&Envelope>>()
            + size_of::<&mut MetadataObserver<'static>>()
            + size_of::<Result<(), ProviderError>>()
    }

    /// Quotes actual retained recursion for the same Controller/capsule loan.
    ///
    /// The returned S includes separately bounded literal comparison frames.
    /// Existing old owner counters and real supervisor controls remain included.
    ///
    /// # Errors
    /// Refuses another original actor/Controller or checked geometry overflow.
    pub fn native_import18_settled_metadata_scratch_data(
        &self,
        capsule: &OriginalNativeImport18Assignment,
    ) -> Result<usize, ProviderError> {
        self.protocol_owner.ensure_current()?;
        capsule.controller.ensure_current()?;
        if !Rc::ptr_eq(&self.protocol_owner, &capsule.controller) {
            return Err(invalid());
        }
        let depth = capsule
            .prepare
            .json_profile
            .maximum_depth_data()
            .max(capsule.uploads.metadata_maximum_depth_data());
        let comparison = depth
            .checked_mul(literal_comparison_frame_data())
            .ok_or_else(credit)?;
        sum(&[
            Self::native_import18_settled_metadata_counter_scratch_data(),
            capsule.retained_metadata_counter_scratch_data()?,
            comparison,
        ])
    }

    /// Observes the actual Controller with only its own capsule's paid profiles.
    ///
    /// Caller first admits the static counter, dynamic S, and existing complete
    /// Controller/supervisor observation row. This does not certify a receipt or
    /// renew the Session cut. No body is cloned, hashed, decoded or serialized.
    ///
    /// # Errors
    /// Refuses changed actor/supervisor/Controller custody, unsupported old owner,
    /// a changed capsule literal, checked overflow or actual traversal limits.
    pub fn native_import18_settled_metadata_data(
        &self,
        supervisor: &OriginalRetainedSupervisor,
        capsule: &OriginalNativeImport18Assignment,
    ) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        self.protocol_owner.ensure_current()?;
        capsule.controller.ensure_current()?;
        if !Rc::ptr_eq(&self.protocol_owner, &capsule.controller) {
            return Err(invalid());
        }
        self.session
            .authenticate_settled_history_supervisor_data(supervisor)?;
        let mut observer = MetadataObserver::native_import18_capsule_data(capsule);
        let result: Result<(), ProviderError> = (|| {
            self.observe_native_import18_controller_metadata_data(&mut observer, capsule)?;
            supervisor.observe_settled_history_metadata_data(&mut observer)?;
            Ok(())
        })();
        // The actual owner and supervisor are rechecked even after a refused
        // field/lookup; no borrowed observer or capsule loan escapes this call.
        self.protocol_owner.ensure_current()?;
        capsule.controller.ensure_current()?;
        self.session
            .authenticate_settled_history_supervisor_data(supervisor)?;
        result?;
        Ok(observer.finish())
    }

    fn observe_native_import18_controller_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
        capsule: &OriginalNativeImport18Assignment,
    ) -> Result<(), ProviderError> {
        let Self {
            session,
            custody,
            route,
            budget: _,
            fenced,
            protocol_owner,
            original_ack_admit,
            original_complete_restore,
            original_complete_restore_prepare,
            original_complete_restore_commit,
            installed_complete_restore,
            original_installed_restoration_activation,
            original_installed_restoration_upload,
            original_installed_restoration_observation,
            original_restored_settled_capture,
        } = self;
        if installed_complete_restore.is_some() {
            return Err(invalid());
        }
        observer.observe(&route.node)?;
        observer.observe(&route.execution_owner)?;
        observer.observe(fenced)?;
        observer.shared_original(MetadataSharedKind::ProtocolOwner, protocol_owner.as_ref())?;
        session.observe_settled_history_metadata_data(observer)?;
        custody.observe_native_import18_metadata_data(observer, capsule)?;
        if let Some(admit) = original_ack_admit {
            admit.observe_settled_history_metadata_data(observer)?;
        }
        for restore in [
            original_complete_restore.as_ref(),
            original_complete_restore_prepare.as_ref(),
            original_complete_restore_commit.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            restore.observe_settled_history_metadata_data(observer)?;
        }
        for activation in original_installed_restoration_activation.iter().flatten() {
            activation.observe_owned_metadata(observer)?;
        }
        for upload in original_installed_restoration_upload.iter().flatten() {
            upload.observe_settled_history_metadata_data(observer)?;
        }
        if let Some(observation) = original_installed_restoration_observation {
            observation.observe_owned_metadata(observer)?;
        }
        if let Some(capture) = original_restored_settled_capture {
            capture.observe_retained_metadata_data(observer)?;
        }
        Ok(())
    }
}

type LiteralHeaderLoans<'a> = (
    &'a String,
    &'a MessageKind,
    &'a Nullable<Id>,
    &'a Nullable<Id>,
    &'a Nullable<Id>,
    &'a Nullable<Id>,
    &'a Nullable<Id>,
    &'a Nullable<Id>,
    &'a Nullable<Id>,
    &'a U64,
    &'a Method,
    &'a serde_json::Map<String, Value>,
    &'a Extensions,
);

struct LiteralComparison {
    work: usize,
    maximum_work: usize,
    maximum_depth: usize,
}

impl LiteralComparison {
    fn visit(&mut self, depth: usize) -> Result<(), ProviderError> {
        self.work = self.work.checked_add(1).ok_or_else(credit)?;
        if self.work > self.maximum_work || depth >= self.maximum_depth {
            return Err(credit());
        }
        Ok(())
    }

    fn envelope_data(&mut self, left: &Envelope, right: &Envelope) -> Result<bool, ProviderError> {
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
        } = left;
        if protocol != &right.protocol
            || message != &right.message
            || session_id != &right.session_id
            || incarnation_id != &right.incarnation_id
            || node_id != &right.node_id
            || execution_owner_id != &right.execution_owner_id
            || capture_owner_id != &right.capture_owner_id
            || request_id != &right.request_id
            || operation_id != &right.operation_id
            || sequence != &right.sequence
            || method != &right.method
        {
            return Ok(false);
        }
        if !self.map_data(body, &right.body, 0)? {
            return Ok(false);
        }
        self.extensions_data(extensions, &right.extensions, 0)
    }

    fn extensions_data(
        &mut self,
        left: &Extensions,
        right: &Extensions,
        depth: usize,
    ) -> Result<bool, ProviderError> {
        self.visit(depth)?;
        if left.len() != right.len() {
            return Ok(false);
        }
        for ((key, value), (other_key, other_value)) in left.iter().zip(right.iter()) {
            if key != other_key || !self.value_data(value, other_value, depth + 1)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn map_data(
        &mut self,
        left: &serde_json::Map<String, Value>,
        right: &serde_json::Map<String, Value>,
        depth: usize,
    ) -> Result<bool, ProviderError> {
        self.visit(depth)?;
        if left.len() != right.len() {
            return Ok(false);
        }
        for ((key, value), (other_key, other_value)) in left.iter().zip(right.iter()) {
            if key != other_key || !self.value_data(value, other_value, depth + 1)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn value_data(
        &mut self,
        left: &Value,
        right: &Value,
        depth: usize,
    ) -> Result<bool, ProviderError> {
        self.visit(depth)?;
        match (left, right) {
            (Value::Null, Value::Null) => Ok(true),
            (Value::Bool(left), Value::Bool(right)) => Ok(left == right),
            (Value::Number(left), Value::Number(right)) => Ok(left == right),
            (Value::String(left), Value::String(right)) => Ok(left == right),
            (Value::Array(left), Value::Array(right)) => {
                if left.len() != right.len() {
                    return Ok(false);
                }
                for (value, other) in left.iter().zip(right.iter()) {
                    if !self.value_data(value, other, depth + 1)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            (Value::Object(left), Value::Object(right)) => self.map_data(left, right, depth),
            _ => Ok(false),
        }
    }
}

fn literal_comparison_frame_data() -> usize {
    size_of::<(&Value, &Value)>()
        + size_of::<(
            &serde_json::Map<String, Value>,
            &serde_json::Map<String, Value>,
        )>()
        + size_of::<std::iter::Zip<serde_json::map::Iter<'static>, serde_json::map::Iter<'static>>>(
        )
        + size_of::<(&Extensions, &Extensions)>()
        + size_of::<
            std::iter::Zip<
                std::collections::btree_map::Iter<'static, String, Value>,
                std::collections::btree_map::Iter<'static, String, Value>,
            >,
        >()
        + size_of::<
            std::iter::Zip<std::slice::Iter<'static, Value>, std::slice::Iter<'static, Value>>,
        >()
        + size_of::<((&String, &Value), (&String, &Value))>()
        + size_of::<Option<((&String, &Value), (&String, &Value))>>()
        + size_of::<(&Value, &Value)>()
        + size_of::<Option<(&Value, &Value)>>()
        + size_of::<usize>()
        + size_of::<&mut LiteralComparison>()
        + size_of::<Result<bool, ProviderError>>()
        + size_of::<Option<usize>>()
}

fn sum(values: &[usize]) -> Result<usize, ProviderError> {
    values.iter().try_fold(0usize, |total, value| {
        total.checked_add(*value).ok_or_else(credit)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn literal(message: MessageKind, value: Value) -> Envelope {
        let mut body = serde_json::Map::new();
        body.insert("retained".into(), value);
        Envelope {
            protocol: "CNP/1".into(),
            message,
            session_id: Nullable(None),
            incarnation_id: Nullable(None),
            node_id: Nullable(None),
            execution_owner_id: Nullable(None),
            capture_owner_id: Nullable(None),
            operation_id: Nullable(None),
            request_id: Nullable(Some(Id::new("literal/data-only").unwrap())),
            sequence: U64::new(3),
            method: Method::BlobChunk,
            body,
            extensions: Default::default(),
        }
    }

    #[test]
    fn equal_header_cannot_select_profile_for_a_different_cached_body() {
        let original = literal(MessageKind::Request, Value::Bool(true));
        let terminal = literal(MessageKind::Response, Value::Bool(true));
        let foreign = literal(MessageKind::Response, Value::Bool(false));
        let profile = NativeImport18JsonMetadataProfileData::strict_raw_data();

        assert!(
            matched_metadata_profile_data(profile, Some(&original), Some(&terminal), &terminal)
                .unwrap()
                .is_some()
        );
        assert!(
            matched_metadata_profile_data(profile, Some(&original), Some(&terminal), &foreign)
                .unwrap()
                .is_none()
        );
        assert!(
            matched_metadata_profile_data(profile, Some(&original), None, &terminal)
                .unwrap()
                .is_none()
        );

        let mut extended = terminal.clone();
        extended
            .extensions
            .insert("literal-extension".into(), Value::Bool(true));
        let mut different_extension = extended.clone();
        different_extension
            .extensions
            .insert("literal-extension".into(), Value::Bool(false));

        assert!(
            matched_metadata_profile_data(profile, Some(&original), Some(&extended), &extended)
                .unwrap()
                .is_some()
        );
        assert!(
            matched_metadata_profile_data(
                profile,
                Some(&original),
                Some(&extended),
                &different_extension,
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn literal_comparison_stops_at_its_actual_profile_before_deeper_recursion() {
        let mut value = Value::Bool(true);
        for _ in 0..70 {
            value = Value::Array(vec![value]);
        }
        let original = literal(MessageKind::Request, Value::Null);
        let terminal = literal(MessageKind::Response, value);
        let profile = NativeImport18JsonMetadataProfileData::strict_raw_data();

        assert!(
            matched_metadata_profile_data(profile, Some(&original), Some(&terminal), &terminal)
                .is_err()
        );
    }
}
