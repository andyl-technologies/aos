//! Retains the actual typed SDK Hello request and scalar decode failures.
//!
//! Request decoding borrows the original checked strict tree. Its completed
//! typed owner is stored before exact correspondence or any terminal guard.
//! This transition neither validates an SDK exchange nor issues a connection.

use super::super::hello_request::{
    Claims, original_octets32_counter_scratch_data, original_octets32_data,
};
use crate::ProviderError;
use crate::handshake::{HelloRequest, Limits};
use crate::operational_time::OperationalDeadline;
use crate::protocol_snapshot::ProtocolCaptureOwner;
use crate::reference_packet::service::native_startup::data_equality;
use crate::retained_metadata::{MetadataObserver, requested_metadata_backing_storage_data};
use serde::Deserialize;
use serde_json::Value;
use std::mem::size_of;

/// Retains every surviving actual SDK request constructor output.
pub(in super::super) struct Attempt {
    owner: ProtocolCaptureOwner,
    stage: Stage,
    cut: Option<OperationalDeadline>,
    row: Option<[usize; 3]>,
    request: Option<HelloRequest>,
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
        request: _,
        failure: _,
    } = value;
};

impl Attempt {
    /// Initializes empty physical slots without decoding or allocation.
    pub(in super::super) fn empty_data() -> Self {
        Self {
            owner: ProtocolCaptureOwner::new(),
            stage: Stage::Empty,
            cut: None,
            row: None,
            request: None,
            failure: None,
        }
    }

    /// Spends the occurrence before any enclosing guard or admission callback.
    ///
    /// # Errors
    /// Refuses a foreign creator or a previously spent attempt.
    pub(super) fn start_data(&mut self, cut: OperationalDeadline) -> Result<(), ProviderError> {
        self.owner.ensure_current()?;
        if self.stage != Stage::Empty {
            return Err(refused());
        }
        self.stage = Stage::Inspecting;
        self.cut = Some(cut);
        Ok(())
    }

    /// Stores the actual independently admitted row before typed construction.
    ///
    /// # Errors
    /// Refuses foreign custody, another stage or an occupied row.
    pub(super) fn quote_data(&mut self, row: [usize; 3]) -> Result<(), ProviderError> {
        self.owner.ensure_current()?;
        if self.stage != Stage::Inspecting || self.row.is_some() {
            return Err(refused());
        }
        self.row = Some(row);
        self.stage = Stage::Quoted;
        Ok(())
    }

    /// Decodes the actual initial body and retains its SDK owner before checks.
    ///
    /// The enclosing original owner authenticates its checked claims and strict
    /// tree around every outcome. No canonical copy or second JSON parse exists.
    /// The temporary serde diagnostic is funded by the admitted transient row;
    /// only its actual scalar coordinates survive a decoding refusal.
    ///
    /// # Errors
    /// Refuses stale/substituted custody, occupied slots, decoding, changed
    /// initial claims or exact original body correspondence.
    pub(super) fn construct_data(
        &mut self,
        value: &Value,
        claims: Claims,
        admission_token: &[u8],
        cut: OperationalDeadline,
    ) -> Result<(), ProviderError> {
        let outcome = self.construct_current_data(value, claims, admission_token, cut);
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
        claims: Claims,
        admission_token: &[u8],
        cut: OperationalDeadline,
    ) -> Result<(), ProviderError> {
        self.guard(cut)?;
        if self.stage != Stage::Quoted
            || self.row.is_none()
            || self.request.is_some()
            || self.failure.is_some()
        {
            return Err(refused());
        }
        let body = value.get("body").ok_or_else(refused)?;
        match HelloRequest::deserialize(body) {
            Ok(request) => self.request = Some(request),
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
        self.authenticate_data(value, claims, admission_token, cut)
    }

    /// Checks the actual typed owner against the same original strict body.
    ///
    /// # Errors
    /// Refuses stale custody, missing output, changed claims or any field
    /// mismatch. Initial resumption and body extensions remain unavailable.
    pub(super) fn authenticate_data(
        &self,
        value: &Value,
        claims: Claims,
        admission_token: &[u8],
        cut: OperationalDeadline,
    ) -> Result<(), ProviderError> {
        self.guard(cut)?;
        let request = self.request.as_ref().ok_or_else(refused)?;
        let body = value
            .get("body")
            .and_then(Value::as_object)
            .ok_or_else(refused)?;
        let nonce = original_octets32_data(
            body.get("controller_nonce")
                .and_then(Value::as_str)
                .ok_or_else(refused)?,
        )?;
        let token = original_octets32_data(
            body.get("admission_token")
                .and_then(Value::as_str)
                .ok_or_else(refused)?,
        )?;
        if self.failure.is_some()
            || body.len() != 8
            || request.controller_nonce.as_slice() != claims.controller_nonce
            || nonce != claims.controller_nonce
            || !same_token_data(request.admission_token.as_slice(), admission_token)
            || !same_token_data(&token, admission_token)
            || !receiving_limits_cover_data(request.limits, claims.limits)
            || request.resume_session.is_some()
            || !request.extensions.is_empty()
            || !body
                .get("extensions")
                .and_then(Value::as_object)
                .is_some_and(serde_json::Map::is_empty)
            || body.get("session_id").and_then(Value::as_str) != Some(request.session_id.as_str())
            || !text_array_matches_data(body.get("versions"), &request.versions, String::as_str)
            || !text_array_matches_data(
                body.get("required_features"),
                &request.required_features,
                crucible_node_format::Id::as_str,
            )
            || !text_array_matches_data(
                body.get("optional_features"),
                &request.optional_features,
                crucible_node_format::Id::as_str,
            )
            || !body
                .get("limits")
                .is_some_and(|limits| data_equality::matches(limits, &request.limits))
        {
            return Err(refused());
        }
        self.guard(cut)
    }

    /// Completes only after the original enclosing census and terminal guards.
    ///
    /// # Errors
    /// Refuses stale custody or incomplete/refused physical construction.
    pub(super) fn complete_data(&mut self) -> Result<(), ProviderError> {
        self.guard(self.cut.ok_or_else(refused)?)?;
        if self.stage != Stage::Decoded || self.request.is_none() || self.failure.is_some() {
            return Err(refused());
        }
        self.stage = Stage::Complete;
        Ok(())
    }

    /// Closes this occurrence without releasing actual initialized outputs.
    pub(super) fn refuse_data(&mut self) {
        self.stage = Stage::Failed;
    }

    /// Lends only the same completed actual SDK request under its original cut.
    ///
    /// # Errors
    /// Refuses stale/substituted custody or incomplete/refused construction.
    pub(in super::super) fn data(
        &self,
        cut: OperationalDeadline,
    ) -> Result<&HelloRequest, ProviderError> {
        self.guard(cut)?;
        if self.stage != Stage::Complete || self.failure.is_some() {
            return Err(refused());
        }
        self.request.as_ref().ok_or_else(refused)
    }

    /// Counts every surviving typed request allocation without formatting Bytes.
    ///
    /// # Errors
    /// Refuses foreign custody, a noninitial branch or checked metadata overflow.
    /// Expiry never erases the retained request or scalar diagnostic.
    pub(in super::super) fn retained_backing_data(&self) -> Result<usize, ProviderError> {
        self.owner.ensure_current()?;
        let mut observer = MetadataObserver::new();
        if let Some(request) = &self.request {
            let HelloRequest {
                versions,
                session_id,
                controller_nonce,
                required_features,
                optional_features,
                limits,
                admission_token,
                resume_session,
                extensions,
            } = request;
            if resume_session.is_some() || !extensions.is_empty() {
                return Err(refused());
            }
            observer.observe(versions)?;
            observer.observe(session_id)?;
            observer.observe(controller_nonce)?;
            observer.observe(required_features)?;
            observer.observe(optional_features)?;
            observer.observe(limits)?;
            observer.observe(admission_token)?;
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

    /// Names actual destination, guards, scalar failure and metadata controls.
    pub(super) fn counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<&mut Self>()
            + size_of::<&Value>() * 2
            + size_of::<&HelloRequest>()
            + size_of::<Claims>()
            + size_of::<OperationalDeadline>()
            + size_of::<Option<OperationalDeadline>>()
            + size_of::<Failure>()
            + size_of::<Option<Failure>>()
            + size_of::<Result<HelloRequest, serde_json::Error>>()
            + size_of::<MetadataObserver<'static>>()
            + size_of::<crate::retained_metadata::RetainedProtocolMetadataFacts>()
            + size_of::<Result<(), ProviderError>>() * 4
            + size_of::<Result<usize, ProviderError>>() * 2
            + size_of::<Limits>() * 2
            + Limits::validation_counter_scratch_data() * 2
            + original_octets32_counter_scratch_data() * 2
            + size_of::<[u8; 32]>() * 2
            + size_of::<&[u8]>() * 2
            + size_of::<u8>() * 3
            + size_of::<usize>() * 2
            + size_of::<(&u8, &u8)>()
            + size_of::<Option<(&u8, &u8)>>()
            + size_of::<std::iter::Zip<std::slice::Iter<'static, u8>, std::slice::Iter<'static, u8>>>(
            )
            + text_array_counter_scratch_data::<String>()
            + text_array_counter_scratch_data::<crucible_node_format::Id>() * 2
    }

    #[cfg(test)]
    pub(in super::super) fn row_fixture_data(&self) -> Option<[usize; 3]> {
        self.row
    }

    #[cfg(test)]
    pub(in super::super) fn request_fixture_data(&self) -> Option<&HelloRequest> {
        self.request.as_ref()
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original import18 SDK Hello request refused")
}

fn receiving_limits_cover_data(receiving: Limits, selected: Limits) -> bool {
    receiving.is_valid_data()
        && selected.is_valid_data()
        && receiving.frame_bytes >= selected.frame_bytes
        && receiving.nesting >= selected.nesting
        && receiving.requests >= selected.requests
        && receiving.journal_entries >= selected.journal_entries
        && receiving.blob_chunk_bytes >= selected.blob_chunk_bytes
}

fn same_token_data(actual: &[u8], original: &[u8]) -> bool {
    actual.len() == 32
        && original.len() == 32
        && actual
            .iter()
            .zip(original)
            .fold(0u8, |difference, (actual, original)| {
                difference | (actual ^ original)
            })
            == 0
}

fn text_array_matches_data<T>(value: Option<&Value>, expected: &[T], text: fn(&T) -> &str) -> bool {
    let Some(values) = value.and_then(Value::as_array) else {
        return false;
    };
    values.len() == expected.len()
        && values
            .iter()
            .zip(expected)
            .all(|(actual, expected)| actual.as_str() == Some(text(expected)))
}

fn text_array_counter_scratch_data<T: 'static>() -> usize {
    size_of::<Option<&Value>>()
        + size_of::<Option<&Vec<Value>>>()
        + size_of::<&[T]>()
        + size_of::<fn(&T) -> &str>()
        + size_of::<std::iter::Zip<std::slice::Iter<'static, Value>, std::slice::Iter<'static, T>>>(
        )
        + size_of::<(&Value, &T)>()
        + size_of::<Option<(&Value, &T)>>()
        + size_of::<Option<&str>>()
        + size_of::<bool>() * 2
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_format::{Bytes, U64, Validate};
    use serde_json::json;
    use std::time::Duration;

    fn fixture() -> (Value, Claims) {
        let selected = crate::reference_packet::service::complete_restore::import18::inert_bootstrap_fixtures::initial_selected_launch(false);
        let limits: Limits = serde_json::from_value(selected["launch"]["limits"].clone()).unwrap();
        let mut advertised = limits;
        advertised.requests = U64::new(limits.requests.get() * 2);
        let value = json!({"body": {
            "versions": ["CNP/2", "CNP/1"], "session_id": "session/original",
            "controller_nonce": Bytes::new(vec![19; 32]),
            "required_features": ["cnp.core/1"], "optional_features": ["vendor.maybe/1"],
            "limits": advertised, "admission_token": Bytes::new(vec![7; 32]),
            "extensions": {},
        }});
        (
            value,
            Claims {
                controller_nonce: [19; 32],
                limits,
            },
        )
    }

    fn quoted(value: &Value, cut: OperationalDeadline) -> (Attempt, [usize; 3]) {
        let literal = serde_json::to_vec(value).unwrap();
        let row = super::super::storage::construction_data(literal.len(), 268_435_456).unwrap();
        let mut attempt = Attempt::empty_data();
        assert_eq!(attempt.retained_backing_data().unwrap(), 0);
        attempt.start_data(cut).unwrap();
        attempt.quote_data(row).unwrap();
        (attempt, row)
    }

    #[test]
    fn actual_sdk_request_preserves_unsorted_versions_optional_claims_and_receiving_limits() {
        let (value, claims) = fixture();
        let cut = OperationalDeadline::after(Duration::from_secs(5)).unwrap();
        let (mut attempt, row) = quoted(&value, cut);

        attempt
            .construct_data(&value, claims, &[7; 32], cut)
            .unwrap();
        let backing = attempt.retained_backing_data().unwrap();
        assert!(backing > 0 && backing <= row[0]);
        let request = attempt.request.as_ref().unwrap();
        request.validate().unwrap();
        assert_eq!(request.versions, ["CNP/2", "CNP/1"]);
        assert_eq!(request.optional_features[0].as_str(), "vendor.maybe/1");
        assert!(request.limits.requests > claims.limits.requests);
        let pointers = (
            request.versions.as_ptr(),
            request.controller_nonce.as_slice().as_ptr(),
        );

        attempt.complete_data().unwrap();
        let retained = attempt.data(cut).unwrap();
        assert_eq!(
            (
                retained.versions.as_ptr(),
                retained.controller_nonce.as_slice().as_ptr()
            ),
            pointers
        );
        assert!(attempt.start_data(cut).is_err());
        assert_eq!(attempt.retained_backing_data().unwrap(), backing);
    }

    #[test]
    fn cautious_serde_capacity_growth_fits_the_original_literal_bound() {
        let (mut value, claims) = fixture();
        let mut versions = (0..crucible_node_format::MAX_ARRAY_ELEMENTS - 1)
            .map(|index| Value::String(format!("version/{index}")))
            .collect::<Vec<_>>();
        versions.push(Value::String("CNP/1".into()));
        value["body"]["versions"] = Value::Array(versions);
        let cut = OperationalDeadline::after(Duration::from_secs(5)).unwrap();
        let (mut attempt, row) = quoted(&value, cut);

        attempt
            .construct_data(&value, claims, &[7; 32], cut)
            .unwrap();

        let request = attempt.request.as_ref().unwrap();
        assert_eq!(
            request.versions.len(),
            crucible_node_format::MAX_ARRAY_ELEMENTS
        );
        assert!(request.versions.capacity() > request.versions.len());
        assert!(attempt.retained_backing_data().unwrap() <= row[0]);
    }

    #[test]
    fn decoding_and_terminal_correspondence_failures_keep_their_actual_outputs() {
        for fault in 0..3 {
            let (mut value, mut claims) = fixture();
            let decoder_failure = fault == 0;
            if decoder_failure {
                value["body"]["optional_features"] = json!([null]);
            } else if fault == 1 {
                claims.controller_nonce[0] ^= 1;
            }
            let token = if fault == 2 { [8; 32] } else { [7; 32] };
            let cut = OperationalDeadline::after(Duration::from_secs(5)).unwrap();
            let (mut attempt, row) = quoted(&value, cut);

            assert!(attempt.construct_data(&value, claims, &token, cut).is_err());

            assert!(attempt.stage == Stage::Failed);
            assert_eq!(attempt.request.is_none(), decoder_failure);
            if decoder_failure {
                let failure = attempt.failure.as_ref().unwrap();
                assert_eq!(failure.category, serde_json::error::Category::Data);
                assert_eq!((failure.line, failure.column), (0, 0));
            }
            let backing = attempt.retained_backing_data().unwrap();
            assert!(backing <= row[0]);
            assert!(attempt.data(cut).is_err());
            assert!(attempt.start_data(cut).is_err());
            assert_eq!(attempt.retained_backing_data().unwrap(), backing);
        }
    }

    #[test]
    fn original_body_correspondence_checks_every_field_without_reencoding_secrets() {
        for field in [
            "versions",
            "session_id",
            "controller_nonce",
            "admission_token",
            "required_features",
            "optional_features",
            "limits",
            "extensions",
            "resume_session",
            "extra",
        ] {
            let (mut value, claims) = fixture();
            let cut = OperationalDeadline::after(Duration::from_secs(5)).unwrap();
            let (mut attempt, _) = quoted(&value, cut);
            attempt
                .construct_data(&value, claims, &[7; 32], cut)
                .unwrap();
            attempt.complete_data().unwrap();
            let backing = attempt.retained_backing_data().unwrap();
            match field {
                "versions" => value["body"][field] = json!(["CNP/1"]),
                "session_id" => value["body"][field] = json!("session/other"),
                "controller_nonce" | "admission_token" => {
                    value["body"][field] = json!(Bytes::new(vec![8; 32]))
                }
                "limits" => value["body"][field]["requests"] = json!("1"),
                "required_features" | "optional_features" => {
                    value["body"][field] = json!(["another/1"])
                }
                "extensions" => value["body"][field] = json!({"fixture/1":1}),
                _ => value["body"][field] = Value::Null,
            }

            assert!(
                attempt
                    .authenticate_data(&value, claims, &[7; 32], cut)
                    .is_err(),
                "{field}"
            );
            assert_eq!(attempt.retained_backing_data().unwrap(), backing);
        }
    }

    #[test]
    fn expired_or_substituted_cut_refuses_before_typed_allocation() {
        let (value, claims) = fixture();
        for expired in [false, true] {
            let original = if expired {
                OperationalDeadline::expired_fixture()
            } else {
                OperationalDeadline::after(Duration::from_secs(5)).unwrap()
            };
            let supplied = if expired {
                original
            } else {
                OperationalDeadline::after(Duration::from_secs(4)).unwrap()
            };
            let (mut attempt, _) = quoted(&value, original);

            assert!(
                attempt
                    .construct_data(&value, claims, &[7; 32], supplied)
                    .is_err()
            );

            assert!(attempt.request.is_none());
            assert_eq!(attempt.retained_backing_data().unwrap(), 0);
            assert!(attempt.start_data(supplied).is_err());
        }
    }
}
