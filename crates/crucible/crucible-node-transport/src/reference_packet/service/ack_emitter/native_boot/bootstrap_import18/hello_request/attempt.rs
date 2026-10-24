//! Retains checked scalar claims and the actual typed versioned Hello offer.

use super::{storage, wire};
use crate::ProviderError;
use crate::handshake::ExtensionOfferV1;
use crate::operational_time::OperationalDeadline;
use crate::protocol_snapshot::ProtocolCaptureOwner;
use crate::reference_packet::service::PacketNative5SourceLaunch;
use crate::reference_packet::service::complete_restore::import18::hello::PacketNativeImport18HelloSelectionData;
use crate::retained_metadata::{MetadataObserver, requested_metadata_backing_storage_data};
use crucible_node_format::{ContractError, Validate};
use serde::Deserialize;
use serde_json::Value;
use std::mem::size_of;

/// Retains an actual request inspection without issuing a Hello connection.
pub(in super::super) struct Attempt {
    owner: ProtocolCaptureOwner,
    stage: Stage,
    row: Option<[usize; 3]>,
    claims: Option<wire::Claims>,
    offer: Option<ExtensionOfferV1>,
    failure: Option<Failure>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Stage {
    Empty,
    Inspecting,
    Quoted,
    Claimed,
    Decoded,
    Checked,
    Complete,
    Failed,
}

enum Failure {
    Claims,
    Json {
        category: serde_json::error::Category,
        line: usize,
        column: usize,
    },
    Validation {
        field: &'static str,
        reason: String,
    },
    Arithmetic,
    RequiredDefinition,
}

impl Attempt {
    /// Constructs empty physical request slots without allocating backing.
    pub(in super::super) fn empty_data() -> Self {
        Self {
            owner: ProtocolCaptureOwner::new(),
            stage: Stage::Empty,
            row: None,
            claims: None,
            offer: None,
            failure: None,
        }
    }

    /// Spends the original request occurrence before any enclosing guard fails.
    ///
    /// # Errors
    /// Refuses foreign custody or a previously spent attempt.
    pub(super) fn start_data(&mut self) -> Result<(), ProviderError> {
        self.owner.ensure_current()?;
        if self.stage != Stage::Empty {
            return Err(refused());
        }
        self.stage = Stage::Inspecting;
        Ok(())
    }

    /// Stores the independently admitted row before inspecting original claims.
    ///
    /// # Errors
    /// Refuses foreign custody, re-entry or an occupied row.
    pub(super) fn quote_data(&mut self, row: [usize; 3]) -> Result<(), ProviderError> {
        self.owner.ensure_current()?;
        if self.stage != Stage::Inspecting || self.row.is_some() {
            return Err(refused());
        }
        self.row = Some(row);
        self.stage = Stage::Quoted;
        Ok(())
    }

    /// Checks the original claims and retains the real typed offer before validation.
    ///
    /// Both offer vectors are checked before their allocating decoder. The
    /// profile's independently declared typed registry is empty: unsupported
    /// optional definitions remain unselected, while required definitions refuse.
    /// This correspondence supplies DATA only, not a live registry or lease.
    ///
    /// # Errors
    /// Refuses stale/incomplete custody, malformed or foreign claims, excessive
    /// populations, typed syntax, invalid definitions or a required definition.
    pub(super) fn inspect_data(
        &mut self,
        value: &Value,
        launch: &PacketNative5SourceLaunch,
        selection: &PacketNativeImport18HelloSelectionData,
        cut: OperationalDeadline,
    ) -> Result<(), ProviderError> {
        self.owner.ensure_current()?;
        if self.stage != Stage::Quoted
            || self.row.is_none()
            || self.claims.is_some()
            || self.offer.is_some()
            || self.failure.is_some()
        {
            return Err(refused());
        }
        let inspected = match wire::inspect_data(value, launch, selection, cut) {
            Ok(inspected) => inspected,
            Err(error) => {
                self.failure = Some(Failure::Claims);
                self.stage = Stage::Failed;
                return Err(error);
            }
        };
        self.claims = Some(inspected.claims);
        self.stage = Stage::Claimed;
        if let Err(error) = storage::admit_populations_data(inspected.offer) {
            self.failure = Some(Failure::Claims);
            self.stage = Stage::Failed;
            return Err(error);
        }

        match ExtensionOfferV1::deserialize(inspected.offer) {
            Ok(offer) => self.offer = Some(offer),
            Err(error) => {
                self.failure = Some(Failure::Json {
                    category: error.classify(),
                    line: error.line(),
                    column: error.column(),
                });
                self.stage = Stage::Failed;
                return Err(refused());
            }
        }
        self.stage = Stage::Decoded;
        if let Err(error) = self.offer.as_ref().ok_or_else(refused)?.validate() {
            self.failure = Some(match error {
                ContractError::Invalid { field, reason } => Failure::Validation { field, reason },
                ContractError::Json(error) => Failure::Json {
                    category: error.classify(),
                    line: error.line(),
                    column: error.column(),
                },
                ContractError::Overflow => Failure::Arithmetic,
            });
            self.stage = Stage::Failed;
            return Err(refused());
        }
        if !self.offer.as_ref().ok_or_else(refused)?.required.is_empty() {
            self.failure = Some(Failure::RequiredDefinition);
            self.stage = Stage::Failed;
            return Err(refused());
        }
        self.stage = Stage::Checked;
        self.owner.ensure_current()
    }

    /// Completes request DATA after all original terminal custody checks.
    ///
    /// # Errors
    /// Refuses stale custody or missing/refused request outputs.
    pub(super) fn complete_data(&mut self) -> Result<(), ProviderError> {
        self.owner.ensure_current()?;
        if self.stage != Stage::Checked
            || self.claims.is_none()
            || self.offer.is_none()
            || self.failure.is_some()
        {
            return Err(refused());
        }
        self.stage = Stage::Complete;
        Ok(())
    }

    /// Permanently refuses the attempt without dropping initialized owners.
    pub(super) fn refuse_data(&mut self) {
        self.stage = Stage::Failed;
    }

    /// Lends completed scalar claims and the actual validated offer.
    ///
    /// # Errors
    /// Refuses foreign custody or an incomplete/refused occurrence.
    pub(super) fn data(&self) -> Result<(wire::Claims, &ExtensionOfferV1), ProviderError> {
        self.owner.ensure_current()?;
        if self.stage != Stage::Complete {
            return Err(refused());
        }
        Ok((
            self.claims.ok_or_else(refused)?,
            self.offer.as_ref().ok_or_else(refused)?,
        ))
    }

    /// Counts surviving typed offer and actual validation-diagnostic backing.
    ///
    /// # Errors
    /// Refuses foreign custody, observer exhaustion or checked capacity overflow.
    pub(in super::super) fn retained_backing_data(&self) -> Result<usize, ProviderError> {
        let Self {
            owner,
            stage: _,
            row: _,
            claims: _,
            offer,
            failure,
        } = self;
        owner.ensure_current()?;
        let mut observer = MetadataObserver::new();
        if let Some(offer) = offer {
            let ExtensionOfferV1 {
                format,
                required,
                optional,
            } = offer;
            observer.observe(format)?;
            observer.observe(required)?;
            observer.observe(optional)?;
        }
        let mut bytes = requested_metadata_backing_storage_data(&observer.finish())?;
        if let Some(failure) = failure {
            match failure {
                Failure::Validation { field: _, reason } => {
                    bytes = bytes.checked_add(reason.capacity()).ok_or_else(refused)?;
                }
                Failure::Json {
                    category: _,
                    line: _,
                    column: _,
                }
                | Failure::Claims
                | Failure::Arithmetic
                | Failure::RequiredDefinition => {}
            }
        }
        Ok(bytes)
    }

    #[cfg(test)]
    pub(in super::super) fn row_fixture_data(&self) -> Option<[usize; 3]> {
        self.row
    }

    #[cfg(test)]
    pub(in super::super) fn offer_fixture_data(&self) -> Option<&ExtensionOfferV1> {
        self.offer.as_ref()
    }

    /// Names actual request, typed-error and retained-output controls.
    pub(super) fn counter_scratch_data() -> usize {
        wire::counter_scratch_data()
            + storage::counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<&mut Self>()
            + size_of::<wire::Claims>() * 2
            + size_of::<Option<wire::Claims>>()
            + size_of::<wire::Inspected<'static>>()
            + size_of::<Result<wire::Inspected<'static>, ProviderError>>()
            + size_of::<ExtensionOfferV1>()
            + size_of::<Result<ExtensionOfferV1, serde_json::Error>>()
            + size_of::<ContractError>()
            + size_of::<Failure>()
            + size_of::<Option<Failure>>()
            + size_of::<Stage>()
            + size_of::<serde_json::error::Category>()
            + size_of::<MetadataObserver<'static>>()
            + size_of::<crate::retained_metadata::RetainedProtocolMetadataFacts>()
            + size_of::<usize>() * 4
            + size_of::<Result<(), ProviderError>>() * 5
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original import18 Hello request attempt")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_format::{ExtensionSelection, Id, SemanticVersion, U64, canonical};
    use serde_json::json;
    use std::time::Duration;

    fn cut() -> OperationalDeadline {
        OperationalDeadline::after(Duration::from_secs(5)).unwrap()
    }

    fn definition() -> Value {
        let declaration =
            canonical::content_ref(b"optional definition DATA", "application/json").unwrap();
        serde_json::to_value(ExtensionSelection {
            schema_digest: declaration.hash.clone(),
            declaration,
            identifier: Id::new("vendor.example/optional").unwrap(),
            semantic_version: SemanticVersion {
                major: U64::new(1),
                minor: U64::new(0),
                patch: U64::new(0),
                prerelease: None,
                build: None,
            },
        })
        .unwrap()
    }

    fn quoted(value: &Value) -> Attempt {
        let mut attempt = Attempt::empty_data();
        assert_eq!(attempt.retained_backing_data().unwrap(), 0);
        attempt.start_data().unwrap();
        let row = storage::construction_data(serde_json::to_vec(value).unwrap().len(), 268_435_456)
            .unwrap();
        attempt.quote_data(row).unwrap();
        attempt
    }

    #[test]
    fn actual_optional_definitions_are_retained_without_selecting_their_semantics() {
        for reactive in [false, true] {
            let (launch, selection, mut value) = wire::tests::fixture(reactive);
            value["extensions"][crate::handshake::EXTENSION_NEGOTIATION_V1]["optional"] =
                json!([definition()]);
            let mut attempt = quoted(&value);

            attempt
                .inspect_data(&value, &launch, &selection, cut())
                .unwrap();
            attempt.complete_data().unwrap();
            let (claims, offer) = attempt.data().unwrap();
            assert_eq!(claims.controller_nonce, [19; 32]);
            assert_eq!(offer.optional.len(), 1);
            assert!(offer.required.is_empty());
            offer.validate().unwrap();
            let pointer = offer.optional.as_ptr();
            let retained = attempt.retained_backing_data().unwrap();
            assert!(retained > 0 && retained <= attempt.row.unwrap()[0]);

            assert!(attempt.start_data().is_err());
            assert_eq!(attempt.data().unwrap().1.optional.as_ptr(), pointer);
            attempt.refuse_data();
            assert!(attempt.data().is_err());
            assert_eq!(attempt.retained_backing_data().unwrap(), retained);
        }
    }

    #[test]
    fn maximum_actual_offer_fits_its_independent_future_row() {
        let (launch, selection, mut value) = wire::tests::fixture(false);
        let mut definitions = Vec::new();
        for index in 0..crate::handshake::MAXIMUM_NEGOTIATED_EXTENSIONS {
            let mut definition = definition();
            definition["identifier"] = json!(format!("vendor.example/optional/{index:03}"));
            definitions.push(definition);
        }
        value["extensions"][crate::handshake::EXTENSION_NEGOTIATION_V1]["optional"] =
            json!(definitions);
        let encoded_bytes = serde_json::to_vec(&value).unwrap().len();
        let actual = storage::construction_data(encoded_bytes, 268_435_456).unwrap();
        let future = storage::construction_data(encoded_bytes + 4096, 268_435_456).unwrap();
        assert!(
            actual
                .into_iter()
                .zip(future)
                .all(|(actual, future)| actual <= future)
        );
        let peak = future.into_iter().sum::<usize>();
        assert!(storage::construction_data(encoded_bytes + 4096, peak - 1).is_err());

        let mut attempt = quoted(&value);
        attempt
            .inspect_data(&value, &launch, &selection, cut())
            .unwrap();
        attempt.complete_data().unwrap();
        assert_eq!(
            attempt.data().unwrap().1.optional.len(),
            crate::handshake::MAXIMUM_NEGOTIATED_EXTENSIONS
        );
        assert!(attempt.retained_backing_data().unwrap() <= actual[0]);
    }

    #[test]
    fn failed_claims_and_decodes_retain_only_the_outputs_actually_constructed() {
        let (launch, selection, original) = wire::tests::fixture(false);
        for (pointer, replacement, claims) in [
            ("/body/admission_token", json!("invalid"), false),
            (
                "/extensions/cnp.extension-negotiation~11/format",
                json!(null),
                true,
            ),
            (
                "/extensions/cnp.extension-negotiation~11/optional",
                json!([null]),
                true,
            ),
            (
                "/extensions/cnp.extension-negotiation~11/optional",
                json!(vec![Value::Null; 257]),
                true,
            ),
        ] {
            let mut value = original.clone();
            *value.pointer_mut(pointer).unwrap() = replacement;
            let mut attempt = quoted(&value);

            assert!(
                attempt
                    .inspect_data(&value, &launch, &selection, cut())
                    .is_err()
            );
            assert_eq!(attempt.claims.is_some(), claims, "{pointer}");
            assert!(attempt.offer.is_none());
            assert!(attempt.failure.is_some());
            assert_eq!(attempt.retained_backing_data().unwrap(), 0);
            assert!(attempt.complete_data().is_err());
            assert!(attempt.start_data().is_err());
        }
    }

    #[test]
    fn every_typed_validation_family_preserves_its_actual_output_and_reason() {
        let (launch, selection, mut original) = wire::tests::fixture(false);
        let offer_key = crate::handshake::EXTENSION_NEGOTIATION_V1;
        original["extensions"][offer_key]["optional"] = json!([definition()]);
        for (pointer, replacement) in [
            ("/format", json!("2")),
            ("/optional/0/declaration/hash/algorithm", json!("sha256")),
            ("/optional/0/declaration/hash/domain", json!("other.domain")),
            ("/optional/0/declaration/hash/digest", json!("bad")),
            ("/optional/0/declaration/media_type", json!("")),
            ("/optional/0/semantic_version/prerelease", json!("01")),
            ("/optional/0/semantic_version/build", json!("a..b")),
            ("/optional/0/schema_digest/domain", json!("other.domain")),
            ("/optional/0/identifier", json!("unqualified")),
            ("/optional", json!([definition(), definition()])),
            ("/required", json!([definition()])),
        ] {
            let mut value = original.clone();
            *value["extensions"][offer_key].pointer_mut(pointer).unwrap() = replacement;
            let mut attempt = quoted(&value);

            assert!(
                attempt
                    .inspect_data(&value, &launch, &selection, cut())
                    .is_err(),
                "{pointer}"
            );
            assert!(attempt.claims.is_some());
            assert!(attempt.offer.is_some(), "{pointer}");
            let Some(Failure::Validation { reason, .. }) = &attempt.failure else {
                panic!("missing actual validation diagnostic: {pointer}");
            };
            assert!(
                super::storage::validation_reason_fixture_data(reason),
                "unpriced validation reason: {reason}"
            );
            let retained = attempt.retained_backing_data().unwrap();
            assert!(retained > 0 && retained <= attempt.row.unwrap()[0]);
            attempt.refuse_data();
            assert_eq!(attempt.retained_backing_data().unwrap(), retained);
            assert!(attempt.start_data().is_err());
        }
    }

    #[test]
    fn valid_required_definition_refuses_the_declared_empty_registry_without_discarding_it() {
        let (launch, selection, mut value) = wire::tests::fixture(false);
        value["extensions"][crate::handshake::EXTENSION_NEGOTIATION_V1]["required"] =
            json!([definition()]);
        let mut attempt = quoted(&value);

        assert!(
            attempt
                .inspect_data(&value, &launch, &selection, cut())
                .is_err()
        );
        assert!(matches!(attempt.failure, Some(Failure::RequiredDefinition)));
        assert_eq!(attempt.offer.as_ref().unwrap().required.len(), 1);
        assert!(attempt.retained_backing_data().unwrap() <= attempt.row.unwrap()[0]);
        assert!(attempt.data().is_err());
        assert!(attempt.start_data().is_err());
    }
}
