//! Retains complete assignments and original canonical or semantic refusals.
//!
//! These destinations use the ordinary assignment codecs. A captured manifest
//! establishes neither current inputs nor permission to publish or execute it.
//! Callers must admit storage before entry and retain their genuine original.

use std::error::Error;
use std::mem::size_of;

use crate::model::{
    AssignmentManifestV1, InvalidAssignmentManifest, InvalidDomainModel,
    MAX_ANCESTRY_DEPTH, MAX_ASSIGNMENT_REQUIRED_FEATURES,
    MAX_ASSIGNMENT_SOURCE_COMMITMENTS, SandboxAncestry,
};
use crate::{CanonicalAssignmentManifestV1, FeatureRef, ObjectDescriptor, SandboxId};

use super::decode_attempt::{DecodeAttempt, DecodeFailure};
use super::{CanonicalCborError, DecodeLimits};

/// Retains the actual typed assignment and its original canonical or typed refusal.
#[derive(Default)]
pub struct AssignmentManifestDecodeCaptureV1 {
    attempt: DecodeAttempt<AssignmentManifestV1>,
    closed: Option<CanonicalCborError>,
}

impl AssignmentManifestDecodeCaptureV1 {
    /// Constructs an inert destination without decoding or allocation.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Decodes once through the shared ordinary assignment engine.
    ///
    /// # Errors
    ///
    /// Returns the original canonical or semantic refusal, or a closed error
    /// after repeated entry. The original failure remains resident; rejected
    /// inert prefixes may drop.
    pub fn decode_once_v1(
        &mut self,
        bytes: &[u8],
        limits: DecodeLimits,
    ) -> Result<(), CanonicalCborError> {
        if let Some(error) = self.closed.as_ref() {
            return Err(error.clone());
        }
        if let Err(error) = self.attempt.begin() {
            self.closed.get_or_insert(error);
            return Err(self
                .closed
                .as_ref()
                .ok_or_else(super::decode_attempt::closed)?
                .clone());
        }
        let result = super::assignment::decode_assignment_manifest_engine_v1(bytes, limits);
        self.attempt.finish(result)
    }

    /// Borrows the first retained canonical refusal or later closed-entry error.
    #[must_use]
    pub fn failure(&self) -> Option<&CanonicalCborError> {
        self.attempt.failure().or(self.closed.as_ref())
    }

    /// Borrows the exact typed constructor or canonical cause.
    #[must_use]
    pub fn cause(&self) -> Option<&(dyn Error + 'static)> {
        self.attempt
            .cause()
            .or_else(|| self.failure().map(|cause| cause as _))
    }

    /// Borrows the complete model only while the once destination remains open.
    #[must_use]
    pub fn value(&self) -> Option<&AssignmentManifestV1> {
        self.attempt.model()
    }

    /// Moves the complete actual model once without reparsing or cloning.
    ///
    /// # Errors
    ///
    /// Returns the retained refusal or a closed error for incomplete, repeated
    /// or already moved destinations.
    pub fn take_model_once(&mut self) -> Result<AssignmentManifestV1, CanonicalCborError> {
        self.attempt.take_model_once()
    }
}

/// Retains the final exact-byte assignment or its original parse refusal.
#[derive(Default)]
pub struct CanonicalAssignmentDecodeCaptureV1 {
    attempt: DecodeAttempt<CanonicalAssignmentManifestV1>,
    closed: Option<CanonicalCborError>,
}

impl CanonicalAssignmentDecodeCaptureV1 {
    /// Constructs an inert canonical assignment destination.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Decodes and compares the exact canonical representation once.
    ///
    /// # Errors
    ///
    /// Returns the shared decoder or canonical comparison refusal. Reentry is
    /// closed and never discards the original complete model or first cause.
    pub fn decode_once_v1(
        &mut self,
        bytes: &[u8],
        limits: DecodeLimits,
    ) -> Result<(), CanonicalCborError> {
        if let Some(error) = self.closed.as_ref() {
            return Err(error.clone());
        }
        if let Err(error) = self.attempt.begin() {
            self.closed.get_or_insert(error);
            return Err(self
                .closed
                .as_ref()
                .ok_or_else(super::decode_attempt::closed)?
                .clone());
        }
        let result = CanonicalAssignmentManifestV1::from_canonical_bytes_engine_v1(bytes, limits);
        self.attempt.finish(result)
    }

    /// Borrows the first actual canonical refusal.
    #[must_use]
    pub fn failure(&self) -> Option<&CanonicalCborError> {
        self.attempt.failure().or(self.closed.as_ref())
    }

    /// Borrows the original nested cause before its canonical projection.
    #[must_use]
    pub fn cause(&self) -> Option<&(dyn Error + 'static)> {
        self.attempt
            .cause()
            .or_else(|| self.failure().map(|cause| cause as _))
    }

    /// Borrows the complete exact-byte assignment DATA.
    #[must_use]
    pub fn value(&self) -> Option<&CanonicalAssignmentManifestV1> {
        self.attempt.model()
    }

    /// Moves the complete canonical DATA once.
    ///
    /// # Errors
    ///
    /// Returns the retained refusal or a closed error if incomplete, repeated,
    /// or already moved.
    pub fn take_model_once(&mut self) -> Result<CanonicalAssignmentManifestV1, CanonicalCborError> {
        self.attempt.take_model_once()
    }

    /// Returns the actual destination plus one construction temporary in bytes.
    #[must_use]
    pub fn receiving_construction_bytes_v1() -> Option<usize> {
        size_of::<Self>().checked_mul(2)?
            .checked_add(size_of::<AssignmentReceivingFramesV1>())
    }

    /// Derives additional heap and diagnostic bytes from the actual input size.
    ///
    /// The whole-CBOR pass precedes schema reserves. A canonical but wrongly
    /// shaped element may occupy one byte, so collection slots are bounded by
    /// bytes and schema ceilings rather than by a valid element's minimum size.
    /// This excludes the caller's resident input and the fixed capsule itself.
    #[must_use]
    pub fn receiving_dynamic_footprint_v1(
        input_bytes: usize,
        limits: DecodeLimits,
    ) -> Option<(usize, usize)> {
        let validation_bytes =
            super::cbor::validation_receiving_bytes_v1(input_bytes, limits)?;
        let ancestor_slots = input_bytes.min(MAX_ANCESTRY_DEPTH);
        let source_slots = input_bytes.min(MAX_ASSIGNMENT_SOURCE_COMMITMENTS);
        let feature_slots = input_bytes.min(MAX_ASSIGNMENT_REQUIRED_FEATURES);
        let ancestry = ancestor_slots.checked_mul(size_of::<SandboxId>())?;
        let sources = source_slots.checked_mul(size_of::<ObjectDescriptor>())?;
        let features = feature_slots.checked_mul(size_of::<FeatureRef>())?;
        // Each typed source/feature slot retains its model and three fields;
        // ancestry retains one fixed identity per slot, including partial Vecs.
        let collection_cells = source_slots.checked_mul(4)?
            .checked_add(feature_slots.checked_mul(4)?)?
            .checked_add(ancestor_slots)?;
        // Disjoint decoded text is bounded by input bytes; a canonical output
        // Vec can grow to less than twice its final length. The extra plane
        // covers simultaneous old/new storage during growth, without cleanup
        // credit. Eight bounded diagnostic planes cover the typed registry,
        // inner/outer/returned canonical errors and retained/returned reentry
        // errors, including their formatting temporaries. Each reaches at most
        // one 255-byte schema name plus fixed registry text/numeric fields;
        // 4096 bytes also covers geometric growth of that formatted String.
        let bytes = ancestry.checked_add(sources)?.checked_add(features)?
            .checked_add(input_bytes.checked_mul(4)?)?.checked_add(8 * 4_096)?
            .checked_add(validation_bytes)?;
        // Diagnostic strings and recursive validation frames are byte backing,
        // not resident namespace entries. Retain the collection bound unchanged.
        Some((bytes, collection_cells))
    }
}

// Actual compiled carrier layouts for construction and the shared call chain.
// These are storage DATA only; this type is never instantiated or admitted by
// caller-supplied dimensions. Collection backing is charged separately below.
#[allow(dead_code)]
struct AssignmentReceivingFramesV1 {
    work: [DecodeAttempt<AssignmentManifestV1>; 2],
    decoder: [super::cbor::Decoder<'static>; 2],
    models: [AssignmentManifestV1; 3],
    canonical_models: [CanonicalAssignmentManifestV1; 2],
    descriptors: [Result<ObjectDescriptor, DecodeFailure>; 2],
    features: [Result<FeatureRef, DecodeFailure>; 2],
    parameter_planes: [AssignmentParametersV1; 3],
    canonical_errors: [CanonicalCborError; 4],
    ancestry_results: [Result<SandboxAncestry, InvalidDomainModel>; 2],
    manifest_results: [Result<AssignmentManifestV1, InvalidAssignmentManifest>; 2],
}

#[allow(dead_code)]
struct AssignmentParametersV1 {
    sandbox: SandboxId,
    project: crate::ProjectId,
    ancestry: &'static SandboxAncestry,
    incarnation: crate::IncarnationId,
    node: crate::NodeId,
    epoch: crate::AssignmentEpoch,
    desired: crate::DesiredGeneration,
    namespace: crate::NamespaceGeneration,
    descriptors: [&'static ObjectDescriptor; 4],
    sources: &'static [ObjectDescriptor],
    resource_commitment: crate::ObjectDigest,
    reservations: crate::ResourceVector,
    features: &'static [FeatureRef],
}

#[cfg(test)]
mod tests {
    use crate::{MediaType, ObjectDigest, PortableMediaType, ResourceDimension};
    use super::super::cbor::Encoder;
    use super::super::tree::{encode_descriptor, encode_feature};
    use super::*;

    #[derive(Clone, Copy)]
    enum Input {
        Valid,
        RepeatedAncestor,
        BadSecondDescriptor,
        RepeatedSource,
        WrongShapedSources,
    }

    fn descriptor(kind: PortableMediaType, byte: u8) -> ObjectDescriptor {
        ObjectDescriptor::new(
            MediaType::new(kind.as_str().to_owned()).unwrap(),
            ObjectDigest::from_bytes([byte; 32]),
            1,
        )
    }

    fn bytes(input: Input) -> Vec<u8> {
        let mut encoder = Encoder::new();
        encoder.array(17);
        encoder.unsigned(1);
        encoder.bytes(&[1; 16]);
        encoder.bytes(&[2; 16]);
        encoder.array(if matches!(input, Input::RepeatedAncestor) { 2 } else { 1 });
        encoder.bytes(&[3; 16]);
        if matches!(input, Input::RepeatedAncestor) {
            encoder.bytes(&[3; 16]);
        }
        encoder.bytes(&[4; 16]);
        encoder.bytes(&[5; 16]);
        encoder.unsigned(1);
        encoder.unsigned(1);
        encoder.unsigned(1);
        encode_descriptor(&mut encoder, &descriptor(PortableMediaType::SandboxSpec, 6));
        if matches!(input, Input::BadSecondDescriptor) {
            encoder.array(4);
            encoder.text(PortableMediaType::Policy.as_str());
            encoder.unsigned(0);
            encoder.bytes(&[7; 32]);
            encoder.unsigned(1);
        } else {
            encode_descriptor(&mut encoder, &descriptor(PortableMediaType::Policy, 7));
        }
        encode_descriptor(&mut encoder, &descriptor(PortableMediaType::Environment, 8));
        encode_descriptor(&mut encoder, &descriptor(PortableMediaType::View, 9));
        if matches!(input, Input::WrongShapedSources) {
            encoder.array(4);
            for _ in 0..4 {
                encoder.unsigned(0);
            }
        } else {
            encoder.array(if matches!(input, Input::RepeatedSource) { 2 } else { 1 });
            encode_descriptor(&mut encoder, &descriptor(PortableMediaType::Content, 10));
            if matches!(input, Input::RepeatedSource) {
                encode_descriptor(&mut encoder, &descriptor(PortableMediaType::Content, 10));
            }
        }
        encoder.bytes(&[11; 32]);
        encoder.array(ResourceDimension::COUNT);
        for _ in 0..ResourceDimension::COUNT {
            encoder.unsigned(0);
        }
        encoder.array(1);
        encode_feature(&mut encoder, &FeatureRef::new("aos.sandbox.runtime.linux-systemd", 1, 0).unwrap());
        encoder.finish()
    }

    #[test]
    fn late_descriptor_refusal_matches_ordinary_without_a_partial_model() {
        let input = bytes(Input::BadSecondDescriptor);
        let mut capture = AssignmentManifestDecodeCaptureV1::new();

        let error = capture
            .decode_once_v1(&input, DecodeLimits::default())
            .unwrap_err();

        assert_eq!(capture.failure(), Some(&error));
        assert!(capture.value().is_none());
        assert_eq!(
            super::super::decode_assignment_manifest_v1(&input, DecodeLimits::default()).unwrap_err(),
            error
        );
    }

    #[test]
    fn constructor_refusal_retains_exact_typed_cause_across_reentry() {
        let mut capture = AssignmentManifestDecodeCaptureV1::new();

        capture
            .decode_once_v1(&bytes(Input::RepeatedSource), DecodeLimits::default())
            .unwrap_err();
        let cause = capture
            .cause()
            .unwrap()
            .downcast_ref::<InvalidAssignmentManifest>()
            .unwrap();
        assert_eq!(
            *cause,
            InvalidAssignmentManifest::SourceCommitmentsNotCanonical
        );
        let original = cause as *const _;
        assert!(
            capture
                .decode_once_v1(&bytes(Input::Valid), DecodeLimits::default())
                .is_err()
        );

        assert_eq!(
            capture
                .cause()
                .unwrap()
                .downcast_ref::<InvalidAssignmentManifest>()
                .unwrap() as *const _,
            original
        );
        assert!(capture.value().is_none());
    }

    #[test]
    fn ancestry_constructor_refusal_retains_its_original_typed_error() {
        let mut capture = AssignmentManifestDecodeCaptureV1::new();

        capture
            .decode_once_v1(&bytes(Input::RepeatedAncestor), DecodeLimits::default())
            .unwrap_err();

        assert_eq!(
            capture
                .cause()
                .unwrap()
                .downcast_ref::<InvalidDomainModel>(),
            Some(&InvalidDomainModel::InvalidAncestry)
        );
        assert!(capture.value().is_none());
    }

    #[test]
    fn canonical_wrong_shape_remains_byte_admitted_without_a_partial_model() {
        use crate::component_receiving::ComponentServiceReceivingLedgerV1;
        use crate::{ResourceDimension as D, ResourceVector};

        let input = bytes(Input::WrongShapedSources);
        let (heap, _) = CanonicalAssignmentDecodeCaptureV1::receiving_dynamic_footprint_v1(
            input.len(),
            DecodeLimits::default(),
        )
        .unwrap();
        let demand = ResourceVector::ZERO.with(D::MemoryBytes, heap as u64);
        let mut ledger = ComponentServiceReceivingLedgerV1::new(demand);
        ledger.reserve(demand).unwrap();
        let mut capture = AssignmentManifestDecodeCaptureV1::new();

        capture
            .decode_once_v1(&input, DecodeLimits::default())
            .unwrap_err();

        assert!(capture.value().is_none());
        assert_eq!(ledger.charged(), demand);
        assert!(
            ledger
                .reserve(ResourceVector::ZERO.with(D::MemoryBytes, 1))
                .is_err()
        );
        assert_eq!(ledger.charged(), demand);
    }

    #[test]
    fn decoder_stack_depth_changes_bytes_without_changing_namespace_demand() {
        let input = bytes(Input::Valid);
        let shallow = DecodeLimits { maximum_depth: 32, ..DecodeLimits::default() };
        let deep = DecodeLimits { maximum_depth: 64, ..DecodeLimits::default() };
        let mut shallow_capture = CanonicalAssignmentDecodeCaptureV1::new();
        let mut deep_capture = CanonicalAssignmentDecodeCaptureV1::new();

        shallow_capture.decode_once_v1(&input, shallow).unwrap();
        deep_capture.decode_once_v1(&input, deep).unwrap();
        let (shallow_bytes, shallow_entries) =
            CanonicalAssignmentDecodeCaptureV1::receiving_dynamic_footprint_v1(input.len(), shallow).unwrap();
        let (deep_bytes, deep_entries) =
            CanonicalAssignmentDecodeCaptureV1::receiving_dynamic_footprint_v1(input.len(), deep).unwrap();

        assert_eq!(shallow_capture.value(), deep_capture.value());
        assert_eq!(shallow_capture.value().unwrap().canonical_bytes(), input);
        assert!(deep_bytes > shallow_bytes);
        assert_eq!(deep_entries, shallow_entries);
        assert!(shallow_entries > 0);
        let source_rows = shallow_capture.value().unwrap().manifest().source_commitments();
        assert!(!source_rows.is_empty());
        assert!(shallow_bytes >= source_rows.len() * size_of::<ObjectDescriptor>());
    }

    #[test]
    fn complete_canonical_data_moves_once_and_reentry_preserves_actual_owner() {
        let input = bytes(Input::Valid);
        let mut capture = CanonicalAssignmentDecodeCaptureV1::new();

        capture.decode_once_v1(&input, DecodeLimits::default()).unwrap();
        assert_eq!(capture.value().unwrap().canonical_bytes(), input);
        let model = capture.take_model_once().unwrap();

        assert_eq!(model.canonical_bytes(), input);
        assert!(capture.value().is_none());
        assert!(capture.decode_once_v1(&input, DecodeLimits::default()).is_err());
        assert!(capture.take_model_once().is_err());
        assert_eq!(model.manifest().source_commitments().len(), 1);
    }
}
