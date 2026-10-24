//! Counts actual semantic operands without issuing or encoding a future cut.
//!
//! Only the private canonical extent sink consumes these serializers. The real
//! writer independently requires its genuine Window claim and preencoder Cut.

use super::super::*;
use super::{
    encoding_extent, logical::OriginalSourceRestoredWorld17View,
    quote_context::OriginalSourceRestoredCaptureQuoteInputs,
};
use crate::node_adapters::cnp::semantic::node::OriginalRestoredSettledNodeHistoryView;
use crate::node_admission::OriginalRestoredCaptureSigningInputs;
use crucible_node_transport::client::CnpController;
use serde::{Serialize, Serializer, ser::SerializeStruct};

struct Accounting<'a> {
    source: &'a PacketCompleteSemanticSource,
    controller: &'a CnpController,
    launch: &'a PacketNative5SourceLaunch,
    inputs: &'a OriginalRestoredCaptureSigningInputs<'a>,
    node: &'a OriginalRestoredSettledNodeHistoryView<'a>,
    quote: &'a OriginalSourceRestoredCaptureQuoteInputs<'a>,
    key: &'a [u8; 32],
    frontier: U64,
}

struct Source<'a, 'b>(&'a Accounting<'b>);

// This is prospective scalar accounting DATA, never a CapturePreEncoderCut.
// It is private and cannot escape the only counting function below.
#[derive(Serialize)]
struct ProspectiveCapture {
    schema: &'static str,
    cut: &'static str,
    phase: &'static str,
    once_spent: bool,
    failed: bool,
    prefix_frontier: Option<U64>,
    frontier: Option<U64>,
    bridge: Option<()>,
}

impl Serialize for Accounting<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let node = (*self.node)
            .with_aliases(self.quote.aliases)
            .with_metadata_banks(self.quote.records, self.quote.provider_aliases);
        let mut r = s.serialize_struct("RestoredSettledSemantic17", 4)?;
        r.serialize_field(
            "schema",
            "source-private.semantic-state-restored-settled/17",
        )?;
        r.serialize_field("ancestry", self.quote.ancestry)?;
        r.serialize_field("node", &node)?;
        r.serialize_field("source", &Source(self))?;
        r.end()
    }
}

impl Serialize for Source<'_, '_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;
        let a = self.0;
        let association = a
            .source
            .ack_peer_association
            .try_borrow()
            .map_err(S::Error::custom)?;
        let original = association
            .as_ref()
            .ok_or_else(|| S::Error::custom("Source absent"))?;
        let producer = original
            .producer_progress
            .try_borrow()
            .map_err(S::Error::custom)?;
        let current = original
            .current_observations
            .try_borrow()
            .map_err(S::Error::custom)?;
        current
            .require_unused_logical17_data()
            .map_err(S::Error::custom)?;
        if producer.failed
            || producer
                .attempts
                .iter()
                .any(|v| v.stage.get() != Stage::Verified)
        {
            return Err(S::Error::custom("Source Producer is incomplete"));
        }
        for attempt in &producer.attempts {
            if attempt.signature
                != Some(proof::signature_data(attempt, a.key).map_err(S::Error::custom)?)
            {
                return Err(S::Error::custom("Source Producer signature differs"));
            }
        }
        let installation = a.source.installation();
        let inherited = a
            .quote
            .inherited
            .map_or(0, |v| v.logical_limits_data().producer_used);
        if a.quote.inherited.is_some_and(|prior| {
            prior.original_generic_limits_data()
                != (
                    installation.maximum_operations,
                    installation.maximum_semantic_bytes,
                    installation.maximum_result_bytes,
                    installation.maximum_authorization_bytes,
                )
        }) {
            return Err(S::Error::custom("Source original generic limits differ"));
        }
        let used = inherited
            .checked_add(producer.attempts.len())
            .filter(|n| *n <= installation.maximum_operations)
            .ok_or_else(|| S::Error::custom("Source lifetime limit"))?;
        let first = original
            .restoration_observation
            .as_ref()
            .ok_or_else(|| S::Error::custom("first Source absent"))?
            .borrowed_logical17_data(a.source, a.controller)
            .map_err(S::Error::custom)?;
        let header = a
            .source
            .borrowed_settled17_header_data(a.quote.aliases)
            .map_err(S::Error::custom)?;
        let once = original
            .borrowed_completed_once17_data(a.source, a.controller, a.key, header)
            .map_err(S::Error::custom)?;
        let limits = super::logical::OriginalSourceRestoredLimits17 {
            maximum_operations: installation.maximum_operations,
            maximum_originals: a
                .source
                .original_restored_settled_source17_boot_original_limit_data()
                .map_err(S::Error::custom)?,
            producer_used: used,
            current_observations_used: 0,
            input_used: 0,
        };
        let mut r = s.serialize_struct("RestoredSettledSource17", 11)?;
        r.serialize_field("schema", "source-private.source-restored-settled-state/17")?;
        r.serialize_field(
            "installation",
            &super::logical::OriginalSourceRestoredInstallationExpected17(installation, a.launch),
        )?;
        r.serialize_field(
            "world",
            &OriginalSourceRestoredWorld17View::new_data(a.inputs.world.record()),
        )?;
        r.serialize_field("once", &once)?;
        r.serialize_field("limits", &limits)?;
        r.serialize_field("first_observation", &first)?;
        r.serialize_field(
            "producer",
            &producer
                .borrowed_logical17_data()
                .map_err(S::Error::custom)?,
        )?;
        r.serialize_field(
            "current_observations",
            &current
                .borrowed_logical17_data()
                .map_err(S::Error::custom)?,
        )?;
        r.serialize_field("input_history", &None::<()>)?;
        r.serialize_field(
            "capture",
            &ProspectiveCapture {
                schema: "source-private.source-capture-housekeeping/17",
                cut: "pre_encoder",
                phase: "preparing",
                once_spent: true,
                failed: false,
                prefix_frontier: Some(a.frontier),
                frontier: None,
                bridge: None,
            },
        )?;
        r.serialize_field("inherited", &a.quote.inherited.map(|v| v.reference_data()))?;
        r.end()
    }
}

pub(super) fn extent_data(
    source: &PacketCompleteSemanticSource,
    controller: &CnpController,
    launch: &PacketNative5SourceLaunch,
    inputs: &OriginalRestoredCaptureSigningInputs<'_>,
    node: &OriginalRestoredSettledNodeHistoryView<'_>,
    quote: &OriginalSourceRestoredCaptureQuoteInputs<'_>,
    frontier: U64,
    checkpoint_bound: usize,
    maximum: usize,
) -> Result<usize, RuntimeError> {
    source.authenticate_capture17_counting_banks_data(
        node,
        quote.aliases,
        quote.records,
        quote.provider_aliases,
        maximum,
    )?;
    inputs.authenticate_current_data()?;
    source.authenticate_unused_signed_observation17_owner_data()?;
    source.authenticate_unused_input17_owner_data()?;
    if !std::ptr::eq(source, inputs.source) {
        return Err(RuntimeError::ForeignAuthority);
    }
    let birth = source
        .ack_peer_birth
        .try_borrow()
        .map_err(|_| RuntimeError::OwnerBusy)?;
    let key = birth
        .as_ref()
        .ok_or(RuntimeError::OwnerUnavailable)?
        .original_fresh_query_key_data()?;
    quote
        .aliases
        .try_borrow_mut()
        .map_err(|_| RuntimeError::OwnerBusy)?
        .begin_pass()?;
    let semantic = encoding_extent::canonical_encoded_extent_data(
        &Accounting {
            source,
            controller,
            launch,
            inputs,
            node,
            quote,
            key,
            frontier,
        },
        maximum,
    )?;
    // A fixed null placeholder prices only syntax. Neither this shell nor its
    // prospective scalar child is sent to a Value or archive encoder.
    let shell = encoding_extent::canonical_encoded_extent_data(
        &Shell {
            schema: "source-private.source-restored-settled-capture-prefix/17",
            history: None,
            coordinator_checkpoint: Checkpoint {
                reference: reference_bound(
                    "application/vnd.crucible.coordinator-commitment-checkpoint+json;version=17",
                ),
                body: None,
            },
        },
        maximum,
    )?;
    // Each null literal contributed exactly four bytes; replace both with the
    // counted semantic body and the genuine canonical Runtime checkpoint body.
    let result = super::construction_quote::sum(
        &[
            shell.checked_sub(8).ok_or(RuntimeError::ResourceLimit)?,
            semantic,
            checkpoint_bound,
        ],
        maximum,
    )?;
    inputs.authenticate_current_data()?;
    source.authenticate_unused_signed_observation17_owner_data()?;
    source.authenticate_unused_input17_owner_data()?;
    Ok(result)
}

pub(super) fn counter_scratch_data() -> usize {
    std::mem::size_of::<Accounting<'static>>()
        + std::mem::size_of::<Source<'static, 'static>>()
        + std::mem::size_of::<ProspectiveCapture>()
        + encoding_extent::counter_scratch_data()
        + OriginalSourceRestoredWorld17View::counter_scratch_data()
        + std::mem::size_of::<Checkpoint>()
        + std::mem::size_of::<Shell>()
        + std::mem::size_of::<HashBound>()
        + std::mem::size_of::<ReferenceBound>()
        + std::mem::size_of::<BridgeBound<'static>>()
        + std::mem::size_of::<LedgerBound<'static>>()
        + std::mem::size_of::<EscapedIdBound>()
        + std::mem::size_of::<[u8; 128]>()
        + std::mem::size_of::<Result<&str, std::str::Utf8Error>>()
}

#[derive(Serialize)]
struct HashBound {
    algorithm: &'static str,
    domain: &'static str,
    digest: &'static str,
}

#[derive(Serialize)]
struct ReferenceBound {
    hash: HashBound,
    length: U64,
    media_type: &'static str,
}

fn reference_bound(media_type: &'static str) -> ReferenceBound {
    ReferenceBound {
        hash: HashBound {
            algorithm: "blake3-256",
            domain: "cnp.blob.v1",
            digest: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        },
        length: U64::new(u64::MAX),
        media_type,
    }
}

struct EscapedIdBound;

impl Serialize for EscapedIdBound {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        // A quoted ASCII control character takes six JSON bytes. Id's actual
        // closed byte grammar allows at most128 bytes; no future Id is issued.
        let bytes = [0x01u8; 128];
        let text = std::str::from_utf8(&bytes).map_err(serde::ser::Error::custom)?;
        s.serialize_str(text)
    }
}

pub(super) fn final_semantic_extent_bound_data(
    prefix: usize,
    world: &crate::node_contract::WorldActivation,
    _capture: &Id,
    maximum: usize,
) -> Result<usize, RuntimeError> {
    let bound = LedgerBound {
        schema: "source-private.source-capture-housekeeping/17",
        cut: "settled",
        phase: "complete",
        once_spent: true,
        failed: false,
        prefix_frontier: Some(U64::new(u64::MAX)),
        frontier: Some(U64::new(u64::MAX)),
        bridge: Some(BridgeBound {
            schema: "source-private.source-restored-capture-admin-bridge/17",
            world: OriginalSourceRestoredWorld17View::new_data(world.record()),
            measurement: reference_bound("application/json"),
            model: reference_bound("application/json"),
            native_after: reference_bound("application/json"),
            capture_request: reference_bound("application/json"),
            capture_id: EscapedIdBound,
            capture_operation: EscapedIdBound,
            prefix_frontier: U64::new(u64::MAX),
            frontier: U64::new(u64::MAX),
            signature: [255; 32],
        }),
    };
    super::construction_quote::sum(
        &[
            prefix,
            encoding_extent::canonical_encoded_extent_data(&bound, maximum)?,
        ],
        maximum,
    )
}

#[derive(Serialize)]
struct Checkpoint {
    reference: ReferenceBound,
    body: Option<()>,
}

#[derive(Serialize)]
struct Shell {
    schema: &'static str,
    history: Option<()>,
    coordinator_checkpoint: Checkpoint,
}

#[derive(Serialize)]
struct BridgeBound<'a> {
    schema: &'static str,
    world: OriginalSourceRestoredWorld17View<'a>,
    measurement: ReferenceBound,
    model: ReferenceBound,
    native_after: ReferenceBound,
    capture_request: ReferenceBound,
    capture_id: EscapedIdBound,
    capture_operation: EscapedIdBound,
    prefix_frontier: U64,
    frontier: U64,
    signature: [u8; 32],
}

#[derive(Serialize)]
struct LedgerBound<'a> {
    schema: &'static str,
    cut: &'static str,
    phase: &'static str,
    once_spent: bool,
    failed: bool,
    prefix_frontier: Option<U64>,
    frontier: Option<U64>,
    bridge: Option<BridgeBound<'a>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_checkpoint_reference_bound_dominates_actual_generated_reference() {
        let media = "application/vnd.crucible.coordinator-commitment-checkpoint+json;version=17";
        let actual = canonical::content_ref(b"actual retained checkpoint", media).unwrap();
        let bound =
            encoding_extent::canonical_encoded_extent_data(&reference_bound(media), usize::MAX)
                .unwrap();
        let actual = encoding_extent::canonical_encoded_extent_data(&actual, usize::MAX).unwrap();
        assert!(actual <= bound);
    }

    #[test]
    fn routing_id_bound_covers_maximum_json_escape_expansion_without_allocating_an_id() {
        let bound =
            encoding_extent::canonical_encoded_extent_data(&EscapedIdBound, usize::MAX).unwrap();
        assert_eq!(bound, 2 + 128 * 6);
        for text in ["short", "quote\"slash\\", "non-ASCII: λ"] {
            assert!(
                encoding_extent::canonical_encoded_extent_data(text, usize::MAX).unwrap() <= bound
            );
        }
    }
}
