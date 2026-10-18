//! Binds final Capture17 settlement beside earlier native/semantic snapshot cuts.
//!
//! ```text
//! {ancestry,capture_request,capture_terminal,confirmation_request,
//!  confirmation_terminal,history_cut,objects,
//!  schema:"source-private.source-restored-settled-journal/17"}
//! ```
//!
//! The final journal follows real confirmation. Its native-before/snapshot and
//! semantic Source snapshots are earlier distinct cuts. No object contains its
//! own full reference or claims a future completion. Decoding never creates a
//! Source birth, Controller, Window, ledger, native adoption or Capture permit.

use super::owned11::{OriginalOwned11Fields as Fields, original_owned11_plain_string as plain};
use crate::reference_packet::service::{
    restored_settled_capture::*, restored_settled_confirmation::*,
};
use crate::{
    ProviderError,
    bodies::*,
    envelope::{Envelope, MessageKind, Method, RequestOrigin},
};
use crucible_node_contract::{ContentRef, U64, Validate, canonical};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::mem::size_of;

/// Names the closed new final Source journal family, independently of old15.
pub const RESTORED_SETTLED_JOURNAL17_SCHEMA: &str =
    "source-private.source-restored-settled-journal/17";

/// Names the current semantic17 object media, independently of its old ancestry.
pub const RESTORED_SETTLED_SEMANTIC17_MEDIA: &str =
    "application/vnd.source-owned.packet-semantic-custody.v17+json";
const RUNTIME7_MEDIA: &str = "application/vnd.crucible.runtime-original-lineage+json;version=7";
const INDEX3_MEDIA: &str = "application/vnd.crucible.native-signed-index-body.v3+json";

/// Retains this World's immutable imported lineage beside its current progress.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketRestoredSettledAncestry17 {
    /// Names the immediate parent's actual signed Index3 body.
    pub parent_archive_index: ContentRef,
    /// Names that same parent's separate authenticated archive artifact.
    pub parent_manifest: ContentRef,
    /// Names this World's actual imported semantic object (old5 or parent17).
    pub first_semantic: ContentRef,
    /// Names this World's actual imported source journal (legacy or parent17).
    pub first_journal: ContentRef,
    /// Names this World's immutable first verified restored Observe evidence.
    pub first_observation: ContentRef,
    /// Names the canonical full reference of the actual assigned Commit request.
    ///
    /// This is the same request named by the first activation scope; its
    /// correlated response remains a distinct original in that scope.
    pub restoration_commit: ContentRef,
    /// Names canonical retained `PacketNativeRestoredCommitHold` evidence.
    ///
    /// The native private proof and the exact Commit must authenticate this
    /// body. A matching model or an unrelated completed Hold is insufficient.
    pub restoration_hold: ContentRef,
}

impl PacketRestoredSettledAncestry17 {
    /// Checks reference syntax/media; signed DAG role/body correspondence is separate.
    ///
    /// # Errors
    /// Refuses malformed references or a substituted parent Index3-body media.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        for reference in self.references_data() {
            reference.validate()?;
        }
        if self.parent_archive_index.media_type != INDEX3_MEDIA {
            return Err(invalid());
        }
        Ok(())
    }

    /// Lends the complete seven-role immutable dependency roster.
    pub fn references_data(&self) -> [&ContentRef; 7] {
        [
            &self.parent_archive_index,
            &self.parent_manifest,
            &self.first_semantic,
            &self.first_journal,
            &self.first_observation,
            &self.restoration_commit,
            &self.restoration_hold,
        ]
    }

    /// Names the actual owned/borrowed field and iterator headers.
    pub fn counter_scratch_data() -> usize {
        size_of::<Self>()
            + size_of::<&Self>()
            + size_of::<[&ContentRef; 7]>()
            + size_of::<std::array::IntoIter<&ContentRef, 7>>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<Result<(), crucible_node_contract::ContractError>>()
    }
}

/// Binds each independently retained object to its exact final journal role.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketRestoredSettledJournal17Objects {
    /// Names complete native snapshot17.
    pub snapshot: ContentRef,
    /// Names exact raw pre-effect protocol embedded in snapshot17.
    pub before: ContentRef,
    /// Names actual current Control17, also embedded in snapshot17.
    pub control: ContentRef,
    /// Names independent unchanged-cut evidence.
    pub anchor: ContentRef,
    /// Names actual fourth protocol body delivered before confirmation terminal.
    pub after: ContentRef,
    /// Names actual current logical Controller/Session/Connection17.
    pub host_protocol: ContentRef,
    /// Names actual post-confirmation/Source-bridge, pre-Journal semantic17.
    pub semantic: ContentRef,
    /// Names the genuine same-ticket current Runtime7 object.
    pub runtime_object: ContentRef,
    /// Names the genuine independently ordered same-ticket coordinator prefix.
    pub coordinator_checkpoint: ContentRef,
}

impl PacketRestoredSettledJournal17Objects {
    /// Checks full references without proving body availability or authority.
    ///
    /// # Errors
    /// Refuses wrong media, malformed references or invalid native object aliasing.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        for reference in [
            &self.snapshot,
            &self.before,
            &self.control,
            &self.anchor,
            &self.after,
            &self.host_protocol,
        ] {
            reference.validate()?;
            if reference.media_type != "application/json" {
                return Err(invalid());
            }
        }
        self.semantic.validate()?;
        self.runtime_object.validate()?;
        self.coordinator_checkpoint.validate()?;
        if self.coordinator_checkpoint.media_type
            != crate::reference_packet::service::complete_restore::settled_recapture::COORDINATOR_CHECKPOINT17_MEDIA
            || self.semantic.media_type != RESTORED_SETTLED_SEMANTIC17_MEDIA
            || self.runtime_object.media_type != RUNTIME7_MEDIA
            || self.snapshot == self.control
            || self.snapshot == self.anchor
            || self.control == self.anchor
            || self.after == self.snapshot
            || self.after == self.control
            || self.after == self.anchor
        {
            return Err(invalid());
        }
        Ok(())
    }
}

/// Retains the actual prefix cut before this Capture's two auxiliary uploads.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketRestoredSettledHistoryCut17 {
    /// Names actual uploaded logical Source/SDK prefix, excluding this Capture.
    pub prefix: ContentRef,
    /// Retains actual nonrenewable next sequence at that earlier prefix cut.
    pub next_sequence: U64,
}

/// Streams only already retained final journal DATA under the actual Source scope.
#[derive(Serialize)]
pub struct PacketRestoredSettledJournal17View<'a> {
    /// Borrows exact immutable lineage roots.
    pub ancestry: &'a PacketRestoredSettledAncestry17,
    /// Borrows the actual proof-filled assigned Begin(Capture) original.
    pub capture_request: &'a Envelope,
    /// Borrows its actual uniquely correlated completed Response.
    pub capture_terminal: &'a Envelope,
    /// Borrows actual assigned Poll17 confirmation original.
    pub confirmation_request: &'a Envelope,
    /// Borrows its actual terminal carrying the fourth-body receipt.
    pub confirmation_terminal: &'a Envelope,
    /// Borrows the prefix cutoff before this Capture/upload owner was populated.
    pub history_cut: &'a PacketRestoredSettledHistoryCut17,
    /// Borrows all actual final object identities.
    pub objects: &'a PacketRestoredSettledJournal17Objects,
    /// Names only the new final journal family.
    pub schema: &'static str,
}

/// Borrows exact closed journal spans before any owning parse has been admitted.
pub struct PacketRestoredSettledJournal17Plan<'a> {
    ancestry: &'a [u8],
    objects: &'a [u8],
    history_cut: &'a [u8],
    capture_request: &'a [u8],
    capture_terminal: &'a [u8],
    confirmation_request: &'a [u8],
    confirmation_terminal: &'a [u8],
}

impl<'a> PacketRestoredSettledJournal17Plan<'a> {
    /// Checks exact family, canonical closed root and bounded raw object spans.
    ///
    /// # Errors
    /// Refuses missing/extra/duplicate root fields, old families or extent excess.
    /// Child logical/typed validation remains independently required after admission.
    pub fn validate(input: &'a [u8], maximum: usize) -> Result<Self, ProviderError> {
        if input.is_empty() || input.len() > maximum {
            return Err(invalid());
        }
        let mut fields = Fields::object(input)?;
        let ancestry = fields.named("ancestry")?;
        let capture_request = fields.named("capture_request")?;
        let capture_terminal = fields.named("capture_terminal")?;
        let confirmation_request = fields.named("confirmation_request")?;
        let confirmation_terminal = fields.named("confirmation_terminal")?;
        let history_cut = fields.named("history_cut")?;
        let objects = fields.named("objects")?;
        if plain(fields.named("schema")?)? != RESTORED_SETTLED_JOURNAL17_SCHEMA {
            return Err(invalid());
        }
        fields.finish()?;
        for body in [
            ancestry,
            capture_request,
            capture_terminal,
            confirmation_request,
            confirmation_terminal,
            history_cut,
            objects,
        ] {
            if body.first() != Some(&b'{') {
                return Err(invalid());
            }
        }
        Ok(Self {
            ancestry,
            objects,
            history_cut,
            capture_request,
            capture_terminal,
            confirmation_request,
            confirmation_terminal,
        })
    }

    /// Borrows exact immutable-role spans for the signed-DAG validator.
    pub const fn ancestry_bytes(&self) -> &'a [u8] {
        self.ancestry
    }

    /// Borrows the exact five-native/Host/semantic/Runtime object role map.
    pub const fn objects_bytes(&self) -> &'a [u8] {
        self.objects
    }

    /// Borrows the exact pre-aux history prefix cut.
    pub const fn history_cut_bytes(&self) -> &'a [u8] {
        self.history_cut
    }

    /// Borrows both actual Capture original/terminal spans.
    pub const fn capture_bytes(&self) -> (&'a [u8], &'a [u8]) {
        (self.capture_request, self.capture_terminal)
    }

    /// Borrows both actual confirmation original/terminal spans.
    pub const fn confirmation_bytes(&self) -> (&'a [u8], &'a [u8]) {
        (self.confirmation_request, self.confirmation_terminal)
    }
}

/// Validates complete final logical correspondence after actual decoder admission.
///
/// This validates DATA only. Native graph/current model/World, literal ACK banks,
/// signed DAG body availability and genuine Source/Window claims are separate
/// conjuncts. No absent historical key is claimed to recompute an old Source MAC.
///
/// # Errors
/// Refuses another grammar, unmatched originals/terminals, failed or incomplete
/// Capture/confirmation, substituted objects/media or changed prefix/Runtime cut.
pub fn validate_restored_settled_journal17_logical_data(
    value: &Value,
) -> Result<(), ProviderError> {
    let root = value.as_object().ok_or_else(invalid)?;
    let names = [
        "ancestry",
        "capture_request",
        "capture_terminal",
        "confirmation_request",
        "confirmation_terminal",
        "history_cut",
        "objects",
        "schema",
    ];
    if root.len() != names.len()
        || names.iter().any(|name| !root.contains_key(*name))
        || root["schema"].as_str() != Some(RESTORED_SETTLED_JOURNAL17_SCHEMA)
    {
        return Err(invalid());
    }
    let ancestry = PacketRestoredSettledAncestry17::deserialize(&root["ancestry"])
        .map_err(crucible_node_contract::ContractError::from)?;
    ancestry.validate_data()?;
    let objects = PacketRestoredSettledJournal17Objects::deserialize(&root["objects"])
        .map_err(crucible_node_contract::ContractError::from)?;
    objects.validate_data()?;
    let cut = PacketRestoredSettledHistoryCut17::deserialize(&root["history_cut"])
        .map_err(crucible_node_contract::ContractError::from)?;
    cut.prefix.validate()?;
    if cut.prefix.media_type != "application/json" || cut.next_sequence.get() == 0 {
        return Err(invalid());
    }
    let capture = Envelope::deserialize(&root["capture_request"])
        .map_err(crucible_node_contract::ContractError::from)?;
    let terminal = Envelope::deserialize(&root["capture_terminal"])
        .map_err(crucible_node_contract::ContractError::from)?;
    let confirmation = Envelope::deserialize(&root["confirmation_request"])
        .map_err(crucible_node_contract::ContractError::from)?;
    let confirmed = Envelope::deserialize(&root["confirmation_terminal"])
        .map_err(crucible_node_contract::ContractError::from)?;
    capture.validate()?;
    terminal.validate()?;
    confirmation.validate()?;
    confirmed.validate()?;
    capture.matches_response(&terminal)?;
    confirmation.matches_response(&confirmed)?;
    if capture.method != Method::Begin
        || confirmation.method != Method::Poll
        || capture.message != MessageKind::Request
        || confirmation.message != MessageKind::Request
        || capture.capture_owner_id.0.is_none()
        || capture.execution_owner_id.0.is_some()
        || capture.session_id != confirmation.session_id
        || capture.incarnation_id != confirmation.incarnation_id
        || capture.node_id != confirmation.node_id
        || capture.capture_owner_id != confirmation.capture_owner_id
        || capture.operation_id != confirmation.operation_id
        || capture.execution_owner_id != confirmation.execution_owner_id
        || capture.sequence.get() < cut.next_sequence.get()
        || confirmation.sequence <= capture.sequence
    {
        return Err(invalid());
    }
    let begin = decode_request(Method::Begin, &capture.body)?;
    let RequestBody::Begin(body) = &begin else {
        return Err(invalid());
    };
    let BeginArguments::Capture(arguments) = body.decoded_arguments()? else {
        return Err(invalid());
    };
    if body.kind != BeginKind::Capture {
        return Err(invalid());
    }
    restored_settled_capture_assigned_request_digest_data(
        &capture,
        crate::transport::MAX_FRAME_BYTES,
    )?;
    let artifact = PacketRestoredSettledCaptureArtifact::deserialize(
        capture
            .extensions
            .get(RESTORED_SETTLED_CAPTURE_FEATURE)
            .ok_or_else(invalid)?,
    )
    .map_err(crucible_node_contract::ContractError::from)?;
    artifact.validate_data()?;
    let request = &artifact.request;
    if capture.extensions.len() != 1
        || request.capture != arguments
        || Some(&request.capture_owner) != capture.capture_owner_id.0.as_ref()
        || Some(&request.capture_operation) != capture.operation_id.0.as_ref()
        || request.runtime_object != objects.runtime_object
        || request.coordinator_checkpoint != objects.coordinator_checkpoint
        || request.parent_archive != ancestry.parent_archive_index
        || request.first_observation != ancestry.first_observation
        || request.history_prefix != cut.prefix
        || request.history_next_sequence != cut.next_sequence
        || capture.session_id.0.as_ref() != Some(&request.scope.target.session)
        || capture.incarnation_id.0.as_ref() != Some(&request.scope.target.incarnation)
        || capture.node_id.0.as_ref() != Some(&request.scope.target.node)
    {
        return Err(invalid());
    }
    let response = decode_response(&begin, &terminal.body)?;
    let Some(MethodResult::Capture(result)) = &response.result else {
        return Err(invalid());
    };
    if !matches!(&response.shape, ResponseShape::Completed { .. })
        || result.capture_manifest != objects.snapshot
        || result.owner_state_refs.as_slice() != std::slice::from_ref(&objects.control)
        || result.unchanged_cut_receipt != objects.anchor
    {
        return Err(invalid());
    }
    let proof = PacketRestoredSettledAfterConfirmationRequest::deserialize(
        confirmation
            .extensions
            .get(PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_FEATURE)
            .ok_or_else(invalid)?,
    )
    .map_err(crucible_node_contract::ContractError::from)?;
    proof.validate_data()?;
    let receipt = PacketRestoredSettledAfterConfirmationReceipt::deserialize(
        confirmed
            .extensions
            .get(PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_FEATURE)
            .ok_or_else(invalid)?,
    )
    .map_err(crucible_node_contract::ContractError::from)?;
    receipt.validate_data()?;
    if confirmation.extensions.len() != 1
        || confirmed.extensions.len() != 1
        || receipt.capture != proof
        || receipt.native_after_ref != objects.after
        || proof.capture_request_id != *capture.request_id.0.as_ref().ok_or_else(invalid)?
        || proof.capture_operation_id != *capture.operation_id.0.as_ref().ok_or_else(invalid)?
        || proof.capture_request_hash != capture.request_hash(RequestOrigin::Controller)?
        || proof.capture_terminal_sequence != terminal.sequence
        || proof.capture_terminal_hash
            != canonical::json_hash(PACKET_RESTORED_SETTLED_CAPTURE_TERMINAL_DOMAIN, &terminal)?
        || proof.settled_capture_request
            != canonical::content_ref(
                &canonical::canonical_json(&root["capture_request"])?,
                "application/json",
            )?
        || proof.native_snapshot_ref != objects.snapshot
        || proof.native_control_ref != objects.control
        || proof.native_anchor_ref != objects.anchor
    {
        return Err(invalid());
    }
    let poll = decode_request(Method::Poll, &confirmation.body)?;
    let response = decode_response(&poll, &confirmed.body)?;
    let Some(MethodResult::Poll(result)) = &response.result else {
        return Err(invalid());
    };
    if !matches!(&response.shape, ResponseShape::Completed { .. })
        || result.operation_state != OperationState::Completed
        || Some(&result.operation_id) != capture.operation_id.0.as_ref()
        || result.outcome.0.as_ref() != Some(&terminal.body)
    {
        return Err(invalid());
    }
    Ok(())
}

/// Borrows the separate current Node/Source semantic wrapper without old casts.
///
/// Both actual defining child validators and signed-DAG provenance remain
/// required; successful framing alone is deliberately not a complete reader.
pub struct PacketRestoredSettledSemantic17Plan<'a> {
    ancestry: &'a [u8],
    node: &'a [u8],
    source: &'a [u8],
}

impl<'a> PacketRestoredSettledSemantic17Plan<'a> {
    /// Checks exact new semantic family/roster and bounded raw component spans.
    ///
    /// # Errors
    /// Refuses unknown/missing/duplicate fields, another family or size excess.
    pub fn validate(input: &'a [u8], maximum: usize) -> Result<Self, ProviderError> {
        if input.is_empty() || input.len() > maximum {
            return Err(invalid());
        }
        let mut fields = Fields::object(input)?;
        let ancestry = fields.named("ancestry")?;
        let node = fields.named("node")?;
        if plain(fields.named("schema")?)? != "source-private.semantic-state-restored-settled/17" {
            return Err(invalid());
        }
        let source = fields.named("source")?;
        fields.finish()?;
        for body in [ancestry, node, source] {
            if body.first() != Some(&b'{') {
                return Err(invalid());
            }
        }
        Ok(Self {
            ancestry,
            node,
            source,
        })
    }

    /// Borrows exact ancestry, independently checked against the signed DAG.
    pub const fn ancestry_bytes(&self) -> &'a [u8] {
        self.ancestry
    }

    /// Borrows actual current Node17 for its defining strict logical reader.
    pub const fn node_bytes(&self) -> &'a [u8] {
        self.node
    }

    /// Borrows actual current Source17 for its defining strict logical reader.
    pub const fn source_bytes(&self) -> &'a [u8] {
        self.source
    }
}

/// Names the actual framing/writer/typed validation headers before admitted work.
pub fn restored_settled_journal17_counter_scratch_data() -> usize {
    let terms = [
        PacketRestoredSettledAncestry17::counter_scratch_data(),
        size_of::<PacketRestoredSettledJournal17Objects>(),
        size_of::<PacketRestoredSettledHistoryCut17>(),
        size_of::<PacketRestoredSettledJournal17View<'static>>(),
        size_of::<PacketRestoredSettledJournal17Plan<'static>>(),
        size_of::<Result<PacketRestoredSettledJournal17Plan<'static>, ProviderError>>(),
        size_of::<PacketRestoredSettledSemantic17Plan<'static>>(),
        size_of::<Result<PacketRestoredSettledSemantic17Plan<'static>, ProviderError>>(),
        2 * size_of::<Fields<'static>>(),
        size_of::<Result<Fields<'static>, ProviderError>>(),
        size_of::<Result<&[u8], ProviderError>>(),
        size_of::<[&[u8]; 7]>(),
        size_of::<std::array::IntoIter<&[u8], 7>>(),
        size_of::<[&[u8]; 3]>(),
        size_of::<std::array::IntoIter<&[u8], 3>>(),
        size_of::<[&str; 8]>(),
        size_of::<std::slice::Iter<'static, &'static str>>(),
        size_of::<Envelope>(),
        4 * size_of::<Result<Envelope, serde_json::Error>>(),
        4 * size_of::<Result<Envelope, crucible_node_contract::ContractError>>(),
        size_of::<Result<PacketRestoredSettledAncestry17, serde_json::Error>>(),
        size_of::<Result<PacketRestoredSettledAncestry17, crucible_node_contract::ContractError>>(),
        size_of::<Result<PacketRestoredSettledJournal17Objects, serde_json::Error>>(),
        size_of::<
            Result<PacketRestoredSettledJournal17Objects, crucible_node_contract::ContractError>,
        >(),
        size_of::<Result<PacketRestoredSettledHistoryCut17, serde_json::Error>>(),
        size_of::<Result<PacketRestoredSettledHistoryCut17, crucible_node_contract::ContractError>>(
        ),
        size_of::<PacketRestoredSettledCaptureArtifact>(),
        size_of::<PacketRestoredSettledAfterConfirmationRequest>(),
        size_of::<PacketRestoredSettledAfterConfirmationReceipt>(),
        size_of::<Result<PacketRestoredSettledCaptureArtifact, serde_json::Error>>(),
        size_of::<
            Result<PacketRestoredSettledCaptureArtifact, crucible_node_contract::ContractError>,
        >(),
        size_of::<Result<PacketRestoredSettledAfterConfirmationRequest, serde_json::Error>>(),
        size_of::<
            Result<
                PacketRestoredSettledAfterConfirmationRequest,
                crucible_node_contract::ContractError,
            >,
        >(),
        size_of::<Result<PacketRestoredSettledAfterConfirmationReceipt, serde_json::Error>>(),
        size_of::<
            Result<
                PacketRestoredSettledAfterConfirmationReceipt,
                crucible_node_contract::ContractError,
            >,
        >(),
        2 * size_of::<RequestBody>(),
        size_of::<Result<RequestBody, ProviderError>>(),
        size_of::<ResponseBody>(),
        size_of::<Result<ResponseBody, ProviderError>>(),
        size_of::<BeginArguments>(),
        size_of::<Result<BeginArguments, crucible_node_contract::ContractError>>(),
        size_of::<Option<&Value>>(),
        size_of::<Result<&Value, ProviderError>>(),
        size_of::<Option<&crucible_node_contract::Id>>(),
        size_of::<Result<&crucible_node_contract::Id, ProviderError>>(),
        size_of::<Result<(), ProviderError>>(),
        size_of::<Result<(), crucible_node_contract::ContractError>>(),
        size_of::<Result<crucible_node_contract::HashRef, ProviderError>>(),
        size_of::<Result<crucible_node_contract::HashRef, crucible_node_contract::ContractError>>(),
        size_of::<Result<ContentRef, crucible_node_contract::ContractError>>(),
        size_of::<Result<Vec<u8>, crucible_node_contract::ContractError>>(),
        size_of::<Result<[u8; 32], ProviderError>>(),
        size_of::<[&ContentRef; 6]>(),
        size_of::<std::array::IntoIter<&ContentRef, 6>>(),
        size_of::<(&[u8], &[u8])>(),
        size_of::<Option<&serde_json::Map<String, Value>>>(),
        size_of::<Result<&serde_json::Map<String, Value>, ProviderError>>(),
        restored_settled_capture_contract_counter_scratch_data(),
        restored_settled_after_confirmation_counter_scratch_data(),
    ];
    std::mem::size_of_val(&terms)
        + size_of::<std::array::IntoIter<usize, 59>>()
        + terms.into_iter().sum::<usize>()
}

fn invalid() -> ProviderError {
    ProviderError::Correlation("restored settled journal17 differs")
}

#[cfg(test)]
#[path = "restored_journal17/tests.rs"]
mod tests;
