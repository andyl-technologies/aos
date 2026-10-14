//! Defines restored native evidence without rewriting captured model gates.
//!
//! A portable record is data. The original source witness independently checks
//! its current child, original controller, actual installed restoration receipt
//! and exact Core target before accepting its physical gate association.
//!
//! ```text
//! restored-native/12 -> unchanged receipt/5 -> unchanged native/2 or native/4
//!                   -> exact original COMMIT request and response full refs
//! ```

use super::*;
use crate::reference_packet::control::PacketNative5Record;

/// Names the separately registered restored native proof feature and schema.
pub const PACKET_NATIVE_RESTORED_RECORD_FEATURE: &str = "source-owned.packet-restored-native/12";

/// Retains both literal logical inventory and a distinct fresh physical gate.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNativeRestoredRecord {
    /// Names the exact separately registered proof grammar.
    pub schema: String,
    /// Retains the unchanged full live receipt and its native model proof ref.
    pub native_receipt: PacketNative5Record,
    /// Names the exact source-signed original pending native snapshot.
    pub captured_owner_state: ContentRef,
    /// Names its source-verified full Capture/after/fourth-Poll journal.
    pub captured_journal: ContentRef,
    /// Names the exact sealed historical mapping retained by the fresh installer.
    pub mapping: ContentRef,
    /// Names the actual complete assigned COMMIT envelope including its proof.
    pub restore_commit: ContentRef,
    /// Names the actual correlated post-sequence response including its receipt.
    pub restore_response: ContentRef,
    /// Binds the actual verified complete COMMIT context, 32 decoded bytes.
    pub context_digest: Bytes,
    /// Reports the independent fresh physical gate; logical inventory stays literal.
    pub physical_gate_held: bool,
}

impl PacketNativeRestoredRecord {
    /// Checks bounded closed record data without admitting a physical gate.
    ///
    /// The source additionally verifies the underlying full native record and
    /// original COMMIT pair, the genuine current child/controller and installed
    /// restoration association. This method creates none of those owners.
    ///
    /// # Errors
    /// Refuses another grammar/selection, missing owned-protocol birth, invalid
    /// full references, wrong digest width or an oversized evidence body.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        if self.schema != PACKET_NATIVE_RESTORED_RECORD_FEATURE
            || self.native_receipt.schema != "source-owned.packet-receipt/5"
            || self.native_receipt.native_pid.get() == 0
            || self.native_receipt.complete_restore_selection
                != Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
            || !matches!(
                self.native_receipt.capture_profile,
                super::super::PacketNative5CaptureProfile::OwnedProtocol11 { .. }
            )
            || self.native_receipt.protocol_metadata_limits.is_none()
            || self.native_receipt.protocol_metadata_birth_facts.is_none()
            || self.context_digest.as_slice().len() != 32
            || self.restore_commit == self.restore_response
        {
            return Err(ProviderError::Correlation("restored native record grammar"));
        }
        for reference in [
            &self.captured_owner_state,
            &self.captured_journal,
            &self.mapping,
            &self.restore_commit,
            &self.restore_response,
            &self.native_receipt.native_record,
        ] {
            reference.validate()?;
        }
        crate::connection::serialized_credit(self, 65_536)?;
        Ok(())
    }
}

/// Encodes the complete distinct restored proof and physical gate contract.
///
/// # Errors
/// Reports canonical specification encoding failure.
pub fn native_restored_record_contract() -> Result<Vec<u8>, ProviderError> {
    Ok(canonical::canonical_json(&serde_json::json!({
        "schema":"source-owned.packet-restored-native-contract/12",
        "feature":PACKET_NATIVE_RESTORED_RECORD_FEATURE,
        "selection":"SourceSignedTransfer12 with actual installed same fresh boot/source/controller/Core restoration; portable value never creates an installed gate",
        "commit_held":{"schema":"source-owned.packet-restored-commit-held/12","fields":["schema","native_pid","target_world","target_owner","target_owner_binding","target_activation","target_generation","captured_owner_state","captured_control","captured_journal","mapping","restore_commit","context_digest","local_cursor","inventory_hash","physical_gate_held"],"meaning":"nonrecursive actual installed same-socket model and fresh physical hold; body exported before actual assigned Commit response; original logical inventory/cursor/hash unchanged; no response reference or portable permit","maximum":"allocation-free shared producer field-view count of max128 IDs, six-byte escaped max128 hash domains, exact64hex digests, five full ContentRefs with max128 quote media, U64MAX counters/coordinate, exact32-byte digest base64 width; actual producer validates same bound before encoding"},
        "fields":["schema","native_receipt","captured_owner_state","captured_journal","mapping","restore_commit","restore_response","context_digest","physical_gate_held"],
        "native_receipt":"complete unchanged PacketNative5Record receipt/5 and full source-selected tuple; native_record names complete unchanged producer2 or reactive4 record, including actual captured logical inventory without gate/PID/ID rewriting",
        "originals":"restore_commit and restore_response are application/json full ContentRefs of complete canonical actual retained Envelope bodies including assigned sequences, commit proof and completed receipt; original literal headers/bodies remain retained in the same actual native and host banks and independently checked; these refs name a strictly earlier completed pair and do not recurse",
        "association":"owner_state/journal/mapping and context_digest equal the actual installed commit context/request; Source witness verifies actual original committed pair, key MAC receipt, signed source archive/Core target and current child/controller rather than accepting decoded refs or bool",
        "physical_gate":"installed native restoration keeps a distinct physical gate while captured logical gate remains false; Stage reports held=true without changing logical inventory; genuine WorldActivate prepares exact prospective held=false proof before its no-allocation physical release, then publishes only after successful release; no pending/error attempt can certify a completed release",
        "later_dispatch":"later Run/Input/Observe proof records retain the same exact completed commit association and physical=false; original model inventory and all historical stage/grant/PID/ID records stay literal; fresh registrations and immutable policy remain fresh",
        "failure":"proof/preflight/callback failure retains original Unknown, gate/attempt/custody and all bytes; no second Admit, copied reply authority, retries, gate rewriting or live reconstruction from data",
        "bounds":"complete evidence <=65536 canonical bytes with actual count before native effect; model/control, input banks and all retained/prospective proof copies have independent source whole-row admission",
        "legacy":"absent restoration keeps the original receipt5/native2/native4 bytes and gate checks exactly; this separate feature/schema must be selected before hashes/Hello; it is a content proof schema, not an envelope extension"
    }))?)
}

/// Names the full immutable restored native evidence definition.
///
/// # Errors
/// Reports invalid static identifiers or canonical specification encoding failure.
pub fn native_restored_record_schema() -> Result<SchemaRef, ProviderError> {
    Ok(SchemaRef {
        id: Id::new(PACKET_NATIVE_RESTORED_RECORD_FEATURE)?,
        version: 12,
        definition: canonical::content_ref(
            &native_restored_record_contract()?,
            "application/json",
        )?,
        extensions: Default::default(),
    })
}
