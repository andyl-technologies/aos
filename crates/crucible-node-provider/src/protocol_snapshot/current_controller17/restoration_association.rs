//! Joins the three actual completed restoration SDK originals to their journals.
//!
//! Typed pairs are temporary historical validation DATA. The native checker
//! borrows these exact terminals and compares its own original wire banks; it
//! does not reconstruct a live Controller, SDK attempt, deadline or authority.

use super::*;
use crate::envelope::Method;
use crate::reference_packet::service::complete_restore::transfer::PacketCompleteRestoreTransferPhase;

struct Pair17 {
    original: Envelope,
    terminal: Envelope,
}

/// Retains the actual completed ACK, Prepare and Commit SDK pair correspondence.
///
/// The enclosing caller admits all three typed pairs before construction and
/// retains the original Controller raw/DOM root on refusal. This result has no
/// live conversion and does not authenticate the native MAC chain on its own.
pub struct ValidatedHistoricalRestorationAssociation17 {
    ack: Pair17,
    prepare: Pair17,
    commit: Pair17,
}

impl ValidatedHistoricalRestorationAssociation17 {
    /// Checks completed once tuples, canonical banks and exact journal pairs.
    ///
    /// # Errors
    /// Refuses another schema/method, incomplete state, absent original literal
    /// slot, a changed canonical bank or journal, or a noncompleted response.
    pub fn validate_data(
        controller: &ValidatedControllerSettledHistory17,
    ) -> Result<Self, ProviderError> {
        let root = controller.parts_data()?.as_object().ok_or_else(invalid)?;
        let ack = pair_data(field(root, "ack_admit")?, None, controller)?;
        let prepare = pair_data(
            field(root, "restore_prepare")?,
            Some(PacketCompleteRestoreTransferPhase::Prepare),
            controller,
        )?;
        let commit = pair_data(
            field(root, "restore_commit")?,
            Some(PacketCompleteRestoreTransferPhase::Commit),
            controller,
        )?;
        if ack.original.sequence >= prepare.original.sequence
            || prepare.original.sequence >= commit.original.sequence
        {
            return Err(invalid());
        }
        Ok(Self {
            ack,
            prepare,
            commit,
        })
    }

    /// Borrows the real acknowledged Admit original and completed terminal.
    pub fn ack_pair_data(&self) -> (&Envelope, &Envelope) {
        (&self.ack.original, &self.ack.terminal)
    }

    /// Borrows the real Prepare original and completed terminal.
    pub fn prepare_pair_data(&self) -> (&Envelope, &Envelope) {
        (&self.prepare.original, &self.prepare.terminal)
    }

    /// Borrows the real Commit original and completed terminal.
    pub fn commit_pair_data(&self) -> (&Envelope, &Envelope) {
        (&self.commit.original, &self.commit.terminal)
    }

    /// Observes the actual six typed envelopes if a caller retains this cache.
    ///
    /// # Errors
    /// Refuses exhaustive metadata traversal or checked counter overflow.
    pub fn retained_metadata_data(
        &self,
    ) -> Result<crate::retained_metadata::RetainedProtocolMetadataFacts, ProviderError> {
        let mut observer = crate::retained_metadata::MetadataObserver::new();
        for pair in [&self.ack, &self.prepare, &self.commit] {
            observer.observe(&pair.original)?;
            observer.observe(&pair.terminal)?;
        }
        Ok(observer.finish())
    }
}

fn pair_data(
    value: &Value,
    phase: Option<PacketCompleteRestoreTransferPhase>,
    controller: &ValidatedControllerSettledHistory17,
) -> Result<Pair17, ProviderError> {
    let restored = phase.is_some();
    let method = if restored {
        Method::Begin
    } else {
        Method::Admit
    };
    let row = tuple(value, if restored { 11 } else { 8 })?;
    text(
        &row[0],
        if restored {
            "source-private.sdk-assigned-restore-current/17"
        } else {
            "source-private.sdk-assigned-admit-current/17"
        },
    )?;
    text(&row[5], "complete")?;
    text(&row[7], "historical-nonrenewable-operational-cut")?;
    number(&row[4])?;
    let original: Envelope = read(&row[1])?;
    let terminal: Envelope = read(&row[6])?;
    original.validate()?;
    terminal.validate()?;
    if original.method != method {
        return Err(invalid());
    }
    controller.authenticate_historical_controller_pair17_data(&original, &terminal)?;
    let request = crate::bodies::decode_request(method, &original.body)?;
    if let Some(phase) = phase {
        // Both real transfer phases use Begin(PrepareRestore); their selected
        // request/proof/receipt extensions distinguish the exact phase.
        if !matches!(&request, RequestBody::Begin(body) if body.kind == BeginKind::PrepareRestore)
            || !original.extensions.contains_key(phase.request_extension())
            || !original.extensions.contains_key(phase.proof_extension())
            || !terminal.extensions.contains_key(phase.receipt_extension())
        {
            return Err(invalid());
        }
    }
    let response = crate::bodies::decode_response(&request, &terminal.body)?;
    if !matches!(
        &response.shape,
        ResponseShape::Completed {
            operation_state: OperationState::Completed,
            ..
        }
    ) {
        return Err(invalid());
    }
    let encoded =
        serde_json::to_vec(&row[2]).map_err(crucible_node_contract::ContractError::from)?;
    let bank = super::super::compact_bytes::ValidatedCompactBytes::validate(
        &encoded,
        encoded.len(),
        usize::MAX,
    )?;
    if u64::try_from(bank.decoded_length()).map_err(|_| invalid())? > number(&row[3])? {
        return Err(invalid());
    }
    let mut actual = Vec::new();
    actual
        .try_reserve_exact(bank.decoded_length())
        .map_err(|_| invalid())?;
    bank.fill_preowned(&mut actual)?;
    if actual
        != crucible_node_contract::canonical::canonical_json(
            &serde_json::to_value(&original)
                .map_err(crucible_node_contract::ContractError::from)?,
        )?
    {
        return Err(invalid());
    }
    Ok(Pair17 { original, terminal })
}

/// Quotes all three pair validators independently of parent raw/DOM retention.
///
/// # Errors
/// Refuses zero geometry or checked arithmetic beyond representable storage.
pub fn historical_restoration_association17_validation_transient_bytes_data(
    maximum_encoded: usize,
) -> Result<usize, ProviderError> {
    super::historical_restored_suffix_pair_validation_transient_bytes_data(maximum_encoded)?
        .checked_mul(3)
        .and_then(|bytes| {
            bytes.checked_add(historical_restoration_association17_counter_scratch_data())
        })
        .ok_or_else(invalid)
}

/// Names the defining typed pair, borrowed loan and compact bank views.
pub fn historical_restoration_association17_counter_scratch_data() -> usize {
    size_of::<ValidatedHistoricalRestorationAssociation17>()
        + size_of::<Option<PacketCompleteRestoreTransferPhase>>()
        + size_of::<PacketCompleteRestoreTransferPhase>()
        + size_of::<Method>()
        + size_of::<RequestBody>()
        + size_of::<Pair17>()
        + size_of::<&Pair17>()
        + size_of::<(&Envelope, &Envelope)>()
        + size_of::<[&Pair17; 3]>()
        + size_of::<std::array::IntoIter<&Pair17, 3>>()
        + size_of::<Result<ValidatedHistoricalRestorationAssociation17, ProviderError>>()
        + size_of::<Result<Pair17, ProviderError>>()
        + size_of::<super::super::compact_bytes::ValidatedCompactBytes<'static>>()
        + size_of::<
            Result<super::super::compact_bytes::ValidatedCompactBytes<'static>, ProviderError>,
        >()
        + super::historical_restored_suffix_pair_counter_scratch_data()
}
