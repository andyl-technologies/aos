//! Durable SourceProvider request-sequence reservations.
//!
//! A provider head permits exactly one outstanding query. Reserving a query
//! advances only the client-to-provider head and retains the exact signed
//! envelope before any socket I/O. Consuming its signed disposition clears the
//! reservation and advances only the provider-to-client head.

use super::*;

impl SourceAcquisitionTableV1 {
    /// Reserves a fresh Acquire query after a signed noncomplete disposition.
    ///
    /// # Errors
    ///
    /// Returns an error unless the row remains PendingQuery, its prior result
    /// was noncomplete, the shared session has no outstanding query, and the
    /// new signed request owns the next exact request sequence.
    pub fn reserve_acquire_retry(
        &mut self,
        journal: &mut Journal,
        acquisition_id: [u8; 32],
        signed_request: Vec<u8>,
    ) -> Result<bool> {
        let current = self
            .acquisitions
            .get(&acquisition_id)
            .ok_or_else(|| state_error("source acquisition is absent"))?;
        let identity = (
            current.provider.holder_authority_id,
            current.provider.provider_authority_id,
        );
        let current_head = self
            .provider_heads
            .get(&identity)
            .ok_or_else(|| state_error("source provider sequence head is absent"))?;
        let owner = ProviderQueryOwnerV1::Acquire { acquisition_id };
        if reservation_matches(current_head, owner, &signed_request) {
            return Ok(false);
        }
        let checkpoint = current
            .acquire_checkpoint
            .as_ref()
            .ok_or_else(|| state_error("provider Acquire retry has no prior disposition"))?;
        if current.phase != SourceAcquisitionPhaseV1::PendingQuery
            || current.evidence.is_some()
            || checkpoint.status == ProviderStatusV1::Complete
        {
            return Err(state_error("provider Acquire retry is not eligible"));
        }

        let reserved_head = reserve_query(current_head, owner, &signed_request)?;
        let mut next = current.clone();
        next.revision = next_revision(current.revision)?;
        if next.acquire_history.len() == MAXIMUM_DISPOSITION_HISTORY {
            next.acquire_history.remove(0);
        }
        next.acquire_history.push(checkpoint.clone());
        next.acquire_checkpoint = None;
        next.provider_acquire_request_digest = Sha256::digest(&signed_request).into();
        next.provider_acquire_request = signed_request;
        next.record_digest = acquisition_record_digest(&next)?;
        next.validate()?;
        let mut tentative = self.acquisitions.clone();
        tentative.insert(acquisition_id, next.clone());
        let mut tentative_heads = self.provider_heads.clone();
        tentative_heads.insert(identity, reserved_head.clone());
        validate_recovered_table(&tentative, &tentative_heads)?;

        let records = vec![put_acquisition(&next)?, put_provider_head(&reserved_head)?];
        let transaction =
            JournalTransaction::new(transaction_id(acquisition_id, next.revision), records)?;
        journal.commit(&transaction)?;
        self.acquisitions.insert(acquisition_id, next);
        self.provider_heads.insert(identity, reserved_head);
        Ok(true)
    }

    /// Reserves a holder-scoped signed Inventory query before provider I/O.
    ///
    /// Admission preflights a maximum-size head replacement after the
    /// reservation. The eventual provider exchange must retain exclusive
    /// journal scheduling so unrelated commits cannot consume that budget.
    ///
    /// # Errors
    ///
    /// Returns an error for an absent head, wrong holder/session/sequence,
    /// another outstanding query, insufficient worst-case completion capacity,
    /// or journal failure.
    pub fn reserve_inventory_query(
        &mut self,
        journal: &mut Journal,
        holder_authority_id: [u8; 16],
        provider_authority_id: [u8; 16],
        signed_request: Vec<u8>,
    ) -> Result<bool> {
        let identity = (holder_authority_id, provider_authority_id);
        let current = self
            .provider_heads
            .get(&identity)
            .ok_or_else(|| state_error("source provider sequence head is absent"))?;
        if reservation_matches(current, ProviderQueryOwnerV1::Inventory, &signed_request) {
            return Ok(false);
        }
        let signed = SignedSourceProviderRequestV1::from_canonical_bytes(&signed_request)
            .map_err(|error| state_error(error.to_string()))?;
        let query = decode_inventory_request(signed.subject())
            .map_err(|error| state_error(error.to_string()))?;
        if query.holder_authority_id() != holder_authority_id
            || query.holder_generation() != current.holder_generation
            || query.holder_authority_digest().as_bytes() != &current.holder_authority_digest
            || query
                .known_inventory_digest()
                .map(|digest| *digest.as_bytes())
                != current.inventory_digest
        {
            return Err(state_error("provider Inventory authority or floor differs"));
        }
        next_inventory_observation_ordinal(current.inventory_observation_ordinal)?;

        let next = reserve_query(current, ProviderQueryOwnerV1::Inventory, &signed_request)?;
        let mut tentative_heads = self.provider_heads.clone();
        tentative_heads.insert(identity, next.clone());
        validate_recovered_table(&self.acquisitions, &tentative_heads)?;
        let transaction = JournalTransaction::new(
            provider_head_transaction_id(&next),
            vec![put_provider_head(&next)?],
        )?;
        preflight_inventory_completion_capacity(journal, &transaction, &next)?;
        journal.commit(&transaction)?;
        self.provider_heads.insert(identity, next);
        Ok(true)
    }

    /// Reserves a fresh Release query after a signed noncomplete disposition.
    ///
    /// # Errors
    ///
    /// Returns an error unless the row remains Releasing, its prior result was
    /// noncomplete, the shared session is idle, and the request owns the next
    /// exact request sequence.
    pub fn reserve_release_retry(
        &mut self,
        journal: &mut Journal,
        acquisition_id: [u8; 32],
        signed_request: Vec<u8>,
        session: &AuthenticatedProviderSessionV1,
    ) -> Result<bool> {
        let current = self
            .acquisitions
            .get(&acquisition_id)
            .ok_or_else(|| state_error("source acquisition is absent"))?;
        let identity = (
            current.provider.holder_authority_id,
            current.provider.provider_authority_id,
        );
        let current_head = self
            .provider_heads
            .get(&identity)
            .ok_or_else(|| state_error("source provider sequence head is absent"))?;
        let owner = ProviderQueryOwnerV1::Release { acquisition_id };
        if reservation_matches(current_head, owner, &signed_request) {
            return Ok(false);
        }
        let checkpoint = current
            .release_checkpoint
            .as_ref()
            .ok_or_else(|| state_error("provider Release retry has no prior disposition"))?;
        if current.phase != SourceAcquisitionPhaseV1::Releasing
            || checkpoint.status == ProviderStatusV1::Complete
        {
            return Err(state_error("provider Release retry is not eligible"));
        }
        if session.head != *current_head
            || session.provider.holder_authority_id != current.provider.holder_authority_id
            || session.provider.provider_authority_id != current.provider.provider_authority_id
        {
            return Err(state_error(
                "source provider Release retry session is not current",
            ));
        }
        validate_release_query(current, session.provider, &signed_request)?;

        let reserved_head = reserve_query(current_head, owner, &signed_request)?;
        let mut next = current.clone();
        next.revision = next_revision(current.revision)?;
        if next.release_history.len() == MAXIMUM_DISPOSITION_HISTORY {
            next.release_history.remove(0);
        }
        next.release_history.push(checkpoint.clone());
        next.release_checkpoint = None;
        next.release_generation = None;
        next.provider_release_request_digest = Some(Sha256::digest(&signed_request).into());
        next.provider_release_request = Some(signed_request);
        next.release_provider = Some(session.provider);
        next.record_digest = acquisition_record_digest(&next)?;
        next.validate()?;
        let mut tentative = self.acquisitions.clone();
        tentative.insert(acquisition_id, next.clone());
        let mut tentative_heads = self.provider_heads.clone();
        tentative_heads.insert(identity, reserved_head.clone());
        validate_recovered_table(&tentative, &tentative_heads)?;

        let records = vec![put_acquisition(&next)?, put_provider_head(&reserved_head)?];
        let transaction =
            JournalTransaction::new(transaction_id(acquisition_id, next.revision), records)?;
        journal.commit(&transaction)?;
        self.acquisitions.insert(acquisition_id, next);
        self.provider_heads.insert(identity, reserved_head);
        Ok(true)
    }
}

pub(super) fn validate_release_query(
    row: &SourceAcquisitionRowV1,
    provider: SourceProviderContextSnapshotV1,
    signed_request_bytes: &[u8],
) -> Result<()> {
    let evidence = row
        .evidence
        .as_ref()
        .ok_or_else(|| state_error("provider Release query has no lease evidence"))?;
    let signed = SignedSourceProviderRequestV1::from_canonical_bytes(signed_request_bytes)
        .map_err(|error| state_error(error.to_string()))?;
    let query =
        decode_release_request(signed.subject()).map_err(|error| state_error(error.to_string()))?;
    if signed.method() != SourceProviderMethod::Release
        || query.acquisition_id().as_bytes() != &row.acquisition_id
        || query.session_binding().as_bytes() != &provider.session_binding
        || query.holder_authority_id() != provider.holder_authority_id
        || query.holder_generation() != provider.holder_generation
        || query.holder_authority_digest().as_bytes() != &provider.holder_authority_digest
        || query.lease_id() != evidence.lease_id
        || query.lease_digest().as_bytes() != &evidence.signed_lease_digest
    {
        return Err(state_error(
            "provider Release query differs from retained lease authority",
        ));
    }
    Ok(())
}

pub(super) fn reserve_query(
    current: &SourceProviderHeadV1,
    owner: ProviderQueryOwnerV1,
    signed_request_bytes: &[u8],
) -> Result<SourceProviderHeadV1> {
    if current.pending_query.is_some() {
        return Err(state_error(
            "source provider session already has an outstanding query",
        ));
    }

    let signed = SignedSourceProviderRequestV1::from_canonical_bytes(signed_request_bytes)
        .map_err(|error| state_error(error.to_string()))?;
    let (method, session_binding, sequence) = query_identity(&signed, owner)?;
    if method != owner_method(owner)
        || session_binding != current.session_binding
        || sequence != current.next_request_sequence
    {
        return Err(state_error(
            "source provider query does not match its durable sequence head",
        ));
    }

    let mut next = current.clone();
    next.next_request_sequence = next_revision(current.next_request_sequence)?;
    next.pending_query = Some(PendingProviderQueryV1 {
        owner,
        request_sequence: sequence,
        signed_request_digest: Sha256::digest(signed_request_bytes).into(),
        signed_request: signed_request_bytes.to_vec(),
    });
    next.validate()?;
    Ok(next)
}

pub(super) fn reservation_matches(
    head: &SourceProviderHeadV1,
    owner: ProviderQueryOwnerV1,
    bytes: &[u8],
) -> bool {
    let signed_request_digest: [u8; 32] = Sha256::digest(bytes).into();
    head.pending_query.as_ref().is_some_and(|pending| {
        pending.owner == owner
            && pending.signed_request == bytes
            && pending.signed_request_digest == signed_request_digest
    })
}

pub(super) fn validate_pending_query(
    head: &SourceProviderHeadV1,
    pending: &PendingProviderQueryV1,
) -> Result<()> {
    let signed = SignedSourceProviderRequestV1::from_canonical_bytes(&pending.signed_request)
        .map_err(|error| state_error(error.to_string()))?;
    let (method, session_binding, sequence) = query_identity(&signed, pending.owner)?;
    if method != owner_method(pending.owner)
        || session_binding != head.session_binding
        || sequence != pending.request_sequence
        || head.next_request_sequence != next_revision(sequence)?
    {
        return Err(state_error(
            "pending provider query differs from its sequence head",
        ));
    }
    Ok(())
}

fn query_identity(
    signed: &SignedSourceProviderRequestV1,
    owner: ProviderQueryOwnerV1,
) -> Result<(SourceProviderMethod, [u8; 32], u64)> {
    match owner {
        ProviderQueryOwnerV1::Acquire { acquisition_id } => {
            let query = decode_acquire_request(signed.subject())
                .map_err(|error| state_error(error.to_string()))?;
            if signed.method() != SourceProviderMethod::Acquire
                || query.acquisition_id().as_bytes() != &acquisition_id
            {
                return Err(state_error("provider Acquire reservation owner differs"));
            }
            let (_, session_binding, sequence) =
                checkpoint_request_identity(signed, ProviderMethodV1::Acquire)?;
            Ok((signed.method(), session_binding, sequence))
        }
        ProviderQueryOwnerV1::Release { acquisition_id } => {
            let query = decode_release_request(signed.subject())
                .map_err(|error| state_error(error.to_string()))?;
            if signed.method() != SourceProviderMethod::Release
                || query.acquisition_id().as_bytes() != &acquisition_id
            {
                return Err(state_error("provider Release reservation owner differs"));
            }
            let (_, session_binding, sequence) =
                checkpoint_request_identity(signed, ProviderMethodV1::Release)?;
            Ok((signed.method(), session_binding, sequence))
        }
        ProviderQueryOwnerV1::Inventory => {
            if signed.method() != SourceProviderMethod::Inventory {
                return Err(state_error("provider Inventory reservation method differs"));
            }
            let (_, session_binding, sequence) =
                checkpoint_request_identity(signed, ProviderMethodV1::Inventory)?;
            Ok((signed.method(), session_binding, sequence))
        }
    }
}

const fn owner_method(owner: ProviderQueryOwnerV1) -> SourceProviderMethod {
    match owner {
        ProviderQueryOwnerV1::Acquire { .. } => SourceProviderMethod::Acquire,
        ProviderQueryOwnerV1::Release { .. } => SourceProviderMethod::Release,
        ProviderQueryOwnerV1::Inventory => SourceProviderMethod::Inventory,
    }
}
