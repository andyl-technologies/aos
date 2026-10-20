//! Shares saved Source comparisons and signing across native dispositions.
//!
//! The query interface is comparison DATA, not a role or currentness proof.
//! Ordinary native owners retain their original query/provenance checks;
//! the selected Source owner implements it only over its own paid fixed replay.
//! A supplied implementation or signing key cannot acquire that selected owner,
//! receiving original, protected writer, or mutation permission.

use aos_sandbox_core::{ObjectDigest, ProjectId};
use aos_sandbox_ledger_replay::source_signer_data::*;
use aos_sandbox_ledger_replay::source_signer_data::{source_genesis_readback,
    source_project_admission_readback, source_successor_readback};
use source_successor_readback::{SourceReadbackRecipe, validate_source_readback_fields_v1,
    signature_message_with_recipe};
use aos_sandbox_ledger_replay::source_signer_data::source_genesis_readback::sign_source_tree_genesis_fields_v2;
use aos_sandbox_ledger_replay::source_signer_data::source_project_admission_readback::{
    sign_source_project_admission_fields_v1, sign_source_project_reservation_fields_v1,
    sign_source_project_completed_terminal_fields_v1};
use aos_sandbox_ledger_replay::replay::{source_tree_genesis, source_tree_successor};
use aos_sandbox_ledger_replay::replay::phase_records::RootFirstSourceSuccessorIntentV2;
use aos_sandbox_protocol::domain_ledger::{protected_names::ProtectedJournalNamesV1,
    source_policy_hold::SourceDomainPolicyHoldV1,
    source_project_history::{SourceProjectAdmissionChallengeV1,
        SourceProjectAdmissionReservationV1, SourceProjectAdmissionTerminalV1}};
use ed25519_dalek::{Signer as _, SigningKey};

/// Compares context DATA against the actual Source owner's expected UID.
///
/// This pure comparison opens no signer view and grants no native authority.
///
/// # Errors
/// Refuses a zero expected UID or a foreign original context owner.
pub fn require_original_source_uid_data_v1(
    expected_uid: u32,
    context: &SourceTreeGenesisIntentContextV1,
) -> Result<(), SourceHoldReadbackErrorV1> {
    if expected_uid == 0 || context.source_uid() != expected_uid {
        return Err(SourceHoldReadbackErrorV1::NonCanonical);
    }
    Ok(())
}

/// Supplies the established saved queries without establishing native authority.
///
/// Implementations preserve their own native health/provenance checks and error
/// categories. The selected service never accepts an external implementation;
/// its closed owner lends only its actual completed fixed replay.
pub trait SourceSignerComparisonV1 {
    /// Preserves the caller's original typed comparison/signature failure.
    type Error: std::error::Error + From<SourceHoldReadbackErrorV1>
        + From<SourceSignerGenesisDataErrorV1>;

    /// Produces the original stale held-row/ancestry diagnostic.
    fn stale() -> Self::Error;
    /// Produces the original malformed genesis/successor diagnostic.
    fn noncanonical_genesis() -> Self::Error;
    /// Produces the original conflicting genesis/successor diagnostic.
    fn conflicting_genesis() -> Self::Error;
    /// Produces the original stale genesis/successor diagnostic.
    fn stale_genesis() -> Self::Error;
    /// Returns the owner's physical-name comparison DATA.
    fn physical_names_v1(&self) -> ProtectedJournalNamesV1;
    /// Returns the owner's replay watermark comparison DATA.
    fn snapshot_sequence(&mut self) -> u64;
    /// Reports whether the same saved map has any records.
    fn has_records(&mut self) -> bool;

    /// Replays the complete saved selected-project genesis family.
    ///
    /// # Errors
    /// Preserves the implementation's original health and family failures.
    fn source_project_genesis_data_v3(&mut self, project: ProjectId)
        -> Result<source_tree_successor::SourceProjectFamilyDataV3, Self::Error>;
    /// Replays the complete saved genesis rows.
    ///
    /// # Errors
    /// Preserves the implementation's original health and family failures.
    fn source_tree_genesis_rows_v1(&mut self)
        -> Result<source_tree_genesis::SourceGenesisRowsV1, Self::Error>;
    /// Replays the complete saved single-project successor rows.
    ///
    /// # Errors
    /// Preserves the implementation's original health and family failures.
    fn source_first_successor_rows_v2(&mut self)
        -> Result<source_tree_successor::SourceFirstSuccessorRowsV2, Self::Error>;
    /// Replays the complete saved mixed-project successor rows.
    ///
    /// # Errors
    /// Preserves the implementation's original health and family failures.
    fn source_project_continuation_rows_v3(&mut self, project: Option<ProjectId>)
        -> Result<source_tree_successor::SourceFirstSuccessorRowsV2, Self::Error>;
    /// Replays and rejoins the exact saved genesis members and lineage.
    ///
    /// # Errors
    /// Preserves the original health, conflict and hierarchy failures.
    fn validate_genesis_rows(&mut self)
        -> Result<source_tree_genesis::SourceGenesisRowsV1, Self::Error>;
    /// Replays the held Source policy row under the implementation's gates.
    ///
    /// # Errors
    /// Preserves the original health, role and saved-row failures.
    fn source_domain_policy_hold_v1(&mut self)
        -> Result<Option<SourceDomainPolicyHoldV1>, Self::Error>;
    /// Replays the complete typed project ancestry and returns only its digest.
    ///
    /// # Errors
    /// Preserves the original complete ancestry failure.
    fn ancestry_head(&mut self, project: ProjectId) -> Result<Option<ObjectDigest>, Self::Error>;
    /// Replays the complete structural lineage and current Tree fields.
    ///
    /// # Errors
    /// Preserves the original hierarchy and absent-project failures.
    fn successor_tree(&mut self, project: ProjectId)
        -> Result<(ObjectDigest, ObjectDigest, ObjectDigest, u64), Self::Error>;
    /// Decodes only the saved project challenge row.
    ///
    /// # Errors
    /// Preserves the original row decoder failure.
    fn project_challenge(&mut self) -> Result<Option<SourceProjectAdmissionChallengeV1>, Self::Error>;
    /// Rejoins the saved project reservation and cancellation rows.
    ///
    /// # Errors
    /// Preserves the original five-row join failure.
    fn source_project_admission_reservation_status_v1(&mut self)
        -> Result<Option<(SourceProjectAdmissionReservationV1, bool)>, Self::Error>;
    /// Rejoins the saved project reservation row.
    ///
    /// # Errors
    /// Preserves the original five-row join failure.
    fn source_project_admission_reservation_v1(&mut self)
        -> Result<Option<SourceProjectAdmissionReservationV1>, Self::Error>;
    /// Rejoins the saved project challenge and settlement rows.
    ///
    /// # Errors
    /// Preserves the original five-row join failure.
    fn source_project_admission_status_v1(&mut self)
        -> Result<Option<(SourceProjectAdmissionChallengeV1, bool)>, Self::Error>;
    /// Rejoins the saved completed project terminal.
    ///
    /// # Errors
    /// Preserves the original health and five-row join failure.
    fn source_project_admission_terminal_v1(&mut self)
        -> Result<Option<SourceProjectAdmissionTerminalV1>, Self::Error>;
}

/// Signs or compares the established saved Source fields without native admission.
///
/// # Errors
/// Preserves the original query, shape, historical join and signature failure.
pub fn sign_project_genesis_from_comparison_v3<R: SourceSignerComparisonV1>(
    readback: &mut R,
    challenge: source_genesis_readback::SourceProjectGenesisChallengeV3,
    context: &SourceTreeGenesisIntentContextV1,
    signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<source_genesis_readback::SourceProjectGenesisReadbackPacketV4, R::Error> {
    let project = challenge.project();
    let journal = &mut *readback;
    let rows = journal.source_project_genesis_data_v3(project)?.into_genesis();
    let receipt = rows.receipts.get(&project);
    if rows.receipts.is_empty()
        || receipt.map(|receipt| receipt.intent_digest()) != challenge.intent()
        || rows.pending.as_ref().is_some_and(|pending| pending.project != project)
    {
        return Err(R::stale());
    }
    let instance = rows.receipts.values().next().ok_or(R::stale())?.instance();
    let names = journal.physical_names_v1();
    if rows.pending.as_ref().is_some_and(|pending| pending.names != names) {
        return Err(R::stale());
    }
    if let Some(receipt) = receipt {
        context.require_actual_receipt(receipt, rows.pending.as_ref())
            .map_err(|_| R::stale())?;
        if let Some(ack) = rows.acks.get(&project) {
            context.require_actual_ack(receipt, ack.root_floor)
                .map_err(|_| R::stale())?;
        }
    }
    let ack = rows.acks.get(&project).map(|ack| (ack.root_floor, ack.digest()));
    source_genesis_readback::sign_source_project_genesis_fields_v4(
        challenge, names, readback.snapshot_sequence(), receipt, ack,
        instance, signer_generation, signing_key, context.has_resource_authorization(),
    ).map_err(Into::into)
}

/// Signs or compares the established saved Source fields without native admission.
///
/// # Errors
/// Preserves the original query, shape, historical join and signature failure.
pub fn sign_genesis_readback_from_comparison<R: SourceSignerComparisonV1>(
    readback: &mut R,
    project: Option<ProjectId>,
    challenge: SourceTreeGenesisChallengeV1,
    intent_context: Option<&SourceTreeGenesisIntentContextV1>,
    signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<[u8; SOURCE_TREE_GENESIS_READBACK_BYTES_V1], R::Error> {
    if intent_context.is_some_and(SourceTreeGenesisIntentContextV1::has_resource_authorization) {
        return Err(SourceHoldReadbackErrorV1::NonCanonical.into());
    }
    sign_genesis_readback_from_comparison_v2(
        readback, project, challenge, intent_context, signer_generation, signing_key,
    )?.into_legacy().map_err(Into::into)
}

/// Signs or compares the established saved Source fields without native admission.
///
/// # Errors
/// Preserves the original query, shape, historical join and signature failure.
pub fn sign_genesis_readback_from_comparison_v2<R: SourceSignerComparisonV1>(
    readback: &mut R,
    project: Option<ProjectId>,
    challenge: SourceTreeGenesisChallengeV1,
    intent_context: Option<&SourceTreeGenesisIntentContextV1>,
    signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<SourceTreeGenesisReadbackPacketV2, R::Error> {
    let rows = readback.validate_genesis_rows()
        .map_err(|_| R::stale())?;
    let names = readback.physical_names_v1();
    let sequence = readback.snapshot_sequence();
    let receipt = match project {
        Some(project) => Some(
            rows.receipts
                .get(&project)
                .ok_or(R::stale())?,
        ),
        None if rows.receipts.is_empty()
            && rows.pending.is_none()
            && rows.acks.is_empty()
            && !readback.has_records() =>
        {
            None
        }
        None => return Err(R::stale()),
    };
    if receipt.map(|receipt| receipt.intent_digest()) != challenge.intent()
        || receipt.is_some() != intent_context.is_some()
        || rows
            .pending
            .as_ref()
            .is_some_and(|pending| Some(pending.project) == project && pending.names != names)
    {
        return Err(R::stale());
    }
    if let (Some(receipt), Some(context)) = (receipt, intent_context) {
        // The challenge correlates this observation only. The original nonce
        // comes from the durable pending marker and must reconstruct the exact
        // intent committed by this actual receipt, including UID and roles.
        context
            .require_actual_receipt(
                receipt,
                rows.pending
                    .as_ref()
                    .filter(|pending| pending.project == receipt.project()),
            )
            .map_err(|_| R::stale())?;
        if let Some(ack) = rows.acks.get(&receipt.project()) {
            context
                .require_actual_ack(receipt, ack.root_floor)
                .map_err(|_| R::stale())?;
        }
    }
    let ack = project
        .and_then(|project| rows.acks.get(&project))
        .map(|ack| (ack.root_floor, ack.digest()));
    let packet = sign_source_tree_genesis_fields_v2(
        challenge,
        names,
        sequence,
        receipt,
        ack,
        signer_generation,
        signing_key,
    )?;

    if readback.physical_names_v1() != names
        || readback.snapshot_sequence() != sequence
        || readback.validate_genesis_rows()
            .map_err(|_| R::stale())?
            != rows
    {
        return Err(R::stale());
    }
    Ok(packet)
}

/// Signs or compares the established saved Source fields without native admission.
///
/// # Errors
/// Preserves the original query, shape, historical join and signature failure.
pub fn sign_source_project_reservation_from_comparison_v1<R: SourceSignerComparisonV1>(
    readback: &mut R,
    client_nonce: [u8; 16],
    project: ProjectId,
    expected_digest: ObjectDigest,
    signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<[u8; SOURCE_PROJECT_RESERVATION_READBACK_BYTES_V1], R::Error> {
    let row = readback
        .source_project_admission_reservation_status_v1()?
        .and_then(|(row, canceled)| (!canceled).then_some(row))
        .ok_or(R::stale())?;
    let names = readback.physical_names_v1();
    if row.client_nonce() != client_nonce
        || row.project() != project
        || row.record_digest() != expected_digest
        || row.names() != names
        || readback
            .source_project_admission_status_v1()?
            .is_some()
    {
        return Err(R::stale());
    }
    let packet =
        sign_source_project_reservation_fields_v1(row, signer_generation, signing_key)?;
    if readback
        .source_project_admission_reservation_status_v1()?
        != Some((row, false))
        || readback
            .source_project_admission_status_v1()?
            .is_some()
        || readback.physical_names_v1() != names
    {
        return Err(R::stale());
    }
    Ok(packet)
}

/// Signs or compares the established saved Source fields without native admission.
///
/// # Errors
/// Preserves the original query, shape, historical join and signature failure.
pub fn sign_source_project_admission_from_comparison_v1<R: SourceSignerComparisonV1>(
    readback: &mut R,
    project: ProjectId,
    challenge: SourceHoldReadbackChallengeV1,
    signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<[u8; SOURCE_PROJECT_ADMISSION_READBACK_BYTES_V1], R::Error> {
    let row = readback.project_challenge()?
        .ok_or(R::stale())?;
    let ancestry = readback.ancestry_head(project)
        .map_err(|_| R::stale())?
        .ok_or(R::stale())?;
    let names = readback.physical_names_v1();
    if !aos_sandbox_ledger_replay::source_project_readback::challenge_matches_current_v1(
        row,
        challenge.nonce(),
        challenge.cut(),
        project,
        ancestry,
        row.stage(),
        names,
    ) {
        return Err(R::stale());
    }
    let reservation = readback
        .source_project_admission_reservation_v1()?
        .ok_or(R::stale())?;
    if reservation.project() != project
        || reservation.names() != names
        || reservation.issue() != row.issue()
    {
        return Err(R::stale());
    }
    let packet = sign_source_project_admission_fields_v1(
        row,
        reservation,
        signer_generation,
        signing_key,
    )?;
    let postflight = readback.project_challenge()?;
    let current_ancestry = readback.ancestry_head(project)
        .map_err(|_| R::stale())?
        .ok_or(R::stale())?;
    if postflight != Some(row)
        || readback
            .source_project_admission_reservation_v1()?
            != Some(reservation)
        || current_ancestry != ancestry
    {
        return Err(R::stale());
    }
    Ok(packet)
}

/// Signs or compares the established saved Source fields without native admission.
///
/// # Errors
/// Preserves the original query, shape, historical join and signature failure.
pub fn sign_source_project_retirement_from_comparison_v1<R: SourceSignerComparisonV1>(
    readback: &mut R,
    project: ProjectId,
    challenge: SourceHoldReadbackChallengeV1,
    signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<[u8; SOURCE_PROJECT_ADMISSION_READBACK_BYTES_V1], R::Error> {
    let (row, settled) = readback
        .source_project_admission_status_v1()?
        .ok_or(R::stale())?;
    let names = readback.physical_names_v1();
    if settled
        || row.nonce() != challenge.nonce()
        || row.cut() != challenge.cut()
        || row.project() != project
        || row.names() != names
    {
        return Err(R::stale());
    }
    let reservation = readback
        .source_project_admission_reservation_v1()?
        .ok_or(R::stale())?;
    if reservation.project() != project
        || reservation.names() != names
        || reservation.issue() != row.issue()
    {
        return Err(R::stale());
    }
    let packet =
        source_project_admission_readback::sign_source_project_retirement_fields_v1(
            row,
            reservation,
            signer_generation,
            signing_key,
        )?;
    if readback
        .source_project_admission_status_v1()?
        != Some((row, false))
        || readback
            .source_project_admission_reservation_v1()?
            != Some(reservation)
        || readback.physical_names_v1() != names
    {
        return Err(R::stale());
    }
    Ok(packet)
}

/// Compares the held Source row against the complete saved project ancestry.
///
/// # Errors
/// Preserves the original query failure or stale held-row/ancestry refusal.
pub fn replay_source_hold<R: SourceSignerComparisonV1>(
    readback: &mut R,
    project: ProjectId,
) -> Result<SourceDomainPolicyHoldV1, R::Error> {
    let journal = &mut *readback;
    let hold = journal
        .source_domain_policy_hold_v1()?
        .filter(|hold| hold.is_held())
        .ok_or(R::stale())?;
    let ancestry = journal.ancestry_head(project)
        .map_err(|_| R::stale())?
        .ok_or(R::stale())?;
    if ancestry != hold.ancestry() {
        return Err(R::stale());
    }
    Ok(hold)
}

/// Signs or compares the established saved Source fields without native admission.
///
/// # Errors
/// Preserves the original query, shape, historical join and signature failure.
pub fn sign_source_first_successor_from_comparison_v2<R: SourceSignerComparisonV1>(
    readback: &mut R, fresh_nonce: [u8; 16],
    context: &RootFirstSourceSuccessorIntentV2, signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<[u8; SOURCE_FIRST_SUCCESSOR_READBACK_BYTES_V2], R::Error> {
    if context.approval_packet().has_resource_authorization() {
        return Err(R::noncanonical_genesis());
    }
    sign_source_successor_from_comparison(
        readback, fresh_nonce, context, signer_generation, signing_key,
        SourceReadbackRecipe::SingleProjectV2,
    )?.try_into().map_err(|_| R::noncanonical_genesis())
}

/// Signs or compares the established saved Source fields without native admission.
///
/// # Errors
/// Preserves the original query, shape, historical join and signature failure.
pub fn sign_source_project_continuation_from_comparison_v3<R: SourceSignerComparisonV1>(
    readback: &mut R, fresh_nonce: [u8; 16],
    context: &RootFirstSourceSuccessorIntentV2, signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<[u8; SOURCE_PROJECT_CONTINUATION_READBACK_BYTES_V3], R::Error> {
    if context.approval_packet().has_resource_authorization() {
        return Err(R::noncanonical_genesis());
    }
    sign_source_successor_from_comparison(
        readback, fresh_nonce, context, signer_generation, signing_key,
        SourceReadbackRecipe::MixedProjectsV3,
    )?.try_into().map_err(|_| R::noncanonical_genesis())
}

/// Signs or compares the established saved Source fields without native admission.
///
/// # Errors
/// Preserves the original query, shape, historical join and signature failure.
pub fn sign_source_resource_successor_from_comparison<R: SourceSignerComparisonV1>(
    readback: &mut R, fresh_nonce: [u8; 16],
    context: &RootFirstSourceSuccessorIntentV2, signer_generation: u64,
    signing_key: &SigningKey, mixed: bool,
) -> Result<Vec<u8>, R::Error> {
    let recipe = if mixed { SourceReadbackRecipe::ResourceMixedProjectsV5 }
        else { SourceReadbackRecipe::ResourceSingleProjectV4 };
    sign_source_successor_from_comparison(readback, fresh_nonce, context, signer_generation, signing_key, recipe)
}

/// Signs or compares the established saved Source fields without native admission.
///
/// # Errors
/// Preserves the original query, shape, historical join and signature failure.
fn sign_source_successor_from_comparison<R: SourceSignerComparisonV1>(
    readback: &mut R, fresh_nonce: [u8; 16],
    context: &RootFirstSourceSuccessorIntentV2, signer_generation: u64,
    signing_key: &SigningKey, recipe: SourceReadbackRecipe,
) -> Result<Vec<u8>, R::Error> {
    if fresh_nonce == [0; 16] || signer_generation == 0
        || recipe.is_resource() != context.approval_packet().has_resource_authorization()
    {
        return Err(R::noncanonical_genesis());
    }
    let names = readback.physical_names_v1();
    let journal = &mut *readback;
    let sequence = journal.snapshot_sequence();
    let successor = if recipe.is_single_project() {
        journal.source_first_successor_rows_v2()?
    } else {
        journal.source_project_continuation_rows_v3(Some(context.project()))?
    };
    let genesis = journal.source_tree_genesis_rows_v1()?;
    let (tree_head, lineage_head, tree_commit, generation) =
        journal.successor_tree(context.project())?;
    let original = genesis.receipts.get(&context.project()).ok_or(R::conflicting_genesis())?;
    let original_ack = genesis.acks.get(&context.project()).ok_or(R::conflicting_genesis())?;
    if genesis.pending.is_some()
        || (recipe.is_single_project()
            && successor.receipts.keys().any(|project| *project != context.project()))
    {
        return Err(R::conflicting_genesis());
    }
    let receipt = successor.receipts.get(&context.project());
    let ack = successor.acks.get(&context.project());
    let phase = match (receipt, ack) {
        (None, None) => {
            if recipe.is_single_project() {
                journal.validate_genesis_rows()?;
            }
            SourceFirstSuccessorReadbackPhaseV2::Before
        }
        (Some(_), None) => SourceFirstSuccessorReadbackPhaseV2::Prepared,
        (Some(_), Some(_)) => SourceFirstSuccessorReadbackPhaseV2::Anchored,
        (None, Some(_)) => return Err(R::conflicting_genesis()),
    };
    if successor.pending.as_ref().is_some_and(|pending| pending.source_names() != names) {
        return Err(R::stale_genesis());
    }

    let genesis_offset = 64 + context.approval_packet().as_bytes().len();
    let tail = genesis_offset + original.as_bytes().len();
    let packet_bytes = tail + 1152;
    if (!recipe.is_resource() && packet_bytes != SOURCE_FIRST_SUCCESSOR_READBACK_BYTES_V2)
        || (recipe.is_resource() && !matches!(packet_bytes,
            SOURCE_RESOURCE_SUCCESSOR_LEGACY_GENESIS_BYTES_V4 | SOURCE_RESOURCE_SUCCESSOR_READBACK_BYTES_V4))
    {
        return Err(R::noncanonical_genesis());
    }
    let mut packet = vec![0; packet_bytes];
    packet[..8].copy_from_slice(recipe.magic());
    packet[8..10].copy_from_slice(&recipe.version().to_be_bytes());
    packet[10] = phase as u8;
    packet[16..32].copy_from_slice(&fresh_nonce);
    packet[32..64].copy_from_slice(context.digest().as_bytes());
    packet[64..genesis_offset].copy_from_slice(context.approval_packet().as_bytes());
    packet[genesis_offset..tail].copy_from_slice(original.as_bytes());
    packet[tail..tail + 192].copy_from_slice(&original_ack.encode());
    if let Some(receipt) = receipt {
        packet[tail + 192..tail + 728].copy_from_slice(receipt.as_bytes());
    }
    if let Some(ack) = ack {
        packet[tail + 728..tail + 920].copy_from_slice(ack.as_bytes());
    }
    packet[tail + 920..tail + 968].copy_from_slice(&names.to_bytes());
    packet[tail + 968..tail + 976].copy_from_slice(&sequence.to_be_bytes());
    packet[tail + 976..tail + 984].copy_from_slice(&signer_generation.to_be_bytes());
    packet[tail + 984..tail + 1016].copy_from_slice(tree_head.as_bytes());
    packet[tail + 1016..tail + 1048].copy_from_slice(lineage_head.as_bytes());
    packet[tail + 1048..tail + 1080].copy_from_slice(tree_commit.as_bytes());
    packet[tail + 1080..tail + 1088].copy_from_slice(&generation.to_be_bytes());
    // Pure DATA shape/bindings precede real signing. Only the public verifier
    // authenticates the complete signature against the independent pinned key.
    validate_source_readback_fields_v1(&packet, fresh_nonce, context, recipe, Some(original))?;
    let signature = signing_key.sign(&signature_message_with_recipe(&packet[..tail + 1088], recipe)).to_bytes();
    packet[tail + 1088..].copy_from_slice(&signature);
    if journal.snapshot_sequence() != sequence {
        return Err(R::stale_genesis());
    }
    Ok(packet)
}

/// Signs or compares the established saved Source fields without native admission.
///
/// # Errors
/// Preserves the original query, shape, historical join and signature failure.
pub fn sign_source_project_completed_terminal_from_comparison_v1<R: SourceSignerComparisonV1>(
    readback: &mut R,
    challenge: SourceHoldReadbackChallengeV1,
    signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<
    [u8; SOURCE_PROJECT_COMPLETED_TERMINAL_READBACK_BYTES_V1],
    R::Error,
> {
    let terminal = readback
        .source_project_admission_terminal_v1()?
        .ok_or(R::stale())?;
    let names = readback.physical_names_v1();
    let sequence = readback.snapshot_sequence();
    if terminal.reservation().names() != names
        || terminal.reservation().client_nonce() != challenge.nonce()
        || terminal.root_terminal_digest() != challenge.cut()
    {
        return Err(R::stale());
    }
    let packet = sign_source_project_completed_terminal_fields_v1(
        terminal,
        sequence,
        signer_generation,
        signing_key,
    )?;
    if readback
        .source_project_admission_terminal_v1()?
        != Some(terminal)
        || readback.snapshot_sequence() != sequence
        || readback.physical_names_v1() != names
    {
        return Err(R::stale());
    }
    Ok(packet)
}

