//! Borrows complete Boot fields and records selected typed lineage row spans.

use super::*;
use crate::connection::settled17::HistoricalByteBank17;

fn data<'body, 'rows>(
    input: &'body [u8],
    ledger: &mut Ledger<'rows, '_, '_>,
) -> Result<BorrowedBootDataLineage17<'body, 'rows>, ProviderError> {
    let mut fields = Fields::object(input)?;
    discard::<String>(fields.named("schema")?, ledger)?;
    let private_key = loan(fields.named("private_key")?, ledger)?;
    let birth_id = loan(fields.named("birth_id")?, ledger)?;
    let source_birth = loan(fields.named("source_birth")?, ledger)?;
    let host_registration = loan(fields.named("expected_host_registration")?, ledger)?;
    let private_launch = loan(fields.named("private_launch")?, ledger)?;
    let host_executable = loan(fields.named("host_executable")?, ledger)?;
    fields.finish()?;

    let result = BorrowedBootDataLineage17 {
        private_key,
        birth_id,
        source_birth,
        host_registration,
        private_launch,
        host_executable,
    };
    let _ = result.private_key.key32_data()?;
    Ok(result)
}

/// Walks the entire exact Boot definition while borrowing only selected lineage.
///
/// # Errors
/// Refuses enabled host-heap target accounting, malformed full source fields,
/// wrong capacity/alias rows or a mismatching enclosing native Boot edge.
pub(crate) fn read_shared_current_boot_lineage17_data<'body, 'rows>(
    input: &'body [u8],
    ledger: &mut Ledger<'rows, '_, '_>,
) -> Result<BorrowedCurrentBootLineage17<'body, 'rows>, ProviderError> {
    // This is an immutable evidence pass. The separate narrow target preflight
    // prices only the signed DTO/model owners selected from these exact spans.
    if ledger.has_native17_targets_data() && !ledger.native17_targets_suspended_data() {
        return Err(invalid());
    }

    let start = ledger.rows.encoded_position();
    let layout = NativeAckBoot::current_boot_shared_layout17_data();
    shared_row17(ledger, layout)?;
    let group = ledger.shared_begin(MetadataSharedKind::NativeBoot)?;
    let mut fields = Fields::object(input)?;
    role(
        fields.named("schema")?,
        "source-private.native-current-boot/17",
    )?;
    let creator_raw = fields.named("creator")?;
    role(
        fields.named("thread_role")?,
        "same-original-native-thread-history-only",
    )?;
    let data_raw = fields.named("data")?;
    let launch_raw = fields.named("launch")?;
    let policy_raw = fields.named("policy_role")?;
    let source_raw = fields.named("source")?;
    let host_raw = fields.named("host")?;
    let normalized_raw = fields.named("normalized")?;
    let banks_raw = fields.named("banks")?;
    let context_raw = fields.named("context")?;
    let proof_raw = fields.named("proof")?;
    let original_raw = fields.named("original")?;
    let ready_raw = fields.named("ready")?;
    let attempted_raw = fields.named("attempted")?;
    let verified_raw = fields.named("verified")?;
    let commit_raw = fields.named("commit")?;
    let prepare_raw = fields.named("prepare")?;
    let startup_raw = fields.named("startup")?;
    let stages_raw = fields.named("restoration_stages")?;
    let reserve_raw = fields.named("settled_reserve")?;
    fields.finish()?;

    let creator = scalar(creator_raw, ledger)?;
    let data = data(data_raw, ledger)?;
    let launch = loan(launch_raw, ledger)?;
    role(policy_raw, "native-policy")?;
    let policy_group = read_reference17(
        ledger,
        MetadataSharedKind::NativePolicy,
        (size_of::<Native5Policy>(), align_of::<Native5Policy>()),
    )?;
    discard::<HistoricalByteBank17>(source_raw, ledger)?;
    discard::<HistoricalByteBank17>(host_raw, ledger)?;

    let mut normalized = Fields::array(normalized_raw)?;
    let normalized_fields = [
        loan(normalized.next()?.ok_or_else(invalid)?, ledger)?,
        loan(normalized.next()?.ok_or_else(invalid)?, ledger)?,
        loan(normalized.next()?.ok_or_else(invalid)?, ledger)?,
        loan(normalized.next()?.ok_or_else(invalid)?, ledger)?,
        loan(normalized.next()?.ok_or_else(invalid)?, ledger)?,
    ];
    normalized.finish()?;

    let mut banks = Fields::array(banks_raw)?;
    for _ in 0..5 {
        discard::<HistoricalByteBank17>(banks.next()?.ok_or_else(invalid)?, ledger)?;
    }
    banks.finish()?;

    let ack_context = loan(context_raw, ledger)?;
    let ack_proof = loan(proof_raw, ledger)?;
    let ack_original = loan(original_raw, ledger)?;
    let ready = scalar(ready_raw, ledger)?;
    let attempted = scalar(attempted_raw, ledger)?;
    let verified = scalar(verified_raw, ledger)?;

    let commit = if commit_raw == b"null" {
        None
    } else {
        Some(super::commit::read_shared(commit_raw, ledger)?)
    };
    let prepare = if prepare_raw == b"null" {
        None
    } else {
        Some(super::prepare::read_shared(prepare_raw, ledger, group)?)
    };

    // This order follows the real observer: full observation roots precede the
    // suffix's weak reference even though startup is emitted earlier in JSON.
    let stages = super::stages::read(stages_raw, ledger)?;
    discard::<Option<CurrentStartup17>>(startup_raw, ledger)?;
    let reserve = super::reserve::read(reserve_raw, ledger, group)?;
    let restored_suffix_maximum_originals = suffix_limit(startup_raw)?;

    let rows = ledger.rows.encoded_between(start)?;
    ledger.shared_finish(group, layout.0, input, rows)?;

    Ok(BorrowedCurrentBootLineage17 {
        definition: input,
        group,
        creator,
        policy_group,
        data,
        launch,
        normalized: normalized_fields,
        ack_context,
        ack_proof,
        ack_original,
        commit,
        prepare,
        stages,
        reserve,
        restored_suffix_maximum_originals,
        ready,
        attempted,
        verified,
    })
}

/// Projects only from the already fully walked startup and sealed suffix rows.
fn suffix_limit(startup: &[u8]) -> Result<Option<U64>, ProviderError> {
    if startup == b"null" {
        return Ok(None);
    }
    let mut startup_fields = Fields::object(startup)?;
    for name in [
        "allocation",
        "source_digest",
        "launch_digest",
        "birth_id",
        "native_birth_issued",
        "baseline_complete",
        "prepare_startup_issued",
    ] {
        let _ = startup_fields.named(name)?;
    }
    let suffix = startup_fields.named("restored_suffix")?;
    startup_fields.finish()?;
    if suffix == b"null" {
        return Ok(None);
    }
    let mut suffix_fields = Fields::object(suffix)?;
    for name in ["schema", "creator", "thread_role", "preamble"] {
        let _ = suffix_fields.named(name)?;
    }
    let reservation = suffix_fields.named("reservation")?;
    for name in [
        "ledger",
        "observe_attempts",
        "observe_capacity",
        "producer_attempts",
        "producer_capacity",
        "raw7",
        "raw7_bytes",
        "raw5",
        "raw5_bytes",
    ] {
        let _ = suffix_fields.named(name)?;
    }
    let sealed = suffix_fields.named("sealed")?;
    let failed = suffix_fields.named("failed")?;
    let _ = suffix_fields.named("first_observation_role")?;
    let _ = suffix_fields.named("first_observation_record")?;
    suffix_fields.finish()?;
    if sealed == b"null" || failed != b"false" {
        return Ok(None);
    }
    let mut sealed_fields = Fields::object(sealed)?;
    for name in [
        "schema",
        "model",
        "launch_digest",
        "launch_bytes",
        "frame_bytes",
    ] {
        let _ = sealed_fields.named(name)?;
    }
    let originals = unsigned(sealed_fields.named("originals")?)?;
    let sealed_reservation = sealed_fields.named("reservation")?;
    for name in ["retained", "transient", "scratch", "requested"] {
        let _ = sealed_fields.named(name)?;
    }
    sealed_fields.finish()?;

    // Both definitions are borrowed from the actual source serializer, whose
    // reservation object has a single emitted order and decimal representation.
    if reservation != sealed_reservation {
        return Err(invalid());
    }
    let mut reservation_fields = Fields::object(sealed_reservation)?;
    let maximum = plain_string(reservation_fields.named("maximum_originals")?)?
        .parse::<u64>()
        .map_err(|_| invalid())?;
    let _ = reservation_fields.named("ingress")?;
    let _ = reservation_fields.named("actions")?;
    reservation_fields.finish()?;
    if maximum == 0 || maximum > 256 || originals != maximum {
        return Err(invalid());
    }
    Ok(Some(U64::new(maximum)))
}
