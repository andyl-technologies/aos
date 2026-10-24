//! Shares the original fixed Root history append DATA quote.
//!
//! The lexical recipe performs only checked ResourceVector/format arithmetic
//! and supplied pure geometry expressions. It observes no native owner, debits
//! no account and constructs no phase, journal, receipt or role lender.

/// Expands the sole fixed history append quote at its existing typed boundary.
///
/// Arguments are lexical DATA bindings and pure quote expressions. Record/head
/// sizing, helper evaluation, full extent and checked-add/error ordering remain
/// the original sequence. The actual role retains its genuine payer and owners.
#[macro_export]
macro_rules! fixed_root_history_append_demand_data_v1 {
    (
        extent: $held:ident,
        body_bytes: $body:ident,
        wire_bytes: $wire:ident,
        owner_bytes: $owner:ident,
        resource_vector: $vector:ident,
        dimension: $dimension:ident,
        record: $record:ty,
        record_shape: $shape:ident,
        append_bytes: $append:ident,
        history: $history:expr,
        names: $names:expr,
        clock: $clock:expr,
        owed: $owed:expr,
        error: $error:expr,
    ) => {{
    let invalid = || $error;
    let record = $crate::domain_ledger::create_storage_history::RECORD_OVERHEAD_BYTES.checked_add($body).ok_or_else(invalid)?;
    let append = $append([
        $shape { key_bytes: $crate::domain_ledger::create_storage_history::KEY_BYTES, value_bytes: Some(record) },
        $shape { key_bytes: $crate::domain_ledger::create_storage_history::KEY_BYTES, value_bytes: Some($crate::domain_ledger::create_storage_history::HEAD_BYTES) },
    ].into_iter()).map_err(|_| invalid())?;
    let cell = std::mem::size_of::<($record, [u8; 16], [usize; 3])>() as u64;
    let cells = 2u64 * 32;
    let memory = append.checked_mul(16)
        .and_then(|bytes| bytes.checked_add(cells.checked_mul(cell)?))
        .and_then(|bytes| bytes.checked_add(64 * 1024))
        .and_then(|bytes| bytes.checked_add(u64::try_from($owner).ok()?)).ok_or_else(invalid)?;
    let hello = u64::try_from($wire)
        .map_err(|_| invalid())?;
    let fixed = $vector::ZERO.with($dimension::MemoryBytes, memory)
        .with($dimension::StorageBytes, append)
        // The transaction introduces its record key and the shared head key.
        // Construction copies above remain Memory, not additional key names.
        .with($dimension::MetadataEntries, 2).with($dimension::PublicationStagingBytes, memory)
        .with($dimension::OutputBytes, memory.checked_add(hello).ok_or_else(invalid)?)
        .with($dimension::NetworkBytes, hello);
    // Actual previous maps remain resident while the sole Native appender
    // validates/materializes its prospective after cut. This is additional
    // to initial replay, with no hypothetical future retirement credit.
    let history = $history?;
    let names = $names?;
    let clock = $clock?;
    let clocks = clock.checked_add(clock).and_then(|value| value.checked_add(clock)).map_err(|_| invalid())?;
    let owed = $owed?;
    let owed = owed.checked_add(owed).and_then(|value| value.checked_add(owed)).map_err(|_| invalid())?;
    $held.dominant_native_receiving_demand_v1()?
        .checked_add($held.dominant_semantic_receiving_demand_v1()?)
        .and_then(|demand| demand.checked_add(fixed))
        .and_then(|demand| demand.checked_add(history))
        .and_then(|demand| demand.checked_add(names))
        .and_then(|demand| demand.checked_add(owed))
        .and_then(|demand| demand.checked_add(clocks)).map_err(|_| invalid())
    }};
}
