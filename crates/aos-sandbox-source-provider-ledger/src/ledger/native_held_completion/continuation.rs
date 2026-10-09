//! Reducer-derived original Source continuation shapes and canonical before DATA.
//!
//! The finite projection shares concrete checkpoint eligibility and lifecycle
//! family planning. Future proof payloads have codec bounds and unresolved joins;
//! no forecast is a canonical owner record, signed proof or funding capability.
//! Independently admitted Release operations require a fresh actual owner cut.

use std::collections::BTreeMap;

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::native_held_completion::{
    NativeHeldControlKindV1 as Kind, witness::native_held_record_byte_digest_v1,
};
use sha2::{Digest as _, Sha256};

use super::{
    MAXIMUM_NATIVE_HELD_RECORD_BYTES_V1, SourceNativeHeldCompletionRecordV1 as Record,
    SourceNativeHeldLifecycleV1 as Lifecycle, SourceNativeHeldStepV1 as Step, corrupt,
    graph::{self, Records}, lifecycle,
    transition::{self, CheckpointFacts},
};
use crate::ledger::{
    LedgerFormatErrorV1, completion, format,
    model::{
        DecodedRecordV1, ProviderAcquisitionStateV1, ProviderAttemptStateV1,
        ProviderReleaseStateV1, ReleaseKeyV1,
    },
    native_completion::{
        self, NativeAcquireCompletionStateV2 as Outer, OriginalSourceAdmissionComparisonV5,
        OriginalSourceOwnerDataV5, OriginalSourceOwnerPrefixV5, OriginalSourceProvenanceV5,
        SourcePreRequestedColdArchiveV1, SourcePreRequestedColdPhaseV1 as ColdPhase,
        SOURCE_PRE_REQUESTED_COLD_ARCHIVE_FIXED_BYTES_V1,
        classify_original_source_owner_v5, classify_original_source_pre_requested_cold_v1,
        derive_original_source_pre_requested_retirement_v1,
    },
};

// Finite append-once kinds, three disposition shapes and two terminal choices
// bound this search. Exceeding the bound refuses the result rather than dropping
// an expensive alternative. Each branch additionally has at most 20 own appends.
const MAXIMUM_ALTERNATIVES: usize = 131_072;
const MAXIMUM_APPENDS: usize = 20;

/// Names the actual validated owner prefix, separately from historical admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OriginalSourceContinuationPrefixV5 {
    /// The accepted Applying quartet is current and no native carrier exists.
    Applying,
    /// A complete actual held graph retains this phase and its exact archive shape.
    Held(u8),
    /// A validated distinct pre-Requested cold archive retains this phase.
    PreRequestedCold(ColdPhase),
}

/// Names a derived edge without selecting or authorizing a continuation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OriginalSourceContinuationKindV5 {
    /// Adds the initial held carrier to an actual absent native key.
    FirstRequested,
    /// Uses the shared concrete held checkpoint predicate.
    Held(Step),
    /// Uses an eligible final lifecycle family, with separate custody requirements.
    Cleanup(Lifecycle),
    /// Uses the integrated three-step distinct cold archive profile.
    PreRequestedCold(ColdPhase),
}

/// Describes the required source of an edge's before bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OriginalSourceBeforeDependencyV5 {
    /// The key's first before is its exact value or absence in the complete cut.
    ActualGraph,
    /// The before is exactly this prior edge's forecast output for the same key.
    PreviousOutput(usize),
    /// A separate ordinary admission/current-owner operation must provide a new cut.
    IndependentlyFundedCut,
}

/// Retains one codec-derived value bound and its key/before dependency.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginalSourceContinuationValueBoundV5 {
    key: Vec<u8>,
    maximum_value_bytes: usize,
    dependency: OriginalSourceBeforeDependencyV5,
    symbolic_key: bool,
    source_floor_relative: bool,
}

impl OriginalSourceContinuationValueBoundV5 {
    /// Borrows an actual derived key, or a family-width symbol requiring a new cut.
    ///
    /// A symbolic key is a private measurement label, never an owner identity.
    #[must_use]
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// Returns the codec ceiling or floor-relative suffix width, excluding framing.
    ///
    /// When `requires_source_floor_width` is true, the actual typed Source5
    /// value width must be added before this becomes a whole-value ceiling.
    #[must_use]
    pub const fn maximum_value_bytes(&self) -> usize {
        self.maximum_value_bytes
    }

    /// Reports a cold suffix whose whole width requires the actual typed floor.
    #[must_use]
    pub const fn requires_source_floor_width(&self) -> bool {
        self.source_floor_relative
    }

    /// Returns the immutable predecessor dependency, not substitutable before DATA.
    #[must_use]
    pub const fn before_dependency(&self) -> OriginalSourceBeforeDependencyV5 {
        self.dependency
    }

    /// Reports a future key family whose actual identity requires another admission.
    #[must_use]
    pub const fn is_symbolic_key(&self) -> bool {
        self.symbolic_key
    }
}

/// Retains a derived owner mutation family, excluding all Journal floor records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginalSourceContinuationEdgeV5 {
    kind: OriginalSourceContinuationKindV5,
    values: Vec<OriginalSourceContinuationValueBoundV5>,
    final_append: bool,
    mode3_terminal: bool,
    independent_cut: bool,
}

impl OriginalSourceContinuationEdgeV5 {
    /// Returns the checkpoint selected by actual schema facts.
    #[must_use]
    pub const fn kind(&self) -> OriginalSourceContinuationKindV5 {
        self.kind
    }

    /// Borrows every after-value bound, including expensive completion families.
    #[must_use]
    pub fn values(&self) -> &[OriginalSourceContinuationValueBoundV5] {
        &self.values
    }

    /// Reports final own-floor removal without authorizing custody retirement.
    #[must_use]
    pub const fn is_final(&self) -> bool {
        self.final_append
    }

    /// Distinguishes the mode3 Root9 terminal alternative from received13.
    #[must_use]
    pub const fn is_mode3_terminal(&self) -> bool {
        self.mode3_terminal
    }

    /// Reports required separately funded ordinary admission and actual cut renewal.
    #[must_use]
    pub const fn requires_independent_cut(&self) -> bool {
        self.independent_cut
    }

    /// Reports a closure prerequisite that marker or terminal DATA cannot discharge.
    #[must_use]
    pub fn requires_original_custody_closure(&self) -> bool {
        matches!(self.kind, OriginalSourceContinuationKindV5::Cleanup(_))
    }
}

/// Retains one complete bounded own-floor alternative as comparison DATA.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginalSourceContinuationAlternativeV5 {
    edges: Vec<OriginalSourceContinuationEdgeV5>,
    poison: bool,
}

impl OriginalSourceContinuationAlternativeV5 {
    /// Borrows the ordered complete continuation, including eligible cleanup.
    #[must_use]
    pub fn edges(&self) -> &[OriginalSourceContinuationEdgeV5] {
        &self.edges
    }

    /// Reports reducer-derived Closed/recovery classification for envelope folding.
    #[must_use]
    pub const fn is_poison(&self) -> bool {
        self.poison
    }
}

/// Retains complete-cut joins and all bounded own-floor continuation alternatives.
///
/// This value has no public constructor or serialization path. Completeness is
/// over the shared finite schema projection; unknown signed artifacts still need
/// every concrete reducer join. Ordinary association/co-settlement, challenge
/// debt, original physical membership and live custody remain separate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginalSourceContinuationDataV5 {
    prefix: OriginalSourceContinuationPrefixV5,
    graph_digest: ObjectDigest,
    records: Records,
    original: Option<OriginalSourceOwnerDataV5>,
    provenance: OriginalSourceProvenanceV5,
    cold: Option<SourcePreRequestedColdArchiveV1>,
    alternatives: Vec<OriginalSourceContinuationAlternativeV5>,
}

impl OriginalSourceContinuationDataV5 {
    /// Returns the actual current prefix, never the historical quartet's state.
    #[must_use]
    pub const fn prefix(&self) -> OriginalSourceContinuationPrefixV5 {
        self.prefix
    }

    /// Returns the shared validator's commitment to every canonical current row.
    #[must_use]
    pub const fn graph_digest(&self) -> ObjectDigest {
        self.graph_digest
    }

    /// Borrows every bounded canonical current row for exact Sandbox cut comparison.
    pub fn current_records(&self) -> impl Iterator<Item = (&[u8], &[u8])> {
        views(&self.records)
    }

    /// Borrows accepted historical Applying bindings only for the original hot path.
    #[must_use]
    pub const fn original(&self) -> Option<&OriginalSourceOwnerDataV5> {
        self.original.as_ref()
    }

    /// Borrows immutable original archive DATA for independent typed floor joins.
    #[must_use]
    pub const fn provenance(&self) -> &OriginalSourceProvenanceV5 {
        &self.provenance
    }

    /// Borrows a validated cold archive; its copied floor remains untrusted DATA.
    #[must_use]
    pub const fn cold_archive(&self) -> Option<&SourcePreRequestedColdArchiveV1> {
        self.cold.as_ref()
    }

    /// Borrows all complete alternatives; callers cannot choose a cheaper subset.
    #[must_use]
    pub fn alternatives(&self) -> &[OriginalSourceContinuationAlternativeV5] {
        &self.alternatives
    }
}

/// Derives original Source continuation DATA from a complete actual owner graph.
///
/// Held prefixes require the separately accepted Applying comparison seed. Cold
/// reopen uses only its integrated historical graph/archive and copied floor;
/// passing a hot comparison seed there is refused. No classifier broadens the
/// existing initial Applying/Requested public prefix enum.
///
/// # Errors
///
/// Rejects incomplete, duplicate, oversize or noncanonical graphs, foreign origin
/// comparisons, unsupported/repeated shapes, bounded search exhaustion and any
/// current logical counter unable to represent a projected continuation.
pub fn derive_original_source_continuations_v5<'record>(
    complete_current_owner_records: impl IntoIterator<Item = (&'record [u8], &'record [u8])>,
    original_admission_owner_comparison: Option<&OriginalSourceAdmissionComparisonV5>,
    provenance: &OriginalSourceProvenanceV5,
    expected_configuration: ObjectDigest,
) -> Result<OriginalSourceContinuationDataV5, LedgerFormatErrorV1> {
    let records = crate::collect_bounded_records(complete_current_owner_records)?;
    let graph_digest = crate::validate_current_records(&records)?.graph_digest();
    if expected_configuration.as_bytes() == &[0; 32]
        || expected_configuration != provenance.claims().configuration
    {
        return Err(corrupt("original Source continuation configuration"));
    }
    let acquisition = provenance.claims().claims.provider_acquisition().1;
    let native_key = native_completion::native_completion_key_v2(acquisition);
    let cold = records
        .get(&native_key)
        .is_some_and(|bytes| native_completion::pre_requested_cold::is_cold(bytes));
    if cold {
        if original_admission_owner_comparison.is_some() {
            return Err(corrupt("cold archive cannot restore hot comparison seed"));
        }
        let archive = classify_original_source_pre_requested_cold_v1(views(&records), acquisition)?;
        validate_cold_provenance(&archive, provenance)?;
        let alternatives = vec![cold_continuation(&records, &native_key, &archive)?];
        return Ok(OriginalSourceContinuationDataV5 {
            prefix: OriginalSourceContinuationPrefixV5::PreRequestedCold(archive.phase()),
            graph_digest,
            records,
            original: None,
            provenance: provenance.clone(),
            cold: Some(archive),
            alternatives,
        });
    }

    let comparison = original_admission_owner_comparison.ok_or(corrupt(
        "original Source continuation accepted Applying comparison missing",
    ))?;
    validate_comparison(comparison, provenance, expected_configuration)?;
    let original = comparison.original().clone();
    let applying = !records.contains_key(&native_key);
    let (prefix, facts, keys, revision) = if applying {
        let actual = classify_original_source_owner_v5(
            views(&records),
            provenance,
            expected_configuration,
        )?;
        if actual != original || actual.prefix != OriginalSourceOwnerPrefixV5::Applying {
            return Err(corrupt("original Source Applying comparison changed"));
        }
        for mutation in comparison.quartet() {
            if records.get(mutation.key()).map(Vec::as_slice) != Some(mutation.after()) {
                return Err(corrupt("original Source historical quartet is not current Applying"));
            }
        }
        (
            OriginalSourceContinuationPrefixV5::Applying,
            requested_facts(),
            companion_keys(provenance),
            0,
        )
    } else {
        let bytes = records
            .get(&native_key)
            .ok_or(corrupt("original Source held row absent"))?;
        let held = Record::from_canonical_bytes(&native_key, bytes)?;
        let rows = graph::Companions::read(&records, &held)?;
        validate_held_origin(&held, &rows, comparison, provenance)?;
        (
            OriginalSourceContinuationPrefixV5::Held(held.suffix().phase()),
            CheckpointFacts::read(&held)?,
            rows.keys,
            held.original().revision,
        )
    };

    let mut alternatives = Vec::new();
    let mut path = Vec::new();
    if applying {
        path.push(edge(
            OriginalSourceContinuationKindV5::FirstRequested,
            vec![bound(native_key.clone(), MAXIMUM_NATIVE_HELD_RECORD_BYTES_V1)],
            false,
            false,
        ));
    }
    enumerate(&records, &keys, facts, &mut path, &mut alternatives)?;
    if applying {
        let retirement = derive_original_source_pre_requested_retirement_v1(
            views(&records),
            provenance,
            expected_configuration,
        )?;
        let mut cold_path = Vec::new();
        for (index, fixed) in SOURCE_PRE_REQUESTED_COLD_ARCHIVE_FIXED_BYTES_V1
            .into_iter()
            .enumerate()
        {
            let mut values = if index == 0 {
                retirement
                    .mutations()
                    .iter()
                    .map(|mutation| bound(mutation.key().to_vec(), mutation.after().len()))
                    .collect()
            } else {
                Vec::new()
            };
            let mut cold_value = bound(native_key.clone(), fixed);
            cold_value.source_floor_relative = true;
            values.push(cold_value);
            cold_path.push(edge(
                OriginalSourceContinuationKindV5::PreRequestedCold(cold_phase(index)?),
                values,
                index == 2,
                false,
            ));
        }
        push_alternative(&mut alternatives, cold_path, true)?;
    }
    for alternative in &mut alternatives {
        attach_dependencies(alternative);
        check_logical_headroom(&records, alternative, &native_key, revision)?;
    }
    if alternatives.is_empty() {
        return Err(corrupt("original Source continuation has no complete branch"));
    }
    Ok(OriginalSourceContinuationDataV5 {
        prefix,
        graph_digest,
        records,
        original: Some(original),
        provenance: provenance.clone(),
        cold: None,
        alternatives,
    })
}

/// Checks an actual original cut without demanding a prospective continuation.
///
/// Retired final-edge DATA still needs every canonical graph and immutable
/// admission join. This helper establishes neither custody nor floor membership.
///
/// # Errors
///
/// Rejects a noncanonical complete graph, substituted admission/provenance or
/// an actual Applying/held/cold carrier that does not join that immutable origin.
pub(crate) fn validate_current_origin<'record>(
    complete_rows: impl IntoIterator<Item = (&'record [u8], &'record [u8])>,
    comparison: &OriginalSourceAdmissionComparisonV5,
    provenance: &OriginalSourceProvenanceV5,
    configuration: ObjectDigest,
) -> Result<(), LedgerFormatErrorV1> {
    let records = crate::collect_bounded_records(complete_rows)?;
    crate::validate_current_records(&records)?;
    validate_comparison(comparison, provenance, configuration)?;
    if provenance.claims().configuration != configuration {
        return Err(corrupt("original Source current origin configuration"));
    }
    let native_key =
        native_completion::native_completion_key_v2(comparison.original().acquisition_id);
    let Some(bytes) = records.get(&native_key) else {
        let actual = classify_original_source_owner_v5(views(&records), provenance, configuration)?;
        if &actual != comparison.original()
            || comparison.quartet().iter().any(|mutation| {
                records.get(mutation.key()).map(Vec::as_slice) != Some(mutation.after())
            })
        {
            return Err(corrupt("original Source current Applying origin changed"));
        }
        return Ok(());
    };
    if native_completion::pre_requested_cold::is_cold(bytes) {
        let archive = classify_original_source_pre_requested_cold_v1(
            views(&records),
            comparison.original().acquisition_id,
        )?;
        return validate_cold_provenance(&archive, provenance);
    }
    let held = Record::from_canonical_bytes(&native_key, bytes)?;
    let rows = graph::Companions::read(&records, &held)?;
    validate_held_origin(&held, &rows, comparison, provenance)
}

/// Joins an accepted historical Applying quartet to its immutable provenance.
///
/// # Errors
///
/// Rejects the original phase/configuration/Root-preparation mismatch or any
/// substituted quartet key/value witness. It establishes no physical membership.
pub(crate) fn validate_comparison(
    comparison: &OriginalSourceAdmissionComparisonV5,
    provenance: &OriginalSourceProvenanceV5,
    configuration: ObjectDigest,
) -> Result<(), LedgerFormatErrorV1> {
    if comparison.original().prefix != OriginalSourceOwnerPrefixV5::Applying
        || comparison.original().configuration_digest != configuration
        || comparison.original().root_prepared_digest != provenance.claims().root_prepared.digest()
    {
        return Err(corrupt("original Source historical admission binding"));
    }
    for witness in &provenance.claims().records {
        let value = comparison
            .quartet()
            .iter()
            .find(|mutation| mutation.key() == witness.key())
            .ok_or(corrupt("original Source historical quartet key"))?;
        let digest = native_held_record_byte_digest_v1(witness.family(), witness.key(), value.after())
            .map_err(|_| corrupt("original Source historical quartet witness"))?;
        if digest != witness.digest() {
            return Err(corrupt("original Source historical quartet bytes"));
        }
    }
    Ok(())
}

fn validate_held_origin(
    held: &Record,
    rows: &graph::Companions,
    comparison: &OriginalSourceAdmissionComparisonV5,
    provenance: &OriginalSourceProvenanceV5,
) -> Result<(), LedgerFormatErrorV1> {
    let native = held.original();
    let original = comparison.original();
    let signed = native
        .canonical_request
        .as_ref()
        .ok_or(corrupt("original Source retained signedN"))?;
    let clock = native
        .original_clock
        .ok_or(corrupt("original Source retained clock"))?;
    let historical = comparison
        .quartet()
        .iter()
        .find(|mutation| mutation.key() == provenance.claims().records[2].key())
        .ok_or(corrupt("original Source historical Session bytes"))?;
    let DecodedRecordV1::Session(session) =
        format::decode_record(historical.key(), historical.after())?
    else {
        return Err(corrupt("original Source historical Session kind"));
    };
    if native.provider_id != original.provider.authority_id()
        || native.holder_id != original.holder.authority_id()
        || native.acquisition_id != original.acquisition_id
        || native.attempt_digest != original.attempt_digest
        || native.root_request_digest != original.root_request_digest
        || native.session_binding != original.session_binding
        || native.reservation_acquisition_digest != Some(original.reservation_acquisition_digest)
        || signed.request().claims() != &provenance.claims().claims
        || signed.request().signed_root_request().to_canonical_bytes() != rows.attempt.signed_request
        || signed.signer() != &session.signers[3]
        || held.suffix().control(Kind::RootPrepared) != Some(&provenance.claims().root_prepared)
        || clock.initial() != provenance.claims().initial
        || clock.deadline() != provenance.claims().narrowed_deadline
        || rows.history.session_binding != session.session_binding
        || rows.history.signers != session.signers
        || rows.history.boot_id != session.boot_id
        || rows.history.root_process_instance != session.root_process_instance
        || rows.history.provider_process_instance != session.provider_process_instance
        || rows.acquisition.provider != original.provider
        || rows.acquisition.holder != original.holder
        || rows.acquisition.effect_id != original.operation_id
        || rows.acquisition.backend_id != original.backend_id
        || rows.acquisition.backend_lineage_digest != original.backend_lineage_digest
        || rows.acquisition.normalized_intent.digest() != original.normalized_intent_digest
    {
        return Err(corrupt("original Source retained immutable admission joins"));
    }
    Ok(())
}

fn validate_cold_provenance(
    archive: &SourcePreRequestedColdArchiveV1,
    provenance: &OriginalSourceProvenanceV5,
) -> Result<(), LedgerFormatErrorV1> {
    let claims = archive.prepared().claims();
    let staged = provenance.claims().claims.to_canonical_bytes();
    let staged_digest = ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos-source-provider-pre-requested-staged-claims.v1\0")
            .chain_update((staged.len() as u32).to_be_bytes())
            .chain_update(staged)
            .finalize()
            .into(),
    );
    let (provider, acquisition) = provenance.claims().claims.provider_acquisition();
    let (holder, session) = provenance.claims().claims.holder_session();
    if claims.provider_id != provider
        || claims.holder_id != holder
        || claims.acquisition_id != acquisition
        || claims.original_session != session
        || claims.original_attempt != provenance.claims().claims.attempt().1
        || claims.original_root_prepared != provenance.claims().root_prepared.digest()
        || claims.original_signed_request != provenance.claims().root_prepared.scope().original_root_request
        || claims.staged_claims != staged_digest
    {
        return Err(corrupt("original Source cold retained provenance"));
    }
    Ok(())
}

fn cold_continuation(
    records: &Records,
    native_key: &[u8],
    archive: &SourcePreRequestedColdArchiveV1,
) -> Result<OriginalSourceContinuationAlternativeV5, LedgerFormatErrorV1> {
    let start = archive.phase() as usize;
    let mut edges = Vec::new();
    for index in start..3 {
        let width = archive.initial_source_floor_bytes().len()
            + SOURCE_PRE_REQUESTED_COLD_ARCHIVE_FIXED_BYTES_V1[index];
        edges.push(edge(
            OriginalSourceContinuationKindV5::PreRequestedCold(cold_phase(index)?),
            vec![bound(native_key.to_vec(), width)],
            index == 2,
            false,
        ));
    }
    let mut alternative = OriginalSourceContinuationAlternativeV5 {
        edges,
        poison: true,
    };
    attach_dependencies(&mut alternative);
    check_logical_headroom(records, &alternative, native_key, archive.phase() as u64)?;
    Ok(alternative)
}

fn requested_facts() -> CheckpointFacts {
    CheckpointFacts {
        phase: 0,
        outer: Outer::Requested,
        prepared: None,
        stored: 1 << Kind::RootPrepared as u8,
        first_recovery: false,
        terminal_recovery: false,
        disposition: None,
        settlement: false,
        reply: false,
        completed: false,
        artifact_claim: false,
    }
}

fn companion_keys(provenance: &OriginalSourceProvenanceV5) -> [Vec<u8>; 6] {
    let (provider, acquisition) = provenance.claims().claims.provider_acquisition();
    [
        format::authority_key(provider),
        provenance.claims().records[0].key().to_vec(),
        provenance.claims().records[1].key().to_vec(),
        provenance.claims().records[2].key().to_vec(),
        provenance.claims().records[3].key().to_vec(),
        native_completion::native_completion_key_v2(acquisition),
    ]
}

fn enumerate(
    records: &Records,
    keys: &[Vec<u8>; 6],
    facts: CheckpointFacts,
    path: &mut Vec<OriginalSourceContinuationEdgeV5>,
    alternatives: &mut Vec<OriginalSourceContinuationAlternativeV5>,
) -> Result<(), LedgerFormatErrorV1> {
    if path.len() >= MAXIMUM_APPENDS {
        return Err(corrupt("original Source continuation append-once bound"));
    }
    if facts.phase == 10 {
        let cleanups = cleanup_edges(records, keys, facts)?;
        if cleanups.is_empty() && facts.outer == Outer::CleanupRequired && !facts.completed {
            push_alternative(alternatives, path.clone(), true)?;
        }
        for cleanup in cleanups {
            let mut complete = path.clone();
            complete.push(cleanup);
            push_alternative(
                alternatives,
                complete,
                facts.first_recovery
                    || facts.disposition != Some(transition::DispositionShape::Accepted),
            )?;
        }
        return Ok(());
    }
    if facts.outer == Outer::Active {
        let mut fault = path.clone();
        fault.push(edge(
            OriginalSourceContinuationKindV5::Cleanup(Lifecycle::OriginalCustodyMarked),
            vec![bound(keys[5].clone(), MAXIMUM_NATIVE_HELD_RECORD_BYTES_V1)],
            true,
            false,
        ));
        push_alternative(alternatives, fault, true)?;
    }
    let successors = transition::checkpoint_successors(facts);
    if successors.is_empty() && facts.outer != Outer::Active {
        return Err(corrupt("original Source unsupported unfinished checkpoint"));
    }
    for (step, next) in successors {
        let selected = transition::checkpoint_owner_indices(step, facts.outer);
        let values = selected
            .iter()
            .map(|index| bound(keys[*index].clone(), owner_value_bound(keys[*index].len())))
            .collect();
        path.push(edge(
            OriginalSourceContinuationKindV5::Held(step),
            values,
            false,
            next.terminal_recovery,
        ));
        enumerate(records, keys, next, path, alternatives)?;
        path.pop();
    }
    Ok(())
}

fn cleanup_edges(
    records: &Records,
    keys: &[Vec<u8>; 6],
    facts: CheckpointFacts,
) -> Result<Vec<OriginalSourceContinuationEdgeV5>, LedgerFormatErrorV1> {
    let mut edges = Vec::new();
    if matches!(facts.outer, Outer::Requested | Outer::Prepared) || facts.outer == Outer::Active {
        let lifecycle = if facts.outer == Outer::Active {
            Lifecycle::OriginalCustodyMarked
        } else {
            Lifecycle::ColdTerminalCleanupMarked
        };
        edges.push(edge(
            OriginalSourceContinuationKindV5::Cleanup(lifecycle),
            vec![bound(keys[5].clone(), MAXIMUM_NATIVE_HELD_RECORD_BYTES_V1)],
            true,
            false,
        ));
    }
    if !facts.completed {
        return Ok(edges);
    }
    let acquisition_bytes = records
        .get(&keys[2])
        .ok_or(corrupt("original Source cleanup acquisition"))?;
    let DecodedRecordV1::Acquisition(acquisition) =
        format::decode_record(&keys[2], acquisition_bytes)?
    else {
        return Err(corrupt("original Source cleanup acquisition kind"));
    };
    let release_key = format::release_key(&ReleaseKeyV1 {
        provider_id: acquisition.provider.authority_id(),
        holder_id: acquisition.holder.authority_id(),
        acquisition_id: acquisition.acquisition_id,
    });
    let release = records
        .get(&release_key)
        .map(|bytes| format::decode_record(&release_key, bytes))
        .transpose()?;
    let actual_release_attempt = if let Some(DecodedRecordV1::Release(release)) = &release {
        records.iter().find_map(|(key, value)| match format::decode_record(key, value).ok()? {
            DecodedRecordV1::Attempt(attempt)
                if attempt.attempt_digest == release.attempt_digest =>
            {
                Some((key.clone(), attempt))
            }
            _ => None,
        })
    } else {
        None
    };
    for (lifecycle, shape) in [
        (
            Lifecycle::ReleaseStatusCompleted,
            Some(completion::HeldReleaseMutationShape::StatusOnly),
        ),
        (
            Lifecycle::ReleaseCompleted,
            Some(completion::HeldReleaseMutationShape::OrdinaryComplete),
        ),
        (
            Lifecycle::ReleaseCompleted,
            Some(completion::HeldReleaseMutationShape::ReceiptOnlyRecovery),
        ),
        (Lifecycle::ReleasedArtifactsCompacted, None),
    ] {
        let is_compaction = lifecycle == Lifecycle::ReleasedArtifactsCompacted;
        let compaction_predecessor_missing = is_compaction
            && !matches!(
                &release,
                Some(DecodedRecordV1::Release(value))
                    if value.state == ProviderReleaseStateV1::Tombstone
            );
        let completed_status = actual_release_attempt.as_ref().is_some_and(|(_, attempt)| {
            native_completion::release_fence::native_release_status_is_completed_v1(attempt)
        });
        let release_predecessor_missing =
            release_cleanup_predecessor_missing(shape, acquisition.state, completed_status);
        let independent = release.is_none()
            || facts.outer != Outer::CleanupRequired
            || compaction_predecessor_missing
            || release_predecessor_missing;
        if let Some(DecodedRecordV1::Release(release)) = &release {
            if release.state == ProviderReleaseStateV1::Tombstone && !is_compaction {
                continue;
            }
            if matches!(
                shape,
                Some(completion::HeldReleaseMutationShape::StatusOnly
                    | completion::HeldReleaseMutationShape::OrdinaryComplete)
            ) && actual_release_attempt
                .as_ref()
                .is_some_and(|(_, attempt)| attempt.state != ProviderAttemptStateV1::Reserved)
            {
                continue;
            }
        }
        let widths = lifecycle::cleanup_key_widths(lifecycle, shape)
            .ok_or(corrupt("original Source cleanup family plan"))?;
        let mut values = Vec::new();
        for width in widths {
            let key = match *width {
                95 => release_key.clone(),
                96 => actual_release_attempt
                    .as_ref()
                    .map(|(key, _)| key.clone())
                    .unwrap_or_else(|| symbolic_key(96)),
                103 => actual_release_attempt
                    .as_ref()
                    .map(|(_, attempt)| {
                        format::session_history_key(
                            attempt.provider.authority_id(),
                            attempt.holder.authority_id(),
                            attempt.session_binding,
                        )
                    })
                    .unwrap_or_else(|| symbolic_key(103)),
                other => keys
                    .iter()
                    .find(|key| key.len() == other)
                    .cloned()
                    .ok_or(corrupt("original Source cleanup owner key family"))?,
            };
            let mut value = bound(key, owner_value_bound(*width));
            value.symbolic_key = matches!(*width, 96 | 103) && actual_release_attempt.is_none();
            if independent || value.symbolic_key {
                value.dependency = OriginalSourceBeforeDependencyV5::IndependentlyFundedCut;
            }
            values.push(value);
        }
        let mut cleanup = edge(
            OriginalSourceContinuationKindV5::Cleanup(lifecycle),
            values,
            true,
            false,
        );
        // Release admission and compaction predecessors are independently
        // funded/revalidated. This records their requirement; it creates no row.
        cleanup.independent_cut = independent;
        edges.push(cleanup);
    }
    Ok(edges)
}

// Complete cuts already passed validate_release_join. The release patch still
// requires Releasing, and receipt-only recovery must preserve completed status.
fn release_cleanup_predecessor_missing(
    shape: Option<completion::HeldReleaseMutationShape>,
    acquisition: ProviderAcquisitionStateV1,
    completed_status: bool,
) -> bool {
    use completion::HeldReleaseMutationShape as Shape;
    match shape {
        Some(Shape::OrdinaryComplete) => acquisition != ProviderAcquisitionStateV1::Releasing,
        Some(Shape::ReceiptOnlyRecovery) => {
            acquisition != ProviderAcquisitionStateV1::Releasing || !completed_status
        }
        Some(Shape::StatusOnly) | None => false,
    }
}

fn owner_value_bound(key_width: usize) -> usize {
    let bounds = format::NATIVE_ACQUIRE_COMPLETION_OWNER_RECORD_BOUNDS_V2;
    match key_width {
        96 => bounds[0] - 96 - 9,
        99 => bounds[1] - 99 - 9,
        63 => bounds[2] - 63 - 9,
        103 => bounds[3] - 103 - 9,
        49 => bounds[4] - 49 - 9,
        40 => MAXIMUM_NATIVE_HELD_RECORD_BYTES_V1,
        95 => format::maximum_release_value_bytes(),
        _ => 0,
    }
}

fn bound(key: Vec<u8>, maximum_value_bytes: usize) -> OriginalSourceContinuationValueBoundV5 {
    OriginalSourceContinuationValueBoundV5 {
        key,
        maximum_value_bytes,
        dependency: OriginalSourceBeforeDependencyV5::ActualGraph,
        symbolic_key: false,
        source_floor_relative: false,
    }
}

fn edge(
    kind: OriginalSourceContinuationKindV5,
    values: Vec<OriginalSourceContinuationValueBoundV5>,
    final_append: bool,
    mode3_terminal: bool,
) -> OriginalSourceContinuationEdgeV5 {
    OriginalSourceContinuationEdgeV5 {
        kind,
        values,
        final_append,
        mode3_terminal,
        independent_cut: false,
    }
}

fn attach_dependencies(alternative: &mut OriginalSourceContinuationAlternativeV5) {
    let mut touched = BTreeMap::new();
    for (index, edge) in alternative.edges.iter_mut().enumerate() {
        for value in &mut edge.values {
            if value.dependency != OriginalSourceBeforeDependencyV5::IndependentlyFundedCut
                && let Some(previous) = touched.get(&value.key)
            {
                value.dependency = OriginalSourceBeforeDependencyV5::PreviousOutput(*previous);
            }
            touched.insert(value.key.clone(), index);
        }
    }
}

fn push_alternative(
    alternatives: &mut Vec<OriginalSourceContinuationAlternativeV5>,
    edges: Vec<OriginalSourceContinuationEdgeV5>,
    poison: bool,
) -> Result<(), LedgerFormatErrorV1> {
    if alternatives.len() >= MAXIMUM_ALTERNATIVES || edges.len() > MAXIMUM_APPENDS {
        return Err(corrupt("original Source complete continuation bound"));
    }
    alternatives.push(OriginalSourceContinuationAlternativeV5 { edges, poison });
    Ok(())
}

fn check_logical_headroom(
    records: &Records,
    alternative: &OriginalSourceContinuationAlternativeV5,
    native_key: &[u8],
    revision: u64,
) -> Result<(), LedgerFormatErrorV1> {
    let mut writes = BTreeMap::<&[u8], u64>::new();
    let mut responses = BTreeMap::<&[u8], u64>::new();
    let mut completes = 0_u64;
    let mut inventory_updates = 0_u64;
    for edge in &alternative.edges {
        for value in &edge.values {
            if value.dependency == OriginalSourceBeforeDependencyV5::IndependentlyFundedCut {
                continue;
            }
            *writes.entry(&value.key).or_default() += 1;
            if value.key.len() == 49 {
                inventory_updates += 1;
            }
        }
        if edge.kind == OriginalSourceContinuationKindV5::Held(Step::CompletionCommitted) {
            completes += 1;
        }
        let response_edge = edge.kind
            == OriginalSourceContinuationKindV5::Held(Step::CompletionCommitted)
            || (matches!(
                edge.kind,
                OriginalSourceContinuationKindV5::Cleanup(
                    Lifecycle::ReleaseCompleted | Lifecycle::ReleaseStatusCompleted
                )
            ) && edge.values.iter().any(|value| value.key.len() == 96));
        if response_edge {
            for value in &edge.values {
                if matches!(value.key.len(), 63 | 103)
                    && value.dependency != OriginalSourceBeforeDependencyV5::IndependentlyFundedCut
                {
                    *responses.entry(&value.key).or_default() += 1;
                }
            }
        }
    }
    for (key, count) in writes {
        if key == native_key {
            checked_counter(revision, count)?;
        } else if let Some(bytes) = records.get(key) {
            match format::decode_record(key, bytes)? {
                DecodedRecordV1::Attempt(value) => checked_counter(value.revision, count)?,
                DecodedRecordV1::Acquisition(value) => checked_counter(value.revision, count)?,
                DecodedRecordV1::Session(value) | DecodedRecordV1::SessionHistory(value) => {
                    checked_counter(value.revision, count)?;
                    checked_counter(
                        value.next_response_sequence,
                        responses.get(key).copied().unwrap_or(0),
                    )?;
                }
                DecodedRecordV1::Authority(value) => {
                    checked_counter(value.revision, count)?;
                    checked_counter(value.inventory_generation, inventory_updates)?;
                    checked_counter(value.last_lease_issue_generation, completes)?;
                }
                DecodedRecordV1::Release(value) => checked_counter(value.revision, count)?,
                _ => return Err(corrupt("original Source forecast counter family")),
            }
        }
    }
    Ok(())
}

fn checked_counter(value: u64, additions: u64) -> Result<(), LedgerFormatErrorV1> {
    if value.checked_add(additions).is_none() {
        return Err(corrupt("original Source forecast logical counter exhausted"));
    }
    Ok(())
}

fn cold_phase(index: usize) -> Result<ColdPhase, LedgerFormatErrorV1> {
    match index {
        0 => Ok(ColdPhase::ClosedPrepared),
        1 => Ok(ColdPhase::ClosureStored),
        2 => Ok(ColdPhase::RootAcknowledged),
        _ => Err(corrupt("original Source cold phase bound")),
    }
}

fn symbolic_key(width: usize) -> Vec<u8> {
    // Width-only labels never leave accounting as canonical owner keys.
    let mut key = vec![0; width];
    key[0] = 0xff;
    key[1] = width as u8;
    key
}

fn views(records: &Records) -> impl Iterator<Item = (&[u8], &[u8])> {
    records
        .iter()
        .map(|(key, value)| (key.as_slice(), value.as_slice()))
}

#[cfg(test)]
#[path = "continuation/tests.rs"]
mod tests;
