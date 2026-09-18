//! Bounded, offline AOSSPL version-2 to version-3 migration planning.
//!
//! This module never opens a journal and never authorizes a write. A normal
//! version-3 open rejects version 2. The planner first validates the canonical
//! version-2 envelopes and their complete sorted graph commitment,
//! then requires an externally authenticated supplemental projection for every
//! identity, sequence, trust-history, and floor fact that version 2 did not
//! retain. Only a complete canonical version-3 replacement graph is returned.
//!
//! ```text
//! source:      canonical AOSSPL01/version=2 records (read-only)
//! provenance:  source graph digest + exact source expectations + v3 records
//! result:      nonauthorizing expected-old/replacement plan
//! ```

use std::collections::{BTreeMap, BTreeSet};

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use crate::ledger::LedgerFormatErrorV1;
use crate::limits::{MAXIMUM_LEDGER_GRAPH_BYTES, MAXIMUM_LEDGER_RECORDS};

const MAGIC: &[u8; 8] = b"AOSSPL01";
const LEGACY_VERSION: u16 = 2;
const ENVELOPE_BYTES: usize = 64;
const HEADER_BYTES: usize = 32;

const SOURCE_GRAPH_DOMAIN: &[u8] =
    b"aos.sandbox.source-provider.ledger.migration-v2-source-graph.v1\0";
const PROVENANCE_DOMAIN: &[u8] = b"aos.sandbox.source-provider.ledger.migration-v2-provenance.v1\0";

const AUTHORITY_DOMAIN: &[u8] = b"aos.sandbox.source-provider.ledger.authority-head.v1\0";
const CATALOG_DOMAIN: &[u8] = b"aos.sandbox.source-provider.ledger.catalog-head.v1\0";
const SESSION_DOMAIN: &[u8] = b"aos.sandbox.source-provider.ledger.session-head.v1\0";
const SESSION_HISTORY_DOMAIN: &[u8] = b"aos.sandbox.source-provider.ledger.session-history.v1\0";
const ATTEMPT_DOMAIN: &[u8] = b"aos.sandbox.source-provider.ledger.attempt.v1\0";
const ACQUISITION_DOMAIN: &[u8] = b"aos.sandbox.source-provider.ledger.acquisition.v1\0";
const RELEASE_DOMAIN: &[u8] = b"aos.sandbox.source-provider.ledger.release.v1\0";

const AUTHORITY_KEY_PREFIX: &[u8] = b"aos.source-provider.authority.v1\0";
const CATALOG_KEY_PREFIX: &[u8] = b"aos.source-provider.catalog.v1\0";
const SESSION_KEY_PREFIX: &[u8] = b"aos.source-provider.session.v1\0";
const SESSION_HISTORY_KEY_PREFIX: &[u8] = b"aos.source-provider.session-history.v1\0";
const ATTEMPT_KEY_PREFIX: &[u8] = b"aos.source-provider.attempt.v1\0";
const ACQUISITION_KEY_PREFIX: &[u8] = b"aos.source-provider.acquisition.v1\0";
const RELEASE_KEY_PREFIX: &[u8] = b"aos.source-provider.release.v1\0";

/// Names one exact canonical legacy record that must still be present.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyRecordExpectationV1 {
    key: Vec<u8>,
    record_digest: ObjectDigest,
}

impl LegacyRecordExpectationV1 {
    /// Creates an expectation copied from an authenticated offline snapshot.
    ///
    /// This value is nonauthorizing. The migration coordinator must separately
    /// authenticate the enclosing provenance digest before applying a plan.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerFormatErrorV1`] for an empty key or zero digest.
    pub fn new(key: Vec<u8>, record_digest: ObjectDigest) -> Result<Self, LedgerFormatErrorV1> {
        if key.is_empty() || record_digest.as_bytes() == &[0; 32] {
            return Err(LedgerFormatErrorV1::NeedsProvenance(
                "legacy record expectation",
            ));
        }
        Ok(Self { key, record_digest })
    }

    /// Borrows the exact legacy key.
    #[must_use]
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// Returns the exact legacy record digest.
    #[must_use]
    pub const fn record_digest(&self) -> ObjectDigest {
        self.record_digest
    }
}

/// Contains one exact canonical version-3 replacement record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationReplacementRecordV1 {
    key: Vec<u8>,
    value: Vec<u8>,
}

impl MigrationReplacementRecordV1 {
    /// Creates a candidate replacement record for pure validation.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerFormatErrorV1`] for an empty key or value. Canonical and
    /// whole-graph checks occur when the migration plan is built.
    pub fn new(key: Vec<u8>, value: Vec<u8>) -> Result<Self, LedgerFormatErrorV1> {
        if key.is_empty() || value.is_empty() {
            return Err(LedgerFormatErrorV1::NeedsProvenance(
                "empty migration replacement record",
            ));
        }
        Ok(Self { key, value })
    }

    /// Borrows the canonical version-3 key.
    #[must_use]
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// Borrows the canonical version-3 record bytes.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

/// Carries externally authenticated facts absent from AOSSPL version 2.
///
/// The opaque provenance digest must be authenticated by protected security
/// custody. This pure type verifies only that the digest commits the complete
/// source expectations and replacement bytes; it grants no apply authority.
pub struct SupplementalV2MigrationProvenanceV1 {
    source_graph_digest: ObjectDigest,
    authenticated_provenance_digest: ObjectDigest,
    source_expectations: Vec<LegacyRecordExpectationV1>,
    replacement_records: Vec<MigrationReplacementRecordV1>,
}

impl SupplementalV2MigrationProvenanceV1 {
    /// Creates a complete supplemental migration projection.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerFormatErrorV1`] when bounds are exceeded, the digest is
    /// zero, source expectations are duplicated, or the provenance commitment
    /// does not cover every supplied byte exactly.
    pub fn from_authenticated_projection(
        source_graph_digest: ObjectDigest,
        authenticated_provenance_digest: ObjectDigest,
        mut source_expectations: Vec<LegacyRecordExpectationV1>,
        mut replacement_records: Vec<MigrationReplacementRecordV1>,
    ) -> Result<Self, LedgerFormatErrorV1> {
        source_expectations.sort_by(|left, right| left.key.cmp(&right.key));
        replacement_records.sort_by(|left, right| left.key.cmp(&right.key));
        validate_projection_bounds(&source_expectations, &replacement_records)?;
        let calculated = provenance_digest(
            source_graph_digest,
            &source_expectations,
            &replacement_records,
        )?;
        if source_graph_digest.as_bytes() == &[0; 32]
            || authenticated_provenance_digest.as_bytes() == &[0; 32]
            || calculated != authenticated_provenance_digest
        {
            return Err(LedgerFormatErrorV1::NeedsProvenance(
                "unauthenticated supplemental provenance commitment",
            ));
        }
        Ok(Self {
            source_graph_digest,
            authenticated_provenance_digest,
            source_expectations,
            replacement_records,
        })
    }

    /// Calculates the exact digest that protected custody must authenticate.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerFormatErrorV1`] when the supplied projection exceeds
    /// migration count or aggregate-byte ceilings.
    pub fn calculate_provenance_digest(
        source_graph_digest: ObjectDigest,
        source_expectations: &[LegacyRecordExpectationV1],
        replacement_records: &[MigrationReplacementRecordV1],
    ) -> Result<ObjectDigest, LedgerFormatErrorV1> {
        validate_projection_bounds(source_expectations, replacement_records)?;
        provenance_digest(
            source_graph_digest,
            source_expectations,
            replacement_records,
        )
    }
}

/// Describes a bounded, nonauthorizing offline migration result.
pub enum AossplV2ToV3MigrationPlanV1 {
    /// Requires the normal protected empty-namespace version-3 bootstrap.
    EmptyNamespace,
    /// Replaces one complete legacy snapshot after all missing facts are supplied.
    Replace {
        /// Commits the complete sorted version-2 source graph.
        source_graph_digest: ObjectDigest,
        /// Names the exact supplemental projection authenticated by custody.
        provenance_digest: ObjectDigest,
        /// Lists every exact old record that must remain unchanged before apply.
        expected_old_records: Vec<LegacyRecordExpectationV1>,
        /// Lists the old authority and catalog heads requiring explicit CAS.
        expected_old_heads: Vec<LegacyRecordExpectationV1>,
        /// Contains the complete canonical version-3 replacement graph.
        replacement_records: Vec<MigrationReplacementRecordV1>,
        /// Commits the validated complete replacement graph.
        prospective_graph_digest: ObjectDigest,
    },
}

/// Builds a bounded offline version-2 to version-3 replacement plan.
///
/// Empty input deterministically routes to protected version-3 bootstrap.
/// Nonempty input requires supplemental provenance covering every canonical
/// legacy record and a complete version-3 graph. The returned plan does not
/// authorize journal mutation; a protected coordinator must revalidate the old
/// snapshot, authenticate provenance, and apply the replacement atomically.
///
/// # Errors
///
/// Returns [`LedgerFormatErrorV1`] for hostile input, ambiguous legacy heads,
/// incomplete or mismatched provenance, or an invalid version-3 graph.
pub fn plan_aosspl_v2_to_v3<'record>(
    records: impl IntoIterator<Item = (&'record [u8], &'record [u8])>,
    provenance: Option<SupplementalV2MigrationProvenanceV1>,
) -> Result<AossplV2ToV3MigrationPlanV1, LedgerFormatErrorV1> {
    let source = collect_legacy_records(records)?;
    if source.is_empty() {
        if provenance.is_some() {
            return Err(LedgerFormatErrorV1::NeedsProvenance(
                "empty namespace must use deterministic bootstrap",
            ));
        }
        return Ok(AossplV2ToV3MigrationPlanV1::EmptyNamespace);
    }

    let decoded = validate_legacy_graph(&source)?;
    let legacy_provider_id = decoded
        .first()
        .map(|record| record.provider_id)
        .ok_or(LedgerFormatErrorV1::Corrupt("empty legacy migration graph"))?;
    let source_graph_digest = legacy_graph_digest(&source)?;
    let provenance = provenance.ok_or(LedgerFormatErrorV1::NeedsProvenance(
        "nonempty AOSSPL v2 graph",
    ))?;
    if provenance.source_graph_digest != source_graph_digest {
        return Err(LedgerFormatErrorV1::NeedsProvenance(
            "supplemental provenance names another source graph",
        ));
    }

    let expected = provenance
        .source_expectations
        .iter()
        .map(|value| (value.key.clone(), value.record_digest))
        .collect::<BTreeMap<_, _>>();
    if expected.len() != source.len()
        || source
            .iter()
            .any(|(key, value)| expected.get(key) != Some(&record_digest_unchecked(value)))
    {
        return Err(LedgerFormatErrorV1::NeedsProvenance(
            "supplemental provenance does not cover the exact legacy graph",
        ));
    }
    let replacement_by_key = provenance
        .replacement_records
        .iter()
        .map(|record| (record.key.as_slice(), record.value.as_slice()))
        .collect::<BTreeMap<_, _>>();
    if replacement_by_key.len() != source.len()
        || source
            .keys()
            .any(|key| !replacement_by_key.contains_key(key.as_slice()))
    {
        return Err(LedgerFormatErrorV1::NeedsProvenance(
            "migration replacement is not a key-bijective legacy graph",
        ));
    }
    let mut record_digest_translation = BTreeMap::<[u8; 32], [u8; 32]>::new();
    let mut replacement_digests = BTreeSet::new();
    for (key, legacy_value) in &source {
        let replacement_value =
            replacement_by_key
                .get(key.as_slice())
                .ok_or(LedgerFormatErrorV1::NeedsProvenance(
                    "missing key-bijective replacement",
                ))?;
        let legacy_digest = array::<32>(legacy_value, 32)?;
        let replacement_digest = array::<32>(replacement_value, 32)?;
        if record_digest_translation
            .insert(legacy_digest, replacement_digest)
            .is_some()
            || !replacement_digests.insert(replacement_digest)
        {
            return Err(LedgerFormatErrorV1::NeedsProvenance(
                "migration record-digest mapping is not bijective",
            ));
        }
    }
    for legacy in &decoded {
        let replacement_bytes = replacement_by_key.get(legacy.key.as_slice()).ok_or(
            LedgerFormatErrorV1::NeedsProvenance("missing key-bijective replacement"),
        )?;
        let replacement_record =
            crate::ledger::format::decode_record(&legacy.key, replacement_bytes)?;
        if !same_record_kind(legacy.kind, &replacement_record) {
            return Err(LedgerFormatErrorV1::NeedsProvenance(
                "migration replacement changes a legacy record kind",
            ));
        }
        validate_preserved_legacy_record(
            legacy,
            source
                .get(&legacy.key)
                .ok_or(LedgerFormatErrorV1::Corrupt("legacy record disappeared"))?,
            replacement_by_key.get(legacy.key.as_slice()).ok_or(
                LedgerFormatErrorV1::NeedsProvenance("missing key-bijective replacement"),
            )?,
            &record_digest_translation,
        )?;
    }

    let prospective = crate::validate_prospective_records(
        provenance
            .replacement_records
            .iter()
            .map(|record| (record.key.as_slice(), record.value.as_slice())),
    )?;
    for record in &provenance.replacement_records {
        let decoded = crate::ledger::format::decode_record(&record.key, &record.value)?;
        if crate::ledger::format::encode_decoded_record(&decoded) != record.value {
            return Err(LedgerFormatErrorV1::Corrupt(
                "noncanonical version-3 migration replacement",
            ));
        }
    }
    let replacement_provider_id = provenance.replacement_records.iter().find_map(|record| {
        match crate::ledger::format::decode_record(&record.key, &record.value).ok()? {
            crate::ledger::model::DecodedRecordV1::Authority(authority) => {
                Some(authority.provider.authority_id())
            }
            _ => None,
        }
    });
    if replacement_provider_id != Some(legacy_provider_id) {
        return Err(LedgerFormatErrorV1::NeedsProvenance(
            "replacement graph changes the stable provider identity",
        ));
    }

    let expected_old_heads = decoded
        .into_iter()
        .filter(|record| matches!(record.kind, LegacyKindV2::Authority | LegacyKindV2::Catalog))
        .map(|record| LegacyRecordExpectationV1 {
            key: record.key,
            record_digest: record.record_digest,
        })
        .collect();
    Ok(AossplV2ToV3MigrationPlanV1::Replace {
        source_graph_digest,
        provenance_digest: provenance.authenticated_provenance_digest,
        expected_old_records: provenance.source_expectations,
        expected_old_heads,
        replacement_records: provenance.replacement_records,
        prospective_graph_digest: prospective.graph_digest(),
    })
}

fn validate_preserved_legacy_record(
    legacy: &DecodedLegacyRecordV2,
    source: &[u8],
    replacement: &[u8],
    digest_translation: &BTreeMap<[u8; 32], [u8; 32]>,
) -> Result<(), LedgerFormatErrorV1> {
    if source.get(11) != replacement.get(11) || source.get(24..32) != replacement.get(24..32) {
        return Err(LedgerFormatErrorV1::NeedsProvenance(
            "migration changes legacy state or revision",
        ));
    }
    let legacy_body = source
        .get(ENVELOPE_BYTES..)
        .ok_or(LedgerFormatErrorV1::Corrupt("legacy body disappeared"))?;
    let replacement_body = replacement
        .get(ENVELOPE_BYTES..)
        .ok_or(LedgerFormatErrorV1::Corrupt("replacement body disappeared"))?;
    let preserved = match legacy.kind {
        LegacyKindV2::Authority | LegacyKindV2::Catalog => legacy_body == replacement_body,
        LegacyKindV2::Session | LegacyKindV2::SessionHistory => {
            legacy_body.get(..1_064) == replacement_body.get(..1_064)
                && legacy_body.get(1_064..1_080) == replacement_body.get(1_080..1_096)
                && legacy_body.get(1_080..) == replacement_body.get(1_096..)
        }
        LegacyKindV2::Attempt => {
            legacy_body.get(..352) == replacement_body.get(..352)
                && legacy_body.get(352..) == replacement_body.get(360..)
        }
        LegacyKindV2::Acquisition => {
            legacy_body.get(..144) == replacement_body.get(..144)
                && legacy_body.get(144..) == replacement_body.get(152..)
        }
        LegacyKindV2::Release => {
            let legacy_acquisition_digest = array::<32>(legacy_body, 416)?;
            let replacement_acquisition_digest = array::<32>(replacement_body, 424)?;
            legacy_body.get(..144) == replacement_body.get(..144)
                && legacy_body.get(144..416) == replacement_body.get(152..424)
                && legacy_body.get(448..) == replacement_body.get(456..)
                && digest_translation.get(&legacy_acquisition_digest)
                    == Some(&replacement_acquisition_digest)
        }
    };
    if !preserved {
        return Err(LedgerFormatErrorV1::NeedsProvenance(
            "migration changes a legacy authoritative field",
        ));
    }
    Ok(())
}

fn same_record_kind(
    legacy: LegacyKindV2,
    replacement: &crate::ledger::model::DecodedRecordV1,
) -> bool {
    matches!(
        (legacy, replacement),
        (
            LegacyKindV2::Authority,
            crate::ledger::model::DecodedRecordV1::Authority(_)
        ) | (
            LegacyKindV2::Catalog,
            crate::ledger::model::DecodedRecordV1::Catalog(_)
        ) | (
            LegacyKindV2::Session,
            crate::ledger::model::DecodedRecordV1::Session(_)
        ) | (
            LegacyKindV2::SessionHistory,
            crate::ledger::model::DecodedRecordV1::SessionHistory(_)
        ) | (
            LegacyKindV2::Attempt,
            crate::ledger::model::DecodedRecordV1::Attempt(_)
        ) | (
            LegacyKindV2::Acquisition,
            crate::ledger::model::DecodedRecordV1::Acquisition(_)
        ) | (
            LegacyKindV2::Release,
            crate::ledger::model::DecodedRecordV1::Release(_)
        )
    )
}

#[derive(Clone, Copy)]
enum LegacyKindV2 {
    Authority,
    Catalog,
    Session,
    Attempt,
    Acquisition,
    Release,
    SessionHistory,
}

struct DecodedLegacyRecordV2 {
    key: Vec<u8>,
    kind: LegacyKindV2,
    provider_id: [u8; 16],
    record_digest: ObjectDigest,
    authority_catalog: Option<(u64, ObjectDigest)>,
    catalog: Option<LegacyCatalogLinkV2>,
}

#[derive(Clone, Copy)]
struct LegacyCatalogLinkV2 {
    generation: u64,
    digest: ObjectDigest,
    predecessor_generation: u64,
    predecessor_digest: ObjectDigest,
    floor_generation: u64,
    floor_digest: ObjectDigest,
}

fn collect_legacy_records<'record>(
    records: impl IntoIterator<Item = (&'record [u8], &'record [u8])>,
) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, LedgerFormatErrorV1> {
    crate::collect_bounded_records(records)
}

fn validate_legacy_graph(
    records: &BTreeMap<Vec<u8>, Vec<u8>>,
) -> Result<Vec<DecodedLegacyRecordV2>, LedgerFormatErrorV1> {
    let mut decoded = Vec::with_capacity(records.len());
    let mut authority_count = 0_usize;
    let mut catalog_count = 0_usize;
    let mut provider_id = None;
    for (key, value) in records {
        let record = decode_legacy_record(key, value)?;
        authority_count += usize::from(matches!(record.kind, LegacyKindV2::Authority));
        catalog_count += usize::from(matches!(record.kind, LegacyKindV2::Catalog));
        if provider_id.is_some_and(|expected| expected != record.provider_id) {
            return Err(LedgerFormatErrorV1::Corrupt(
                "legacy graph contains another provider",
            ));
        }
        provider_id = Some(record.provider_id);
        decoded.push(record);
    }
    if authority_count != 1 || catalog_count == 0 {
        return Err(LedgerFormatErrorV1::Corrupt(
            "legacy graph authority or catalog heads are ambiguous",
        ));
    }
    validate_legacy_catalog_chain(&decoded)?;
    Ok(decoded)
}

fn decode_legacy_record(
    key: &[u8],
    value: &[u8],
) -> Result<DecodedLegacyRecordV2, LedgerFormatErrorV1> {
    if value.len() < ENVELOPE_BYTES || value.get(..8) != Some(MAGIC.as_slice()) {
        return Err(LedgerFormatErrorV1::Corrupt("legacy record header"));
    }
    if u16::from_be_bytes(array(value, 8)?) != LEGACY_VERSION
        || value.get(12..16) != Some([0_u8; 4].as_slice())
        || value.get(20..24) != Some([0_u8; 4].as_slice())
        || u64::from_be_bytes(array(value, 24)?) == 0
    {
        return Err(LedgerFormatErrorV1::Corrupt("legacy record header"));
    }
    let body_len = u32::from_be_bytes(array(value, 16)?) as usize;
    if ENVELOPE_BYTES.checked_add(body_len) != Some(value.len()) {
        return Err(LedgerFormatErrorV1::Corrupt("legacy record length"));
    }
    let (kind, domain, prefix, key_len, states) = legacy_kind(value[10])?;
    let provider_id = validate_legacy_key(key, prefix, key_len, kind)?;
    if !states.contains(&value[11]) {
        return Err(LedgerFormatErrorV1::Corrupt("legacy record state"));
    }
    validate_legacy_body_shape(kind, &value[ENVELOPE_BYTES..])?;
    let body = &value[ENVELOPE_BYTES..];
    validate_legacy_body_identity(kind, key, prefix.len(), provider_id, body)?;

    let record_digest = ObjectDigest::from_bytes(array(value, 32)?);
    let expected =
        calculate_legacy_record_digest(domain, key, &value[..HEADER_BYTES], &value[64..])?;
    if record_digest != expected {
        return Err(LedgerFormatErrorV1::Corrupt(
            "legacy record digest mismatch",
        ));
    }
    Ok(DecodedLegacyRecordV2 {
        key: key.to_vec(),
        kind,
        provider_id,
        record_digest,
        authority_catalog: if matches!(kind, LegacyKindV2::Authority) {
            Some((
                u64::from_be_bytes(array(body, 488)?),
                ObjectDigest::from_bytes(array(body, 496)?),
            ))
        } else {
            None
        },
        catalog: if matches!(kind, LegacyKindV2::Catalog) {
            Some(LegacyCatalogLinkV2 {
                generation: u64::from_be_bytes(array(body, 88)?),
                digest: ObjectDigest::from_bytes(array(body, 96)?),
                predecessor_generation: u64::from_be_bytes(array(body, 184)?),
                predecessor_digest: ObjectDigest::from_bytes(array(body, 192)?),
                floor_generation: u64::from_be_bytes(array(body, 224)?),
                floor_digest: ObjectDigest::from_bytes(array(body, 232)?),
            })
        } else {
            None
        },
    })
}

type LegacyKindShape = (
    LegacyKindV2,
    &'static [u8],
    &'static [u8],
    usize,
    &'static [u8],
);

fn legacy_kind(value: u8) -> Result<LegacyKindShape, LedgerFormatErrorV1> {
    match value {
        1 => Ok((
            LegacyKindV2::Authority,
            AUTHORITY_DOMAIN,
            AUTHORITY_KEY_PREFIX,
            49,
            &[1, 2, 3],
        )),
        2 => Ok((
            LegacyKindV2::Catalog,
            CATALOG_DOMAIN,
            CATALOG_KEY_PREFIX,
            55,
            &[0],
        )),
        3 => Ok((
            LegacyKindV2::Session,
            SESSION_DOMAIN,
            SESSION_KEY_PREFIX,
            63,
            &[0],
        )),
        4 => Ok((
            LegacyKindV2::Attempt,
            ATTEMPT_DOMAIN,
            ATTEMPT_KEY_PREFIX,
            96,
            &[1, 2, 3],
        )),
        5 => Ok((
            LegacyKindV2::Acquisition,
            ACQUISITION_DOMAIN,
            ACQUISITION_KEY_PREFIX,
            99,
            &[1, 2, 3, 4, 5, 6],
        )),
        6 => Ok((
            LegacyKindV2::Release,
            RELEASE_DOMAIN,
            RELEASE_KEY_PREFIX,
            95,
            &[1, 2],
        )),
        7 => Ok((
            LegacyKindV2::SessionHistory,
            SESSION_HISTORY_DOMAIN,
            SESSION_HISTORY_KEY_PREFIX,
            103,
            &[0],
        )),
        _ => Err(LedgerFormatErrorV1::Corrupt("legacy record kind")),
    }
}

fn validate_legacy_body_shape(kind: LegacyKindV2, body: &[u8]) -> Result<(), LedgerFormatErrorV1> {
    let expected = match kind {
        LegacyKindV2::Authority => Some(632),
        LegacyKindV2::Catalog => {
            let publication_len = bounded_u32_at(body, 472, 520, "legacy catalog publication")?;
            476_usize.checked_add(publication_len)
        }
        LegacyKindV2::Session | LegacyKindV2::SessionHistory => {
            let root_len = bounded_u32_at(body, 1_208, 4_096, "legacy Root Mount hello")?;
            let provider_len = bounded_u32_at(body, 1_212, 4_096, "legacy provider hello")?;
            1_216_usize
                .checked_add(root_len)
                .and_then(|total| total.checked_add(provider_len))
        }
        LegacyKindV2::Attempt => {
            let request_len = bounded_u32_at(body, 840, 1_048_576, "legacy signed request")?;
            let response_len = bounded_u32_at(body, 844, 1_048_576, "legacy response")?;
            require_zeros(body, 848, 96)?;
            944_usize
                .checked_add(request_len)
                .and_then(|total| total.checked_add(response_len))
        }
        LegacyKindV2::Acquisition => {
            let intent_len = bounded_u32_at(
                body,
                760,
                crate::MAXIMUM_NORMALIZED_ACQUISITION_INTENT_BYTES,
                "legacy normalized intent",
            )?;
            let evidence_len = bounded_u32_at(body, 764, 65_656, "legacy backend evidence")?;
            let reopen_len = bounded_u32_at(body, 768, 256, "legacy reopen identity")?;
            let lease_len = bounded_u32_at(body, 772, 262_144, "legacy signed lease")?;
            let lease_history = bounded_u32_at(body, 776, 1_024, "legacy lease history")?;
            require_zeros(body, 780, 4)?;
            let lease_history_bytes =
                lease_history
                    .checked_mul(88)
                    .ok_or(LedgerFormatErrorV1::LimitExceeded(
                        "legacy lease history bytes",
                    ))?;
            784_usize
                .checked_add(lease_history_bytes)
                .and_then(|total| total.checked_add(intent_len))
                .and_then(|total| total.checked_add(evidence_len))
                .and_then(|total| total.checked_add(reopen_len))
                .and_then(|total| total.checked_add(lease_len))
        }
        LegacyKindV2::Release => {
            let evidence_len = bounded_u32_at(body, 448, 65_656, "legacy release evidence")?;
            let receipt_len = bounded_u32_at(body, 452, 65_536, "legacy release receipt")?;
            456_usize
                .checked_add(evidence_len)
                .and_then(|total| total.checked_add(receipt_len))
        }
    }
    .ok_or(LedgerFormatErrorV1::LimitExceeded(
        "legacy record body length",
    ))?;
    if body.len() != expected {
        return Err(LedgerFormatErrorV1::Corrupt("legacy record body shape"));
    }
    Ok(())
}

fn bounded_u32_at(
    body: &[u8],
    offset: usize,
    maximum: usize,
    name: &'static str,
) -> Result<usize, LedgerFormatErrorV1> {
    let value = usize::try_from(u32::from_be_bytes(array(body, offset)?))
        .map_err(|_| LedgerFormatErrorV1::LimitExceeded(name))?;
    if value > maximum {
        return Err(LedgerFormatErrorV1::LimitExceeded(name));
    }
    Ok(value)
}

fn require_zeros(body: &[u8], offset: usize, length: usize) -> Result<(), LedgerFormatErrorV1> {
    if body
        .get(offset..offset + length)
        .is_none_or(|bytes| bytes.iter().any(|byte| *byte != 0))
    {
        return Err(LedgerFormatErrorV1::Corrupt("legacy record reserved bytes"));
    }
    Ok(())
}

fn validate_legacy_body_identity(
    kind: LegacyKindV2,
    key: &[u8],
    prefix_len: usize,
    provider_id: [u8; 16],
    body: &[u8],
) -> Result<(), LedgerFormatErrorV1> {
    if array::<16>(body, 0)? != provider_id {
        return Err(LedgerFormatErrorV1::Corrupt(
            "legacy provider key/body identity",
        ));
    }
    let identity_matches = match kind {
        LegacyKindV2::Authority => true,
        LegacyKindV2::Catalog => key.get(prefix_len + 16..prefix_len + 24) == body.get(88..96),
        LegacyKindV2::Session => key.get(prefix_len + 16..prefix_len + 32) == body.get(56..72),
        LegacyKindV2::SessionHistory => {
            key.get(prefix_len + 16..prefix_len + 32) == body.get(56..72)
                && key.get(prefix_len + 32..prefix_len + 64) == body.get(120..152)
        }
        LegacyKindV2::Attempt => {
            key.get(prefix_len + 16..prefix_len + 32) == body.get(56..72)
                && key.get(prefix_len + 32..prefix_len + 48) == body.get(168..184)
                && key.get(prefix_len + 48) == body.get(232)
                && key.get(prefix_len + 49..prefix_len + 65) == body.get(240..256)
        }
        LegacyKindV2::Acquisition | LegacyKindV2::Release => {
            key.get(prefix_len + 16..prefix_len + 32) == body.get(56..72)
                && key.get(prefix_len + 32..prefix_len + 64) == body.get(112..144)
        }
    };
    if !identity_matches {
        return Err(LedgerFormatErrorV1::Corrupt(
            "legacy record key/body identity",
        ));
    }
    Ok(())
}

fn validate_legacy_catalog_chain(
    records: &[DecodedLegacyRecordV2],
) -> Result<(), LedgerFormatErrorV1> {
    let catalogs = records
        .iter()
        .filter_map(|record| record.catalog)
        .map(|catalog| (catalog.generation, catalog))
        .collect::<BTreeMap<_, _>>();
    let (current_generation, current_digest) = records
        .iter()
        .find_map(|record| record.authority_catalog)
        .ok_or(LedgerFormatErrorV1::Corrupt(
            "legacy authority catalog head absent",
        ))?;
    let current = catalogs
        .get(&current_generation)
        .copied()
        .filter(|catalog| catalog.digest == current_digest)
        .ok_or(LedgerFormatErrorV1::Corrupt(
            "legacy authority catalog head mismatch",
        ))?;
    if current.floor_generation == 0
        || current.floor_generation > current.generation
        || current.floor_digest.as_bytes() == &[0; 32]
    {
        return Err(LedgerFormatErrorV1::Corrupt(
            "legacy catalog floor identity",
        ));
    }

    let mut generation = current.generation;
    let mut digest = current.digest;
    let mut reachable = BTreeSet::new();
    loop {
        if !reachable.insert(generation) {
            return Err(LedgerFormatErrorV1::Corrupt(
                "legacy catalog predecessor cycle",
            ));
        }
        let link = catalogs
            .get(&generation)
            .ok_or(LedgerFormatErrorV1::Corrupt(
                "legacy catalog predecessor absent",
            ))?;
        if link.digest != digest {
            return Err(LedgerFormatErrorV1::Corrupt(
                "legacy catalog chain commitment",
            ));
        }
        if generation == current.floor_generation {
            if digest != current.floor_digest {
                return Err(LedgerFormatErrorV1::Corrupt("legacy catalog floor digest"));
            }
            break;
        }
        if link.predecessor_generation < current.floor_generation
            || link.predecessor_generation >= generation
            || link.predecessor_digest.as_bytes() == &[0; 32]
        {
            return Err(LedgerFormatErrorV1::Corrupt(
                "legacy catalog predecessor link",
            ));
        }
        generation = link.predecessor_generation;
        digest = link.predecessor_digest;
    }
    if catalogs
        .keys()
        .any(|candidate| *candidate >= current.floor_generation && !reachable.contains(candidate))
    {
        return Err(LedgerFormatErrorV1::Corrupt(
            "legacy catalog branch or unreachable generation",
        ));
    }
    Ok(())
}

fn validate_legacy_key(
    key: &[u8],
    prefix: &[u8],
    expected_len: usize,
    kind: LegacyKindV2,
) -> Result<[u8; 16], LedgerFormatErrorV1> {
    if key.len() != expected_len || !key.starts_with(prefix) {
        return Err(LedgerFormatErrorV1::Corrupt("legacy record key"));
    }
    let provider_id = array(key, prefix.len())?;
    if provider_id == [0; 16]
        || matches!(kind, LegacyKindV2::Catalog)
            && u64::from_be_bytes(array(key, prefix.len() + 16)?) == 0
    {
        return Err(LedgerFormatErrorV1::Corrupt("legacy record key identity"));
    }
    Ok(provider_id)
}

fn calculate_legacy_record_digest(
    domain: &[u8],
    key: &[u8],
    header: &[u8],
    body: &[u8],
) -> Result<ObjectDigest, LedgerFormatErrorV1> {
    let key_len = u32::try_from(key.len())
        .map_err(|_| LedgerFormatErrorV1::LimitExceeded("legacy key length"))?;
    let committed_len = HEADER_BYTES
        .checked_add(body.len())
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(LedgerFormatErrorV1::LimitExceeded("legacy record length"))?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(key_len.to_be_bytes());
    hasher.update(key);
    hasher.update(committed_len.to_be_bytes());
    hasher.update(header);
    hasher.update(body);
    Ok(ObjectDigest::from_bytes(hasher.finalize().into()))
}

fn legacy_graph_digest(
    records: &BTreeMap<Vec<u8>, Vec<u8>>,
) -> Result<ObjectDigest, LedgerFormatErrorV1> {
    let mut hasher = Sha256::new();
    hasher.update(SOURCE_GRAPH_DOMAIN);
    update_record_set_digest(
        &mut hasher,
        records
            .iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice())),
    )?;
    Ok(ObjectDigest::from_bytes(hasher.finalize().into()))
}

fn provenance_digest(
    source_graph_digest: ObjectDigest,
    expectations: &[LegacyRecordExpectationV1],
    replacements: &[MigrationReplacementRecordV1],
) -> Result<ObjectDigest, LedgerFormatErrorV1> {
    let mut expected = expectations.iter().collect::<Vec<_>>();
    expected.sort_by(|left, right| left.key.cmp(&right.key));
    if expected
        .windows(2)
        .any(|window| window[0].key == window[1].key)
    {
        return Err(LedgerFormatErrorV1::NeedsProvenance(
            "duplicate legacy provenance expectation",
        ));
    }
    let mut replacement = replacements.iter().collect::<Vec<_>>();
    replacement.sort_by(|left, right| left.key.cmp(&right.key));
    if replacement
        .windows(2)
        .any(|window| window[0].key == window[1].key)
    {
        return Err(LedgerFormatErrorV1::NeedsProvenance(
            "duplicate migration replacement key",
        ));
    }

    let mut hasher = Sha256::new();
    hasher.update(PROVENANCE_DOMAIN);
    hasher.update(source_graph_digest.as_bytes());
    hasher.update(u32_len(expected.len(), "legacy expectation count")?.to_be_bytes());
    for value in expected {
        update_bytes(&mut hasher, &value.key, "legacy expectation key")?;
        hasher.update(value.record_digest.as_bytes());
    }
    hasher.update(u32_len(replacement.len(), "replacement count")?.to_be_bytes());
    for value in replacement {
        update_bytes(&mut hasher, &value.key, "replacement key")?;
        update_bytes(&mut hasher, &value.value, "replacement record")?;
    }
    Ok(ObjectDigest::from_bytes(hasher.finalize().into()))
}

fn validate_projection_bounds(
    expectations: &[LegacyRecordExpectationV1],
    replacements: &[MigrationReplacementRecordV1],
) -> Result<(), LedgerFormatErrorV1> {
    if expectations.len() > MAXIMUM_LEDGER_RECORDS || replacements.len() > MAXIMUM_LEDGER_RECORDS {
        return Err(LedgerFormatErrorV1::LimitExceeded(
            "migration projection record count",
        ));
    }
    let mut aggregate = 0_usize;
    for value in expectations {
        aggregate = aggregate
            .checked_add(value.key.len())
            .and_then(|total| total.checked_add(32))
            .ok_or(LedgerFormatErrorV1::LimitExceeded(
                "migration projection bytes",
            ))?;
    }
    for value in replacements {
        aggregate = aggregate
            .checked_add(value.key.len())
            .and_then(|total| total.checked_add(value.value.len()))
            .ok_or(LedgerFormatErrorV1::LimitExceeded(
                "migration projection bytes",
            ))?;
    }
    if aggregate > MAXIMUM_LEDGER_GRAPH_BYTES {
        return Err(LedgerFormatErrorV1::LimitExceeded(
            "migration projection aggregate bytes",
        ));
    }
    Ok(())
}

fn update_record_set_digest<'record>(
    hasher: &mut Sha256,
    records: impl IntoIterator<Item = (&'record [u8], &'record [u8])>,
) -> Result<(), LedgerFormatErrorV1> {
    for (key, value) in records {
        update_bytes(hasher, key, "migration graph key")?;
        update_bytes(hasher, value, "migration graph record")?;
    }
    Ok(())
}

fn update_bytes(
    hasher: &mut Sha256,
    value: &[u8],
    limit_name: &'static str,
) -> Result<(), LedgerFormatErrorV1> {
    hasher.update(u32_len(value.len(), limit_name)?.to_be_bytes());
    hasher.update(value);
    Ok(())
}

fn u32_len(value: usize, name: &'static str) -> Result<u32, LedgerFormatErrorV1> {
    u32::try_from(value).map_err(|_| LedgerFormatErrorV1::LimitExceeded(name))
}

fn record_digest_unchecked(value: &[u8]) -> ObjectDigest {
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(&value[32..64]);
    ObjectDigest::from_bytes(bytes)
}

fn array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], LedgerFormatErrorV1> {
    bytes
        .get(offset..offset + N)
        .and_then(|value| value.try_into().ok())
        .ok_or(LedgerFormatErrorV1::Corrupt("truncated legacy record"))
}
