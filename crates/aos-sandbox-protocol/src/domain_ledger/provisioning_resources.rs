//! Canonical historical parent, assignment and reservation comparison records.
//!
//! These three DesiredState rows name real logical resources created atomically
//! with an internal publication operation. Their decoder establishes only DATA;
//! Native activation, current bank custody, Root admission and observed workspace
//! completion remain separate requirements. No bank identity is a ResourceId.
//!
//! ```text
//! key = "provisioning/resources/v1/" || row-kind:u8 || identity:16
//! value = "AOSCPR01" || row-kind:u8 || mode:u8 || identities:96
//!         || epoch:u64be || revision:u64be || commitments:192 || sha256:32
//! row-kind = parent:1 | assignment:2 | reservation:3
//! mode = create-stopped:1 | start-running:2
//! ```

mod links;
mod receiving;
mod retirement;
pub use retirement::{
    ProvisioningCompanionRetirementDataV2, ProvisioningCompanionRetirementErrorV2,
    PROVISIONING_COMPANION_DESCRIPTOR_BYTES_V2,
};
pub use receiving::{
    provisioning_links_decoding_receiving_bytes_v1,
    provisioning_links_reached_receiving_bytes_v1,
};
pub use links::{
    ProvisioningResourceLinkErrorV1, require_provisioning_publication_gate_v1,
    validate_provisioning_resource_links_v1,
};

use std::collections::BTreeMap;

use aos_sandbox_core::{
    AssignmentEpoch, ObjectDigest, OperationId, ProjectId, RecordNamespace,
    ResourceDimension, ResourceId, ResourceVector, Revision, SandboxId,
};
use sha2::{Digest as _, Sha256};

use super::transaction::JournalRecord;

const MAGIC: &[u8; 8] = b"AOSCPR01";
const DOMAIN: &[u8] = b"aos.sandbox.provisioning-resource-record.v1\0";
const PREFIX: &[u8] = b"provisioning/resources/v1/";
/// Gives the exact width of each canonical resource row.
pub const PROVISIONING_RESOURCE_ROW_BYTES_V1: usize = 346;
const PAYLOAD_BYTES: usize = PROVISIONING_RESOURCE_ROW_BYTES_V1 - 32;
/// Gives the exact width of each canonical resource key.
pub const PROVISIONING_RESOURCE_KEY_BYTES_V1: usize = PREFIX.len() + 1 + 16;

type State = BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;

/// Distinguishes desired Create provisioning from an admitted Start publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProvisioningModeDataV1 {
    /// Keeps the accepted Create desired state STOPPED.
    CreateStopped,
    /// Refers to the separately accepted Start desired state RUNNING.
    StartRunning,
}

/// Identifies one of the three atomically related historical rows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProvisioningResourceRowKindV1 {
    /// Joins the accepted public parent to its internal gated operation.
    Parent,
    /// Names the independently allocated logical assignment resource.
    Assignment,
    /// Names the independently allocated logical reservation resource.
    Reservation,
}

/// Carries writable, nonauthorizing historical record inputs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProvisioningResourceFieldsV1 {
    /// Selects Create STOPPED or accepted Start RUNNING.
    pub mode: ProvisioningModeDataV1,
    /// Names the actual accepted public operation.
    pub parent: OperationId,
    /// Names the distinct internal ownership-gated operation.
    pub publication_operation: OperationId,
    /// Names the same protected Sandbox.
    pub sandbox: SandboxId,
    /// Names the same protected Project.
    pub project: ProjectId,
    /// Names a fresh logical resource, independent of all bank IDs.
    pub assignment: ResourceId,
    /// Names a second fresh logical resource, independent of all bank IDs.
    pub reservation: ResourceId,
    /// Retains the canonical manifest's assignment epoch.
    pub epoch: AssignmentEpoch,
    /// Orders this logical reservation's immutable initial record.
    pub reservation_revision: Revision,
    /// Commits the complete canonical accepted public request.
    pub public_request: ObjectDigest,
    /// Commits the complete canonical assignment manifest.
    pub manifest: ObjectDigest,
    /// Commits the admitted internal Source draft.
    pub source_draft: ObjectDigest,
    /// Commits the fresh independently admitted Root plan.
    pub root_plan: ObjectDigest,
    /// Commits the exact recorded inclusive Sandbox child head.
    pub child_head: ObjectDigest,
    /// Commits the exact original inclusive grant, distinct from consumptive U.
    pub inclusive_grant: ObjectDigest,
}

/// Reports malformed records or an incomplete atomic companion set.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProvisioningResourceDataErrorV1 {
    /// A width, tag, checksum, key or semantic field is invalid.
    #[error("provisioning resource record is not canonical")]
    NonCanonical,
    /// One of the three exact companion rows is absent or differs.
    #[error("provisioning resource companion rows differ")]
    Incomplete,
}

/// Retains one checked historical companion set without Native authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProvisioningResourceRecordsV1 {
    fields: ProvisioningResourceFieldsV1,
}

impl ProvisioningResourceRecordsV1 {
    /// Checks the closed historical record shape without creating resources.
    ///
    /// # Errors
    /// Rejects zero identities/commitments, equal parent/child or resource IDs,
    /// zero epoch, or a reservation revision other than its initial revision.
    pub fn from_data_v1(fields: ProvisioningResourceFieldsV1)
        -> Result<Self, ProvisioningResourceDataErrorV1>
    {
        if fields.parent.as_bytes() == &[0; 16]
            || fields.publication_operation.as_bytes() == &[0; 16]
            || fields.parent == fields.publication_operation
            || fields.sandbox.as_bytes() == &[0; 16]
            || fields.project.as_bytes() == &[0; 16]
            || fields.assignment.as_bytes() == &[0; 16]
            || fields.reservation.as_bytes() == &[0; 16]
            || fields.assignment == fields.reservation
            || fields.epoch.get() == 0
            || fields.reservation_revision.get() != 1
            || [fields.public_request, fields.manifest, fields.source_draft,
                fields.root_plan, fields.child_head, fields.inclusive_grant]
                .iter().any(|digest| digest.as_bytes() == &[0; 32])
        {
            return Err(ProvisioningResourceDataErrorV1::NonCanonical);
        }
        Ok(Self { fields })
    }

    /// Bounds the complete three-row construction peak as inert DATA.
    ///
    /// Namespace pricing counts the three actual persisted entries. Fresh
    /// entropy, native append/replay, complete decoder models and cumulative
    /// traffic remain obligations of the genuine enclosing Native interval.
    #[must_use]
    pub fn receiving_demand_v1() -> Option<ResourceVector> {
        let row = PROVISIONING_RESOURCE_ROW_BYTES_V1
            .checked_add(PROVISIONING_RESOURCE_KEY_BYTES_V1)?
            .checked_add(std::mem::size_of::<JournalRecord>())?
            .checked_add(std::mem::align_of::<JournalRecord>().checked_mul(2)?)?;
        let bytes = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(row.checked_mul(6)?)?;
        Some(ResourceVector::ZERO
            .with(ResourceDimension::MemoryBytes, u64::try_from(bytes).ok()?)
            .with(ResourceDimension::MetadataEntries, 3))
    }

    /// Returns historical comparison fields; they establish no currentness.
    #[must_use]
    pub const fn fields_v1(self) -> ProvisioningResourceFieldsV1 { self.fields }

    /// Commits the exact ordered keys and values of all three typed companions.
    ///
    /// This is comparison DATA, not resource creation or native membership.
    #[must_use]
    pub fn commitment_v1(self) -> ObjectDigest {
        let mut hash = Sha256::new();
        hash.update(b"aos.sandbox.provisioning-resource-set.v1\0");
        for kind in [ProvisioningResourceRowKindV1::Parent,
            ProvisioningResourceRowKindV1::Assignment,
            ProvisioningResourceRowKindV1::Reservation] {
            hash.update(self.key_v1(kind));
            hash.update(self.encode_v1(kind));
        }
        ObjectDigest::from_bytes(hash.finalize().into())
    }

    /// Builds the exact three companion rows for the enclosing atomic engine.
    ///
    /// This is a DATA assembler. Only the private provisioning admission route
    /// may insert these rows; calling this method grants no Journal mutation.
    #[must_use]
    pub fn records_v1(self) -> [JournalRecord; 3] {
        [ProvisioningResourceRowKindV1::Parent, ProvisioningResourceRowKindV1::Assignment,
            ProvisioningResourceRowKindV1::Reservation].map(|kind| JournalRecord::put(
                RecordNamespace::DesiredState, self.key_v1(kind).to_vec(),
                self.encode_v1(kind).to_vec(),
            ))
    }

    /// Encodes one exact row using the sole format recipe.
    #[must_use]
    pub fn encode_v1(self, kind: ProvisioningResourceRowKindV1)
        -> [u8; PROVISIONING_RESOURCE_ROW_BYTES_V1]
    {
        let mut bytes = [0; PROVISIONING_RESOURCE_ROW_BYTES_V1];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8] = kind.tag();
        bytes[9] = match self.fields.mode {
            ProvisioningModeDataV1::CreateStopped => 1,
            ProvisioningModeDataV1::StartRunning => 2,
        };
        let ids = [self.fields.parent.into_bytes(), self.fields.publication_operation.into_bytes(),
            self.fields.sandbox.into_bytes(), self.fields.project.into_bytes(),
            self.fields.assignment.into_bytes(), self.fields.reservation.into_bytes()];
        for (index, id) in ids.iter().enumerate() {
            bytes[10 + index * 16..26 + index * 16].copy_from_slice(id);
        }
        bytes[106..114].copy_from_slice(&self.fields.epoch.get().to_be_bytes());
        bytes[114..122].copy_from_slice(&self.fields.reservation_revision.get().to_be_bytes());
        let digests = [self.fields.public_request, self.fields.manifest, self.fields.source_draft,
            self.fields.root_plan, self.fields.child_head, self.fields.inclusive_grant];
        for (index, digest) in digests.iter().enumerate() {
            bytes[122 + index * 32..154 + index * 32].copy_from_slice(digest.as_bytes());
        }
        let checksum = checksum(&bytes[..PAYLOAD_BYTES]);
        bytes[PAYLOAD_BYTES..].copy_from_slice(&checksum);
        bytes
    }

    /// Returns the exact fixed key without allocating.
    #[must_use]
    pub fn key_v1(self, kind: ProvisioningResourceRowKindV1)
        -> [u8; PROVISIONING_RESOURCE_KEY_BYTES_V1]
    {
        resource_key(kind, match kind {
            ProvisioningResourceRowKindV1::Parent => self.fields.parent.as_bytes(),
            ProvisioningResourceRowKindV1::Assignment => self.fields.assignment.as_bytes(),
            ProvisioningResourceRowKindV1::Reservation => self.fields.reservation.as_bytes(),
        })
    }

    /// Compares every companion row against the same captured historical map.
    ///
    /// # Errors
    /// Rejects any absent or byte-different companion. This checks no native
    /// names, current lease, activation, financial owner or workspace outcome.
    pub fn require_companions_v1(self, state: &State)
        -> Result<(), ProvisioningResourceDataErrorV1>
    {
        for (kind, id) in [
            (ProvisioningResourceRowKindV1::Reservation, self.fields.assignment),
            (ProvisioningResourceRowKindV1::Assignment, self.fields.reservation),
        ] {
            if state.contains_key(&(RecordNamespace::DesiredState, resource_key(kind, id.as_bytes()).to_vec())) {
                return Err(ProvisioningResourceDataErrorV1::NonCanonical);
            }
        }
        for kind in [ProvisioningResourceRowKindV1::Parent,
            ProvisioningResourceRowKindV1::Assignment, ProvisioningResourceRowKindV1::Reservation]
        {
            if state.get(&(RecordNamespace::DesiredState, self.key_v1(kind).to_vec()))
                .is_none_or(|value| value.as_slice() != self.encode_v1(kind))
            {
                return Err(ProvisioningResourceDataErrorV1::Incomplete);
            }
        }
        Ok(())
    }

    /// Returns the checksum of the actual reservation row as comparison DATA.
    #[must_use]
    pub fn reservation_state_digest_v1(self) -> ObjectDigest {
        ObjectDigest::from_bytes(checksum(&self.encode_v1(ProvisioningResourceRowKindV1::Reservation)))
    }
}

impl ProvisioningResourceRowKindV1 {
    const fn tag(self) -> u8 {
        match self { Self::Parent => 1, Self::Assignment => 2, Self::Reservation => 3 }
    }
}

/// Decodes a recognized provisioning row without allocation.
///
/// `None` means another DesiredState family. A recognized prefix with malformed
/// suffix or value fails closed; it cannot be hidden as an unknown family.
///
/// # Errors
/// Rejects invalid widths, tags, checksum, semantic fields or key/value identity.
pub fn decode_provisioning_resource_row_v1(key: &[u8], value: &[u8])
    -> Result<Option<(ProvisioningResourceRowKindV1, ProvisioningResourceRecordsV1)>,
        ProvisioningResourceDataErrorV1>
{
    if !key.starts_with(PREFIX) { return Ok(None); }
    if key.len() != PROVISIONING_RESOURCE_KEY_BYTES_V1 {
        return Err(ProvisioningResourceDataErrorV1::NonCanonical);
    }
    let (kind, records) = decode_original_value_v1(value)?;
    if key != records.key_v1(kind) {
        return Err(ProvisioningResourceDataErrorV1::NonCanonical);
    }
    Ok(Some((kind, records)))
}

// The descriptor and keyed row both use this same complete original decoder.
// It owns the value offsets; no companion child duplicates that format.
fn decode_original_value_v1(value: &[u8])
    -> Result<(ProvisioningResourceRowKindV1, ProvisioningResourceRecordsV1),
        ProvisioningResourceDataErrorV1>
{
    if value.len() != PROVISIONING_RESOURCE_ROW_BYTES_V1
        || &value[..8] != MAGIC
        || value[PAYLOAD_BYTES..] != checksum(&value[..PAYLOAD_BYTES])
    {
        return Err(ProvisioningResourceDataErrorV1::NonCanonical);
    }
    let kind = match value[8] {
        1 => ProvisioningResourceRowKindV1::Parent,
        2 => ProvisioningResourceRowKindV1::Assignment,
        3 => ProvisioningResourceRowKindV1::Reservation,
        _ => return Err(ProvisioningResourceDataErrorV1::NonCanonical),
    };
    let mode = match value[9] {
        1 => ProvisioningModeDataV1::CreateStopped,
        2 => ProvisioningModeDataV1::StartRunning,
        _ => return Err(ProvisioningResourceDataErrorV1::NonCanonical),
    };
    let records = ProvisioningResourceRecordsV1::from_data_v1(ProvisioningResourceFieldsV1 {
        mode,
        parent: OperationId::from_bytes(fixed(&value[10..26])?),
        publication_operation: OperationId::from_bytes(fixed(&value[26..42])?),
        sandbox: SandboxId::from_bytes(fixed(&value[42..58])?),
        project: ProjectId::from_bytes(fixed(&value[58..74])?),
        assignment: ResourceId::from_bytes(fixed(&value[74..90])?),
        reservation: ResourceId::from_bytes(fixed(&value[90..106])?),
        epoch: AssignmentEpoch::new(u64::from_be_bytes(fixed(&value[106..114])?)),
        reservation_revision: Revision::new(u64::from_be_bytes(fixed(&value[114..122])?)),
        public_request: ObjectDigest::from_bytes(fixed(&value[122..154])?),
        manifest: ObjectDigest::from_bytes(fixed(&value[154..186])?),
        source_draft: ObjectDigest::from_bytes(fixed(&value[186..218])?),
        root_plan: ObjectDigest::from_bytes(fixed(&value[218..250])?),
        child_head: ObjectDigest::from_bytes(fixed(&value[250..282])?),
        inclusive_grant: ObjectDigest::from_bytes(fixed(&value[282..314])?),
    })?;
    Ok((kind, records))
}

/// Validates all recognized rows and their complete atomic companions.
///
/// # Errors
/// Rejects malformed recognized records and incomplete companion sets. Other
/// DesiredState families keep their existing independent validators.
pub fn validate_provisioning_resource_state_v1(state: &State)
    -> Result<(), ProvisioningResourceDataErrorV1>
{
    for ((namespace, key), value) in state {
        if *namespace != RecordNamespace::DesiredState { continue; }
        if let Some((_, records)) = decode_provisioning_resource_row_v1(key, value)? {
            records.require_companions_v1(state)?;
        }
    }
    Ok(())
}

/// Returns the fixed lookup key of an actual protected public parent.
#[must_use]
pub fn provisioning_parent_key_v1(parent: OperationId)
    -> [u8; PROVISIONING_RESOURCE_KEY_BYTES_V1]
{
    resource_key(ProvisioningResourceRowKindV1::Parent, parent.as_bytes())
}

/// Commits the full canonical public request, independently of lifecycle intent.
///
/// This computes comparison DATA only. The actual public decoder and accepted
/// caller/project/time record must still be validated independently.
#[must_use]
pub fn provisioning_public_request_digest_v1(canonical_request: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(Sha256::new()
        .chain_update(b"aos.sandbox.provisioning-public-request.v1\0")
        .chain_update(canonical_request).finalize().into())
}

fn resource_key(kind: ProvisioningResourceRowKindV1, id: &[u8; 16])
    -> [u8; PROVISIONING_RESOURCE_KEY_BYTES_V1]
{
    let mut key = [0; PROVISIONING_RESOURCE_KEY_BYTES_V1];
    key[..PREFIX.len()].copy_from_slice(PREFIX);
    key[PREFIX.len()] = kind.tag();
    key[PREFIX.len() + 1..].copy_from_slice(id);
    key
}

fn checksum(bytes: &[u8]) -> [u8; 32] {
    Sha256::new().chain_update(DOMAIN).chain_update(bytes).finalize().into()
}

fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], ProvisioningResourceDataErrorV1> {
    bytes.try_into().map_err(|_| ProvisioningResourceDataErrorV1::NonCanonical)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn records(seed: u8) -> ProvisioningResourceRecordsV1 {
        ProvisioningResourceRecordsV1::from_data_v1(ProvisioningResourceFieldsV1 {
            mode: ProvisioningModeDataV1::CreateStopped,
            parent: OperationId::from_bytes([seed; 16]),
            publication_operation: OperationId::from_bytes([seed + 1; 16]),
            sandbox: SandboxId::from_bytes([seed + 2; 16]),
            project: ProjectId::from_bytes([seed + 3; 16]),
            assignment: ResourceId::from_bytes([seed + 4; 16]),
            reservation: ResourceId::from_bytes([seed + 5; 16]),
            epoch: AssignmentEpoch::new(1), reservation_revision: Revision::new(1),
            public_request: ObjectDigest::from_bytes([1; 32]),
            manifest: ObjectDigest::from_bytes([2; 32]),
            source_draft: ObjectDigest::from_bytes([3; 32]),
            root_plan: ObjectDigest::from_bytes([4; 32]),
            child_head: ObjectDigest::from_bytes([5; 32]),
            inclusive_grant: ObjectDigest::from_bytes([6; 32]),
        }).unwrap()
    }

    pub(super) fn state(records: ProvisioningResourceRecordsV1) -> State {
        records.records_v1().into_iter().map(|row| (
            (row.namespace(), row.key().to_vec()), row.value().unwrap().to_vec(),
        )).collect()
    }

    #[test]
    fn canonical_rows_require_all_three_same_parent_companions() {
        let expected = records(10);
        let mut state = state(expected);
        validate_provisioning_resource_state_v1(&state).unwrap();
        let key = expected.key_v1(ProvisioningResourceRowKindV1::Reservation);
        state.remove(&(RecordNamespace::DesiredState, key.to_vec()));

        assert_eq!(validate_provisioning_resource_state_v1(&state),
            Err(ProvisioningResourceDataErrorV1::Incomplete));
    }

    #[test]
    fn substituted_canonical_companion_cannot_cross_parent_binding() {
        let expected = records(10);
        let mut actual = state(expected);
        let mut substituted = expected.fields_v1();
        substituted.root_plan = ObjectDigest::from_bytes([77; 32]);
        let substituted = ProvisioningResourceRecordsV1::from_data_v1(substituted).unwrap();
        actual.insert((RecordNamespace::DesiredState,
            expected.key_v1(ProvisioningResourceRowKindV1::Assignment).to_vec()),
            substituted.encode_v1(ProvisioningResourceRowKindV1::Assignment).to_vec());

        assert_eq!(validate_provisioning_resource_state_v1(&actual),
            Err(ProvisioningResourceDataErrorV1::Incomplete));
    }

    #[test]
    fn checksum_and_key_identity_are_both_required() {
        let expected = records(10);
        let kind = ProvisioningResourceRowKindV1::Parent;
        let key = expected.key_v1(kind);
        let value = expected.encode_v1(kind);
        assert_eq!(decode_provisioning_resource_row_v1(&key, &value).unwrap(),
            Some((kind, expected)));
        let mut damaged = value;
        damaged[122] ^= 1;
        assert_eq!(decode_provisioning_resource_row_v1(&key, &damaged),
            Err(ProvisioningResourceDataErrorV1::NonCanonical));
        let mut wrong_key = key;
        wrong_key[PROVISIONING_RESOURCE_KEY_BYTES_V1 - 1] ^= 1;
        assert_eq!(decode_provisioning_resource_row_v1(&wrong_key, &value),
            Err(ProvisioningResourceDataErrorV1::NonCanonical));
    }

    #[test]
    fn separate_sets_cannot_alias_assignment_and_reservation_resources() {
        let first = records(10);
        let mut second = records(30).fields_v1();
        second.reservation = first.fields_v1().assignment;
        let second = ProvisioningResourceRecordsV1::from_data_v1(second).unwrap();
        let mut actual = state(first);
        actual.extend(state(second));

        assert_eq!(validate_provisioning_resource_state_v1(&actual),
            Err(ProvisioningResourceDataErrorV1::NonCanonical));
    }
}
