//! Prepaid encoding and publication of closed RAM root manifests.
//!
//! The complete input partition precedes logical encoding, body, child table
//! and shared envelope construction. Backend callbacks retain original authority.
//!
//! ```text
//! body: logical-record-length:u32be | RootRecord | region-TreeRefs
//! child roles: region-00000000, region-00000001, ...
//! ```

use std::collections::BTreeSet;

use crucible_ram::RootRecord;

use crate::content_envelope::{ContentChild, ContentEnvelope};
use crate::content_store::{ContentId, ObjectKind};

use super::codec::{
    ROOT_SCHEMA, SCHEMA_VERSION, TreeRef, allocate_charged_body, copy_charged_identifier,
    encode_ref,
};
use super::codec_ownership::{OwnedEnvelope, PublicationInput, SharedEnvelope, admission};
use super::record_account::{RecordAccount, RecordAllocationPlan, child_node_bytes, shared_extent};
use super::{MAX_RAM_OBJECT_BYTES, RamRetention, RamStore, RamStoreError, Work};

impl RamStore {
    pub(super) fn put_root(
        &self,
        record: &RootRecord,
        regions: &[TreeRef],
        retention: &dyn RamRetention,
        work: &mut Work<'_>,
    ) -> Result<ContentId, RamStoreError> {
        let (body_length, envelope_length) = encoding_lengths(record, regions)?;
        let original = work.original().child().map_err(admission)?;
        let account = RecordAccount::phase(
            &original,
            RecordAllocationPlan::root_input(record.encoded_len(), body_length, regions.len())?,
        )?;
        let scope = account.codec.enter();
        account
            .codec
            .charge_array::<u8>(record.encoded_len())
            .map_err(admission)?;
        let canonical = record
            .try_encode()
            .map_err(|source| admission(account.codec.retain_allocation_refusal(source)))?;
        account
            .codec
            .charge_array::<u8>(body_length)
            .map_err(admission)?;
        let mut body = allocate_charged_body(&account.codec, body_length)?;
        let logical_length = u32::try_from(canonical.len())
            .map_err(|_| RamStoreError::Limit("logical root record"))?;
        body.extend_from_slice(&logical_length.to_be_bytes());
        body.extend_from_slice(&canonical);
        drop(canonical);

        let mut children = BTreeSet::new();
        for (index, reference) in regions.iter().enumerate() {
            account
                .codec
                .charge_bytes(child_node_bytes())
                .map_err(admission)?;
            account.codec.charge_array::<u8>(15).map_err(admission)?;
            let role = region_role(index)?;
            let role = std::str::from_utf8(&role)
                .map_err(|_| RamStoreError::Invalid("root child role"))?;
            children.insert(ContentChild::new(
                copy_charged_identifier(&account.codec, role)?,
                reference.id,
            )?);
            encode_ref(&mut body, *reference);
        }
        account
            .codec
            .charge_array::<u8>(ROOT_SCHEMA.len())
            .map_err(admission)?;
        let schema = copy_charged_identifier(&account.codec, ROOT_SCHEMA)?;
        let envelope = ContentEnvelope::new(schema, SCHEMA_VERSION, children, body)?;
        account
            .codec
            .charge_bytes(shared_extent::<OwnedEnvelope>()?)
            .map_err(admission)?;
        let envelope = SharedEnvelope::new(OwnedEnvelope::new(envelope, &account.codec));
        drop(scope);

        let canonical = RecordAccount::phase(
            &original,
            RecordAllocationPlan::root_canonical(envelope_length)?,
        )?;
        self.put_envelope_with_account(
            PublicationInput::OwnedSmall(envelope),
            ObjectKind::ExactManifest,
            retention,
            work,
            &canonical,
        )
    }
}

fn encoding_lengths(
    record: &RootRecord,
    regions: &[TreeRef],
) -> Result<(usize, usize), RamStoreError> {
    if regions.len() > crucible_ram::Limits::default().max_regions
        || regions.len() != record.region_roots().len()
    {
        return Err(RamStoreError::Limit("root region count"));
    }
    let overflow = || RamStoreError::Limit("root encoding length");
    let body = regions
        .len()
        .checked_mul(44)
        .and_then(|references| references.checked_add(4))
        .and_then(|prefix| prefix.checked_add(record.encoded_len()))
        .ok_or_else(overflow)?;
    let mut envelope = body
        .checked_add(30 + ROOT_SCHEMA.len())
        .ok_or_else(overflow)?;
    for reference in regions {
        envelope = envelope
            .checked_add(4 + 15 + reference.id.encoded_len())
            .ok_or_else(overflow)?;
    }
    if envelope as u64 > MAX_RAM_OBJECT_BYTES {
        return Err(RamStoreError::Limit("root encoding length"));
    }
    Ok((body, envelope))
}

fn region_role(index: usize) -> Result<[u8; 15], RamStoreError> {
    let index = u32::try_from(index).map_err(|_| RamStoreError::Limit("root region index"))?;
    let mut role = *b"region-00000000";
    for (position, byte) in role[7..].iter_mut().enumerate() {
        *byte = b"0123456789abcdef"[((index >> (4 * (7 - position))) & 15) as usize];
    }
    Ok(role)
}
