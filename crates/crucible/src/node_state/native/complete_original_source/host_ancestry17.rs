//! Lends genuine retained archive ancestry to the actual current Host17 writer.
//!
//! The signed Index3 identity is computed from this exact retained archive under
//! the existing bounded encoding admission. It stays borrowed inside the callback;
//! no permanent cache or changed legacy Source constructor is introduced.

use super::*;
use crate::node_contract::RestoredHostCaptureAncestryBorrowed17;

const INITIAL_SEMANTIC_MEDIA: &str = "application/vnd.source-owned.packet-semantic-custody.v5+json";

impl CompleteOriginalHostTicket {
    /// Lends exact initial ancestry beside this actual signed parent index.
    ///
    /// The caller independently funds its clone and all enclosing construction
    /// before entry. `additional_retained_bytes` covers owners outside this same
    /// Source; the complete retained Source is included here. The callback must
    /// retain its output before any later fallible native or serialization work.
    ///
    /// # Errors
    /// Refuses foreign custody, unsupported or ambiguous historical roles,
    /// incomplete signed metadata, unavailable verified bodies, exhausted index
    /// encoding admission, and callback refusal. No Capture or restore authority
    /// follows from these historical borrowed references.
    pub(crate) fn with_restored_capture_ancestry17_data<R>(
        &self,
        maximum_record_bytes: usize,
        additional_retained_bytes: usize,
        inspect: impl FnOnce(RestoredHostCaptureAncestryBorrowed17<'_>) -> Result<R, RuntimeError>,
    ) -> Result<R, RuntimeError> {
        self.source.authenticate_birth()?;
        let source_storage = self.source.capture_owned_storage()?;
        let additional = additional_retained_bytes
            .checked_add(source_storage)
            .and_then(|bytes| {
                bytes.checked_add(Self::restored_capture_ancestry17_counter_scratch_data())
            })
            .ok_or(RuntimeError::ResourceLimit)?;
        let parent = self
            .source
            .archive
            .complete_original_index_identity(maximum_record_bytes, additional)
            .map_err(|error| match error.code {
                crate::node_state::StateErrorCode::ResourceLimit => RuntimeError::ResourceLimit,
                _ => RuntimeError::InvalidReceipt,
            })?;

        let result = self.with_restored_capture_first_roles17_data(|first_host, first_semantic| {
            inspect(RestoredHostCaptureAncestryBorrowed17 {
                parent_archive_index: &parent,
                first_host,
                first_semantic,
            })
        });
        self.source.authenticate_birth()?;
        result
    }

    /// Lends exact first Host/semantic roles without encoding the parent Index3.
    ///
    /// This separate metadata loan permits the Host17 counter to borrow all
    /// immutable ancestry and use the Index3 codec's defining output projection.
    /// No placeholder ContentRef or owning archive identity is manufactured.
    ///
    /// # Errors
    /// Refuses foreign custody, ambiguous first roles, wrong participants or
    /// first objects outside the actual authenticated archive closure.
    pub(crate) fn with_restored_capture_first_roles17_data<R>(
        &self,
        inspect: impl FnOnce(&ContentRef, [(&Id, &ContentRef); 3]) -> Result<R, RuntimeError>,
    ) -> Result<R, RuntimeError> {
        self.source.authenticate_birth()?;
        let result = match &self.source.host {
            CompleteHostArchiveRecord::InitialInvocation15(host) => {
                let owners = self.source.archive.owners();
                if owners.len() != 4 {
                    return Err(RuntimeError::ForeignAuthority);
                }
                let mut host_rows = owners
                    .iter()
                    .filter(|owner| owner.owner == host.source.owner.owner.id);
                let host_row = host_rows.next().ok_or(RuntimeError::OwnerUnavailable)?;
                if host_rows.next().is_some()
                    || host_row.participants.as_slice()
                        != std::slice::from_ref(&host.source.descriptor.id)
                    || self.source.content.get(&host_row.state).is_none()
                {
                    return Err(RuntimeError::ForeignAuthority);
                }

                let mut semantic = [None; 3];
                let mut count = 0usize;
                for owner in owners.iter().filter(|owner| owner.owner != host_row.owner) {
                    if owner.participants.len() != 1 || count == semantic.len() {
                        return Err(RuntimeError::ForeignAuthority);
                    }
                    let mut references = owner
                        .evidence
                        .iter()
                        .filter(|reference| reference.media_type == INITIAL_SEMANTIC_MEDIA);
                    let reference = references.next().ok_or(RuntimeError::OwnerUnavailable)?;
                    if references.next().is_some() || self.source.content.get(reference).is_none() {
                        return Err(RuntimeError::ForeignAuthority);
                    }
                    semantic[count] = Some((&owner.participants[0], reference));
                    count += 1;
                }
                if count != 3 {
                    return Err(RuntimeError::ForeignAuthority);
                }
                let [first, second, third] =
                    semantic.map(|entry| entry.ok_or(RuntimeError::OwnerUnavailable));
                let mut semantic = [first?, second?, third?];
                semantic.sort_unstable_by(|left, right| left.0.cmp(right.0));
                if semantic.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
                    return Err(RuntimeError::ForeignAuthority);
                }
                inspect(&host_row.state, semantic)
            }
            CompleteHostArchiveRecord::Settled17(host) => {
                let ancestry = &host.ancestry;
                if self.source.content.get(&ancestry.first_host).is_none()
                    || ancestry
                        .first_semantic
                        .iter()
                        .any(|row| self.source.content.get(&row.object).is_none())
                {
                    return Err(RuntimeError::InvalidReceipt);
                }
                inspect(
                    &ancestry.first_host,
                    ancestry
                        .first_semantic
                        .each_ref()
                        .map(|row| (&row.node, &row.object)),
                )
            }
        };
        self.source.authenticate_birth()?;
        result
    }

    pub(crate) fn restored_capture_ancestry17_counter_scratch_data() -> usize {
        use std::mem::size_of;
        size_of::<&Self>()
            + size_of::<ContentRef>()
            + size_of::<RestoredHostCaptureAncestryBorrowed17<'static>>()
            + size_of::<[Option<(&Id, &ContentRef)>; 3]>()
            + size_of::<[(&Id, &ContentRef); 3]>()
            + size_of::<Result<(&Id, &ContentRef), RuntimeError>>()
            + size_of::<[Result<(&Id, &ContentRef), RuntimeError>; 3]>()
            + size_of::<std::slice::Iter<'static, NativeOwnerState>>()
            + size_of::<std::slice::Iter<'static, ContentRef>>()
            + size_of::<std::slice::Windows<'static, (&Id, &ContentRef)>>()
            + size_of::<Result<ContentRef, StateError>>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<usize>() * 4
    }
}

impl CompleteOriginalHostTicket {
    /// Quotes the real signed parent-index encoder used by the ancestry loan.
    ///
    /// The caller prices its own actual Source/archive storage independently.
    /// Returned axes carry no parent provenance or execution permission.
    ///
    /// # Errors
    /// Refuses foreign custody, actual index encoding or independent bounds.
    pub(crate) fn restored_capture_ancestry17_index_construction_data(
        &self,
        maximum_record_bytes: usize,
        maximum_requested_bytes: usize,
    ) -> Result<(usize, usize, usize), RuntimeError> {
        self.source.authenticate_birth()?;
        let row = self
            .source
            .archive
            .complete_original_index_identity_construction_data(
                maximum_record_bytes,
                maximum_requested_bytes,
            )
            .map_err(|error| match error.code {
                crate::node_state::StateErrorCode::ResourceLimit => RuntimeError::ResourceLimit,
                _ => RuntimeError::InvalidReceipt,
            })?;
        self.source.authenticate_birth()?;
        Ok(row)
    }

    /// Names the known prewalk formatter temporary of the genuine Index3 codec.
    pub(crate) fn restored_capture_ancestry17_index_counter_transient_data() -> usize {
        NativeArchiveRecord::complete_original_index_identity_counter_transient_data()
    }

    /// Names fixed controls admitted before quoting the genuine signed Index3.
    pub(crate) fn restored_capture_ancestry17_index_counter_scratch_data() -> usize {
        NativeArchiveRecord::complete_original_index_identity_counter_scratch_data()
    }
}
