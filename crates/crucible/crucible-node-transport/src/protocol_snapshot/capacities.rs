//! Preserves actual snapshot banks and retained association views as capacity DATA.
//!
//! Inline owner headers belong to their enclosing Source allocation. Encoded,
//! literal, record and lookup vectors retain their independent capacities; shared
//! association views are repeated without address-based sharing credit.

use super::*;
use crate::retained_metadata::MetadataObserver;
use crate::transport::original_frames::OriginalFrameReservation;
use std::{cell::RefCell, mem::size_of};

/// Keeps fixed fields closed to newly owning storage without inventing work rows.
pub(super) const fn inline<T: Copy>(_value: &T) {}

impl ProtocolSnapshotReservation {
    pub(crate) fn check_capacity_creator_data(&self) -> Result<(), ProviderError> {
        if let Some((_, owner, _, _)) = &self.issuer {
            owner.ensure_current()?;
        }
        Ok(())
    }

    pub(crate) fn observe_capacity_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self {
            bytes,
            maximum,
            compact,
            owned11_records,
            owned11_aliases,
            original_assigned_cut,
            original_restore_cut,
            original_hello,
            complete,
            literal,
            codec,
            issuer,
        } = self;
        inline(maximum);
        inline(compact);
        inline(original_assigned_cut);
        inline(original_restore_cut);
        inline(complete);

        observer.vector::<u8>(bytes.capacity())?;
        observe_banks(
            owned11_records.as_ref(),
            owned11_aliases.as_ref(),
            literal.as_ref(),
            observer,
        )?;
        if let Some((authority, owner, cut, deadline)) = issuer {
            inline(cut);
            inline(deadline);
            observe_association(
                owner,
                authority,
                codec.as_ref(),
                original_hello.as_ref(),
                observer,
            )
        } else {
            observe_codec_hello(codec.as_ref(), original_hello.as_ref(), observer)
        }
    }
}

impl OriginalProtocolSnapshot {
    pub(crate) fn check_capacity_creator_data(&self) -> Result<(), ProviderError> {
        self.owner.ensure_current()
    }

    pub(crate) fn observe_capacity_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self {
            maximum,
            compact,
            owned11_records,
            owned11_aliases,
            original_assigned_cut,
            original_restore_cut,
            original_hello,
            codec,
            bytes,
            authority,
            owner,
            cut,
            deadline,
            literal,
        } = self;
        inline(maximum);
        inline(compact);
        inline(original_assigned_cut);
        inline(original_restore_cut);
        inline(cut);
        inline(deadline);

        observer.vector::<u8>(bytes.capacity())?;
        observe_banks(
            owned11_records.as_ref(),
            owned11_aliases.as_ref(),
            literal.as_ref(),
            observer,
        )?;
        observe_association(
            owner,
            authority,
            codec.as_ref(),
            original_hello.as_ref(),
            observer,
        )
    }
}

pub(super) fn observe_banks(
    records: Option<&MetadataRecordBank>,
    aliases: Option<&MetadataAliasBank>,
    literal: Option<&OriginalFrameReservation>,
    observer: &mut MetadataObserver<'_>,
) -> Result<(), ProviderError> {
    if let Some(records) = records {
        records.observe_retained_capacity_data(observer)?;
    }
    if let Some(aliases) = aliases {
        aliases.observe_retained_capacity_data(observer)?;
    }
    if let Some(literal) = literal {
        literal.observe_owned11_metadata(observer)?;
    }
    Ok(())
}

pub(super) fn observe_association(
    owner: &Rc<ProtocolCaptureOwner>,
    authority: &ConnectionAuthority,
    codec: Option<&Rc<crate::connection::Native5CodecOwner>>,
    hello: Option<&Rc<RefCell<OriginalFrameReservation>>>,
    observer: &mut MetadataObserver<'_>,
) -> Result<(), ProviderError> {
    owner.ensure_current()?;
    let ProtocolCaptureOwner { pid, thread } = owner.as_ref();
    inline(pid);
    inline(thread);
    observer.shared_value(owner.as_ref())?;
    authority.observe_retained_metadata(observer)?;
    observe_codec_hello(codec, hello, observer)
}

fn observe_codec_hello(
    codec: Option<&Rc<crate::connection::Native5CodecOwner>>,
    hello: Option<&Rc<RefCell<OriginalFrameReservation>>>,
    observer: &mut MetadataObserver<'_>,
) -> Result<(), ProviderError> {
    if let Some(codec) = codec {
        observer.shared_value(codec.as_ref())?;
        codec.observe_retained_metadata(observer)?;
    }
    if let Some(hello) = hello {
        observer.shared_value(hello.as_ref())?;
        let bank = hello
            .try_borrow()
            .map_err(|_| ProviderError::Conflict("original capture Hello metadata borrowed"))?;
        bank.observe_owned11_metadata(observer)?;
    }
    Ok(())
}

pub(crate) fn capture_capacity_counter_scratch_data() -> usize {
    MetadataRecordBank::retained_capacity_counter_scratch_data()
        + MetadataAliasBank::retained_capacity_counter_scratch_data()
        + size_of::<&ProtocolSnapshotReservation>()
        + size_of::<&OriginalProtocolSnapshot>()
        + size_of::<&OriginalProtocolPayloadOwner>()
        + size_of::<&Vec<u8>>()
        + size_of::<&OriginalFrameReservation>()
        + size_of::<&Rc<ProtocolCaptureOwner>>()
        + size_of::<&ConnectionAuthority>()
        + size_of::<&Rc<crate::connection::Native5CodecOwner>>()
        + size_of::<&Rc<RefCell<OriginalFrameReservation>>>()
        + size_of::<std::cell::Ref<'static, OriginalFrameReservation>>()
        + size_of::<Result<std::cell::Ref<'static, OriginalFrameReservation>, std::cell::BorrowError>>(
        )
}

#[cfg(test)]
mod tests;
