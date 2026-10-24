//! Restores historical keyed-admission state without issuing a native marker.

use super::super::{
    state::{HistoricalAuthority, next, tag},
    typed::{Fields, invalid},
};
use super::{
    boot::HistoricalNativeBoot, identity::HistoricalNativeAckIdentity,
    policy::HistoricalNativePolicy, shared::NativeLedger,
};
use crate::{ProviderError, envelope::Envelope};
use std::rc::Rc;

/// Retains complete historical token state with its actual archive alias groups.
pub struct HistoricalNativeAckToken {
    /// Retains the exact assigned original and connection bank correspondence.
    pub identity: HistoricalNativeAckIdentity,
    /// Shares the complete original boot history with the bootstrap owner.
    pub boot: Rc<HistoricalNativeBoot>,
    /// Shares the complete original immutable native policy.
    pub policy: Rc<HistoricalNativePolicy>,
    /// Retains the separately owned authority fields and original capacities.
    pub authority: HistoricalAuthority,
    /// Retains the exact received assigned Admit envelope including proof.
    pub original: Envelope,
}

impl HistoricalNativeAckToken {
    /// Checks repeated original correspondence after the owner reaches its result slot.
    ///
    /// # Errors
    /// Refuses changed literals, a different original or inconsistent shared groups.
    /// The outer decoder retains the completed historical owner on refusal.
    pub(crate) fn authenticate_correspondence(&self) -> Result<(), ProviderError> {
        self.identity.authenticate_original(&self.original)?;
        if !Rc::ptr_eq(&self.policy, &self.identity.policy)
            || !Rc::ptr_eq(&self.policy, &self.boot.policy)
            || self.original != self.boot.original
        {
            return Err(invalid());
        }
        Ok(())
    }
}

pub(super) fn read(
    input: &[u8],
    ledger: &mut NativeLedger<'_, '_, '_, '_, '_>,
    build: bool,
    boot_layout: usize,
) -> Result<Option<HistoricalNativeAckToken>, ProviderError> {
    let mut fields = Fields::array(input)?;
    tag(
        &mut fields,
        if ledger.requires_invocation_class()? {
            "source-private.native-ack-token/15"
        } else if ledger.requires_startup_class()? {
            "source-private.native-ack-token/14"
        } else {
            "source-private.native-ack-token/11"
        },
    )?;
    let identity = super::identity::read(next(&mut fields)?, ledger, build)?;
    let boot = ledger.boot(next(&mut fields)?, build, boot_layout)?;
    let policy = ledger.policy(next(&mut fields)?, build)?;
    let authority = ledger
        .ledger
        .read::<HistoricalAuthority>(next(&mut fields)?, build)?;
    let original = ledger.ledger.read::<Envelope>(next(&mut fields)?, build)?;
    fields.finish()?;
    if !build {
        return Ok(None);
    }
    let token = HistoricalNativeAckToken {
        identity: identity.ok_or_else(invalid)?,
        boot: boot.ok_or_else(invalid)?,
        policy: policy.ok_or_else(invalid)?,
        authority: authority.ok_or_else(invalid)?,
        original: original.ok_or_else(invalid)?,
    };
    Ok(Some(token))
}

// The closed owning walk fails to compile if a historical field is added.
super::super::retained_storage::fields!(
    HistoricalNativeAckToken,
    identity,
    boot,
    policy,
    authority,
    original
);

pub(crate) mod current17;

/// Names actual fixed local and returned headers of this handwritten reader.
///
/// Empty maps and `Option` payloads remain real controls when `build` is false;
/// no tree entries, backing allocations or owning reconstruction are included.
pub(super) fn borrowed_validation_headers_data() -> usize {
    use std::mem::size_of;

    fn header<T>() -> usize {
        size_of::<Option<T>>() + size_of::<Result<Option<T>, ProviderError>>()
    }

    fn field<T: super::super::typed::HistoricalType>() -> usize {
        header::<T>() + T::borrowed_header_counter_scratch_data()
    }

    field::<HistoricalAuthority>()
        + field::<Envelope>()
        + header::<HistoricalNativeAckToken>()
        + header::<super::identity::HistoricalNativeAckIdentity>()
        + header::<std::rc::Rc<super::policy::HistoricalNativePolicy>>()
        + header::<std::rc::Rc<super::boot::HistoricalNativeBoot>>()
}
