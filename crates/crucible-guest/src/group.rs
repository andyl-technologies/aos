//! Atomic guest choice groups carried in the versioned selectable envelope.
//!
//! A group occupies one catalog declaration and one reply-bearing request.
//! The campaign codec validates the complete typed tuple before the guest
//! exposes it to an application; the transport owns only bounded byte ranges.

use std::collections::{BTreeMap, BTreeSet};

use crucible_campaign::{
    CampaignCodecError, ChoiceClassContext, ChoiceDomain, ChoiceGroup, ChoiceGroupApplication,
    ChoiceGroupDomain, ChoiceGroupValue, ChoiceRelationalConstraint, ChoiceSource, ChoiceTuple,
    ChoiceValue, SelectableDeclaration, SelectableId,
};
use crucible_protocol::{SelectableRegister, SelectionReplyStatus, SelectionRequest};
use thiserror::Error;

use crate::DoorbellTransport;
use crate::selectable::{
    GuestSelectableError, GuestSelection, build_selectable_registration_bytes, request_selection,
};

/// One complete group selection with its acknowledged transport exchange.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestGroupSelection {
    exchange: GuestSelection,
    value: ChoiceGroupValue,
}

impl GuestGroupSelection {
    /// Returns the one request and acknowledged reply carrying the group.
    #[must_use]
    pub const fn exchange(&self) -> &GuestSelection {
        &self.exchange
    }

    /// Returns the complete tuple after group identity and domain validation.
    #[must_use]
    pub const fn value(&self) -> &ChoiceGroupValue {
        &self.value
    }
}

/// Error constructing or requesting an atomic guest choice group.
#[derive(Debug, Error)]
pub enum GuestGroupError {
    /// The typed group or one of its members is invalid.
    #[error("guest choice group is invalid: {0}")]
    Campaign(#[from] CampaignCodecError),
    /// The selectable transport or reply is invalid.
    #[error("guest choice group transport failed: {0}")]
    Selectable(#[from] GuestSelectableError),
    /// The host rejected the one complete group request.
    #[error("host rejected guest choice group: {0:?}")]
    Rejected(SelectionReplyStatus),
    /// The host selected a scalar or a value outside this exact group.
    #[error("host reply did not contain one admitted tuple for this group")]
    InvalidSelection,
    /// A member declaration key is inconsistent with its content identity.
    #[error("guest choice group member ID disagrees with its declaration")]
    MemberIdentityMismatch,
}

/// Constructs one Cartesian group from guest-owned member declarations.
///
/// The member declarations are embedded in the group identity. They are not
/// registered as independent guest opportunities. `application_version`
/// identifies the atomic adapter contract.
///
/// # Errors
///
/// Returns [`GuestGroupError`] when a member, application, or group domain is
/// invalid, or when a declaration key differs from its content identity.
pub fn build_guest_group(
    node: &str,
    adapter: &str,
    application_version: u32,
    members: Vec<(String, ChoiceDomain, ChoiceValue)>,
    constraints: BTreeSet<ChoiceRelationalConstraint>,
) -> Result<(ChoiceGroup, ChoiceValue, BTreeMap<String, SelectableId>), GuestGroupError> {
    let source = ChoiceSource::Guest {
        node: node.to_owned(),
        protocol_version: u32::from(crucible_protocol::SELECTABLE_PROTOCOL_VERSION),
    };
    let context = ChoiceClassContext::new(BTreeSet::new())?;
    let mut declarations = BTreeMap::new();
    let mut domains = BTreeMap::new();
    let mut defaults = BTreeMap::new();
    let mut names = BTreeMap::new();

    for (name, domain, default) in members {
        let declaration = SelectableDeclaration::new(
            name.clone(),
            source.clone(),
            domain.clone(),
            default.clone(),
            context.clone(),
            BTreeSet::new(),
            true,
        )?;
        let id = declaration.id()?;
        if declarations.insert(id, declaration).is_some() {
            return Err(GuestGroupError::MemberIdentityMismatch);
        }
        names.insert(name, id);
        domains.insert(id, domain);
        defaults.insert(id, default);
    }

    let group = ChoiceGroup::new(
        &declarations,
        ChoiceGroupDomain::Cartesian {
            members: domains,
            constraints,
        },
        ChoiceGroupApplication::new(adapter, application_version)?,
    )?;
    let default = ChoiceValue::Group(group.select(ChoiceTuple::new(defaults))?);
    Ok((group, default, names))
}

/// Builds one bounded setup registration for a complete group.
///
/// # Errors
///
/// Returns [`GuestGroupError`] when the default is outside the group or its
/// canonical domain/value bytes exceed the selectable envelope.
pub fn build_group_registration(
    sequence: u64,
    name: &str,
    group: &ChoiceGroup,
    default: &ChoiceValue,
) -> Result<SelectableRegister, GuestGroupError> {
    let domain = ChoiceDomain::Group(Box::new(group.clone()));
    if !domain.contains(default) {
        return Err(GuestGroupError::InvalidSelection);
    }
    build_selectable_registration_bytes(
        sequence,
        name,
        domain.canonical_bytes(),
        default.canonical_bytes(),
        Vec::new(),
    )
    .map_err(Into::into)
}

/// Requests one complete group tuple and validates the acknowledged reply.
///
/// # Errors
///
/// Returns [`GuestGroupError`] for a transport failure, typed host rejection,
/// malformed group value, wrong group identity, or incomplete/illegal tuple.
pub fn request_group_selection<T>(
    request: &SelectionRequest,
    group: &ChoiceGroup,
    transport: &mut T,
) -> Result<GuestGroupSelection, GuestGroupError>
where
    T: DoorbellTransport + ?Sized,
{
    let exchange = request_selection(request, transport)?;
    if exchange.reply().status() != SelectionReplyStatus::Selected {
        return Err(GuestGroupError::Rejected(exchange.reply().status()));
    }
    let domain = ChoiceDomain::Group(Box::new(group.clone()));
    if *exchange.reply().domain_id() != domain.id()?.content_id().digest() {
        return Err(GuestGroupError::InvalidSelection);
    }
    let bytes = exchange
        .reply()
        .selected_value()
        .ok_or(GuestGroupError::InvalidSelection)?;
    let value = ChoiceValue::from_canonical_bytes(bytes)?;
    if !domain.contains(&value) {
        return Err(GuestGroupError::InvalidSelection);
    }
    let ChoiceValue::Group(value) = value else {
        return Err(GuestGroupError::InvalidSelection);
    };
    Ok(GuestGroupSelection { exchange, value })
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use crucible_campaign::{BooleanDomain, IntegerDomain, IntegerRepresentation, IntegerValue};
    use crucible_protocol::{SELECTABLE_MESSAGE_MAX_BYTES, SelectionReply};

    use super::*;
    use crate::GuestEmitterError;

    struct ReplyTransport(Vec<u8>);

    impl DoorbellTransport for ReplyTransport {
        fn ring(&mut self, buffer: &mut [u8]) -> Result<(), GuestEmitterError> {
            buffer.fill(0);
            buffer[..self.0.len()].copy_from_slice(&self.0);
            Ok(())
        }
    }

    fn fixture() -> Result<(ChoiceGroup, ChoiceValue), Box<dyn Error>> {
        let scale = crucible_campaign::ExactRational::new(1, 1)?;
        let retry = ChoiceDomain::Integer(IntegerDomain::new(
            1,
            IntegerRepresentation::Unsigned64,
            IntegerValue::Unsigned(0),
            IntegerValue::Unsigned(12),
            1,
            Some(String::from("count")),
            scale,
            Vec::new(),
        )?);
        let fast = ChoiceDomain::Boolean(BooleanDomain::new(1)?);
        let (group, default, _) = build_guest_group(
            "router-a",
            "envoy.recovery",
            1,
            vec![
                (
                    String::from("recovery.retry_limit"),
                    retry,
                    ChoiceValue::Integer(IntegerValue::Unsigned(3)),
                ),
                (
                    String::from("recovery.fast_reroute"),
                    fast,
                    ChoiceValue::Boolean(true),
                ),
            ],
            BTreeSet::new(),
        )?;
        Ok((group, default))
    }

    #[test]
    fn one_group_registration_and_reply_carry_a_complete_tuple() -> Result<(), Box<dyn Error>> {
        let (group, default) = fixture()?;
        let registration = build_group_registration(1, "recovery.response", &group, &default)?;
        assert_eq!(
            ChoiceDomain::from_canonical_bytes(registration.domain())?,
            ChoiceDomain::Group(Box::new(group.clone()))
        );
        assert_eq!(
            ChoiceValue::from_canonical_bytes(registration.default_value())?,
            default
        );
        assert!(registration.encode()?.len() <= SELECTABLE_MESSAGE_MAX_BYTES);

        let request = SelectionRequest::new(2, "recovery.response", "transport/one", None, 4096)?;
        let domain_id = ChoiceDomain::Group(Box::new(group.clone()))
            .id()?
            .content_id()
            .digest();
        let reply = SelectionReply::selected(2, [1; 32], domain_id, default.canonical_bytes())?;
        let selected =
            request_group_selection(&request, &group, &mut ReplyTransport(reply.encode()?))?;
        assert_eq!(selected.value().tuple().values().len(), 2);
        assert_eq!(selected.exchange().reply(), &reply);
        Ok(())
    }

    #[test]
    fn incomplete_group_reply_is_rejected_before_application() -> Result<(), Box<dyn Error>> {
        let (group, default) = fixture()?;
        let ChoiceValue::Group(value) = default else {
            return Err("default was not a group".into());
        };
        let mut values = value.tuple().values().clone();
        values.pop_first();
        assert!(group.select(ChoiceTuple::new(values)).is_err());
        let request = SelectionRequest::new(2, "recovery.response", "transport/one", None, 4096)?;
        let domain_id = ChoiceDomain::Group(Box::new(group.clone()))
            .id()?
            .content_id()
            .digest();
        let reply = SelectionReply::selected(
            2,
            [1; 32],
            domain_id,
            ChoiceValue::Boolean(false).canonical_bytes(),
        )?;
        assert!(
            request_group_selection(&request, &group, &mut ReplyTransport(reply.encode()?))
                .is_err()
        );
        Ok(())
    }
}
