//! Atomic guest choice groups over the L1 selectable protocol.
//!
//! The protocol encodes complete group declarations and revalidates selected
//! tuples before application. One request still carries one complete tuple.

use std::collections::{BTreeMap, BTreeSet};

use crucible_protocol::{
    ChoiceCodecError, ChoiceDomain, ChoiceValue, GuestChoiceConstraint, GuestChoiceGroup,
    SelectableRegister, SelectionReplyStatus, SelectionRequest,
};
use thiserror::Error;

use crate::DoorbellTransport;
use crate::selectable::{
    GuestSelectableError, GuestSelection, build_selectable_registration_bytes, request_selection,
};

/// One complete group selection with its acknowledged transport exchange.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestGroupSelection {
    exchange: GuestSelection,
    values: BTreeMap<String, ChoiceValue>,
}

impl GuestGroupSelection {
    /// Returns the one request and acknowledged reply carrying the group.
    #[must_use]
    pub const fn exchange(&self) -> &GuestSelection {
        &self.exchange
    }

    /// Returns validated member values keyed by guest declaration name.
    #[must_use]
    pub const fn values(&self) -> &BTreeMap<String, ChoiceValue> {
        &self.values
    }
}

/// Error constructing or requesting an atomic guest choice group.
#[derive(Debug, Error)]
pub enum GuestGroupError {
    /// The typed group or one of its members is invalid.
    #[error("guest choice group is invalid: {0}")]
    Codec(#[from] ChoiceCodecError),
    /// The selectable transport or reply is invalid.
    #[error("guest choice group transport failed: {0}")]
    Selectable(#[from] GuestSelectableError),
    /// The host rejected the one complete group request.
    #[error("host rejected guest choice group: {0:?}")]
    Rejected(SelectionReplyStatus),
    /// The host selected a scalar or a value outside this exact group.
    #[error("host reply did not contain one admitted tuple for this group")]
    InvalidSelection,
}

/// Constructs one Cartesian group from guest-owned scalar declarations.
///
/// The members are embedded in one group and cannot be registered as
/// independent guest opportunities.
///
/// # Errors
///
/// Returns [`GuestGroupError`] for invalid identifiers, members, constraints,
/// or defaults.
pub fn build_guest_group(
    node: &str,
    adapter: &str,
    application_version: u32,
    members: Vec<(String, ChoiceDomain, ChoiceValue)>,
    constraints: BTreeSet<GuestChoiceConstraint>,
) -> Result<GuestChoiceGroup, GuestGroupError> {
    GuestChoiceGroup::new(node, adapter, application_version, members, constraints)
        .map_err(Into::into)
}

/// Builds one bounded setup registration for a complete group.
///
/// # Errors
///
/// Returns [`GuestGroupError`] when the canonical domain or default exceeds
/// the selectable envelope.
pub fn build_group_registration(
    sequence: u64,
    name: &str,
    group: &GuestChoiceGroup,
) -> Result<SelectableRegister, GuestGroupError> {
    build_selectable_registration_bytes(
        sequence,
        name,
        group.domain_bytes().to_vec(),
        group.default_bytes().to_vec(),
        Vec::new(),
    )
    .map_err(Into::into)
}

/// Requests one complete group tuple and validates the acknowledged reply.
///
/// # Errors
///
/// Returns [`GuestGroupError`] for a transport failure, typed host rejection,
/// malformed group value, wrong group identity, or incomplete or illegal tuple.
pub fn request_group_selection<T>(
    request: &SelectionRequest,
    group: &GuestChoiceGroup,
    transport: &mut T,
) -> Result<GuestGroupSelection, GuestGroupError>
where
    T: DoorbellTransport + ?Sized,
{
    let exchange = request_selection(request, transport)?;
    if exchange.reply().status() != SelectionReplyStatus::Selected {
        return Err(GuestGroupError::Rejected(exchange.reply().status()));
    }
    if *exchange.reply().domain_id() != group.domain_digest() {
        return Err(GuestGroupError::InvalidSelection);
    }
    let bytes = exchange
        .reply()
        .selected_value()
        .ok_or(GuestGroupError::InvalidSelection)?;
    let values = group
        .decode_selection(bytes)
        .map_err(|_error| GuestGroupError::InvalidSelection)?;
    Ok(GuestGroupSelection { exchange, values })
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use crucible_campaign as campaign;
    use crucible_protocol::{
        AlternativeId, BooleanDomain, ChoiceDomain, ChoiceValue, DiscreteAlternative,
        DiscreteDomain, ExactRational, GuestChoiceConstraint, IntegerDomain, IntegerRepresentation,
        IntegerValue, SelectionReply,
    };

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

    fn fixture() -> Result<GuestChoiceGroup, Box<dyn Error>> {
        Ok(build_guest_group(
            "router-a",
            "envoy.recovery",
            1,
            vec![
                (
                    String::from("recovery.fast_reroute"),
                    ChoiceDomain::Boolean(BooleanDomain::new(1)?),
                    ChoiceValue::Boolean(true),
                ),
                (
                    String::from("recovery.retry_limit"),
                    ChoiceDomain::Integer(IntegerDomain::new(
                        1,
                        IntegerRepresentation::Unsigned64,
                        IntegerValue::Unsigned(0),
                        IntegerValue::Unsigned(12),
                        1,
                        Some(String::from("count")),
                        ExactRational::new(1, 1)?,
                        Vec::new(),
                    )?),
                    ChoiceValue::Integer(IntegerValue::Unsigned(3)),
                ),
            ],
            BTreeSet::new(),
        )?)
    }

    #[test]
    fn l1_group_bytes_match_campaign_codec_and_reply() -> Result<(), Box<dyn Error>> {
        let guest = fixture()?;
        let domain = campaign::ChoiceDomain::from_canonical_bytes(guest.domain_bytes())?;
        let default = campaign::ChoiceValue::from_canonical_bytes(guest.default_bytes())?;
        assert!(domain.contains(&default));
        assert_eq!(domain.canonical_bytes(), guest.domain_bytes());
        assert_eq!(default.canonical_bytes(), guest.default_bytes());
        assert_eq!(domain.id()?.content_id().digest(), guest.domain_digest());

        let registration = build_group_registration(1, "recovery.response", &guest)?;
        assert_eq!(registration.domain(), guest.domain_bytes());
        assert_eq!(registration.default_value(), guest.default_bytes());

        let request = SelectionRequest::new(2, "recovery.response", "transport/one", None, 4096)?;
        let reply = SelectionReply::selected(
            2,
            [1; 32],
            guest.domain_digest(),
            guest.default_bytes().to_vec(),
        )?;
        let selected =
            request_group_selection(&request, &guest, &mut ReplyTransport(reply.encode()?))?;
        assert_eq!(selected.values().len(), 2);
        assert_eq!(selected.exchange().reply(), &reply);
        Ok(())
    }

    #[test]
    fn incomplete_or_foreign_group_reply_is_rejected() -> Result<(), Box<dyn Error>> {
        let guest = fixture()?;
        let request = SelectionRequest::new(2, "recovery.response", "transport/one", None, 4096)?;
        let reply = SelectionReply::selected(
            2,
            [1; 32],
            guest.domain_digest(),
            ChoiceValue::Boolean(false).canonical_bytes(),
        )?;
        assert!(
            request_group_selection(&request, &guest, &mut ReplyTransport(reply.encode()?),)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn constrained_group_matches_campaign_and_rejects_violating_reply() -> Result<(), Box<dyn Error>>
    {
        let name = String::from("recovery.fast_reroute");
        let admitted = BTreeSet::from([ChoiceValue::Boolean(true)]);
        let guest = build_guest_group(
            "router-a",
            "envoy.recovery",
            1,
            vec![(
                name.clone(),
                ChoiceDomain::Boolean(BooleanDomain::new(1)?),
                ChoiceValue::Boolean(true),
            )],
            BTreeSet::from([GuestChoiceConstraint::Member(name.clone(), admitted)]),
        )?;

        let domain = campaign::ChoiceDomain::Boolean(campaign::BooleanDomain::new(1)?);
        let default = campaign::ChoiceValue::Boolean(true);
        let declaration = campaign::SelectableDeclaration::new(
            name,
            campaign::ChoiceSource::Guest {
                node: String::from("router-a"),
                protocol_version: u32::from(crucible_protocol::SELECTABLE_PROTOCOL_VERSION),
            },
            domain.clone(),
            default.clone(),
            campaign::ChoiceClassContext::new(BTreeSet::new())?,
            BTreeSet::new(),
            true,
        )?;
        let id = declaration.id()?;
        let group = campaign::ChoiceGroup::new(
            &BTreeMap::from([(id, declaration)]),
            campaign::ChoiceGroupDomain::Cartesian {
                members: BTreeMap::from([(id, domain)]),
                constraints: BTreeSet::from([campaign::ChoiceRelationalConstraint::Member(
                    id,
                    BTreeSet::from([default.clone()]),
                )]),
            },
            campaign::ChoiceGroupApplication::new("envoy.recovery", 1)?,
        )?;
        let campaign_domain = campaign::ChoiceDomain::Group(Box::new(group.clone()));
        let campaign_default = campaign::ChoiceValue::Group(
            group.select(campaign::ChoiceTuple::new(BTreeMap::from([(id, default)])))?,
        );
        assert_eq!(guest.domain_bytes(), campaign_domain.canonical_bytes());
        assert_eq!(guest.default_bytes(), campaign_default.canonical_bytes());
        assert_eq!(
            guest.domain_digest(),
            campaign_domain.id()?.content_id().digest()
        );

        let mut violating = guest.default_bytes().to_vec();
        *violating.last_mut().ok_or("empty group default")? = 0;
        assert!(
            !campaign_domain.contains(&campaign::ChoiceValue::from_canonical_bytes(&violating)?)
        );
        let request = SelectionRequest::new(2, "recovery.response", "transport/one", None, 4096)?;
        let reply = SelectionReply::selected(2, [1; 32], guest.domain_digest(), violating)?;
        assert!(
            request_group_selection(&request, &guest, &mut ReplyTransport(reply.encode()?),)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn oversized_group_is_rejected_before_registration() -> Result<(), Box<dyn Error>> {
        let alternatives = (1..=3)
            .map(|index| {
                let id = AlternativeId::from_bytes([index; 32]);
                Ok((id, DiscreteAlternative::new(id, "x".repeat(1800), None)?))
            })
            .collect::<Result<BTreeMap<_, _>, ChoiceCodecError>>()?;
        let group = build_guest_group(
            "router-a",
            "envoy.recovery",
            1,
            vec![(
                String::from("recovery.route"),
                ChoiceDomain::Discrete(DiscreteDomain::new(1, alternatives)?),
                ChoiceValue::Discrete(AlternativeId::from_bytes([1; 32])),
            )],
            BTreeSet::new(),
        );
        assert!(matches!(
            group,
            Err(GuestGroupError::Codec(ChoiceCodecError::LimitExceeded {
                limit: "guest-selectable-envelope-bytes"
            }))
        ));
        Ok(())
    }
}
