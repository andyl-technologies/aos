//! Guest selectable helper tests over a safe in-process transport.

use std::collections::BTreeMap;

use crucible_campaign as campaign;
use crucible_protocol::{
    AlternativeId, ChoiceDomain, ChoiceValue, DiscreteAlternative, DiscreteDomain,
    SELECTABLE_DIGEST_BYTES, SelectableMessageKind, SelectionReplyStatus,
};

use super::*;

struct Untouched;

impl DoorbellTransport for Untouched {
    fn ring(&mut self, _frame: &mut [u8]) -> Result<(), GuestEmitterError> {
        Ok(())
    }
}

struct Replace {
    reply: Vec<u8>,
    clear_tail: bool,
}

fn must<T, E: std::fmt::Display>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| panic!("test fixture construction failed: {error}"))
}

impl DoorbellTransport for Replace {
    fn ring(&mut self, frame: &mut [u8]) -> Result<(), GuestEmitterError> {
        if self.clear_tail {
            frame.fill(0);
        }
        if self.reply.len() > frame.len() {
            return Err(GuestEmitterError::Transport {
                message: String::from("test reply exceeds lent buffer"),
            });
        }
        frame[..self.reply.len()].copy_from_slice(&self.reply);
        Ok(())
    }
}

fn registration() -> Result<SelectableRegister, SelectableProtocolError> {
    SelectableRegister::new(
        1,
        "network.recovery-policy",
        vec![1, 2, 3],
        vec![1],
        vec![String::from("network"), String::from("recovery")],
    )
}

fn request(sequence: u64) -> Result<SelectionRequest, SelectableProtocolError> {
    SelectionRequest::new(sequence, "network.recovery-policy", "routing/7", None, 256)
}

fn recovery_domain() -> ChoiceDomain {
    let fast = AlternativeId::from_bytes([1; 32]);
    let safe = AlternativeId::from_bytes([2; 32]);
    let mut alternatives = BTreeMap::new();
    alternatives.insert(fast, must(DiscreteAlternative::new(fast, "fast", None)));
    alternatives.insert(safe, must(DiscreteAlternative::new(safe, "safe", None)));
    ChoiceDomain::Discrete(must(DiscreteDomain::new(1, alternatives)))
}

#[test]
fn l1_choice_codec_matches_the_campaign_semantic_codec() {
    let protocol_domain = recovery_domain();
    let campaign_fast =
        campaign::AlternativeId::from_hash(campaign::CampaignHash::from_bytes([1; 32]));
    let campaign_safe =
        campaign::AlternativeId::from_hash(campaign::CampaignHash::from_bytes([2; 32]));
    let mut campaign_alternatives = BTreeMap::new();
    campaign_alternatives.insert(
        campaign_fast,
        must(campaign::DiscreteAlternative::new(
            campaign_fast,
            "fast",
            None,
        )),
    );
    campaign_alternatives.insert(
        campaign_safe,
        must(campaign::DiscreteAlternative::new(
            campaign_safe,
            "safe",
            None,
        )),
    );
    let campaign_domain = campaign::ChoiceDomain::Discrete(must(campaign::DiscreteDomain::new(
        1,
        campaign_alternatives,
    )));

    assert_eq!(
        protocol_domain.canonical_bytes(),
        campaign_domain.canonical_bytes()
    );
    assert_eq!(
        ChoiceValue::Discrete(AlternativeId::from_bytes([1; 32])).canonical_bytes(),
        campaign::ChoiceValue::Discrete(campaign_fast).canonical_bytes(),
    );
}

#[test]
fn typed_registration_emits_exact_observational_bytes() -> Result<(), GuestSelectableError> {
    let registration = registration()?;
    let outcome = emit_selectable_registration(&registration, &mut Untouched)?;
    assert_eq!(outcome.bytes(), registration.encode()?);
    assert_eq!(
        u16::from_le_bytes([outcome.bytes()[2], outcome.bytes()[3]]),
        SelectableMessageKind::Register.wire_value()
    );
    Ok(())
}

#[test]
fn typed_request_accepts_only_the_exact_sequence_bound_reply() -> Result<(), GuestSelectableError> {
    let request = request(41)?;
    let reply = SelectionReply::selected(
        41,
        [1; SELECTABLE_DIGEST_BYTES],
        [2; SELECTABLE_DIGEST_BYTES],
        vec![3],
    )?;
    let mut transport = Replace {
        reply: reply.encode()?,
        clear_tail: true,
    };
    let outcome = request_selection(&request, &mut transport)?;
    assert_eq!(outcome.request_bytes(), request.encode()?);
    assert_eq!(outcome.reply(), &reply);
    Ok(())
}

#[test]
fn typed_request_preserves_typed_rejections() -> Result<(), GuestSelectableError> {
    let request = request(7)?;
    let reply = SelectionReply::rejected(
        7,
        SelectionReplyStatus::UnknownSelectable,
        [0; SELECTABLE_DIGEST_BYTES],
        [0; SELECTABLE_DIGEST_BYTES],
    )?;
    let outcome = request_selection(
        &request,
        &mut Replace {
            reply: reply.encode()?,
            clear_tail: true,
        },
    )?;
    assert_eq!(
        outcome.reply().status(),
        SelectionReplyStatus::UnknownSelectable
    );
    assert_eq!(outcome.reply().selected_value(), None);
    Ok(())
}

#[test]
fn typed_helpers_reject_mutation_stale_reply_and_uncleared_tail() -> Result<(), GuestSelectableError>
{
    let registration = registration()?;
    let mut mutation = Replace {
        reply: vec![2],
        clear_tail: false,
    };
    assert_eq!(
        emit_selectable_registration(&registration, &mut mutation),
        Err(GuestSelectableError::RegistrationMutated)
    );

    let request = request(11)?;
    let stale = SelectionReply::rejected(
        10,
        SelectionReplyStatus::Unavailable,
        [0; SELECTABLE_DIGEST_BYTES],
        [0; SELECTABLE_DIGEST_BYTES],
    )?;
    assert_eq!(
        request_selection(
            &request,
            &mut Replace {
                reply: stale.encode()?,
                clear_tail: true,
            }
        ),
        Err(GuestSelectableError::ReplySequenceMismatch {
            expected: 11,
            actual: 10,
        })
    );

    let reply = SelectionReply::rejected(
        11,
        SelectionReplyStatus::Unavailable,
        [0; SELECTABLE_DIGEST_BYTES],
        [0; SELECTABLE_DIGEST_BYTES],
    )?;
    let mut dirty_reply = reply.encode()?;
    dirty_reply.push(1);
    assert_eq!(
        request_selection(
            &request,
            &mut Replace {
                reply: dirty_reply,
                clear_tail: false,
            }
        ),
        Err(GuestSelectableError::ReplyTailNotCleared)
    );
    Ok(())
}

#[test]
fn product_registration_uses_the_shared_typed_domain_codec() -> Result<(), GuestSelectableError> {
    let domain = recovery_domain();
    let default = ChoiceValue::Discrete(AlternativeId::from_bytes([2; 32]));
    let registration = build_selectable_registration(
        1,
        "network.recovery-policy",
        &domain,
        &default,
        vec![String::from("network"), String::from("recovery")],
    )?;
    assert_eq!(registration.domain(), domain.canonical_bytes());
    assert_eq!(registration.default_value(), default.canonical_bytes());

    let foreign = ChoiceValue::Discrete(AlternativeId::from_bytes([9; 32]));
    assert_eq!(
        build_selectable_registration(2, "network.recovery-policy", &domain, &foreign, Vec::new()),
        Err(GuestSelectableError::DefaultOutsideDomain)
    );
    Ok(())
}

#[test]
fn product_request_decodes_and_revalidates_the_selected_value() -> Result<(), GuestSelectableError>
{
    let domain = recovery_domain();
    let selected = ChoiceValue::Discrete(AlternativeId::from_bytes([1; 32]));
    let request = request(71)?;
    let reply = SelectionReply::selected(
        71,
        [3; SELECTABLE_DIGEST_BYTES],
        [4; SELECTABLE_DIGEST_BYTES],
        selected.canonical_bytes(),
    )?;
    let outcome = request_typed_selection(
        &request,
        &domain,
        &mut Replace {
            reply: reply.encode()?,
            clear_tail: true,
        },
    )?;
    assert_eq!(outcome.value(), &selected);

    let foreign = ChoiceValue::Discrete(AlternativeId::from_bytes([9; 32]));
    let reply = SelectionReply::selected(
        71,
        [3; SELECTABLE_DIGEST_BYTES],
        [4; SELECTABLE_DIGEST_BYTES],
        foreign.canonical_bytes(),
    )?;
    assert_eq!(
        request_typed_selection(
            &request,
            &domain,
            &mut Replace {
                reply: reply.encode()?,
                clear_tail: true,
            },
        ),
        Err(GuestSelectableError::SelectedValueOutsideDomain)
    );
    Ok(())
}

#[test]
fn product_request_keeps_typed_host_rejection_distinct() -> Result<(), GuestSelectableError> {
    let domain = recovery_domain();
    let request = request(81)?;
    let reply = SelectionReply::rejected(
        81,
        SelectionReplyStatus::NoAdmissibleValue,
        [0; SELECTABLE_DIGEST_BYTES],
        [0; SELECTABLE_DIGEST_BYTES],
    )?;
    assert_eq!(
        request_typed_selection(
            &request,
            &domain,
            &mut Replace {
                reply: reply.encode()?,
                clear_tail: true,
            },
        ),
        Err(GuestSelectableError::SelectionRejected {
            status: SelectionReplyStatus::NoAdmissibleValue,
        })
    );
    Ok(())
}
