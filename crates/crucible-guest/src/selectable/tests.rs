//! Guest selectable helper tests over a safe in-process transport.

use crucible_protocol::{SELECTABLE_DIGEST_BYTES, SelectableMessageKind, SelectionReplyStatus};

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
