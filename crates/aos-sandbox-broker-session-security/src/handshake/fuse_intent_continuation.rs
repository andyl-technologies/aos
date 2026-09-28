//! Nonterminal preparation controls on the original authenticated FUSE socket.
//!
//! ```text
//! AOSFIC01 || version:u16be=1 || kind:u8 || reserved:u8=0 ||
//! method:u16be=44 || purpose:u32be=57 || major:u16be=3 || minor:u16be=0 ||
//! deadline:u64be || session[32] || signed-request[32] || semantics[32] ||
//! challenge[32] || optional exact reservation coordinates[80]
//! ```
//!
//! These zero-FD controls never advance RequestPrepared into a terminal
//! outcome. The holder borrows the actual session (and therefore its original
//! socket and locked journal) throughout the exchange. Rechecking a temporary
//! journal borrow does not unlock, drop, reopen or replace that writer.
//! Reservation coordinates are comparison data, not a worker/Root read grant.
//! The eventual owner composition must additionally keep its genuine Mount
//! reservation, Controller writer and original Host/kernel custody held.

use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodRequestV1, AuthenticatedBrokerRequestDirectionV1,
};

use super::DormantAuthenticatedBrokerSessionV1;
use crate::entropy::{KernelEntropy, nonzero_random};
use crate::{BrokerSessionSecurityError, DormantBrokerSessionHandshakeErrorV1};

const MAGIC: &[u8; 8] = b"AOSFIC01";
const HEADER_BYTES: usize = 158;
const COORDINATE_BYTES: usize = 80;
const MAXIMUM_BYTES: usize = HEADER_BYTES + COORDINATE_BYTES;

/// Carries only broker-assigned comparison coordinates for local Host issuance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FuseIntentReservationCoordinatesV1 {
    /// Carries a structural worker locator, never proof of reservation or reuse safety.
    pub(crate) worker_locator: [u8; 16],
    /// Carries the expected durable reservation/origin commitment for comparison.
    pub(crate) reservation_digest: [u8; 32],
    /// Carries the exact presentation-plan commitment for local request joining.
    pub(crate) presentation_plan_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Control {
    Challenge,
    HeldAcknowledgement,
    Reservation(FuseIntentReservationCoordinatesV1),
    ReservationAcknowledgement(FuseIntentReservationCoordinatesV1),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Binding {
    deadline: u64,
    session: [u8; 32],
    signed_request: [u8; 32],
    semantics: [u8; 32],
    challenge: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stage {
    BrokerChallenge,
    ClientChallenge,
    ClientHeldAck,
    BrokerHeldAck,
    BrokerReservation,
    ClientReservation,
    ClientReservationAck(FuseIntentReservationCoordinatesV1),
    BrokerReservationAck(FuseIntentReservationCoordinatesV1),
    Prepared(FuseIntentReservationCoordinatesV1),
    ReconciliationRequired,
}

/// Holds original pending-request transport custody, never consumer authority.
#[must_use = "retain original session custody through preparation/reconciliation"]
pub(crate) struct HeldFuseIntentTransportV1<'session> {
    session: &'session mut DormantAuthenticatedBrokerSessionV1,
    request: &'session AuthenticatedBrokerMethodRequestV1,
    original_head: [u8; 32],
    binding: Binding,
    stage: Stage,
}

impl<'session> HeldFuseIntentTransportV1<'session> {
    pub(super) fn capture(
        session: &'session mut DormantAuthenticatedBrokerSessionV1,
        request: &'session AuthenticatedBrokerMethodRequestV1,
    ) -> Result<Self, BrokerSessionSecurityError> {
        if usize::try_from(request.maximum_response_bytes())
            .map_err(|_| BrokerSessionSecurityError::Currentness)?
            < MAXIMUM_BYTES
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let original_head = session
            .owner
            .hold_fuse_intent_request(request, &session.transcript, session.socket.peer())?
            .head_commitment();
        let broker = request.direction() == AuthenticatedBrokerRequestDirectionV1::ServerReceive;
        let challenge = if broker {
            nonzero_random(&mut KernelEntropy)?
        } else {
            [0; 32]
        };
        Ok(Self {
            session,
            request,
            original_head,
            binding: Binding {
                deadline: request.deadline_boottime_nanoseconds(),
                session: request.session_binding(),
                signed_request: request.signed_request_digest(),
                semantics: request.semantic_commitment(),
                challenge,
            },
            stage: if broker {
                Stage::BrokerChallenge
            } else {
                Stage::ClientChallenge
            },
        })
    }

    /// Reauthenticates the same nonterminal protected head and original peer.
    pub(crate) fn recheck(&mut self) -> Result<(), BrokerSessionSecurityError> {
        let result = self.recheck_original_head();
        if result.is_err() {
            self.stage = Stage::ReconciliationRequired;
        }
        result
    }

    fn recheck_original_head(&mut self) -> Result<(), BrokerSessionSecurityError> {
        if self.stage == Stage::ReconciliationRequired {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let mut pending = self.session.owner.hold_fuse_intent_request(
            self.request,
            &self.session.transcript,
            self.session.socket.peer(),
        )?;
        pending.recheck()?;
        if pending.head_commitment() != self.original_head {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(())
    }

    /// Sends one challenge/ack on the same socket without issuing an outcome.
    pub(crate) fn send_preparation_control(
        &mut self,
    ) -> Result<(), DormantBrokerSessionHandshakeErrorV1> {
        let (control, next) = match self.stage {
            Stage::BrokerChallenge => (Control::Challenge, Stage::BrokerHeldAck),
            Stage::ClientHeldAck => (Control::HeldAcknowledgement, Stage::ClientReservation),
            Stage::ClientReservationAck(coordinates) => (
                Control::ReservationAcknowledgement(coordinates),
                Stage::Prepared(coordinates),
            ),
            _ => return Err(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid),
        };
        self.send(control, next)
    }

    /// Sends comparison coordinates only; the caller still owes genuine Mount custody.
    ///
    /// This does not certify the row or mint a guard from these scalar fields.
    /// It is private to the closed owner composition and remains unadvertised.
    pub(crate) fn send_reservation_coordinates(
        &mut self,
        coordinates: FuseIntentReservationCoordinatesV1,
    ) -> Result<(), DormantBrokerSessionHandshakeErrorV1> {
        if self.stage != Stage::BrokerReservation || !coordinates_valid(coordinates) {
            return Err(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid);
        }
        self.send(
            Control::Reservation(coordinates),
            Stage::BrokerReservationAck(coordinates),
        )
    }

    /// Receives only an exact original-peer zero-FD preparation record.
    pub(crate) fn receive_preparation_control(
        &mut self,
    ) -> Result<(), DormantBrokerSessionHandshakeErrorV1> {
        self.recheck()?;
        // The reused receive path binds every record's SCM credentials/pidfd
        // to the retained original peer, then rechecks live endpoint custody.
        let packet = match self.session.receive_response_packet(MAXIMUM_BYTES) {
            Ok(packet) => packet,
            Err(DormantBrokerSessionHandshakeErrorV1::Transport) => {
                return Err(DormantBrokerSessionHandshakeErrorV1::Transport);
            }
            Err(error) => {
                self.stage = Stage::ReconciliationRequired;
                return Err(error);
            }
        };
        let result = self.admit_control(&packet);
        if result.is_err() {
            self.stage = Stage::ReconciliationRequired;
        }
        result?;
        self.recheck()?;
        Ok(())
    }

    /// Returns prepared coordinates for comparison/local issuance, not authority.
    pub(crate) fn prepared_coordinates(
        &mut self,
    ) -> Result<FuseIntentReservationCoordinatesV1, BrokerSessionSecurityError> {
        self.recheck()?;
        match self.stage {
            Stage::Prepared(coordinates) => Ok(coordinates),
            _ => Err(BrokerSessionSecurityError::Currentness),
        }
    }

    fn send(
        &mut self,
        control: Control,
        next: Stage,
    ) -> Result<(), DormantBrokerSessionHandshakeErrorV1> {
        self.recheck()?;
        let packet = encode(self.binding, control);
        match self.session.send_request_packet(&packet) {
            Ok(()) => self.stage = next,
            Err(DormantBrokerSessionHandshakeErrorV1::Transport) => {
                return Err(DormantBrokerSessionHandshakeErrorV1::Transport);
            }
            Err(error) => {
                self.stage = Stage::ReconciliationRequired;
                return Err(error);
            }
        }
        self.recheck()?;
        Ok(())
    }

    fn admit_control(&mut self, packet: &[u8]) -> Result<(), DormantBrokerSessionHandshakeErrorV1> {
        let (binding, control) = decode(packet)?;
        let original = Binding {
            challenge: binding.challenge,
            ..self.binding
        };
        if binding != original
            || binding.challenge == [0; 32]
            || (self.binding.challenge != [0; 32] && binding.challenge != self.binding.challenge)
        {
            return Err(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid);
        }
        self.stage = match (self.stage, control) {
            (Stage::ClientChallenge, Control::Challenge) => Stage::ClientHeldAck,
            (Stage::BrokerHeldAck, Control::HeldAcknowledgement) => Stage::BrokerReservation,
            (Stage::ClientReservation, Control::Reservation(coordinates)) => {
                Stage::ClientReservationAck(coordinates)
            }
            (
                Stage::BrokerReservationAck(expected),
                Control::ReservationAcknowledgement(observed),
            ) if expected == observed => Stage::Prepared(expected),
            _ => return Err(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid),
        };
        self.binding.challenge = binding.challenge;
        Ok(())
    }
}

fn coordinates_valid(coordinates: FuseIntentReservationCoordinatesV1) -> bool {
    coordinates.worker_locator != [0; 16]
        && coordinates.reservation_digest != [0; 32]
        && coordinates.presentation_plan_digest != [0; 32]
}

fn encode(binding: Binding, control: Control) -> Vec<u8> {
    let (kind, coordinates) = match control {
        Control::Challenge => (1, None),
        Control::HeldAcknowledgement => (2, None),
        Control::Reservation(coordinates) => (3, Some(coordinates)),
        Control::ReservationAcknowledgement(coordinates) => (4, Some(coordinates)),
    };
    let mut bytes = Vec::with_capacity(MAXIMUM_BYTES);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&[kind, 0]);
    bytes.extend_from_slice(&44_u16.to_be_bytes());
    bytes.extend_from_slice(&57_u32.to_be_bytes());
    bytes.extend_from_slice(&3_u16.to_be_bytes());
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    bytes.extend_from_slice(&binding.deadline.to_be_bytes());
    for commitment in [
        binding.session,
        binding.signed_request,
        binding.semantics,
        binding.challenge,
    ] {
        bytes.extend_from_slice(&commitment);
    }
    if let Some(coordinates) = coordinates {
        bytes.extend_from_slice(&coordinates.worker_locator);
        bytes.extend_from_slice(&coordinates.reservation_digest);
        bytes.extend_from_slice(&coordinates.presentation_plan_digest);
    }
    bytes
}

fn decode(bytes: &[u8]) -> Result<(Binding, Control), DormantBrokerSessionHandshakeErrorV1> {
    let invalid = || DormantBrokerSessionHandshakeErrorV1::RemoteInvalid;
    if !matches!(bytes.len(), HEADER_BYTES | MAXIMUM_BYTES)
        || bytes.get(..8) != Some(MAGIC.as_slice())
        || bytes.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
        || bytes[11] != 0
        || bytes.get(12..22) != Some([0, 44, 0, 0, 0, 57, 0, 3, 0, 0].as_slice())
    {
        return Err(invalid());
    }
    let binding = Binding {
        deadline: u64::from_be_bytes(bytes[22..30].try_into().map_err(|_| invalid())?),
        session: bytes[30..62].try_into().map_err(|_| invalid())?,
        signed_request: bytes[62..94].try_into().map_err(|_| invalid())?,
        semantics: bytes[94..126].try_into().map_err(|_| invalid())?,
        challenge: bytes[126..158].try_into().map_err(|_| invalid())?,
    };
    if binding.deadline == 0
        || [
            binding.session,
            binding.signed_request,
            binding.semantics,
            binding.challenge,
        ]
        .contains(&[0; 32])
    {
        return Err(invalid());
    }
    let control = match (bytes[10], bytes.len()) {
        (1, HEADER_BYTES) => Control::Challenge,
        (2, HEADER_BYTES) => Control::HeldAcknowledgement,
        (kind @ (3 | 4), MAXIMUM_BYTES) => {
            let coordinates = FuseIntentReservationCoordinatesV1 {
                worker_locator: bytes[158..174].try_into().map_err(|_| invalid())?,
                reservation_digest: bytes[174..206].try_into().map_err(|_| invalid())?,
                presentation_plan_digest: bytes[206..238].try_into().map_err(|_| invalid())?,
            };
            if !coordinates_valid(coordinates) {
                return Err(invalid());
            }
            if kind == 3 {
                Control::Reservation(coordinates)
            } else {
                Control::ReservationAcknowledgement(coordinates)
            }
        }
        _ => return Err(invalid()),
    };
    Ok((binding, control))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest as _;

    #[test]
    fn preparation_records_bind_the_original_request_and_refuse_extensions() {
        let binding = Binding {
            deadline: 100,
            session: [1; 32],
            signed_request: [2; 32],
            semantics: [3; 32],
            challenge: [4; 32],
        };
        let coordinates = FuseIntentReservationCoordinatesV1 {
            worker_locator: [5; 16],
            reservation_digest: [6; 32],
            presentation_plan_digest: [7; 32],
        };
        assert_eq!(
            hex::encode(sha2::Sha256::digest(encode(
                binding,
                Control::Reservation(coordinates)
            ))),
            "bab05e80d4f41a124308d26e954092bc0b35e256e2e48b868ea6d55e104ee432"
        );
        for control in [
            Control::Challenge,
            Control::HeldAcknowledgement,
            Control::Reservation(coordinates),
            Control::ReservationAcknowledgement(coordinates),
        ] {
            let bytes = encode(binding, control);
            assert_eq!(decode(&bytes).unwrap(), (binding, control));
            for length in 0..bytes.len() {
                assert!(decode(&bytes[..length]).is_err(), "truncation {length}");
            }
            let mut trailing = bytes.clone();
            trailing.push(0);
            assert!(decode(&trailing).is_err());
            for offset in [0, 8, 9, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21] {
                let mut changed = bytes.clone();
                changed[offset] ^= 1;
                assert!(decode(&changed).is_err(), "header substitution {offset}");
            }
        }
    }
}
