//! Original fixed readiness cursors on the same lifetime socket and budget.
//!
//! Native callbacks own source issuance, current-cut revalidation and consumed
//! phase publication. This module retains and transports their exact bytes; it
//! never constructs an issuer permit or derives readiness from parsed metadata.
//! Every partial attempt remains in the same original socket journal. Failure
//! keeps the original actor, native receipt and offered/consumed ACK backing.

use std::sync::Arc;

use crucible_qemu_protocol::whole_control::{
    WHOLE_ACK_BYTES, WHOLE_FRAME_HEADER_BYTES,
    staged::{
        StagedControlProfile, StagedFrameKind, decode_frame_header, encode_frame_header,
        source_ready::{
            SOURCE_READY_BYTES, SourceReadyAcknowledgement, SourceReadyBinding, SourceReadyReceipt,
        },
    },
};
use thiserror::Error;

use super::whole_original_socket::{OriginalWholeSocket, WholeSocketError};

#[derive(Debug, Error)]
pub(crate) enum WholeSourceReadyError {
    #[error("original source readiness socket failed: {0}")]
    Socket(#[from] WholeSocketError),
    #[error("original source readiness correlation was refused")]
    Correlation,
    #[error("original source readiness peer closed")]
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "The Preparing-only controller keeps genuine source adoption and execution closed."
        )
    )]
    Closed,
}

#[derive(Clone, Copy, Eq, PartialEq)]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "The Preparing-only controller keeps genuine source adoption and execution closed."
    )
)]
enum ReadyPhase {
    Empty,
    Offering,
    ReceivingHeader,
    ReceivingAcknowledgement,
    AcknowledgementRetained,
    PublishingConsumed,
    Published,
    Refused,
}

/// Retains one original native receipt exchange with no renewable backing.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "The Preparing-only controller keeps genuine source adoption and execution closed."
    )
)]
pub(crate) struct OriginalWholeReadyExchange {
    process: u32,
    socket: Arc<OriginalWholeSocket>,
    profile: StagedControlProfile,
    phase: ReadyPhase,
    receipt: [u8; WHOLE_FRAME_HEADER_BYTES + SOURCE_READY_BYTES],
    receipt_extent: usize,
    binding: Option<SourceReadyBinding>,
    offered_written: usize,
    acknowledgement_header: [u8; WHOLE_FRAME_HEADER_BYTES],
    acknowledgement_header_received: usize,
    acknowledgement: [u8; WHOLE_ACK_BYTES],
    acknowledgement_received: usize,
    consumed: [u8; WHOLE_FRAME_HEADER_BYTES + WHOLE_ACK_BYTES],
    consumed_extent: usize,
    consumed_written: usize,
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "The Preparing-only controller keeps genuine source adoption and execution closed."
    )
)]
impl OriginalWholeReadyExchange {
    /// Prepares fixed transport storage before any native HOLD or socket claim.
    ///
    /// The caller charges this complete layout, retained profile and shared Arc
    /// metadata in its summed original provider constructor admission. No native
    /// getter, descriptor duplication, socket I/O or source effect occurs here.
    pub(crate) fn prepare(
        socket: Arc<OriginalWholeSocket>,
        profile: &StagedControlProfile,
    ) -> Result<Self, WholeSourceReadyError> {
        profile
            .validate_ready_exchange_capacity()
            .map_err(|_| WholeSourceReadyError::Correlation)?;
        Ok(Self {
            process: std::process::id(),
            socket,
            profile: profile.clone(),
            phase: ReadyPhase::Empty,
            receipt: [0; WHOLE_FRAME_HEADER_BYTES + SOURCE_READY_BYTES],
            receipt_extent: 0,
            binding: None,
            offered_written: 0,
            acknowledgement_header: [0; WHOLE_FRAME_HEADER_BYTES],
            acknowledgement_header_received: 0,
            acknowledgement: [0; WHOLE_ACK_BYTES],
            acknowledgement_received: 0,
            consumed: [0; WHOLE_FRAME_HEADER_BYTES + WHOLE_ACK_BYTES],
            consumed_extent: 0,
            consumed_written: 0,
        })
    }

    /// Retains a literal native-issued receipt before its first physical offer.
    ///
    /// Reentry may continue the same immutable offer; changed bytes or binding
    /// refuse without replacing storage, resetting cursors or refunding credit.
    pub(crate) fn offer_native_receipt(
        &mut self,
        body: &[u8],
        binding: &SourceReadyBinding,
        now_monotonic_ns: u64,
    ) -> Result<bool, WholeSourceReadyError> {
        self.check_owner()?;
        if self.phase == ReadyPhase::Empty {
            self.receipt_extent = body.len();
            let retained = body.len().min(SOURCE_READY_BYTES);
            self.receipt[WHOLE_FRAME_HEADER_BYTES..WHOLE_FRAME_HEADER_BYTES + retained]
                .copy_from_slice(&body[..retained]);
            self.binding = Some(binding.clone());
            let validation = SourceReadyReceipt::decode(body)
                .and_then(|receipt| receipt.validate_against(binding));
            if validation.is_err()
                || binding.scope != self.profile.compute.scope
                || self.profile.digest().ok() != Some(binding.profile_digest)
            {
                return self.refuse();
            }
            let header =
                encode_frame_header(StagedFrameKind::SourceReady, body.len(), &self.profile)
                    .map_err(|_| WholeSourceReadyError::Correlation)?;
            self.receipt[..WHOLE_FRAME_HEADER_BYTES].copy_from_slice(&header);
            self.phase = ReadyPhase::Offering;
        } else if self.phase != ReadyPhase::Offering
            || body != &self.receipt[WHOLE_FRAME_HEADER_BYTES..]
            || self.binding.as_ref() != Some(binding)
        {
            return self.refuse();
        }

        // One complete preowned frame keeps the constructor's two write-attempt
        // minimum honest; a short syscall retains and retries only its suffix.
        let source = &self.receipt[self.offered_written..];
        let progress = match self.socket.write_step(source, now_monotonic_ns) {
            Ok(progress) => progress,
            Err(error) => {
                self.phase = ReadyPhase::Refused;
                return Err(error.into());
            }
        };
        if progress.peer_closed {
            self.phase = ReadyPhase::Refused;
            return Err(WholeSourceReadyError::Closed);
        }
        self.offered_written += progress.actual_bytes;
        if self.offered_written == WHOLE_FRAME_HEADER_BYTES + SOURCE_READY_BYTES {
            self.phase = ReadyPhase::ReceivingHeader;
            return Ok(true);
        }
        Ok(false)
    }

    /// Receives at most one physical prefix of the exact original offered ACK.
    ///
    /// The native issuer subsequently consumes this full retained ACK against
    /// its own receipt and fresh cut. Transport completion grants no readiness.
    pub(crate) fn receive_acknowledgement(
        &mut self,
        now_monotonic_ns: u64,
    ) -> Result<bool, WholeSourceReadyError> {
        self.check_owner()?;
        if self.phase == ReadyPhase::AcknowledgementRetained {
            return Ok(true);
        }
        let destination = match self.phase {
            ReadyPhase::ReceivingHeader => {
                &mut self.acknowledgement_header[self.acknowledgement_header_received..]
            }
            ReadyPhase::ReceivingAcknowledgement => {
                &mut self.acknowledgement[self.acknowledgement_received..]
            }
            _ => return self.refuse(),
        };
        let progress = match self.socket.read_step(destination, now_monotonic_ns) {
            Ok(progress) => progress,
            Err(error) => {
                self.phase = ReadyPhase::Refused;
                return Err(error.into());
            }
        };
        if progress.peer_closed {
            self.phase = ReadyPhase::Refused;
            return Err(WholeSourceReadyError::Closed);
        }
        if self.phase == ReadyPhase::ReceivingHeader {
            self.acknowledgement_header_received += progress.actual_bytes;
            if self.acknowledgement_header_received == WHOLE_FRAME_HEADER_BYTES {
                if decode_frame_header(&self.acknowledgement_header, &self.profile)
                    != Ok((StagedFrameKind::SourceReadyAcknowledgement, WHOLE_ACK_BYTES))
                {
                    return self.refuse();
                }
                self.phase = ReadyPhase::ReceivingAcknowledgement;
            }
        } else {
            self.acknowledgement_received += progress.actual_bytes;
            if self.acknowledgement_received == WHOLE_ACK_BYTES {
                let validation = SourceReadyAcknowledgement::decode(&self.acknowledgement)
                    .and_then(|ack| {
                        ack.validate_against(&SourceReadyReceipt::decode(
                            &self.receipt[WHOLE_FRAME_HEADER_BYTES..],
                        )?)
                    });
                if validation.is_err() {
                    return self.refuse();
                }
                self.phase = ReadyPhase::AcknowledgementRetained;
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Borrows the same complete original ACK for literal native consumption.
    pub(crate) fn acknowledgement(&self) -> Result<&[u8; WHOLE_ACK_BYTES], WholeSourceReadyError> {
        self.check_owner()?;
        if self.phase != ReadyPhase::AcknowledgementRetained {
            return Err(WholeSourceReadyError::Correlation);
        }
        Ok(&self.acknowledgement)
    }

    /// Publishes the source's exact consumed ACK after its genuine phase commit.
    ///
    /// The caller invokes this only from the source-owned publication callback
    /// after full native cut revalidation. The byte equality below is necessary
    /// correlation and cannot substitute for that native predicate.
    pub(crate) fn publish_native_consumed(
        &mut self,
        body: &[u8],
        now_monotonic_ns: u64,
    ) -> Result<bool, WholeSourceReadyError> {
        self.check_owner()?;
        if self.phase == ReadyPhase::AcknowledgementRetained {
            self.consumed_extent = body.len();
            let retained = body.len().min(WHOLE_ACK_BYTES);
            self.consumed[WHOLE_FRAME_HEADER_BYTES..WHOLE_FRAME_HEADER_BYTES + retained]
                .copy_from_slice(&body[..retained]);
            if body != self.acknowledgement {
                return self.refuse();
            }
            let header = encode_frame_header(
                StagedFrameKind::SourceReadyAcknowledgementConsumed,
                body.len(),
                &self.profile,
            )
            .map_err(|_| WholeSourceReadyError::Correlation)?;
            self.consumed[..WHOLE_FRAME_HEADER_BYTES].copy_from_slice(&header);
            self.phase = ReadyPhase::PublishingConsumed;
        } else if self.phase != ReadyPhase::PublishingConsumed
            || body != &self.consumed[WHOLE_FRAME_HEADER_BYTES..]
        {
            return self.refuse();
        }
        let source = &self.consumed[self.consumed_written..];
        let progress = match self.socket.write_step(source, now_monotonic_ns) {
            Ok(progress) => progress,
            Err(error) => {
                self.phase = ReadyPhase::Refused;
                return Err(error.into());
            }
        };
        if progress.peer_closed {
            self.phase = ReadyPhase::Refused;
            return Err(WholeSourceReadyError::Closed);
        }
        self.consumed_written += progress.actual_bytes;
        if self.consumed_written == WHOLE_FRAME_HEADER_BYTES + WHOLE_ACK_BYTES {
            self.phase = ReadyPhase::Published;
            return Ok(true);
        }
        Ok(false)
    }

    fn check_owner(&self) -> Result<(), WholeSourceReadyError> {
        // Reject inherited state before touching any original socket mutex.
        if self.process != std::process::id() || self.phase == ReadyPhase::Refused {
            return Err(WholeSourceReadyError::Correlation);
        }
        Ok(())
    }

    fn refuse<T>(&mut self) -> Result<T, WholeSourceReadyError> {
        self.phase = ReadyPhase::Refused;
        Err(WholeSourceReadyError::Correlation)
    }
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- Actual socket controls fail on invariant violations.
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crucible_qemu_protocol::whole_control::WholeControlProfile;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    fn original_actor() -> (OriginalWholeReadyExchange, UnixStream) {
        let profile = StagedControlProfile {
            compute: WholeControlProfile {
                scope: [1; 32],
                operation_capacity: 2,
                body_byte_limit: 1024,
                native_history_byte_limit: 1_000_000,
                provider_history_byte_limit: 1_000_000,
                administrative_read_attempt_limit: 100,
                administrative_read_byte_limit: 100_000,
                administrative_write_attempt_limit: 100,
                administrative_write_byte_limit: 100_000,
                deadline_monotonic_ns: 1000,
                cpu_retirement_limit: 100,
                event_step_limit: 100,
                input_byte_limit: 100,
                input_record_limit: 10,
                output_byte_limit: 100,
                output_record_limit: 10,
            },
            input_stage_limit: 3,
            stage_body_byte_limit: 1024,
        };
        let (source, host) = UnixStream::pair().unwrap();
        let actor = Arc::new(
            OriginalWholeSocket::prepare(
                &profile,
                std::mem::size_of::<OriginalWholeReadyExchange>() as u64,
            )
            .unwrap(),
        );
        let exchange = OriginalWholeReadyExchange::prepare(Arc::clone(&actor), &profile).unwrap();
        actor.install_original_socket(source).unwrap();
        (exchange, host)
    }

    fn modeled_receipt(exchange: &OriginalWholeReadyExchange) -> [u8; SOURCE_READY_BYTES] {
        let mut receipt = SourceReadyReceipt::decode(include_bytes!(
            "../../../../protocol/crucible-qemu-protocol/testdata/source-ready-modeled-v1.bin"
        ))
        .unwrap();
        receipt.binding.profile_digest = exchange.profile.digest().unwrap();
        receipt.encode().unwrap()
    }

    fn acknowledge(exchange: &OriginalWholeReadyExchange) -> [u8; WHOLE_ACK_BYTES] {
        let receipt = SourceReadyReceipt::decode(&modeled_receipt(exchange)).unwrap();
        let acknowledgement = SourceReadyAcknowledgement::for_receipt(&receipt).unwrap();
        assert_eq!(
            exchange.receipt[WHOLE_FRAME_HEADER_BYTES..],
            modeled_receipt(exchange)
        );
        acknowledgement.encode().unwrap()
    }

    #[test]
    fn same_original_actor_retains_partial_ready_ack_and_exact_consumed_publication() {
        let (mut exchange, mut host) = original_actor();
        // Earlier lifetime activity remains charged in this same actor.
        exchange.socket.write_step(b"prior", 0).unwrap();
        let mut prior = [0; 5];
        host.read_exact(&mut prior).unwrap();
        let before = exchange.socket.counters().unwrap();
        let body = modeled_receipt(&exchange);
        let receipt = SourceReadyReceipt::decode(&body).unwrap();
        assert!(
            exchange
                .offer_native_receipt(&body, &receipt.binding, 0)
                .unwrap()
        );
        let mut offered = [0; WHOLE_FRAME_HEADER_BYTES + SOURCE_READY_BYTES];
        host.read_exact(&mut offered).unwrap();
        assert_eq!(&offered[WHOLE_FRAME_HEADER_BYTES..], &body);
        assert_eq!(
            decode_frame_header(&offered[..24], &exchange.profile).unwrap(),
            (StagedFrameKind::SourceReady, SOURCE_READY_BYTES)
        );
        let acknowledgement = acknowledge(&exchange);
        let header = encode_frame_header(
            StagedFrameKind::SourceReadyAcknowledgement,
            WHOLE_ACK_BYTES,
            &exchange.profile,
        )
        .unwrap();

        host.write_all(&header[..6]).unwrap();
        assert!(!exchange.receive_acknowledgement(0).unwrap());
        assert_eq!(exchange.acknowledgement_header_received, 6);
        host.write_all(&header[6..]).unwrap();
        assert!(!exchange.receive_acknowledgement(0).unwrap());
        host.write_all(&acknowledgement[..31]).unwrap();
        assert!(!exchange.receive_acknowledgement(0).unwrap());
        assert!(exchange.acknowledgement().is_err());
        host.write_all(&acknowledgement[31..]).unwrap();
        assert!(exchange.receive_acknowledgement(0).unwrap());
        assert_eq!(exchange.acknowledgement().unwrap(), &acknowledgement);
        assert!(
            exchange
                .publish_native_consumed(&acknowledgement, 0)
                .unwrap()
        );

        let mut consumed = [0; WHOLE_FRAME_HEADER_BYTES + WHOLE_ACK_BYTES];
        host.read_exact(&mut consumed).unwrap();
        assert_eq!(
            decode_frame_header(&consumed[..24], &exchange.profile).unwrap(),
            (
                StagedFrameKind::SourceReadyAcknowledgementConsumed,
                WHOLE_ACK_BYTES
            )
        );
        assert_eq!(&consumed[24..], &acknowledgement);
        let after = exchange.socket.counters().unwrap();
        assert_eq!(after.read_attempts - before.read_attempts, 4);
        assert_eq!(after.read_bytes - before.read_bytes, 152);
        assert_eq!(after.write_attempts - before.write_attempts, 2);
        assert_eq!(after.offered_write_bytes - before.offered_write_bytes, 520);
        assert!(exchange.receive_acknowledgement(0).is_err());
        assert_eq!(exchange.socket.counters().unwrap(), after);
    }

    #[test]
    fn changed_full_ack_retains_original_bytes_and_refuses_without_publication_or_renewal() {
        let (mut exchange, mut host) = original_actor();
        let body = modeled_receipt(&exchange);
        let receipt = SourceReadyReceipt::decode(&body).unwrap();
        exchange
            .offer_native_receipt(&body, &receipt.binding, 0)
            .unwrap();
        let header = encode_frame_header(
            StagedFrameKind::SourceReadyAcknowledgement,
            WHOLE_ACK_BYTES,
            &exchange.profile,
        )
        .unwrap();
        let mut changed = acknowledge(&exchange);
        changed[56] ^= 1;
        host.write_all(&header).unwrap();
        host.write_all(&changed).unwrap();
        assert!(!exchange.receive_acknowledgement(0).unwrap());
        assert!(exchange.receive_acknowledgement(0).is_err());
        assert_eq!(exchange.acknowledgement, changed);
        let counters = exchange.socket.counters().unwrap();
        assert!(exchange.publish_native_consumed(&changed, 0).is_err());
        assert!(
            exchange
                .offer_native_receipt(&body, &receipt.binding, 0)
                .is_err()
        );
        assert_eq!(exchange.socket.counters().unwrap(), counters);
        assert_eq!(exchange.consumed_written, 0);
        assert_eq!(exchange.receipt[24..], body);
    }

    #[test]
    fn premature_consumed_publication_and_changed_native_offer_are_sticky_refusals() {
        let (mut exchange, _host) = original_actor();
        let body = modeled_receipt(&exchange);
        let receipt = SourceReadyReceipt::decode(&body).unwrap();
        exchange
            .offer_native_receipt(&body, &receipt.binding, 0)
            .unwrap();
        let acknowledgement = acknowledge(&exchange);
        let counters = exchange.socket.counters().unwrap();
        assert!(
            exchange
                .publish_native_consumed(&acknowledgement, 0)
                .is_err()
        );
        assert_eq!(exchange.socket.counters().unwrap(), counters);
        assert_eq!(exchange.consumed_written, 0);

        let (mut exchange, _host) = original_actor();
        exchange
            .offer_native_receipt(&body, &receipt.binding, 0)
            .unwrap();
        let mut changed = body;
        changed[200] ^= 1;
        let counters = exchange.socket.counters().unwrap();
        assert!(
            exchange
                .offer_native_receipt(&changed, &receipt.binding, 0)
                .is_err()
        );
        assert_eq!(exchange.socket.counters().unwrap(), counters);
        assert_eq!(exchange.receipt[24..], body);
        assert_eq!(exchange.receipt_extent, 344);
    }
    #[test]
    fn actual_partial_ready_offer_keeps_full_receipt_and_nonrenewing_byte_credit() {
        let (mut exchange, mut host) = original_actor();
        let body = modeled_receipt(&exchange);
        let binding = SourceReadyReceipt::decode(&body).unwrap().binding;
        let remaining = 17usize;
        let limit = exchange.profile.compute.administrative_write_byte_limit as usize;
        let prior = vec![0x70; limit - remaining];

        let progress = exchange.socket.write_step(&prior, 0).unwrap();
        assert_eq!(progress.actual_bytes, prior.len());
        let mut received_prior = vec![0; prior.len()];
        host.read_exact(&mut received_prior).unwrap();
        assert_eq!(received_prior, prior);

        assert!(!exchange.offer_native_receipt(&body, &binding, 0).unwrap());
        assert_eq!(exchange.offered_written, remaining);
        let mut prefix = [0; 17];
        host.read_exact(&mut prefix).unwrap();
        assert_eq!(prefix, exchange.receipt[..remaining]);
        assert_eq!(&exchange.receipt[WHOLE_FRAME_HEADER_BYTES..], body);
        assert_eq!(
            exchange.socket.counters().unwrap().offered_write_bytes,
            limit as u64
        );

        assert!(exchange.offer_native_receipt(&body, &binding, 0).is_err());
        assert_eq!(exchange.offered_written, remaining);
        assert_eq!(&exchange.receipt[WHOLE_FRAME_HEADER_BYTES..], body);
        assert!(exchange.acknowledgement().is_err());
        assert!(exchange.publish_native_consumed(&[0; 128], 0).is_err());
    }
}
