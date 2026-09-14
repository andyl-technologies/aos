//! Sealed descriptor-subject carrier operations for SourceProvider records.

use std::os::fd::OwnedFd;

use aos_sandbox_linux::seqpacket::SeqpacketError;
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;
use aos_sandbox_source_provider_protocol::MAXIMUM_FRAME_BYTES;

use crate::SourceProviderSecurityError;
use crate::execution::ProcessExecutionEvidenceV1;

pub(crate) struct ReceivedSourceProviderRecordV1 {
    pub(crate) payload: Vec<u8>,
    pub(crate) descriptors: Vec<OwnedFd>,
    pub(crate) execution: ProcessExecutionEvidenceV1,
}

pub(crate) struct InertSourceProviderCarrierV1 {
    socket: DescriptorSubjectSocket,
    poisoned: bool,
    interrupted_retries: u8,
}

pub(crate) struct ClosedSourceProviderCarrierV1 {
    _carrier: InertSourceProviderCarrierV1,
}

impl InertSourceProviderCarrierV1 {
    pub(crate) fn adopt(
        socket: DescriptorSubjectSocket,
    ) -> Result<Self, SourceProviderSecurityError> {
        socket
            .provision_packet_capacity(MAXIMUM_FRAME_BYTES)
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        Ok(Self {
            socket,
            poisoned: false,
            interrupted_retries: 0,
        })
    }

    pub(crate) const fn socket(&self) -> &DescriptorSubjectSocket {
        &self.socket
    }

    pub(crate) fn close(&mut self) {
        self.poisoned = true;
        self.socket.close();
    }

    pub(crate) fn close_owned(mut self) -> ClosedSourceProviderCarrierV1 {
        self.close();
        ClosedSourceProviderCarrierV1 { _carrier: self }
    }

    pub(crate) fn send(&mut self, payload: &[u8]) -> Result<(), CarrierFailureV1> {
        if self.poisoned {
            return Err(CarrierFailureV1::Fatal(
                SourceProviderSecurityError::Poisoned,
            ));
        }
        match self.socket.send(payload) {
            Ok(()) => {
                self.interrupted_retries = 0;
                Ok(())
            }
            Err(SeqpacketError::WouldBlock) => Err(CarrierFailureV1::Retryable),
            Err(SeqpacketError::Interrupted) => self.interrupted_retry(),
            Err(_) => {
                self.close();
                Err(CarrierFailureV1::Fatal(
                    SourceProviderSecurityError::SessionContinuity,
                ))
            }
        }
    }

    pub(crate) fn receive_zero_descriptors(
        &mut self,
        maximum_bytes: usize,
    ) -> Result<ReceivedSourceProviderRecordV1, CarrierFailureV1> {
        self.receive(false, maximum_bytes)
    }

    pub(crate) fn receive_optional_source_root(
        &mut self,
    ) -> Result<ReceivedSourceProviderRecordV1, CarrierFailureV1> {
        self.receive(true, MAXIMUM_FRAME_BYTES)
    }

    fn receive(
        &mut self,
        optional_source_root: bool,
        maximum_bytes: usize,
    ) -> Result<ReceivedSourceProviderRecordV1, CarrierFailureV1> {
        if self.poisoned {
            return Err(CarrierFailureV1::Fatal(
                SourceProviderSecurityError::Poisoned,
            ));
        }
        let received = if optional_source_root {
            self.socket.receive_optional_descriptor_reply(maximum_bytes)
        } else {
            self.socket.receive(maximum_bytes, 0)
        };
        let received = match received {
            Ok(received) => received,
            Err(SeqpacketError::WouldBlock) => {
                return Err(CarrierFailureV1::Retryable);
            }
            Err(SeqpacketError::Interrupted) => return self.interrupted_retry(),
            Err(_) => {
                self.close();
                return Err(CarrierFailureV1::Fatal(
                    SourceProviderSecurityError::SessionContinuity,
                ));
            }
        };
        let bound = match self.socket.bind_received(received) {
            Ok(bound) => bound,
            Err(_) => {
                self.close();
                return Err(CarrierFailureV1::Fatal(
                    SourceProviderSecurityError::SessionContinuity,
                ));
            }
        };
        self.interrupted_retries = 0;
        let (payload, subject, descriptors, peer) = bound.into_parts();
        let execution = match ProcessExecutionEvidenceV1::capture(peer, subject) {
            Ok(execution) => execution,
            Err(error) => {
                self.close();
                return Err(CarrierFailureV1::Fatal(error));
            }
        };
        Ok(ReceivedSourceProviderRecordV1 {
            payload,
            descriptors,
            execution,
        })
    }

    fn interrupted_retry<T>(&mut self) -> Result<T, CarrierFailureV1> {
        match self.interrupted_retries.checked_add(1) {
            Some(retries) if retries <= 8 => {
                self.interrupted_retries = retries;
                Err(CarrierFailureV1::Retryable)
            }
            _ => {
                self.close();
                Err(CarrierFailureV1::Fatal(
                    SourceProviderSecurityError::SessionContinuity,
                ))
            }
        }
    }
}

pub(crate) enum CarrierFailureV1 {
    Retryable,
    Fatal(SourceProviderSecurityError),
}
