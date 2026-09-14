//! Root Mount hello preparation, send, and provider authentication states.

use std::num::NonZeroU64;

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;
use aos_sandbox_source_provider_protocol::{
    SignedSourceProviderHelloV1, SourceProviderHelloV1, SourceProviderMessageV1,
    SourceProviderPeerRole, SourceProviderSessionV1, decode_message, encode_message, sign_hello,
};

use super::{HandshakeTransitionV1, current_unix_seconds, process_identity};
use crate::SourceProviderSecurityError;
use crate::carrier::{CarrierFailureV1, InertSourceProviderCarrierV1};
use crate::custody::ProtectedRootMountCustodyV1;
use crate::execution::ProcessExecutionEvidenceV1;

pub(super) struct RootMountHelloPreparedV1 {
    custody: ProtectedRootMountCustodyV1,
    carrier: InertSourceProviderCarrierV1,
    nonce: [u8; 32],
    signed_hello: SignedSourceProviderHelloV1,
    packet: Vec<u8>,
}

pub(super) struct RootMountHelloSentV1 {
    custody: ProtectedRootMountCustodyV1,
    carrier: InertSourceProviderCarrierV1,
    nonce: [u8; 32],
    signed_hello: SignedSourceProviderHelloV1,
}

/// Owns the current authenticated Root Mount view of one provider session.
///
/// No public constructor or carrier/session extractor exists.
pub struct CurrentRootMountSourceProviderSessionV1 {
    custody: ProtectedRootMountCustodyV1,
    carrier: InertSourceProviderCarrierV1,
    session: SourceProviderSessionV1,
    provider_execution: ProcessExecutionEvidenceV1,
}

impl core::fmt::Debug for CurrentRootMountSourceProviderSessionV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("CurrentRootMountSourceProviderSessionV1([redacted])")
    }
}

impl RootMountHelloPreparedV1 {
    pub(super) fn prepare(
        mut custody: ProtectedRootMountCustodyV1,
        socket: DescriptorSubjectSocket,
    ) -> Result<Self, SourceProviderSecurityError> {
        let mut carrier = InertSourceProviderCarrierV1::adopt(socket)?;
        let now = match current_unix_seconds() {
            Ok(now) => now,
            Err(error) => return Err(poison_and_close(&mut custody, &mut carrier, error)),
        };
        if let Err(error) = custody.inner_mut().revalidate_at(now) {
            return Err(poison_and_close(&mut custody, &mut carrier, error));
        }
        let nonce = match custody.draw_nonce_at(now) {
            Ok(nonce) => nonce,
            Err(error) => return Err(poison_and_close(&mut custody, &mut carrier, error)),
        };
        let hello = {
            let inner = custody.inner();
            SourceProviderHelloV1::new(
                SourceProviderPeerRole::RootMount,
                nonce,
                inner.process_instance(),
                inner.execution().boot_id(),
                inner.root_authority().traffic_signer().clone(),
                inner.provider_authority().traffic_signer().clone(),
                inner.route().route_id(),
                inner.route().route_generation(),
                inner.route().route_digest(),
                None,
                inner.manifest().proof_capabilities(),
                inner.manifest().allow_recursive(),
                inner.manifest().allow_kernel_coupled(),
            )
        };
        let hello = match hello {
            Ok(hello) => hello,
            Err(_) => {
                return Err(poison_and_close(
                    &mut custody,
                    &mut carrier,
                    SourceProviderSecurityError::SessionContinuity,
                ));
            }
        };
        let before_signature =
            current_unix_seconds().and_then(|now| custody.inner_mut().revalidate_at(now));
        if let Err(error) = before_signature {
            return Err(poison_and_close(&mut custody, &mut carrier, error));
        }
        let signed_hello = {
            let inner = custody.inner();
            sign_hello(
                hello,
                inner.root_authority().hello_signer().clone(),
                inner.hello_key().signing_key(),
            )
        };
        let signed_hello = match signed_hello {
            Ok(signed) => signed,
            Err(_) => {
                return Err(poison_and_close(
                    &mut custody,
                    &mut carrier,
                    SourceProviderSecurityError::SessionContinuity,
                ));
            }
        };
        let after_signature =
            current_unix_seconds().and_then(|now| custody.inner_mut().revalidate_at(now));
        if let Err(error) = after_signature {
            return Err(poison_and_close(&mut custody, &mut carrier, error));
        }
        let packet =
            match encode_message(&SourceProviderMessageV1::HelloRequest(signed_hello.clone())) {
                Ok(packet) => packet,
                Err(_) => {
                    return Err(poison_and_close(
                        &mut custody,
                        &mut carrier,
                        SourceProviderSecurityError::SessionContinuity,
                    ));
                }
            };
        if packet.len() != aos_sandbox_source_provider_protocol::SOURCE_PROVIDER_HELLO_FRAME_BYTES {
            return Err(poison_and_close(
                &mut custody,
                &mut carrier,
                SourceProviderSecurityError::SessionContinuity,
            ));
        }
        let now = match current_unix_seconds() {
            Ok(now) => now,
            Err(error) => return Err(poison_and_close(&mut custody, &mut carrier, error)),
        };
        if let Err(error) = custody.inner_mut().revalidate_at(now) {
            return Err(poison_and_close(&mut custody, &mut carrier, error));
        }
        Ok(Self {
            custody,
            carrier,
            nonce,
            signed_hello,
            packet,
        })
    }

    pub(super) fn send(
        mut self,
    ) -> HandshakeTransitionV1<RootMountHelloPreparedV1, RootMountHelloSentV1> {
        if let Err(error) = self.revalidate_before_action() {
            return HandshakeTransitionV1::Fatal(error);
        }
        match self.carrier.send(&self.packet) {
            Err(CarrierFailureV1::Retryable) => HandshakeTransitionV1::Retry(self),
            Err(CarrierFailureV1::Fatal(error)) => HandshakeTransitionV1::Fatal(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                error,
            )),
            Ok(()) => {
                if let Err(error) = self.revalidate_before_action() {
                    return HandshakeTransitionV1::Fatal(error);
                }
                HandshakeTransitionV1::Complete(RootMountHelloSentV1 {
                    custody: self.custody,
                    carrier: self.carrier,
                    nonce: self.nonce,
                    signed_hello: self.signed_hello,
                })
            }
        }
    }

    fn revalidate_before_action(&mut self) -> Result<(), SourceProviderSecurityError> {
        let result =
            current_unix_seconds().and_then(|now| self.custody.inner_mut().revalidate_at(now));
        match result {
            Ok(()) => Ok(()),
            Err(error) => Err(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                error,
            )),
        }
    }
}

impl RootMountHelloSentV1 {
    pub(super) fn receive_provider(
        mut self,
    ) -> HandshakeTransitionV1<RootMountHelloSentV1, CurrentRootMountSourceProviderSessionV1> {
        if let Err(error) = self.revalidate_before_action() {
            return HandshakeTransitionV1::Fatal(error);
        }
        let received = match self.carrier.receive_zero_descriptors(
            aos_sandbox_source_provider_protocol::SOURCE_PROVIDER_HELLO_FRAME_BYTES,
        ) {
            Ok(received) => received,
            Err(CarrierFailureV1::Retryable) => return HandshakeTransitionV1::Retry(self),
            Err(CarrierFailureV1::Fatal(error)) => {
                return HandshakeTransitionV1::Fatal(poison_and_close(
                    &mut self.custody,
                    &mut self.carrier,
                    error,
                ));
            }
        };
        let provider_hello = match decode_message(&received.payload) {
            Ok(SourceProviderMessageV1::HelloResponse(hello)) => hello,
            _ => {
                return HandshakeTransitionV1::Fatal(poison_and_close(
                    &mut self.custody,
                    &mut self.carrier,
                    SourceProviderSecurityError::SessionContinuity,
                ));
            }
        };
        let identity = match process_identity(&received.execution) {
            Ok(identity) => identity,
            Err(error) => {
                return HandshakeTransitionV1::Fatal(poison_and_close(
                    &mut self.custody,
                    &mut self.carrier,
                    error,
                ));
            }
        };
        let now = match current_unix_seconds() {
            Ok(now) => now,
            Err(error) => {
                return HandshakeTransitionV1::Fatal(poison_and_close(
                    &mut self.custody,
                    &mut self.carrier,
                    error,
                ));
            }
        };
        if let Err(error) = self.custody.inner_mut().revalidate_at(now) {
            return HandshakeTransitionV1::Fatal(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                error,
            ));
        }
        let inner = self.custody.inner();
        let session = SourceProviderSessionV1::authenticate(
            self.nonce,
            now,
            self.signed_hello,
            provider_hello,
            inner.trust(),
            inner.root_authority(),
            inner.provider_authority(),
            identity.clone(),
            identity,
            inner.route(),
        );
        let session = match session {
            Ok(session) => session,
            Err(_) => {
                return HandshakeTransitionV1::Fatal(poison_and_close(
                    &mut self.custody,
                    &mut self.carrier,
                    SourceProviderSecurityError::SessionContinuity,
                ));
            }
        };
        if received.execution.boot_id() != inner.execution().boot_id()
            || received
                .execution
                .revalidate(self.carrier.socket().peer())
                .is_err()
        {
            return HandshakeTransitionV1::Fatal(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                SourceProviderSecurityError::SessionContinuity,
            ));
        }
        if let Err(error) = self.revalidate_before_action() {
            return HandshakeTransitionV1::Fatal(error);
        }
        HandshakeTransitionV1::Complete(CurrentRootMountSourceProviderSessionV1 {
            custody: self.custody,
            carrier: self.carrier,
            session,
            provider_execution: received.execution,
        })
    }

    fn revalidate_before_action(&mut self) -> Result<(), SourceProviderSecurityError> {
        let result =
            current_unix_seconds().and_then(|now| self.custody.inner_mut().revalidate_at(now));
        match result {
            Ok(()) => Ok(()),
            Err(error) => Err(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                error,
            )),
        }
    }
}

impl CurrentRootMountSourceProviderSessionV1 {
    pub(crate) fn poison(
        &mut self,
        error: SourceProviderSecurityError,
    ) -> SourceProviderSecurityError {
        poison_and_close(&mut self.custody, &mut self.carrier, error)
    }

    pub(crate) fn revalidate(&mut self) -> Result<(), SourceProviderSecurityError> {
        let result = current_unix_seconds()
            .and_then(|now| self.custody.inner_mut().revalidate_at(now))
            .and_then(|_| {
                self.provider_execution
                    .revalidate(self.carrier.socket().peer())
            })
            .and_then(|_| {
                (self.session.provider_hello().kernel_boot_id()
                    == self.custody.inner().execution().boot_id())
                .then_some(())
                .ok_or(SourceProviderSecurityError::SessionContinuity)
            });
        if let Err(error) = result {
            return Err(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                error,
            ));
        }
        Ok(())
    }

    pub(crate) fn require_complete_acquire_association(
        &mut self,
        session_binding: ObjectDigest,
        socket_cookie: NonZeroU64,
        execution: &ProcessExecutionEvidenceV1,
    ) -> Result<(), SourceProviderSecurityError> {
        let result = self.revalidate().and_then(|_| {
            (session_binding == self.session.binding()
                && socket_cookie == self.carrier.socket().peer().socket_cookie()
                && execution.has_same_execution(&self.provider_execution))
            .then_some(())
            .ok_or(SourceProviderSecurityError::SessionContinuity)
        });
        if let Err(error) = result {
            return Err(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                error,
            ));
        }
        execution
            .revalidate(self.carrier.socket().peer())
            .map_err(|error| poison_and_close(&mut self.custody, &mut self.carrier, error))
    }
}

fn poison_and_close(
    custody: &mut ProtectedRootMountCustodyV1,
    carrier: &mut InertSourceProviderCarrierV1,
    error: SourceProviderSecurityError,
) -> SourceProviderSecurityError {
    custody.inner_mut().poison();
    carrier.close();
    error
}
