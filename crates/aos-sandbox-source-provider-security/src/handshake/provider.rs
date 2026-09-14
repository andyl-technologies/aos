//! Provider-side Root Mount authentication and hello-response states.

use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;
use aos_sandbox_source_provider_protocol::{
    SignedSourceProviderHelloV1, SourceProviderHelloV1, SourceProviderIngressSessionV1,
    SourceProviderMessageV1, SourceProviderPeerRole, decode_message, digest_signed_hello,
    encode_message, sign_hello, verify_hello,
};

use super::{HandshakeTransitionV1, current_unix_seconds, process_identity};
use crate::SourceProviderSecurityError;
use crate::carrier::{CarrierFailureV1, InertSourceProviderCarrierV1};
use crate::custody::ProtectedProviderCustodyV1;
use crate::execution::ProcessExecutionEvidenceV1;

pub(super) struct AwaitingRootMountHelloV1 {
    custody: ProtectedProviderCustodyV1,
    carrier: InertSourceProviderCarrierV1,
}

pub(super) struct VerifiedRootMountHelloV1 {
    custody: ProtectedProviderCustodyV1,
    carrier: InertSourceProviderCarrierV1,
    root_mount_hello: SignedSourceProviderHelloV1,
    root_mount_execution: ProcessExecutionEvidenceV1,
}

pub(super) struct ProviderHelloPreparedV1 {
    custody: ProtectedProviderCustodyV1,
    carrier: InertSourceProviderCarrierV1,
    session: SourceProviderIngressSessionV1,
    root_mount_execution: ProcessExecutionEvidenceV1,
    packet: Vec<u8>,
}

/// Owns the current authenticated provider-ingress session.
///
/// No public constructor, request verifier, signer, or carrier extractor exists.
pub struct CurrentProviderIngressSessionV1 {
    custody: ProtectedProviderCustodyV1,
    carrier: InertSourceProviderCarrierV1,
    session: SourceProviderIngressSessionV1,
    root_mount_execution: ProcessExecutionEvidenceV1,
}

impl core::fmt::Debug for CurrentProviderIngressSessionV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("CurrentProviderIngressSessionV1([redacted])")
    }
}

impl AwaitingRootMountHelloV1 {
    pub(super) fn accept(
        mut custody: ProtectedProviderCustodyV1,
        socket: DescriptorSubjectSocket,
    ) -> Result<Self, SourceProviderSecurityError> {
        let mut carrier = InertSourceProviderCarrierV1::adopt(socket)?;
        let result = current_unix_seconds().and_then(|now| custody.inner_mut().revalidate_at(now));
        if let Err(error) = result {
            return Err(poison_and_close(&mut custody, &mut carrier, error));
        }
        Ok(Self { custody, carrier })
    }

    pub(super) fn receive_root_mount(
        mut self,
    ) -> HandshakeTransitionV1<AwaitingRootMountHelloV1, VerifiedRootMountHelloV1> {
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
        let root_mount_hello = match decode_message(&received.payload) {
            Ok(SourceProviderMessageV1::HelloRequest(hello)) => hello,
            _ => {
                return HandshakeTransitionV1::Fatal(poison_and_close(
                    &mut self.custody,
                    &mut self.carrier,
                    SourceProviderSecurityError::SessionContinuity,
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
        if verify_root_hello_preflight(&self.custody, &root_mount_hello, &received.execution, now)
            .is_err()
            || received.execution.boot_id() != self.custody.inner().execution().boot_id()
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
        HandshakeTransitionV1::Complete(VerifiedRootMountHelloV1 {
            custody: self.custody,
            carrier: self.carrier,
            root_mount_hello,
            root_mount_execution: received.execution,
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

impl VerifiedRootMountHelloV1 {
    pub(super) fn prepare_provider_hello(
        mut self,
    ) -> Result<ProviderHelloPreparedV1, SourceProviderSecurityError> {
        let now = match current_unix_seconds() {
            Ok(now) => now,
            Err(error) => {
                return Err(poison_and_close(
                    &mut self.custody,
                    &mut self.carrier,
                    error,
                ));
            }
        };
        let initial = self.custody.inner_mut().revalidate_at(now).and_then(|_| {
            self.root_mount_execution
                .revalidate(self.carrier.socket().peer())
        });
        if let Err(error) = initial {
            return Err(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                error,
            ));
        }
        let nonce = match self.custody.draw_nonce_at(now) {
            Ok(nonce) => nonce,
            Err(error) => {
                return Err(poison_and_close(
                    &mut self.custody,
                    &mut self.carrier,
                    error,
                ));
            }
        };
        let (client_nonce, client_digest, capabilities, recursive, kernel_coupled) = {
            let inner = self.custody.inner();
            let client = self.root_mount_hello.subject();
            (
                client.nonce(),
                digest_signed_hello(&self.root_mount_hello),
                client.proof_class_capabilities() & inner.manifest().proof_capabilities(),
                client.supports_recursive() && inner.manifest().allow_recursive(),
                client.supports_kernel_coupled() && inner.manifest().allow_kernel_coupled(),
            )
        };
        if capabilities == 0 {
            return Err(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                SourceProviderSecurityError::SessionContinuity,
            ));
        }
        let hello = {
            let inner = self.custody.inner();
            SourceProviderHelloV1::new(
                SourceProviderPeerRole::Provider,
                nonce,
                inner.process_instance(),
                inner.execution().boot_id(),
                inner.provider_authority().traffic_signer().clone(),
                inner.root_authority().traffic_signer().clone(),
                inner.route().route_id(),
                inner.route().route_generation(),
                inner.route().route_digest(),
                Some(client_digest),
                capabilities,
                recursive,
                kernel_coupled,
            )
        };
        let hello = match hello {
            Ok(hello) => hello,
            Err(_) => {
                return Err(poison_and_close(
                    &mut self.custody,
                    &mut self.carrier,
                    SourceProviderSecurityError::SessionContinuity,
                ));
            }
        };
        let before_signature = current_unix_seconds()
            .and_then(|now| self.custody.inner_mut().revalidate_at(now))
            .and_then(|_| {
                self.root_mount_execution
                    .revalidate(self.carrier.socket().peer())
            });
        if let Err(error) = before_signature {
            return Err(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                error,
            ));
        }
        let provider_hello = {
            let inner = self.custody.inner();
            sign_hello(
                hello,
                inner.provider_authority().hello_signer().clone(),
                inner.hello_key().signing_key(),
            )
        };
        let provider_hello = match provider_hello {
            Ok(hello) => hello,
            Err(_) => {
                return Err(poison_and_close(
                    &mut self.custody,
                    &mut self.carrier,
                    SourceProviderSecurityError::SessionContinuity,
                ));
            }
        };
        let after_signature = current_unix_seconds()
            .and_then(|now| self.custody.inner_mut().revalidate_at(now))
            .and_then(|_| {
                self.root_mount_execution
                    .revalidate(self.carrier.socket().peer())
            });
        if let Err(error) = after_signature {
            return Err(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                error,
            ));
        }
        let root_identity = match process_identity(&self.root_mount_execution) {
            Ok(identity) => identity,
            Err(error) => {
                return Err(poison_and_close(
                    &mut self.custody,
                    &mut self.carrier,
                    error,
                ));
            }
        };
        let session = {
            let inner = self.custody.inner();
            SourceProviderIngressSessionV1::authenticate(
                client_nonce,
                now,
                self.root_mount_hello,
                provider_hello.clone(),
                inner.trust(),
                inner.root_authority(),
                inner.provider_authority(),
                root_identity.clone(),
                root_identity,
                inner.root_peer(),
                inner.route(),
            )
        };
        let session = match session {
            Ok(session) => session,
            Err(_) => {
                return Err(poison_and_close(
                    &mut self.custody,
                    &mut self.carrier,
                    SourceProviderSecurityError::SessionContinuity,
                ));
            }
        };
        let packet = match encode_message(&SourceProviderMessageV1::HelloResponse(provider_hello)) {
            Ok(packet) => packet,
            Err(_) => {
                return Err(poison_and_close(
                    &mut self.custody,
                    &mut self.carrier,
                    SourceProviderSecurityError::SessionContinuity,
                ));
            }
        };
        if packet.len() != aos_sandbox_source_provider_protocol::SOURCE_PROVIDER_HELLO_FRAME_BYTES {
            return Err(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                SourceProviderSecurityError::SessionContinuity,
            ));
        }
        let final_check = current_unix_seconds()
            .and_then(|now| self.custody.inner_mut().revalidate_at(now))
            .and_then(|_| {
                self.root_mount_execution
                    .revalidate(self.carrier.socket().peer())
            });
        if let Err(error) = final_check {
            return Err(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                error,
            ));
        }
        Ok(ProviderHelloPreparedV1 {
            custody: self.custody,
            carrier: self.carrier,
            session,
            root_mount_execution: self.root_mount_execution,
            packet,
        })
    }
}

impl ProviderHelloPreparedV1 {
    pub(super) fn send(
        mut self,
    ) -> HandshakeTransitionV1<ProviderHelloPreparedV1, CurrentProviderIngressSessionV1> {
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
                HandshakeTransitionV1::Complete(CurrentProviderIngressSessionV1 {
                    custody: self.custody,
                    carrier: self.carrier,
                    session: self.session,
                    root_mount_execution: self.root_mount_execution,
                })
            }
        }
    }

    fn revalidate_before_action(&mut self) -> Result<(), SourceProviderSecurityError> {
        let result = current_unix_seconds()
            .and_then(|now| self.custody.inner_mut().revalidate_at(now))
            .and_then(|_| {
                self.root_mount_execution
                    .revalidate(self.carrier.socket().peer())
            });
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

impl CurrentProviderIngressSessionV1 {
    pub(crate) fn revalidate(&mut self) -> Result<(), SourceProviderSecurityError> {
        let result = current_unix_seconds()
            .and_then(|now| self.custody.inner_mut().revalidate_at(now))
            .and_then(|_| {
                self.root_mount_execution
                    .revalidate(self.carrier.socket().peer())
            })
            .and_then(|_| {
                (self.session.root_mount_process_instance() != [0; 16]
                    && self.session.provider_process_instance()
                        == self.custody.inner().process_instance())
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
}

fn verify_root_hello_preflight(
    custody: &ProtectedProviderCustodyV1,
    signed: &SignedSourceProviderHelloV1,
    execution: &ProcessExecutionEvidenceV1,
    now_seconds: i64,
) -> Result<(), SourceProviderSecurityError> {
    let inner = custody.inner();
    let signer = signed.signer();
    let subject = signed.subject();
    if signer != inner.root_authority().hello_signer()
        || subject.role() != SourceProviderPeerRole::RootMount
        || subject.kernel_boot_id() != inner.execution().boot_id()
        || subject.expected_peer_traffic_signer() != inner.provider_authority().traffic_signer()
        || subject.traffic_signer() != inner.root_authority().traffic_signer()
        || subject.route_id() != inner.route().route_id()
        || subject.route_generation() != inner.route().route_generation()
        || subject.route_digest() != inner.route().route_digest()
        || subject.proof_class_capabilities() & !inner.manifest().proof_capabilities() != 0
        || (subject.supports_recursive() && !inner.manifest().allow_recursive())
        || (subject.supports_kernel_coupled() && !inner.manifest().allow_kernel_coupled())
        || execution.credentials().effective_user_id() != inner.route_file().root_mount_uid()
        || execution.credentials().effective_group_id() != inner.route_file().root_mount_gid()
        || crate::execution::cgroup_object_digest(execution.cgroup_path_digest())
            != inner.route_file().root_mount_cgroup_digest()
    {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    inner
        .root_authority()
        .validate_at(now_seconds)
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    let key = inner
        .trust()
        .keys()
        .iter()
        .find(|entry| entry.signer() == signer)
        .ok_or(SourceProviderSecurityError::SessionContinuity)?;
    verify_hello(signed, key.public_key())
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)
}

fn poison_and_close(
    custody: &mut ProtectedProviderCustodyV1,
    carrier: &mut InertSourceProviderCarrierV1,
    error: SourceProviderSecurityError,
) -> SourceProviderSecurityError {
    custody.inner_mut().poison();
    carrier.close();
    error
}
