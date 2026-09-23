//! Role-local protected custody and narrow safe outputs.
//!
//! Client and broker endpoint types own only their two local signing seeds.
//! The seeds and purpose-specific hello and traffic finalizers remain
//! crate-private; the internal custody surface exposes no generic signing operation.
//! Every output is surrounded by protected-file and process-incarnation
//! currentness checks; any failure permanently poisons the object.

use std::path::Path;

use aos_proto::aos::sandbox::local::v1::{BrokerRequestEnvelope, BrokerResponseEnvelope};
use aos_sandbox_broker_session_protocol::{
    BrokerClientHelloSubjectV1, BrokerHelloSubjectV1, BrokerOutcomeSubjectV1,
    BrokerRequestSubjectV1, CanonicalBrokerClientHelloV1,
    ProtectedBrokerSessionVerificationContextV1, UntrustedBrokerSessionEndpointPublicationV1,
    client_hello_fields_digest_v1, complete_signed_client_hello_digest_v1,
    encode_signed_client_hello_packet_v1, encode_signed_request_packet_v1,
    encode_signed_response_packet_v1, encode_signed_server_hello_packet_v1,
    hello_message::{BrokerClientHello, BrokerMethod, BrokerServerHello},
    outcome_fields_digest_v1, request_fields_digest_v1, server_hello_fields_digest_v1,
    sign_broker_hello_v1, sign_client_hello_v1, sign_outcome_v1, sign_request_v1,
};
use aos_sandbox_protocol::authenticated_session::{
    AuthenticatedBrokerSessionStateV1, AuthenticatedNetworkInventoryOutcomeSigningPlanV1,
    PreparedAuthenticatedNetworkInventoryOutcomeV1, PreparedAuthenticatedNetworkInventoryRequestV1,
};
use aos_sandbox_protocol::{PeerCredentials, PeerPolicy};
use ed25519_dalek::{Signer as _, SigningKey};
use zeroize::{Zeroize, Zeroizing};

use crate::BrokerSessionSecurityError;
use crate::entropy::{EntropySource, KernelEntropy, nonzero_random};
use crate::manifest::BrokerSessionManifestBindingV1;
use crate::protected_files::{EndpointRole, ProtectedEndpointFiles};
use crate::self_execution::{CurrentSelfExecutionGuard, RetainedSelfExecutionGuard};

/// Identifies one protected endpoint process execution without granting authority.
///
/// The identifier is intentionally opaque and non-cloneable:
///
/// ```compile_fail
/// use aos_sandbox_broker_session_security::BrokerSessionProcessExecutionIdV1;
///
/// fn duplicate(value: BrokerSessionProcessExecutionIdV1) {
///     let _copy = value.clone();
/// }
/// ```
#[derive(Eq, PartialEq)]
pub struct BrokerSessionProcessExecutionIdV1([u8; 16]);

impl core::fmt::Debug for BrokerSessionProcessExecutionIdV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("BrokerSessionProcessExecutionIdV1([redacted])")
    }
}

/// Holds one fresh client-hello nonce and its private issuance context.
///
/// The nonce has no public byte accessor or constructor:
///
/// ```compile_fail
/// use aos_sandbox_broker_session_security::FreshClientHelloNonceV1;
///
/// fn expose(value: &FreshClientHelloNonceV1) {
///     let _bytes = value.as_bytes();
/// }
/// ```
pub struct FreshClientHelloNonceV1(FreshNonce);

impl Drop for FreshClientHelloNonceV1 {
    fn drop(&mut self) {
        self.0.clear_private_context();
    }
}

impl core::fmt::Debug for FreshClientHelloNonceV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("FreshClientHelloNonceV1([redacted])")
    }
}

/// Holds one fresh broker-hello nonce and its private issuance context.
///
/// The nonce is intentionally non-cloneable:
///
/// ```compile_fail
/// use aos_sandbox_broker_session_security::FreshBrokerHelloNonceV1;
///
/// fn duplicate(value: FreshBrokerHelloNonceV1) {
///     let _copy = value.clone();
/// }
/// ```
pub struct FreshBrokerHelloNonceV1(FreshNonce);

impl Drop for FreshBrokerHelloNonceV1 {
    fn drop(&mut self) {
        self.0.clear_private_context();
    }
}

impl core::fmt::Debug for FreshBrokerHelloNonceV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("FreshBrokerHelloNonceV1([redacted])")
    }
}

struct FreshNonce {
    bytes: Zeroizing<[u8; 32]>,
    process_execution_id: [u8; 16],
    manifest_binding: [u8; 32],
    counter: u64,
}

impl FreshNonce {
    fn clear_private_context(&mut self) {
        self.bytes.zeroize();
        self.process_execution_id.zeroize();
        self.manifest_binding.zeroize();
        self.counter.zeroize();
    }

    fn matches_endpoint(&self, endpoint: &ProtectedEndpointV1) -> bool {
        let expected_counter = endpoint
            .next_nonce_counter
            .and_then(|counter| counter.checked_sub(1))
            .unwrap_or(u64::MAX);
        self.process_execution_id == endpoint.process_execution_id
            && self.manifest_binding == *endpoint.files.manifest().binding().as_bytes()
            && self.counter == expected_counter
    }
}

enum EndpointExecution {
    Retained(RetainedSelfExecutionGuard),
    #[cfg(test)]
    Scripted(Box<dyn CurrentSelfExecutionGuard>),
}

impl EndpointExecution {
    fn boot_id(&self) -> [u8; 16] {
        match self {
            Self::Retained(guard) => guard.boot_id(),
            #[cfg(test)]
            Self::Scripted(_) => [0x77; 16],
        }
    }
}

impl CurrentSelfExecutionGuard for EndpointExecution {
    fn validate_current(&self) -> Result<(), BrokerSessionSecurityError> {
        match self {
            Self::Retained(guard) => guard.validate_current(),
            #[cfg(test)]
            Self::Scripted(guard) => guard.validate_current(),
        }
    }
}

struct ProtectedEndpointV1 {
    files: ProtectedEndpointFiles,
    execution: EndpointExecution,
    process_execution_id: [u8; 16],
    next_nonce_counter: Option<u64>,
    poisoned: bool,
}

impl ProtectedEndpointV1 {
    fn load(path: &Path, role: EndpointRole) -> Result<Self, BrokerSessionSecurityError> {
        let execution = EndpointExecution::Retained(RetainedSelfExecutionGuard::capture()?);
        Self::load_with_execution(path, role, &mut KernelEntropy, execution)
    }

    fn load_with_execution<Entropy: EntropySource>(
        path: &Path,
        role: EndpointRole,
        entropy: &mut Entropy,
        execution: EndpointExecution,
    ) -> Result<Self, BrokerSessionSecurityError> {
        let files = ProtectedEndpointFiles::load(path, role)?;
        let process_execution_id = nonzero_random(entropy)?;
        files.revalidate()?;
        execution.validate_current()?;

        Ok(Self {
            files,
            execution,
            process_execution_id,
            next_nonce_counter: Some(1),
            poisoned: false,
        })
    }

    #[cfg(test)]
    fn load_with_guard<Entropy, Execution>(
        path: &Path,
        role: EndpointRole,
        entropy: &mut Entropy,
        execution: Execution,
    ) -> Result<Self, BrokerSessionSecurityError>
    where
        Entropy: EntropySource,
        Execution: CurrentSelfExecutionGuard + 'static,
    {
        Self::load_with_execution(
            path,
            role,
            entropy,
            EndpointExecution::Scripted(Box::new(execution)),
        )
    }

    fn manifest_binding(
        &mut self,
    ) -> Result<BrokerSessionManifestBindingV1, BrokerSessionSecurityError> {
        self.revalidate_before()?;
        let output = self.files.manifest().binding();
        self.revalidate_after()?;
        Ok(output)
    }

    fn process_execution_id(
        &mut self,
    ) -> Result<BrokerSessionProcessExecutionIdV1, BrokerSessionSecurityError> {
        self.revalidate_before()?;
        let output = BrokerSessionProcessExecutionIdV1(self.process_execution_id);
        self.revalidate_after()?;
        Ok(output)
    }

    fn fresh_nonce<Entropy: EntropySource>(
        &mut self,
        entropy: &mut Entropy,
    ) -> Result<FreshNonce, BrokerSessionSecurityError> {
        self.revalidate_before()?;
        let counter = match self.next_nonce_counter {
            Some(counter) => counter,
            None => {
                self.poisoned = true;
                return Err(BrokerSessionSecurityError::NonceExhausted);
            }
        };
        let bytes = match nonzero_random(entropy) {
            Ok(bytes) => Zeroizing::new(bytes),
            Err(error) => {
                self.poisoned = true;
                return Err(error);
            }
        };
        let binding = self.files.manifest().binding();
        let output = FreshNonce {
            bytes,
            process_execution_id: self.process_execution_id,
            manifest_binding: *binding.as_bytes(),
            counter,
        };
        self.revalidate_after()?;
        self.next_nonce_counter = counter.checked_add(1);
        Ok(output)
    }

    fn revalidate_before(&mut self) -> Result<(), BrokerSessionSecurityError> {
        if self.poisoned {
            return Err(BrokerSessionSecurityError::Poisoned);
        }
        if let Err(error) = self.check_current() {
            self.poisoned = true;
            return Err(error);
        }
        Ok(())
    }

    fn revalidate_after(&mut self) -> Result<(), BrokerSessionSecurityError> {
        if let Err(error) = self.check_current() {
            self.poisoned = true;
            return Err(error);
        }
        Ok(())
    }

    fn check_current(&self) -> Result<(), BrokerSessionSecurityError> {
        self.execution.validate_current()?;
        self.files.revalidate()?;
        self.execution.validate_current()?;
        Ok(())
    }

    fn context(
        &self,
        client_process: [u8; 16],
        broker_process: [u8; 16],
    ) -> Result<ProtectedBrokerSessionVerificationContextV1, BrokerSessionSecurityError> {
        self.files.manifest().verification_context(
            self.execution.boot_id(),
            client_process,
            broker_process,
        )
    }

    fn poison<T>(
        &mut self,
        error: BrokerSessionSecurityError,
    ) -> Result<T, BrokerSessionSecurityError> {
        self.poisoned = true;
        Err(error)
    }
}

/// Retains a client endpoint's protected manifest and two client signing seeds.
///
/// The type is intentionally non-cloneable and non-authorizing. It exposes no
/// key material and no signing operation.
pub(crate) struct ProtectedBrokerSessionClientV1 {
    inner: ProtectedEndpointV1,
}

impl core::fmt::Debug for ProtectedBrokerSessionClientV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProtectedBrokerSessionClientV1([redacted])")
    }
}

impl ProtectedBrokerSessionClientV1 {
    pub(crate) fn sign_lifecycle_bootstrap_attestation(
        &mut self,
        message: &[u8; 32],
    ) -> Result<[u8; 64], BrokerSessionSecurityError> {
        self.inner.revalidate_before()?;
        let signature = SigningKey::from_bytes(self.inner.files.client_record_seed()?)
            .sign(message)
            .to_bytes();
        if let Err(error) = self.inner.revalidate_after() {
            return self.inner.poison(error);
        }
        Ok(signature)
    }

    pub(crate) fn fresh_method_request_id(
        &mut self,
    ) -> Result<[u8; 16], BrokerSessionSecurityError> {
        self.inner.revalidate_before()?;
        let request_id = match nonzero_random::<16, _>(&mut KernelEntropy) {
            Ok(request_id) => request_id,
            Err(error) => return self.inner.poison(error),
        };
        if let Err(error) = self.inner.revalidate_after() {
            return self.inner.poison(error);
        }
        Ok(request_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn finalize_method_request(
        &mut self,
        message: BrokerRequestEnvelope,
        method: BrokerMethod,
        session_binding: [u8; 32],
        client_process: [u8; 16],
        sequence: u64,
        request_id: [u8; 16],
    ) -> Result<Vec<u8>, BrokerSessionSecurityError> {
        self.inner.revalidate_before()?;
        let result = (|| {
            if client_process != self.inner.process_execution_id
                || message.method.as_known() != Some(method)
                || !message.signed_session_request.is_empty()
            {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            let subject = BrokerRequestSubjectV1::new(
                session_binding,
                client_process,
                sequence,
                request_id,
                request_fields_digest_v1(&message)
                    .map_err(|_| BrokerSessionSecurityError::Currentness)?,
            )
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            let pin = &self.inner.files.manifest().key_pins()[2];
            let key = SigningKey::from_bytes(self.inner.files.client_record_seed()?);
            let signed = sign_request_v1(method, subject, pin.signer().clone(), &key)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            encode_signed_request_packet_v1(message, &signed)
                .map_err(|_| BrokerSessionSecurityError::Currentness)
        })();
        let packet = match result {
            Ok(packet) => packet,
            Err(error) => return self.inner.poison(error),
        };
        if let Err(error) = self.inner.revalidate_after() {
            return self.inner.poison(error);
        }
        Ok(packet)
    }

    /// Loads and exclusively pins one protected client endpoint directory.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionSecurityError`] unless the path, manifest, both
    /// client secrets, current process/kernel incarnation, and initial kernel
    /// entropy sample satisfy the complete protected profile.
    pub(crate) fn load(path: impl AsRef<Path>) -> Result<Self, BrokerSessionSecurityError> {
        Ok(Self {
            inner: ProtectedEndpointV1::load(path.as_ref(), EndpointRole::Client)?,
        })
    }

    /// Returns the currently revalidated protected manifest binding.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionSecurityError`] after any protected state or
    /// execution-incarnation change. A failure permanently poisons the object.
    pub fn manifest_binding(
        &mut self,
    ) -> Result<BrokerSessionManifestBindingV1, BrokerSessionSecurityError> {
        self.inner.manifest_binding()
    }

    /// Returns the opaque, currently revalidated process-execution identifier.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionSecurityError`] after any protected state or
    /// execution-incarnation change. A failure permanently poisons the object.
    pub fn process_execution_id(
        &mut self,
    ) -> Result<BrokerSessionProcessExecutionIdV1, BrokerSessionSecurityError> {
        self.inner.process_execution_id()
    }

    /// Obtains one fresh, role-specific client-hello nonce from the kernel.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionSecurityError`] for entropy failure, nonce-space
    /// exhaustion, or any pre/post currentness failure. Any failure permanently
    /// poisons the object.
    pub fn fresh_client_hello_nonce(
        &mut self,
    ) -> Result<FreshClientHelloNonceV1, BrokerSessionSecurityError> {
        self.inner
            .fresh_nonce(&mut KernelEntropy)
            .map(FreshClientHelloNonceV1)
    }

    pub(crate) fn revalidate_handshake_custody(
        &mut self,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.inner.revalidate_before()?;
        self.inner.revalidate_after()
    }

    pub(crate) fn poison_handshake_custody(&mut self) -> BrokerSessionSecurityError {
        self.inner.poisoned = true;
        BrokerSessionSecurityError::Currentness
    }

    pub(crate) fn process_execution_id_bytes(&self) -> [u8; 16] {
        self.inner.process_execution_id
    }

    pub(crate) fn context_for_handshake(
        &self,
        broker_process: [u8; 16],
    ) -> Result<ProtectedBrokerSessionVerificationContextV1, BrokerSessionSecurityError> {
        self.inner
            .context(self.inner.process_execution_id, broker_process)
    }

    /// Reconstructs an old context from the still-pinned manifest for history only.
    pub(crate) fn context_for_history(
        &mut self,
        historical: &ProtectedBrokerSessionVerificationContextV1,
    ) -> Result<ProtectedBrokerSessionVerificationContextV1, BrokerSessionSecurityError> {
        self.inner.revalidate_before()?;
        let context = self.inner.files.manifest().verification_context(
            historical.boot_id(),
            historical.client_process(),
            historical.broker_process(),
        )?;
        self.inner.revalidate_after()?;
        Ok(context)
    }

    pub(crate) fn finalize_client_hello(
        &mut self,
        message: BrokerClientHello,
        broker_process: [u8; 16],
    ) -> Result<Vec<u8>, BrokerSessionSecurityError> {
        self.inner.revalidate_before()?;
        let result = (|| {
            let nonce = self.inner.fresh_nonce(&mut KernelEntropy)?;
            if !nonce.matches_endpoint(&self.inner) {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            let context = self
                .inner
                .context(self.inner.process_execution_id, broker_process)?;
            let cleared_fields = client_hello_fields_digest_v1(&message)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            let subject = BrokerClientHelloSubjectV1::new(
                context.node_id(),
                context.boot_id(),
                context.protocol(),
                context.protocol_major(),
                context.protocol_minor(),
                context.audience(),
                self.inner.process_execution_id,
                *nonce.bytes,
                context.protected_context_digest(),
                cleared_fields,
            )
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            let pin = &self.inner.files.manifest().key_pins()[0];
            let key = SigningKey::from_bytes(self.inner.files.client_hello_seed()?);
            let signed = sign_client_hello_v1(subject, pin.signer().clone(), &key)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            encode_signed_client_hello_packet_v1(message, &signed)
                .map_err(|_| BrokerSessionSecurityError::Currentness)
        })();
        let packet = match result {
            Ok(packet) => packet,
            Err(error) => return self.inner.poison(error),
        };
        if let Err(error) = self.inner.revalidate_after() {
            return self.inner.poison(error);
        }
        Ok(packet)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn finalize_initial_client_record(
        &mut self,
        state: AuthenticatedBrokerSessionStateV1,
        broker_process: [u8; 16],
        deadline_boottime_nanoseconds: u64,
        maximum_response_bytes: u32,
        peer: PeerCredentials,
        policy: PeerPolicy,
        now_boottime_nanoseconds: u64,
    ) -> Result<PreparedAuthenticatedNetworkInventoryRequestV1, BrokerSessionSecurityError> {
        self.inner.revalidate_before()?;
        let result = (|| {
            let request_id = nonzero_random::<16, _>(&mut KernelEntropy)?;
            let context = self
                .inner
                .context(self.inner.process_execution_id, broker_process)?;
            let plan = state
                .into_initial_network_inventory_request_plan(
                    request_id,
                    deadline_boottime_nanoseconds,
                    maximum_response_bytes,
                    peer,
                    policy,
                    now_boottime_nanoseconds,
                    &context,
                )
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            let subject = plan.signing_subject().clone();
            let pin = &self.inner.files.manifest().key_pins()[2];
            let key = SigningKey::from_bytes(self.inner.files.client_record_seed()?);
            let signed = sign_request_v1(
                BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES,
                subject,
                pin.signer().clone(),
                &key,
            )
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            plan.finalize(&signed, &context)
                .map_err(|_| BrokerSessionSecurityError::Currentness)
        })();
        let prepared = match result {
            Ok(prepared) => prepared,
            Err(error) => return self.inner.poison(error),
        };
        if let Err(error) = self.inner.revalidate_after() {
            return self.inner.poison(error);
        }
        Ok(prepared)
    }
}

/// Retains a broker endpoint's protected manifest and two broker signing seeds.
///
/// The type is intentionally non-cloneable and non-authorizing. It exposes no
/// key material and no signing operation.
pub(crate) struct ProtectedBrokerSessionBrokerV1 {
    inner: ProtectedEndpointV1,
}

impl core::fmt::Debug for ProtectedBrokerSessionBrokerV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProtectedBrokerSessionBrokerV1([redacted])")
    }
}

impl ProtectedBrokerSessionBrokerV1 {
    pub(crate) fn broker_outcome_verifier(
        &mut self,
    ) -> Result<aos_sandbox_protocol::BrokerTerminalCommitVerifierV1, BrokerSessionSecurityError>
    {
        self.inner.revalidate_before()?;
        let pin = &self.inner.files.manifest().key_pins()[3];
        let verifier = aos_sandbox_protocol::BrokerTerminalCommitVerifierV1::new(
            pin.signer().clone(),
            *pin.public_key(),
        )
        .ok_or(BrokerSessionSecurityError::Currentness)?;
        self.inner.revalidate_after()?;
        Ok(verifier)
    }

    pub(crate) fn sign_terminal_commit_receipt(
        &mut self,
        binding: aos_sandbox_protocol::BrokerTerminalCommitBindingV1,
    ) -> Result<aos_sandbox_protocol::BrokerTerminalCommitReceiptV1, BrokerSessionSecurityError>
    {
        self.inner.revalidate_before()?;
        let pin = &self.inner.files.manifest().key_pins()[3];
        let key = SigningKey::from_bytes(self.inner.files.broker_outcome_seed()?);
        let receipt = aos_sandbox_protocol::BrokerTerminalCommitReceiptV1::sign(
            binding,
            pin.signer().clone(),
            &key,
        )
        .ok_or(BrokerSessionSecurityError::Currentness)?;
        self.inner.revalidate_after()?;
        Ok(receipt)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn finalize_method_outcome(
        &mut self,
        message: BrokerResponseEnvelope,
        method: BrokerMethod,
        session_binding: [u8; 32],
        broker_process: [u8; 16],
        sequence: u64,
        request_id: [u8; 16],
        signed_request_digest: [u8; 32],
    ) -> Result<Vec<u8>, BrokerSessionSecurityError> {
        self.inner.revalidate_before()?;
        let result = (|| {
            if broker_process != self.inner.process_execution_id
                || message.method.as_known() != Some(method)
                || message.request_id.as_slice() != request_id
                || !message.signed_session_outcome.is_empty()
            {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            let subject = BrokerOutcomeSubjectV1::new(
                session_binding,
                broker_process,
                sequence,
                request_id,
                signed_request_digest,
                outcome_fields_digest_v1(&message)
                    .map_err(|_| BrokerSessionSecurityError::Currentness)?,
            )
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            let pin = &self.inner.files.manifest().key_pins()[3];
            let key = SigningKey::from_bytes(self.inner.files.broker_outcome_seed()?);
            let signed = sign_outcome_v1(method, subject, pin.signer().clone(), &key)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            encode_signed_response_packet_v1(message, &signed)
                .map_err(|_| BrokerSessionSecurityError::Currentness)
        })();
        let packet = match result {
            Ok(packet) => packet,
            Err(error) => return self.inner.poison(error),
        };
        if let Err(error) = self.inner.revalidate_after() {
            return self.inner.poison(error);
        }
        Ok(packet)
    }

    /// Loads and exclusively pins one protected broker endpoint directory.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionSecurityError`] unless the path, manifest, both
    /// broker secrets, current process/kernel incarnation, and initial kernel
    /// entropy sample satisfy the complete protected profile.
    pub(crate) fn load(path: impl AsRef<Path>) -> Result<Self, BrokerSessionSecurityError> {
        Ok(Self {
            inner: ProtectedEndpointV1::load(path.as_ref(), EndpointRole::Broker)?,
        })
    }

    /// Returns the currently revalidated protected manifest binding.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionSecurityError`] after any protected state or
    /// execution-incarnation change. A failure permanently poisons the object.
    pub fn manifest_binding(
        &mut self,
    ) -> Result<BrokerSessionManifestBindingV1, BrokerSessionSecurityError> {
        self.inner.manifest_binding()
    }

    /// Returns the opaque, currently revalidated process-execution identifier.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionSecurityError`] after any protected state or
    /// execution-incarnation change. A failure permanently poisons the object.
    pub fn process_execution_id(
        &mut self,
    ) -> Result<BrokerSessionProcessExecutionIdV1, BrokerSessionSecurityError> {
        self.inner.process_execution_id()
    }

    /// Obtains one fresh, role-specific broker-hello nonce from the kernel.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionSecurityError`] for entropy failure, nonce-space
    /// exhaustion, or any pre/post currentness failure. Any failure permanently
    /// poisons the object.
    pub fn fresh_broker_hello_nonce(
        &mut self,
    ) -> Result<FreshBrokerHelloNonceV1, BrokerSessionSecurityError> {
        self.inner
            .fresh_nonce(&mut KernelEntropy)
            .map(FreshBrokerHelloNonceV1)
    }

    pub(crate) fn revalidate_handshake_custody(
        &mut self,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.inner.revalidate_before()?;
        self.inner.revalidate_after()
    }

    pub(crate) fn poison_handshake_custody(&mut self) -> BrokerSessionSecurityError {
        self.inner.poisoned = true;
        BrokerSessionSecurityError::Currentness
    }

    pub(crate) fn process_execution_id_bytes(&self) -> [u8; 16] {
        self.inner.process_execution_id
    }

    pub(crate) fn context_for_handshake(
        &self,
        client_process: [u8; 16],
    ) -> Result<ProtectedBrokerSessionVerificationContextV1, BrokerSessionSecurityError> {
        self.inner
            .context(client_process, self.inner.process_execution_id)
    }

    /// Reconstructs an old context from the still-pinned manifest for history only.
    pub(crate) fn context_for_history(
        &mut self,
        historical: &ProtectedBrokerSessionVerificationContextV1,
    ) -> Result<ProtectedBrokerSessionVerificationContextV1, BrokerSessionSecurityError> {
        self.inner.revalidate_before()?;
        let context = self.inner.files.manifest().verification_context(
            historical.boot_id(),
            historical.client_process(),
            historical.broker_process(),
        )?;
        self.inner.revalidate_after()?;
        Ok(context)
    }

    pub(crate) fn client_hello_verification_key(
        &self,
    ) -> Result<
        aos_sandbox_broker_session_protocol::ProtectedBrokerSessionKeyV1,
        BrokerSessionSecurityError,
    > {
        let pin = &self.inner.files.manifest().key_pins()[0];
        aos_sandbox_broker_session_protocol::ProtectedBrokerSessionKeyV1::new(
            pin.signer().clone(),
            *pin.public_key(),
            pin.minimum_authority_generation(),
            pin.minimum_key_generation(),
            pin.is_revoked(),
            pin.superseded_by_key_generation(),
        )
        .map_err(|_| BrokerSessionSecurityError::Currentness)
    }

    pub(crate) fn finalize_endpoint_publication(
        &mut self,
    ) -> Result<[u8; 64], BrokerSessionSecurityError> {
        self.inner.revalidate_before()?;
        let result = UntrustedBrokerSessionEndpointPublicationV1::from_untrusted_broker_claims(
            self.inner.process_execution_id,
            *self.inner.files.manifest().binding().as_bytes(),
        )
        .map(UntrustedBrokerSessionEndpointPublicationV1::to_canonical_bytes)
        .map_err(|_| BrokerSessionSecurityError::Currentness);
        let packet = match result {
            Ok(packet) => packet,
            Err(error) => return self.inner.poison(error),
        };
        if let Err(error) = self.inner.revalidate_after() {
            return self.inner.poison(error);
        }
        Ok(packet)
    }

    pub(crate) fn finalize_broker_hello(
        &mut self,
        message: BrokerServerHello,
        client: &CanonicalBrokerClientHelloV1,
    ) -> Result<Vec<u8>, BrokerSessionSecurityError> {
        self.inner.revalidate_before()?;
        let result = (|| {
            let mut nonce = self.inner.fresh_nonce(&mut KernelEntropy)?;
            for _ in 0..8 {
                if *nonce.bytes != client.signed_artifact().subject().nonce() {
                    break;
                }
                nonce = self.inner.fresh_nonce(&mut KernelEntropy)?;
            }
            if *nonce.bytes == client.signed_artifact().subject().nonce()
                || !nonce.matches_endpoint(&self.inner)
            {
                return Err(BrokerSessionSecurityError::Entropy);
            }
            let context = self.inner.context(
                client.signed_artifact().subject().client_process(),
                self.inner.process_execution_id,
            )?;
            let cleared_fields = server_hello_fields_digest_v1(&message)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            let subject = BrokerHelloSubjectV1::new(
                context.node_id(),
                context.boot_id(),
                context.protocol(),
                context.protocol_major(),
                context.protocol_minor(),
                context.audience(),
                self.inner.process_execution_id,
                *nonce.bytes,
                context.protected_context_digest(),
                complete_signed_client_hello_digest_v1(client.signed_artifact()),
                cleared_fields,
            )
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            let pin = &self.inner.files.manifest().key_pins()[1];
            let key = SigningKey::from_bytes(self.inner.files.broker_hello_seed()?);
            let signed = sign_broker_hello_v1(subject, pin.signer().clone(), &key)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            encode_signed_server_hello_packet_v1(message, &signed)
                .map_err(|_| BrokerSessionSecurityError::Currentness)
        })();
        let packet = match result {
            Ok(packet) => packet,
            Err(error) => return self.inner.poison(error),
        };
        if let Err(error) = self.inner.revalidate_after() {
            return self.inner.poison(error);
        }
        Ok(packet)
    }

    pub(crate) fn finalize_initial_broker_outcome(
        &mut self,
        plan: AuthenticatedNetworkInventoryOutcomeSigningPlanV1,
        client_process: [u8; 16],
    ) -> Result<PreparedAuthenticatedNetworkInventoryOutcomeV1, BrokerSessionSecurityError> {
        self.inner.revalidate_before()?;
        let result = (|| {
            let context = self
                .inner
                .context(client_process, self.inner.process_execution_id)?;
            let subject = plan.signing_subject().clone();
            let pin = &self.inner.files.manifest().key_pins()[3];
            let key = SigningKey::from_bytes(self.inner.files.broker_outcome_seed()?);
            let signed = sign_outcome_v1(
                BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES,
                subject,
                pin.signer().clone(),
                &key,
            )
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            plan.finalize(&signed, &context)
                .map_err(|_| BrokerSessionSecurityError::Currentness)
        })();
        let prepared = match result {
            Ok(prepared) => prepared,
            Err(error) => return self.inner.poison(error),
        };
        if let Err(error) = self.inner.revalidate_after() {
            return self.inner.poison(error);
        }
        Ok(prepared)
    }
}

#[cfg(test)]
struct HandshakeTestEntropy {
    next: u8,
}

#[cfg(test)]
impl EntropySource for HandshakeTestEntropy {
    fn fill_once(&mut self, output: &mut [u8]) -> Result<usize, rustix::io::Errno> {
        output.fill(self.next);
        self.next = self.next.wrapping_add(1).max(1);
        Ok(output.len())
    }
}

#[cfg(test)]
struct HandshakeTestExecution;

#[cfg(test)]
impl CurrentSelfExecutionGuard for HandshakeTestExecution {
    fn validate_current(&self) -> Result<(), BrokerSessionSecurityError> {
        Ok(())
    }
}

#[cfg(test)]
struct HandshakeScriptedExecution {
    results: std::sync::Mutex<std::collections::VecDeque<Result<(), BrokerSessionSecurityError>>>,
}

#[cfg(test)]
impl CurrentSelfExecutionGuard for HandshakeScriptedExecution {
    fn validate_current(&self) -> Result<(), BrokerSessionSecurityError> {
        self.results
            .lock()
            .map_err(|_| BrokerSessionSecurityError::ExecutionChanged)?
            .pop_front()
            .unwrap_or(Err(BrokerSessionSecurityError::ExecutionChanged))
    }
}

#[cfg(test)]
pub(crate) fn load_client_for_handshake_test(
    path: &Path,
    entropy_byte: u8,
) -> Result<ProtectedBrokerSessionClientV1, BrokerSessionSecurityError> {
    Ok(ProtectedBrokerSessionClientV1 {
        inner: ProtectedEndpointV1::load_with_guard(
            path,
            EndpointRole::Client,
            &mut HandshakeTestEntropy { next: entropy_byte },
            HandshakeTestExecution,
        )?,
    })
}

#[cfg(test)]
pub(crate) fn load_broker_for_handshake_test(
    path: &Path,
    entropy_byte: u8,
) -> Result<ProtectedBrokerSessionBrokerV1, BrokerSessionSecurityError> {
    Ok(ProtectedBrokerSessionBrokerV1 {
        inner: ProtectedEndpointV1::load_with_guard(
            path,
            EndpointRole::Broker,
            &mut HandshakeTestEntropy { next: entropy_byte },
            HandshakeTestExecution,
        )?,
    })
}

#[cfg(test)]
pub(crate) fn load_client_for_handshake_scripted_test(
    path: &Path,
    entropy_byte: u8,
    results: impl IntoIterator<Item = Result<(), BrokerSessionSecurityError>>,
) -> Result<ProtectedBrokerSessionClientV1, BrokerSessionSecurityError> {
    Ok(ProtectedBrokerSessionClientV1 {
        inner: ProtectedEndpointV1::load_with_guard(
            path,
            EndpointRole::Client,
            &mut HandshakeTestEntropy { next: entropy_byte },
            HandshakeScriptedExecution {
                results: std::sync::Mutex::new(results.into_iter().collect()),
            },
        )?,
    })
}

#[cfg(test)]
pub(crate) fn load_broker_for_handshake_scripted_test(
    path: &Path,
    entropy_byte: u8,
    results: impl IntoIterator<Item = Result<(), BrokerSessionSecurityError>>,
) -> Result<ProtectedBrokerSessionBrokerV1, BrokerSessionSecurityError> {
    Ok(ProtectedBrokerSessionBrokerV1 {
        inner: ProtectedEndpointV1::load_with_guard(
            path,
            EndpointRole::Broker,
            &mut HandshakeTestEntropy { next: entropy_byte },
            HandshakeScriptedExecution {
                results: std::sync::Mutex::new(results.into_iter().collect()),
            },
        )?,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::net::UnixListener;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use aos_sandbox_broker_session_protocol::{
        BrokerSessionKeyUsageV1, BrokerSessionProtocolV1, BrokerSessionSignerReferenceV1,
    };
    use ed25519_dalek::SigningKey;
    use rustix::io::Errno;
    use tempfile::TempDir;

    use super::*;
    use crate::manifest::{
        BrokerSessionSecurityAudienceV1, BrokerSessionSecurityKeyPinV1,
        BrokerSessionSecurityManifestV1,
    };
    use crate::protected_files::MANIFEST_NAME;

    const CLIENT_KEY_NAMES: [&str; 2] = ["client-hello-signing-key", "client-record-signing-key"];
    const BROKER_KEY_NAMES: [&str; 2] = ["broker-hello-signing-key", "broker-outcome-signing-key"];

    struct Fixture {
        _temporary: TempDir,
        endpoint: PathBuf,
        manifest: BrokerSessionSecurityManifestV1,
        secrets: [[u8; 48]; 4],
    }

    impl Fixture {
        fn new(role: EndpointRole) -> Self {
            let temporary = tempfile::tempdir()
                .unwrap_or_else(|error| panic!("temporary directory failed: {error}"));
            let endpoint = temporary.path().join("endpoint");
            fs::create_dir(&endpoint)
                .unwrap_or_else(|error| panic!("endpoint directory failed: {error}"));
            let (manifest, secrets) = test_manifest();
            write_protected(&endpoint.join(MANIFEST_NAME), &manifest.encode());
            let (names, indices) = match role {
                EndpointRole::Client => (CLIENT_KEY_NAMES, [0, 2]),
                EndpointRole::Broker => (BROKER_KEY_NAMES, [1, 3]),
            };
            for (name, index) in names.into_iter().zip(indices) {
                write_protected(&endpoint.join(name), &secrets[index]);
            }
            fs::set_permissions(&endpoint, fs::Permissions::from_mode(0o500))
                .unwrap_or_else(|error| panic!("endpoint permissions failed: {error}"));
            Self {
                _temporary: temporary,
                endpoint,
                manifest,
                secrets,
            }
        }

        fn rewrite_manifest(&self, manifest: &BrokerSessionSecurityManifestV1) {
            rewrite_protected(&self.endpoint.join(MANIFEST_NAME), &manifest.encode());
        }
    }

    struct RepeatingEntropy {
        byte: u8,
    }

    impl EntropySource for RepeatingEntropy {
        fn fill_once(&mut self, output: &mut [u8]) -> Result<usize, Errno> {
            output.fill(self.byte);
            self.byte = self.byte.wrapping_add(1).max(1);
            Ok(output.len())
        }
    }

    struct AlwaysCurrentExecution;

    impl CurrentSelfExecutionGuard for AlwaysCurrentExecution {
        fn validate_current(&self) -> Result<(), BrokerSessionSecurityError> {
            Ok(())
        }
    }

    struct ScriptedCurrentExecution {
        results: Mutex<VecDeque<Result<(), BrokerSessionSecurityError>>>,
    }

    impl ScriptedCurrentExecution {
        fn new(results: impl IntoIterator<Item = Result<(), BrokerSessionSecurityError>>) -> Self {
            Self {
                results: Mutex::new(results.into_iter().collect()),
            }
        }
    }

    impl CurrentSelfExecutionGuard for ScriptedCurrentExecution {
        fn validate_current(&self) -> Result<(), BrokerSessionSecurityError> {
            self.results
                .lock()
                .map_err(|_| BrokerSessionSecurityError::ExecutionChanged)?
                .pop_front()
                .unwrap_or(Err(BrokerSessionSecurityError::ExecutionChanged))
        }
    }

    struct CountingCurrentExecution {
        validations: Arc<AtomicUsize>,
    }

    impl CurrentSelfExecutionGuard for CountingCurrentExecution {
        fn validate_current(&self) -> Result<(), BrokerSessionSecurityError> {
            self.validations.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    struct MutatingEntropy {
        path: PathBuf,
        replacement: [u8; 48],
        byte: u8,
    }

    impl EntropySource for MutatingEntropy {
        fn fill_once(&mut self, output: &mut [u8]) -> Result<usize, Errno> {
            rewrite_protected(&self.path, &self.replacement);
            output.fill(self.byte);
            Ok(output.len())
        }
    }

    struct FailingEntropy;

    impl EntropySource for FailingEntropy {
        fn fill_once(&mut self, _output: &mut [u8]) -> Result<usize, Errno> {
            Err(Errno::IO)
        }
    }

    fn test_manifest() -> (BrokerSessionSecurityManifestV1, [[u8; 48]; 4]) {
        let usages = [
            BrokerSessionKeyUsageV1::ClientHello,
            BrokerSessionKeyUsageV1::BrokerHello,
            BrokerSessionKeyUsageV1::ClientRecord,
            BrokerSessionKeyUsageV1::BrokerOutcome,
        ];
        let mut secrets = [[0_u8; 48]; 4];
        let pins = core::array::from_fn(|index| {
            let seed = [u8::try_from(index + 1).unwrap_or(1); 32];
            let key_id = [0x50 + u8::try_from(index).unwrap_or(0); 16];
            secrets[index][..16].copy_from_slice(&key_id);
            secrets[index][16..].copy_from_slice(&seed);
            let signing_key = SigningKey::from_bytes(&seed);
            let signer = BrokerSessionSignerReferenceV1::for_signing_key(
                [0x30 + u8::try_from(index).unwrap_or(0); 16],
                10 + u64::try_from(index).unwrap_or(0),
                [0x40 + u8::try_from(index).unwrap_or(0); 32],
                key_id,
                20 + u64::try_from(index).unwrap_or(0),
                usages[index],
                &signing_key,
            )
            .unwrap_or_else(|error| panic!("signer failed: {error}"));
            BrokerSessionSecurityKeyPinV1::new(
                signer,
                signing_key.verifying_key().to_bytes(),
                1,
                1,
                false,
                None,
            )
            .unwrap_or_else(|error| panic!("pin failed: {error}"))
        });
        let manifest = BrokerSessionSecurityManifestV1::new(
            BrokerSessionProtocolV1::Network,
            BrokerSessionSecurityAudienceV1::NodeController,
            1,
            0,
            [1; 16],
            [2; 16],
            1,
            [3; 32],
            1,
            [4; 32],
            1,
            [5; 32],
            [6; 16],
            pins,
        )
        .unwrap_or_else(|error| panic!("manifest failed: {error}"));
        (manifest, secrets)
    }

    fn write_protected(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap_or_else(|error| panic!("protected write failed: {error}"));
        fs::set_permissions(path, fs::Permissions::from_mode(0o400))
            .unwrap_or_else(|error| panic!("protected permissions failed: {error}"));
    }

    fn rewrite_protected(path: &Path, bytes: &[u8]) {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("temporary write permission failed: {error}"));
        fs::write(path, bytes).unwrap_or_else(|error| panic!("protected rewrite failed: {error}"));
        fs::set_permissions(path, fs::Permissions::from_mode(0o400))
            .unwrap_or_else(|error| panic!("protected permissions failed: {error}"));
    }

    fn make_directory_mutable(path: &Path) {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("temporary directory permission failed: {error}"));
    }

    fn restore_directory_mode(path: &Path) {
        fs::set_permissions(path, fs::Permissions::from_mode(0o500))
            .unwrap_or_else(|error| panic!("protected directory permission failed: {error}"));
    }

    fn with_raw_suffix(path: &Path, suffix: &[u8]) -> PathBuf {
        let mut bytes = path.as_os_str().as_bytes().to_vec();
        bytes.extend_from_slice(suffix);
        PathBuf::from(OsString::from_vec(bytes))
    }

    fn assert_directory_path_rejected(path: &Path) {
        assert_eq!(
            ProtectedEndpointFiles::load(path, EndpointRole::Client).err(),
            Some(BrokerSessionSecurityError::DirectoryPath)
        );
    }

    fn load_deterministic(fixture: &Fixture, role: EndpointRole) -> ProtectedEndpointV1 {
        ProtectedEndpointV1::load_with_guard(
            &fixture.endpoint,
            role,
            &mut RepeatingEntropy { byte: 9 },
            AlwaysCurrentExecution,
        )
        .unwrap_or_else(|error| panic!("deterministic load failed: {error}"))
    }

    #[test]
    fn role_endpoints_issue_only_opaque_nonzero_distinct_outputs() {
        let client_fixture = Fixture::new(EndpointRole::Client);
        let mut client = load_deterministic(&client_fixture, EndpointRole::Client);
        assert_eq!(client.process_execution_id, [9; 16]);
        let first = client
            .fresh_nonce(&mut RepeatingEntropy { byte: 10 })
            .unwrap_or_else(|error| panic!("first nonce failed: {error}"));
        let second = client
            .fresh_nonce(&mut RepeatingEntropy { byte: 11 })
            .unwrap_or_else(|error| panic!("second nonce failed: {error}"));
        assert_eq!(*first.bytes, [10; 32]);
        assert_eq!(*second.bytes, [11; 32]);
        assert_ne!(*first.bytes, *second.bytes);
        assert_eq!(first.counter, 1);
        assert_eq!(second.counter, 2);
        assert_eq!(first.process_execution_id, [9; 16]);
        assert_eq!(
            first.manifest_binding,
            *client_fixture.manifest.binding().as_bytes()
        );

        let broker_fixture = Fixture::new(EndpointRole::Broker);
        let mut broker = load_deterministic(&broker_fixture, EndpointRole::Broker);
        assert!(
            broker
                .fresh_nonce(&mut RepeatingEntropy { byte: 12 })
                .is_ok()
        );
    }

    #[cfg(feature = "kernel-tests")]
    #[test]
    fn public_role_apis_load_and_revalidate_real_process_state() {
        let client_fixture = Fixture::new(EndpointRole::Client);
        let mut client = ProtectedBrokerSessionClientV1::load(&client_fixture.endpoint)
            .unwrap_or_else(|error| panic!("public client load failed: {error}"));
        assert_eq!(
            client
                .manifest_binding()
                .unwrap_or_else(|error| panic!("client binding failed: {error}")),
            client_fixture.manifest.binding()
        );
        assert!(client.process_execution_id().is_ok());
        assert!(client.fresh_client_hello_nonce().is_ok());

        let broker_fixture = Fixture::new(EndpointRole::Broker);
        let mut broker = ProtectedBrokerSessionBrokerV1::load(&broker_fixture.endpoint)
            .unwrap_or_else(|error| panic!("public broker load failed: {error}"));
        assert_eq!(
            broker
                .manifest_binding()
                .unwrap_or_else(|error| panic!("broker binding failed: {error}")),
            broker_fixture.manifest.binding()
        );
        assert!(broker.process_execution_id().is_ok());
        assert!(broker.fresh_broker_hello_nonce().is_ok());
    }

    #[test]
    fn manifest_lock_is_exclusive_for_conforming_loaders() {
        let fixture = Fixture::new(EndpointRole::Client);
        let first = load_deterministic(&fixture, EndpointRole::Client);
        assert!(matches!(
            ProtectedEndpointV1::load_with_guard(
                &fixture.endpoint,
                EndpointRole::Client,
                &mut RepeatingEntropy { byte: 8 },
                AlwaysCurrentExecution,
            ),
            Err(BrokerSessionSecurityError::AlreadyInUse)
        ));
        drop(first);
        assert!(
            ProtectedEndpointV1::load_with_guard(
                &fixture.endpoint,
                EndpointRole::Client,
                &mut RepeatingEntropy { byte: 8 },
                AlwaysCurrentExecution,
            )
            .is_ok()
        );
    }

    #[test]
    fn secret_length_seed_id_public_key_and_role_set_fail_closed() {
        for length in [47, 49] {
            let fixture = Fixture::new(EndpointRole::Client);
            rewrite_protected(
                &fixture.endpoint.join(CLIENT_KEY_NAMES[0]),
                &vec![1; length],
            );
            assert!(ProtectedEndpointFiles::load(&fixture.endpoint, EndpointRole::Client).is_err());
        }

        let zero_seed = Fixture::new(EndpointRole::Client);
        let mut bytes = zero_seed.secrets[0];
        bytes[16..].fill(0);
        rewrite_protected(&zero_seed.endpoint.join(CLIENT_KEY_NAMES[0]), &bytes);
        assert!(ProtectedEndpointFiles::load(&zero_seed.endpoint, EndpointRole::Client).is_err());

        let wrong_id = Fixture::new(EndpointRole::Client);
        let mut bytes = wrong_id.secrets[0];
        bytes[0] ^= 1;
        rewrite_protected(&wrong_id.endpoint.join(CLIENT_KEY_NAMES[0]), &bytes);
        assert!(ProtectedEndpointFiles::load(&wrong_id.endpoint, EndpointRole::Client).is_err());

        let wrong_public_key = Fixture::new(EndpointRole::Client);
        let mut bytes = wrong_public_key.secrets[0];
        bytes[16..].fill(9);
        rewrite_protected(&wrong_public_key.endpoint.join(CLIENT_KEY_NAMES[0]), &bytes);
        assert!(
            ProtectedEndpointFiles::load(&wrong_public_key.endpoint, EndpointRole::Client).is_err()
        );

        let swapped = Fixture::new(EndpointRole::Client);
        rewrite_protected(
            &swapped.endpoint.join(CLIENT_KEY_NAMES[0]),
            &swapped.secrets[2],
        );
        assert!(ProtectedEndpointFiles::load(&swapped.endpoint, EndpointRole::Client).is_err());

        let missing = Fixture::new(EndpointRole::Client);
        make_directory_mutable(&missing.endpoint);
        fs::remove_file(missing.endpoint.join(CLIENT_KEY_NAMES[1]))
            .unwrap_or_else(|error| panic!("remove secret failed: {error}"));
        restore_directory_mode(&missing.endpoint);
        assert!(ProtectedEndpointFiles::load(&missing.endpoint, EndpointRole::Client).is_err());

        let opposite = Fixture::new(EndpointRole::Client);
        make_directory_mutable(&opposite.endpoint);
        write_protected(
            &opposite.endpoint.join(BROKER_KEY_NAMES[0]),
            &opposite.secrets[1],
        );
        restore_directory_mode(&opposite.endpoint);
        assert_eq!(
            ProtectedEndpointFiles::load(&opposite.endpoint, EndpointRole::Client).err(),
            Some(BrokerSessionSecurityError::OppositeRoleSecret)
        );
    }

    #[test]
    fn inactive_peer_pin_prevents_role_local_load() {
        let fixture = Fixture::new(EndpointRole::Client);
        let mut encoded = fixture.manifest.encode();
        encoded[184 + 184 + 168] = 1;
        let revoked = BrokerSessionSecurityManifestV1::decode(&encoded)
            .unwrap_or_else(|error| panic!("revoked manifest decode failed: {error}"));
        fixture.rewrite_manifest(&revoked);
        assert!(ProtectedEndpointFiles::load(&fixture.endpoint, EndpointRole::Client).is_err());
    }

    #[test]
    fn path_and_retained_file_changes_poison_permanently() {
        let fixture = Fixture::new(EndpointRole::Client);
        let mut endpoint = load_deterministic(&fixture, EndpointRole::Client);
        let path = fixture.endpoint.join(CLIENT_KEY_NAMES[0]);
        let original = fixture.secrets[0];
        let mut changed = original;
        changed[20] ^= 1;
        rewrite_protected(&path, &changed);
        assert!(
            endpoint
                .fresh_nonce(&mut RepeatingEntropy { byte: 10 })
                .is_err()
        );
        rewrite_protected(&path, &original);
        assert_eq!(
            endpoint
                .fresh_nonce(&mut RepeatingEntropy { byte: 10 })
                .err(),
            Some(BrokerSessionSecurityError::Poisoned)
        );
    }

    #[test]
    fn rename_replacement_and_whole_directory_rebinding_are_detected() {
        let replacement = Fixture::new(EndpointRole::Client);
        let mut endpoint = load_deterministic(&replacement, EndpointRole::Client);
        let secret = replacement.endpoint.join(CLIENT_KEY_NAMES[0]);
        let saved = replacement.endpoint.join("saved-secret");
        make_directory_mutable(&replacement.endpoint);
        fs::rename(&secret, &saved).unwrap_or_else(|error| panic!("save secret failed: {error}"));
        write_protected(&secret, &replacement.secrets[0]);
        restore_directory_mode(&replacement.endpoint);
        assert!(endpoint.manifest_binding().is_err());

        let rebinding = Fixture::new(EndpointRole::Client);
        let mut endpoint = load_deterministic(&rebinding, EndpointRole::Client);
        let old = rebinding._temporary.path().join("old-endpoint");
        fs::rename(&rebinding.endpoint, &old)
            .unwrap_or_else(|error| panic!("rename endpoint failed: {error}"));
        fs::create_dir(&rebinding.endpoint)
            .unwrap_or_else(|error| panic!("replacement endpoint failed: {error}"));
        fs::set_permissions(&rebinding.endpoint, fs::Permissions::from_mode(0o500))
            .unwrap_or_else(|error| panic!("replacement mode failed: {error}"));
        assert!(endpoint.manifest_binding().is_err());
    }

    #[test]
    fn file_type_symlink_mode_and_link_count_are_rejected() {
        assert_eq!(
            ProtectedEndpointFiles::load(Path::new("relative"), EndpointRole::Client).err(),
            Some(BrokerSessionSecurityError::DirectoryPath)
        );
        let temporary = tempfile::tempdir()
            .unwrap_or_else(|error| panic!("temporary directory failed: {error}"));
        let ordinary_file = temporary.path().join("not-directory");
        fs::write(&ordinary_file, b"x")
            .unwrap_or_else(|error| panic!("ordinary file failed: {error}"));
        assert!(ProtectedEndpointFiles::load(&ordinary_file, EndpointRole::Client).is_err());

        let directory_mode = Fixture::new(EndpointRole::Client);
        fs::set_permissions(&directory_mode.endpoint, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("directory mode failed: {error}"));
        assert!(
            ProtectedEndpointFiles::load(&directory_mode.endpoint, EndpointRole::Client).is_err()
        );

        let file_mode = Fixture::new(EndpointRole::Client);
        fs::set_permissions(
            file_mode.endpoint.join(MANIFEST_NAME),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap_or_else(|error| panic!("file mode failed: {error}"));
        assert!(ProtectedEndpointFiles::load(&file_mode.endpoint, EndpointRole::Client).is_err());

        let linked = Fixture::new(EndpointRole::Client);
        fs::hard_link(
            linked.endpoint.join(CLIENT_KEY_NAMES[0]),
            linked._temporary.path().join("hard-link"),
        )
        .unwrap_or_else(|error| panic!("hard link failed: {error}"));
        assert!(ProtectedEndpointFiles::load(&linked.endpoint, EndpointRole::Client).is_err());

        let symlinked = Fixture::new(EndpointRole::Client);
        let key = symlinked.endpoint.join(CLIENT_KEY_NAMES[0]);
        make_directory_mutable(&symlinked.endpoint);
        fs::rename(&key, symlinked._temporary.path().join("real-key"))
            .unwrap_or_else(|error| panic!("move key failed: {error}"));
        std::os::unix::fs::symlink(symlinked._temporary.path().join("real-key"), &key)
            .unwrap_or_else(|error| panic!("key symlink failed: {error}"));
        restore_directory_mode(&symlinked.endpoint);
        assert!(ProtectedEndpointFiles::load(&symlinked.endpoint, EndpointRole::Client).is_err());

        let target = Fixture::new(EndpointRole::Client);
        let nonfixed = target.endpoint.join("..").join("endpoint");
        assert_eq!(
            ProtectedEndpointFiles::load(&nonfixed, EndpointRole::Client).err(),
            Some(BrokerSessionSecurityError::DirectoryPath)
        );
        let final_symlink = target._temporary.path().join("endpoint-link");
        std::os::unix::fs::symlink(&target.endpoint, &final_symlink)
            .unwrap_or_else(|error| panic!("endpoint symlink failed: {error}"));
        assert!(ProtectedEndpointFiles::load(&final_symlink, EndpointRole::Client).is_err());
    }

    #[test]
    fn endpoint_path_spelling_is_lexically_closed_before_open() {
        assert_directory_path_rejected(Path::new("/"));

        let fixture = Fixture::new(EndpointRole::Client);
        let endpoint_bytes = fixture.endpoint.as_os_str().as_bytes();
        let separator = endpoint_bytes
            .iter()
            .rposition(|byte| *byte == b'/')
            .unwrap_or_else(|| panic!("absolute fixture path lacks separator"));
        let parent = &endpoint_bytes[..separator];
        let name = &endpoint_bytes[separator + 1..];

        assert_directory_path_rejected(&with_raw_suffix(&fixture.endpoint, b"/"));
        assert_directory_path_rejected(&PathBuf::from(OsString::from_vec(
            [parent, b"//", name].concat(),
        )));
        assert_directory_path_rejected(&PathBuf::from(OsString::from_vec(
            [parent, b"/./", name].concat(),
        )));
        assert_directory_path_rejected(&with_raw_suffix(&fixture.endpoint, b"/../endpoint"));
        assert_directory_path_rejected(&with_raw_suffix(&fixture.endpoint, b"\0suffix"));

        let link = fixture._temporary.path().join("endpoint-link");
        std::os::unix::fs::symlink(&fixture.endpoint, &link)
            .unwrap_or_else(|error| panic!("endpoint symlink failed: {error}"));
        assert_directory_path_rejected(&with_raw_suffix(&link, b"/"));
        assert_directory_path_rejected(&with_raw_suffix(&link, b"/."));
    }

    #[test]
    fn nonregular_child_types_are_rejected() {
        let directory_child = Fixture::new(EndpointRole::Client);
        let key_path = directory_child.endpoint.join(CLIENT_KEY_NAMES[0]);
        make_directory_mutable(&directory_child.endpoint);
        fs::remove_file(&key_path).unwrap_or_else(|error| panic!("remove key failed: {error}"));
        fs::create_dir(&key_path).unwrap_or_else(|error| panic!("child directory failed: {error}"));
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o400))
            .unwrap_or_else(|error| panic!("child directory mode failed: {error}"));
        restore_directory_mode(&directory_child.endpoint);
        assert!(
            ProtectedEndpointFiles::load(&directory_child.endpoint, EndpointRole::Client).is_err()
        );

        let fifo_child = Fixture::new(EndpointRole::Client);
        let key_path = fifo_child.endpoint.join(CLIENT_KEY_NAMES[0]);
        make_directory_mutable(&fifo_child.endpoint);
        fs::remove_file(&key_path).unwrap_or_else(|error| panic!("remove key failed: {error}"));
        let directory = rustix::fs::open(
            &fifo_child.endpoint,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap_or_else(|error| panic!("directory open failed: {error}"));
        rustix::fs::mkfifoat(
            &directory,
            CLIENT_KEY_NAMES[0],
            rustix::fs::Mode::from_raw_mode(0o400),
        )
        .unwrap_or_else(|error| panic!("fifo creation failed: {error}"));
        restore_directory_mode(&fifo_child.endpoint);
        assert!(ProtectedEndpointFiles::load(&fifo_child.endpoint, EndpointRole::Client).is_err());

        let socket_child = Fixture::new(EndpointRole::Client);
        let key_path = socket_child.endpoint.join(CLIENT_KEY_NAMES[0]);
        make_directory_mutable(&socket_child.endpoint);
        fs::remove_file(&key_path).unwrap_or_else(|error| panic!("remove key failed: {error}"));
        let listener = UnixListener::bind(&key_path)
            .unwrap_or_else(|error| panic!("socket creation failed: {error}"));
        restore_directory_mode(&socket_child.endpoint);
        assert!(
            ProtectedEndpointFiles::load(&socket_child.endpoint, EndpointRole::Client).is_err()
        );
        drop(listener);
    }

    #[test]
    fn all_group_other_and_executable_mode_variants_are_rejected() {
        for mode in [0o500, 0o440, 0o404] {
            let fixture = Fixture::new(EndpointRole::Client);
            fs::set_permissions(
                fixture.endpoint.join(CLIENT_KEY_NAMES[0]),
                fs::Permissions::from_mode(mode),
            )
            .unwrap_or_else(|error| panic!("child mode failed: {error}"));
            assert!(ProtectedEndpointFiles::load(&fixture.endpoint, EndpointRole::Client).is_err());
        }

        for mode in [0o510, 0o501, 0o700] {
            let fixture = Fixture::new(EndpointRole::Client);
            fs::set_permissions(&fixture.endpoint, fs::Permissions::from_mode(mode))
                .unwrap_or_else(|error| panic!("directory mode failed: {error}"));
            assert!(ProtectedEndpointFiles::load(&fixture.endpoint, EndpointRole::Client).is_err());
        }
    }

    #[test]
    fn retained_directory_and_manifest_mutations_are_detected() {
        let directory_mode = Fixture::new(EndpointRole::Client);
        let files = ProtectedEndpointFiles::load(&directory_mode.endpoint, EndpointRole::Client)
            .unwrap_or_else(|error| panic!("protected load failed: {error}"));
        fs::set_permissions(&directory_mode.endpoint, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("directory chmod failed: {error}"));
        assert!(files.revalidate().is_err());

        let in_place = Fixture::new(EndpointRole::Client);
        let files = ProtectedEndpointFiles::load(&in_place.endpoint, EndpointRole::Client)
            .unwrap_or_else(|error| panic!("protected load failed: {error}"));
        let mut changed = in_place.manifest.encode();
        changed[56] ^= 1;
        rewrite_protected(&in_place.endpoint.join(MANIFEST_NAME), &changed);
        assert!(files.revalidate().is_err());

        let replacement = Fixture::new(EndpointRole::Client);
        let files = ProtectedEndpointFiles::load(&replacement.endpoint, EndpointRole::Client)
            .unwrap_or_else(|error| panic!("protected load failed: {error}"));
        let manifest_path = replacement.endpoint.join(MANIFEST_NAME);
        make_directory_mutable(&replacement.endpoint);
        fs::rename(&manifest_path, replacement.endpoint.join("saved-manifest"))
            .unwrap_or_else(|error| panic!("save manifest failed: {error}"));
        write_protected(&manifest_path, &replacement.manifest.encode());
        restore_directory_mode(&replacement.endpoint);
        assert!(files.revalidate().is_err());
    }

    #[test]
    fn retained_chmod_truncate_link_and_opposite_name_are_detected() {
        let chmod_fixture = Fixture::new(EndpointRole::Client);
        let files = ProtectedEndpointFiles::load(&chmod_fixture.endpoint, EndpointRole::Client)
            .unwrap_or_else(|error| panic!("protected load failed: {error}"));
        fs::set_permissions(
            chmod_fixture.endpoint.join(CLIENT_KEY_NAMES[0]),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap_or_else(|error| panic!("chmod failed: {error}"));
        assert!(files.revalidate().is_err());

        let truncate_fixture = Fixture::new(EndpointRole::Client);
        let files = ProtectedEndpointFiles::load(&truncate_fixture.endpoint, EndpointRole::Client)
            .unwrap_or_else(|error| panic!("protected load failed: {error}"));
        rewrite_protected(
            &truncate_fixture.endpoint.join(CLIENT_KEY_NAMES[0]),
            &[1; 47],
        );
        assert!(files.revalidate().is_err());

        let link_fixture = Fixture::new(EndpointRole::Client);
        let files = ProtectedEndpointFiles::load(&link_fixture.endpoint, EndpointRole::Client)
            .unwrap_or_else(|error| panic!("protected load failed: {error}"));
        fs::hard_link(
            link_fixture.endpoint.join(CLIENT_KEY_NAMES[0]),
            link_fixture._temporary.path().join("late-hard-link"),
        )
        .unwrap_or_else(|error| panic!("hard link failed: {error}"));
        assert!(files.revalidate().is_err());

        let opposite_fixture = Fixture::new(EndpointRole::Client);
        let files = ProtectedEndpointFiles::load(&opposite_fixture.endpoint, EndpointRole::Client)
            .unwrap_or_else(|error| panic!("protected load failed: {error}"));
        make_directory_mutable(&opposite_fixture.endpoint);
        write_protected(
            &opposite_fixture.endpoint.join(BROKER_KEY_NAMES[0]),
            &opposite_fixture.secrets[1],
        );
        restore_directory_mode(&opposite_fixture.endpoint);
        assert!(files.revalidate().is_err());
    }

    #[test]
    fn manifest_file_length_is_checked_before_decode() {
        for length in [919, 921] {
            let fixture = Fixture::new(EndpointRole::Client);
            rewrite_protected(&fixture.endpoint.join(MANIFEST_NAME), &vec![1; length]);
            assert!(ProtectedEndpointFiles::load(&fixture.endpoint, EndpointRole::Client).is_err());
        }
    }

    #[test]
    fn configuration_and_entropy_failures_during_issuance_poison() {
        let fixture = Fixture::new(EndpointRole::Client);
        let mut endpoint = load_deterministic(&fixture, EndpointRole::Client);
        let mut replacement = fixture.secrets[0];
        replacement[20] ^= 1;
        assert!(
            endpoint
                .fresh_nonce(&mut MutatingEntropy {
                    path: fixture.endpoint.join(CLIENT_KEY_NAMES[0]),
                    replacement,
                    byte: 10,
                })
                .is_err()
        );
        assert!(endpoint.poisoned);

        rewrite_protected(
            &fixture.endpoint.join(CLIENT_KEY_NAMES[0]),
            &fixture.secrets[0],
        );
        drop(endpoint);
        let mut endpoint = load_deterministic(&fixture, EndpointRole::Client);
        assert_eq!(
            endpoint.fresh_nonce(&mut FailingEntropy).err(),
            Some(BrokerSessionSecurityError::Entropy)
        );
        assert!(endpoint.poisoned);
    }

    #[test]
    fn configuration_change_during_process_id_generation_aborts_load() {
        let fixture = Fixture::new(EndpointRole::Client);
        let mut replacement = fixture.secrets[0];
        replacement[20] ^= 1;
        let result = ProtectedEndpointV1::load_with_guard(
            &fixture.endpoint,
            EndpointRole::Client,
            &mut MutatingEntropy {
                path: fixture.endpoint.join(CLIENT_KEY_NAMES[0]),
                replacement,
                byte: 9,
            },
            AlwaysCurrentExecution,
        );
        assert!(result.is_err());
    }

    #[test]
    fn execution_sandwich_and_counter_exhaustion_poison() {
        let fixture = Fixture::new(EndpointRole::Client);
        assert!(
            ProtectedEndpointV1::load_with_guard(
                &fixture.endpoint,
                EndpointRole::Client,
                &mut RepeatingEntropy { byte: 9 },
                ScriptedCurrentExecution::new([Err(BrokerSessionSecurityError::ExecutionChanged,)]),
            )
            .is_err()
        );

        let mut endpoint = ProtectedEndpointV1::load_with_guard(
            &fixture.endpoint,
            EndpointRole::Client,
            &mut RepeatingEntropy { byte: 9 },
            ScriptedCurrentExecution::new([
                Ok(()),
                Err(BrokerSessionSecurityError::ExecutionChanged),
            ]),
        )
        .unwrap_or_else(|error| panic!("scripted load failed: {error}"));
        assert_eq!(
            endpoint
                .fresh_nonce(&mut RepeatingEntropy { byte: 10 })
                .err(),
            Some(BrokerSessionSecurityError::ExecutionChanged)
        );
        assert!(endpoint.poisoned);

        drop(endpoint);
        let mut endpoint = ProtectedEndpointV1::load_with_guard(
            &fixture.endpoint,
            EndpointRole::Client,
            &mut RepeatingEntropy { byte: 9 },
            ScriptedCurrentExecution::new([
                Ok(()),
                Ok(()),
                Ok(()),
                Err(BrokerSessionSecurityError::ExecutionChanged),
            ]),
        )
        .unwrap_or_else(|error| panic!("scripted load failed: {error}"));
        assert_eq!(
            endpoint
                .fresh_nonce(&mut RepeatingEntropy { byte: 10 })
                .err(),
            Some(BrokerSessionSecurityError::ExecutionChanged)
        );
        assert!(endpoint.poisoned);

        drop(endpoint);
        let mut endpoint = load_deterministic(&fixture, EndpointRole::Client);
        endpoint.next_nonce_counter = Some(u64::MAX);
        let last = endpoint
            .fresh_nonce(&mut RepeatingEntropy { byte: 10 })
            .unwrap_or_else(|error| panic!("terminal nonce failed: {error}"));
        assert_eq!(last.counter, u64::MAX);
        assert_eq!(
            endpoint
                .fresh_nonce(&mut RepeatingEntropy { byte: 11 })
                .err(),
            Some(BrokerSessionSecurityError::NonceExhausted)
        );
        assert!(endpoint.poisoned);
    }

    #[test]
    fn every_custody_output_has_complete_execution_sandwiches() {
        let fixture = Fixture::new(EndpointRole::Client);
        let validations = Arc::new(AtomicUsize::new(0));
        let mut endpoint = ProtectedEndpointV1::load_with_guard(
            &fixture.endpoint,
            EndpointRole::Client,
            &mut RepeatingEntropy { byte: 9 },
            CountingCurrentExecution {
                validations: Arc::clone(&validations),
            },
        )
        .unwrap_or_else(|error| panic!("counted load failed: {error}"));
        assert_eq!(validations.load(Ordering::Relaxed), 1);

        assert!(endpoint.manifest_binding().is_ok());
        assert_eq!(validations.load(Ordering::Relaxed), 5);

        assert!(endpoint.process_execution_id().is_ok());
        assert_eq!(validations.load(Ordering::Relaxed), 9);

        assert!(
            endpoint
                .fresh_nonce(&mut RepeatingEntropy { byte: 10 })
                .is_ok()
        );
        assert_eq!(validations.load(Ordering::Relaxed), 13);
    }

    #[test]
    fn scripted_execution_guard_exhaustion_fails_closed() {
        let guard = ScriptedCurrentExecution::new([Ok(())]);
        assert!(guard.validate_current().is_ok());
        assert_eq!(
            guard.validate_current().err(),
            Some(BrokerSessionSecurityError::ExecutionChanged)
        );
    }

    #[test]
    fn public_debug_and_errors_are_redacted() {
        let fixture = Fixture::new(EndpointRole::Client);
        let path_text = fixture.endpoint.to_string_lossy();
        let protected_client = ProtectedBrokerSessionClientV1 {
            inner: load_deterministic(&fixture, EndpointRole::Client),
        };
        for rendered in [
            format!("{protected_client:?}"),
            format!("{:?}", BrokerSessionProcessExecutionIdV1([9; 16])),
            format!("{:?}", fixture.manifest),
            format!("{:?}", fixture.manifest.key_pins()[0]),
            format!("{:?}", fixture.manifest.binding()),
            format!(
                "{:?}",
                FreshClientHelloNonceV1(FreshNonce {
                    bytes: Zeroizing::new([10; 32]),
                    process_execution_id: [9; 16],
                    manifest_binding: [8; 32],
                    counter: 1,
                })
            ),
            BrokerSessionSecurityError::filesystem("manifest", "read").to_string(),
        ] {
            assert!(!rendered.contains(path_text.as_ref()));
            assert!(!rendered.contains("09090909"));
            assert!(!rendered.contains("0a0a0a0a"));
            assert!(!rendered.contains("08080808"));
        }
    }
}
