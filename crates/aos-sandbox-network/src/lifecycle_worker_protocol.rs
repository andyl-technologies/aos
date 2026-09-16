//! Authenticated dispatch and pure ordering for existing Network resources.
//!
//! A dispatch can be minted only from the move-only value produced while an
//! exact lifecycle record crosses its durable `Ambiguous` boundary. The wire
//! record carries no descriptor number, PID, path, unit name, or caller-chosen
//! cgroup identity. Its closed roles bind the existing fixed mutation-worker
//! path to exactly the broker's retained target Network namespace.
//!
//! ```text
//! AOSNLW01 | version:u16 | worker-role:u8 | descriptor-role:u8 | total:u32
//! request-id:16 | effect-digest:32
//! lengths:(request, plan, catalog, catalog-seal, context, current-fence,
//!          operation-fence, effect, dispatch-seal):u32[9]
//! payloads:length-delimited bytes in the same order
//! ```
//!
//! This module deliberately performs no syscall and launches no helper. It
//! exposes a non-clone ordered-step authorization whose next visible step is
//! returned only after another current-fence and effect-time check.
//! Its dormant reducer defines bounded canonical recovery checkpoints, and the
//! publicly re-exported opaque protected owner uses a crate-sealed adapter to
//! require atomic protected write and exact readback. No production activation
//! is introduced here.

use aos_sandbox_broker::{
    BrokerAuthorizationFenceV1, BrokerEffectIntentV1, BrokerEffectStatusV1, BrokerLocalRecordDomain,
};
use aos_sandbox_core::{BrokerGrantTarget, BrokerResourceHandle, BrokerVerb, ObjectDigest};
use aos_sandbox_protocol::semantics::network::{CanonicalNetworkSemanticsV1, NetworkOperation};
use sha2::{Digest as _, Sha256};

use crate::authorization::NetworkAuthorityV1;
use crate::catalog::{
    AuthenticatedNetworkPreparationV1, ResolvedNetworkPreparationV1,
    encode_authenticated_resolution,
};
use crate::kernel_plan::NetworkKernelPlanV1;
use crate::lifecycle_state::{AmbiguousNetworkLifecycleDispatchV1, lifecycle_effect_digest};
use crate::namespace_catalog::{
    NetworkNamespaceIdentityV1, NetworkNamespaceLifecycleActionV1,
    NetworkNamespaceLifecycleAuthorityV1, NetworkNamespaceObservedStateKindV1,
    NetworkNamespaceObservedStateV1,
};
use crate::worker_protocol::{
    NetworkWorkerProtocolError, decode_admitted_semantics, decode_catalog,
    kernel_plan_matches_catalog,
};
use aos_sandbox_linux::pidfd::NamespaceIdentity;

mod codec;
mod execution;
mod reducer;
pub use reducer::{
    DormantNetworkLifecycleEffectHandoffV1, DormantNetworkLifecycleEffectStepV1,
    DormantNetworkLifecycleOwnerErrorV1, DormantNetworkLifecycleProtectedCommitV1,
    DormantNetworkLifecycleProtectedOwnerV1,
};

pub use codec::MAXIMUM_NETWORK_LIFECYCLE_WORKER_REQUEST_BYTES;
use codec::{
    CONTEXT_BYTES, CONTEXT_MAGIC, CONTEXT_VERSION, Decoder, REQUEST_FIELD_COUNT,
    REQUEST_HEADER_BYTES, REQUEST_MAGIC, REQUEST_VERSION, action_code, action_matches_verb,
    decode_action, decode_descriptor_role, decode_state, decode_verb, decode_worker_role,
    descriptor_role_code, encode_state, invalid, push_length, validate_lengths, verb_code,
    worker_role_code,
};
pub use execution::{
    NetworkLifecycleAuthorizedStepV1, NetworkLifecycleExecutionAuthorizationV1,
    NetworkLifecycleExecutionStepV1,
};

const DISPATCH_MAGIC: &[u8; 8] = b"AOSNLDP1";
const DISPATCH_VERSION: u16 = 1;

fn dispatch_domain() -> Result<BrokerLocalRecordDomain, NetworkWorkerProtocolError> {
    BrokerLocalRecordDomain::new(*b"AOSNETLIFEDISP01")
        .map_err(|_| NetworkWorkerProtocolError::Authority)
}

/// Selects the only worker role admitted by the lifecycle wire contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkLifecycleWorkerRoleV1 {
    /// A fresh fixed worker may execute one existing-resource mutation plan.
    Mutation,
}

/// Selects the only descriptor role admitted by the lifecycle wire contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkLifecycleDescriptorRoleV1 {
    /// The broker must supply its retained exact target Network namespace.
    TargetNamespace,
}

/// Carries a bounded canonical existing-resource dispatch before authentication.
///
/// Decoding establishes framing only. Call [`Self::authenticate`] before using
/// any plan, target identity, action, or state as authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkLifecycleWorkerDispatchV1 {
    worker_role: NetworkLifecycleWorkerRoleV1,
    descriptor_role: NetworkLifecycleDescriptorRoleV1,
    request_id: [u8; 16],
    effect_digest: ObjectDigest,
    request_body: Vec<u8>,
    kernel_plan: NetworkKernelPlanV1,
    catalog: AuthenticatedNetworkPreparationV1,
    context: NetworkLifecycleDispatchContextV1,
    current_fence: Vec<u8>,
    operation_fence: Vec<u8>,
    effect: Vec<u8>,
    dispatch: Vec<u8>,
}

impl NetworkLifecycleWorkerDispatchV1 {
    /// Returns the untrusted durable request identifier.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the untrusted lifecycle-effect commitment.
    #[must_use]
    pub const fn effect_digest(&self) -> ObjectDigest {
        self.effect_digest
    }

    /// Returns the closed worker role carried by this canonical record.
    #[must_use]
    pub const fn worker_role(&self) -> NetworkLifecycleWorkerRoleV1 {
        self.worker_role
    }

    /// Returns the closed descriptor role carried by this canonical record.
    #[must_use]
    pub const fn descriptor_role(&self) -> NetworkLifecycleDescriptorRoleV1 {
        self.descriptor_role
    }

    /// Returns the untrusted canonical kernel plan.
    #[must_use]
    pub const fn kernel_plan(&self) -> &NetworkKernelPlanV1 {
        &self.kernel_plan
    }

    /// Returns the sealed fence this untrusted record claims was current.
    ///
    /// A caller must obtain the latest fence independently from protected
    /// broker state. Echoing this value back as a freshness source does not
    /// establish that no later authority was committed.
    #[must_use]
    pub fn claimed_current_fence(&self) -> &[u8] {
        &self.current_fence
    }

    /// Returns the target namespace identity claimed by this untrusted record.
    ///
    /// Canonical decoding does not authenticate this value. A process boundary
    /// may use it only to correlate bytes received from an independently
    /// authenticated broker execution. Broker-side authority decisions must
    /// instead use [`Self::authenticate_target_association`].
    #[must_use]
    pub const fn claimed_target_namespace(&self) -> NetworkNamespaceIdentityV1 {
        self.context.authority.identity
    }

    /// Authenticates this exact dispatch and its retained target association.
    ///
    /// This is a broker-side admission check only. It does not reload the
    /// protected current fence, inspect a clock, claim replay, or authorize an
    /// execution step.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkWorkerProtocolError::Authority`] unless the complete
    /// dispatch authenticates and its sealed resource handle and namespace
    /// identity equal the broker's retained custody descriptor.
    pub fn authenticate_target_association(
        self,
        authority: &NetworkAuthorityV1,
        network_handle: [u8; 32],
        target: NamespaceIdentity,
    ) -> Result<(), NetworkWorkerProtocolError> {
        let authenticated = self.authenticate(authority)?;
        let claimed = authenticated.request.context.authority.identity;
        if claimed.network_handle() != network_handle
            || claimed.namespace_device() != target.device
            || claimed.namespace_inode() != target.inode
        {
            return Err(NetworkWorkerProtocolError::Authority);
        }
        Ok(())
    }

    /// Decodes one bounded canonical lifecycle worker record.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkWorkerProtocolError`] for an unknown role or version,
    /// malformed length, oversized field, invalid plan, or noncanonical bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, NetworkWorkerProtocolError> {
        if bytes.len() > MAXIMUM_NETWORK_LIFECYCLE_WORKER_REQUEST_BYTES {
            return Err(NetworkWorkerProtocolError::TooLarge);
        }
        if bytes.len() < REQUEST_HEADER_BYTES {
            return invalid("truncated lifecycle header");
        }

        let mut decoder = Decoder::new(bytes);
        if decoder.take::<8>()? != *REQUEST_MAGIC || decoder.u16()? != REQUEST_VERSION {
            return invalid("unsupported lifecycle version");
        }
        let worker_role = decode_worker_role(decoder.byte()?)?;
        let descriptor_role = decode_descriptor_role(decoder.byte()?)?;
        let total = decoder.usize_u32()?;
        if total != bytes.len() {
            return invalid("lifecycle length is not exact");
        }
        let request_id = decoder.take()?;
        let effect_digest = ObjectDigest::from_bytes(decoder.take()?);
        let mut lengths = [0_usize; REQUEST_FIELD_COUNT];
        for length in &mut lengths {
            *length = decoder.usize_u32()?;
        }
        validate_lengths(lengths, bytes.len())?;

        let request_body = decoder.bytes(lengths[0])?.to_vec();
        let kernel_plan = NetworkKernelPlanV1::decode(decoder.bytes(lengths[1])?)
            .map_err(|_| NetworkWorkerProtocolError::InvalidWire("invalid lifecycle plan"))?;
        let (assignment, resolution) = decode_catalog(decoder.bytes(lengths[2])?)?;
        let catalog = AuthenticatedNetworkPreparationV1 {
            resolution,
            assignment,
            sealed: decoder.bytes(lengths[3])?.to_vec(),
        };
        let context = NetworkLifecycleDispatchContextV1::decode(decoder.bytes(lengths[4])?)?;
        let current_fence = decoder.bytes(lengths[5])?.to_vec();
        let operation_fence = decoder.bytes(lengths[6])?.to_vec();
        let effect = decoder.bytes(lengths[7])?.to_vec();
        let dispatch = decoder.bytes(lengths[8])?.to_vec();
        decoder.finish()?;

        let message = Self {
            worker_role,
            descriptor_role,
            request_id,
            effect_digest,
            request_body,
            kernel_plan,
            catalog,
            context,
            current_fence,
            operation_fence,
            effect,
            dispatch,
        };
        message.validate_shape()?;
        if message.encode()? != bytes {
            return invalid("noncanonical lifecycle encoding");
        }
        Ok(message)
    }

    /// Encodes this record in canonical lifecycle-worker format one.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkWorkerProtocolError`] when a field is invalid,
    /// oversized, or inconsistent with the fixed message ceiling.
    pub fn encode(&self) -> Result<Vec<u8>, NetworkWorkerProtocolError> {
        self.validate_shape()?;
        let catalog =
            encode_authenticated_resolution(self.catalog.assignment, &self.catalog.resolution);
        let context = self.context.encode()?;
        let fields: [&[u8]; REQUEST_FIELD_COUNT] = [
            &self.request_body,
            self.kernel_plan.as_bytes(),
            &catalog,
            &self.catalog.sealed,
            &context,
            &self.current_fence,
            &self.operation_fence,
            &self.effect,
            &self.dispatch,
        ];
        let total = fields.iter().try_fold(REQUEST_HEADER_BYTES, |sum, field| {
            sum.checked_add(field.len())
                .ok_or(NetworkWorkerProtocolError::TooLarge)
        })?;
        if total > MAXIMUM_NETWORK_LIFECYCLE_WORKER_REQUEST_BYTES {
            return Err(NetworkWorkerProtocolError::TooLarge);
        }

        let mut bytes = Vec::with_capacity(total);
        bytes.extend_from_slice(REQUEST_MAGIC);
        bytes.extend_from_slice(&REQUEST_VERSION.to_be_bytes());
        bytes.push(worker_role_code(self.worker_role));
        bytes.push(descriptor_role_code(self.descriptor_role));
        push_length(&mut bytes, total)?;
        bytes.extend_from_slice(&self.request_id);
        bytes.extend_from_slice(self.effect_digest.as_bytes());
        for field in fields {
            push_length(&mut bytes, field.len())?;
        }
        for field in fields {
            bytes.extend_from_slice(field);
        }
        Ok(bytes)
    }

    /// Authenticates every durable, request, target, plan, and role relation.
    ///
    /// This does not authorize a mutation. The returned value hides its plan
    /// and target until [`AuthenticatedNetworkLifecycleWorkerDispatchV1::authorize_execution`]
    /// has claimed the attempt under fresh effect authority.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkWorkerProtocolError::Authority`] unless all protected
    /// records and their current/resource targets form one exact association.
    pub fn authenticate(
        self,
        authority: &NetworkAuthorityV1,
    ) -> Result<AuthenticatedNetworkLifecycleWorkerDispatchV1, NetworkWorkerProtocolError> {
        let (current_fence, effect) = authenticate_association(authority, &self)?;
        Ok(AuthenticatedNetworkLifecycleWorkerDispatchV1 {
            request: self,
            current_fence,
            effect,
        })
    }

    fn validate_shape(&self) -> Result<(), NetworkWorkerProtocolError> {
        let catalog =
            encode_authenticated_resolution(self.catalog.assignment, &self.catalog.resolution);
        let context = self.context.encode()?;
        let lengths = [
            self.request_body.len(),
            self.kernel_plan.as_bytes().len(),
            catalog.len(),
            self.catalog.sealed.len(),
            context.len(),
            self.current_fence.len(),
            self.operation_fence.len(),
            self.effect.len(),
            self.dispatch.len(),
        ];
        let total = lengths
            .iter()
            .try_fold(REQUEST_HEADER_BYTES, |sum, length| {
                sum.checked_add(*length)
                    .ok_or(NetworkWorkerProtocolError::TooLarge)
            })?;
        validate_lengths(lengths, total)?;
        if self.request_id == [0; 16]
            || self.effect_digest.as_bytes() == &[0; 32]
            || self.worker_role != NetworkLifecycleWorkerRoleV1::Mutation
            || self.descriptor_role != NetworkLifecycleDescriptorRoleV1::TargetNamespace
        {
            return invalid("invalid lifecycle identity or role");
        }
        Ok(())
    }
}

/// Carries a fully authenticated lifecycle request before its replay claim.
pub struct AuthenticatedNetworkLifecycleWorkerDispatchV1 {
    request: NetworkLifecycleWorkerDispatchV1,
    current_fence: BrokerAuthorizationFenceV1,
    effect: BrokerEffectIntentV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NetworkLifecycleDispatchContextV1 {
    sandbox_id: [u8; 16],
    transport_digest: ObjectDigest,
    semantic_digest: ObjectDigest,
    verb: BrokerVerb,
    action: NetworkNamespaceLifecycleActionV1,
    preparation_generation: u64,
    preparation_digest: ObjectDigest,
    authority: NetworkNamespaceLifecycleAuthorityV1,
    desired_state: NetworkNamespaceObservedStateV1,
}

impl NetworkLifecycleDispatchContextV1 {
    fn from_durable(
        durable: &AmbiguousNetworkLifecycleDispatchV1,
    ) -> Result<Self, NetworkWorkerProtocolError> {
        let context = Self {
            sandbox_id: durable.sandbox_id,
            transport_digest: durable.transport_digest,
            semantic_digest: durable.semantic_digest,
            verb: durable.verb,
            action: durable.action,
            preparation_generation: durable.preparation_generation,
            preparation_digest: durable.preparation_digest,
            authority: durable.authority,
            desired_state: durable.desired_state,
        };
        context.validate()?;
        Ok(context)
    }

    fn encode(self) -> Result<Vec<u8>, NetworkWorkerProtocolError> {
        self.validate()?;
        let identity = self.authority.identity;
        let kernel_plan_digest = self.authority.kernel_plan_digest;
        let mut bytes = Vec::with_capacity(CONTEXT_BYTES);
        bytes.extend_from_slice(CONTEXT_MAGIC);
        bytes.extend_from_slice(&CONTEXT_VERSION.to_be_bytes());
        bytes.push(action_code(self.action));
        bytes.push(verb_code(self.verb)?);
        bytes.extend_from_slice(&self.sandbox_id);
        bytes.extend_from_slice(&self.preparation_generation.to_be_bytes());
        bytes.extend_from_slice(self.preparation_digest.as_bytes());
        bytes.extend_from_slice(kernel_plan_digest.as_bytes());
        bytes.extend_from_slice(&identity.network_handle());
        bytes.extend_from_slice(&identity.kernel_boot_id());
        bytes.extend_from_slice(&identity.namespace_device().to_be_bytes());
        bytes.extend_from_slice(&identity.namespace_inode().to_be_bytes());
        bytes.extend_from_slice(self.authority.resource_digest.as_bytes());
        bytes.extend_from_slice(&self.authority.highest_lease_generation.to_be_bytes());
        bytes.extend_from_slice(self.authority.highest_lease_digest.as_bytes());
        encode_state(&mut bytes, self.authority.observed_state);
        encode_state(&mut bytes, self.desired_state);
        bytes.extend_from_slice(self.transport_digest.as_bytes());
        bytes.extend_from_slice(self.semantic_digest.as_bytes());
        if bytes.len() != CONTEXT_BYTES {
            return invalid("lifecycle context size changed");
        }
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, NetworkWorkerProtocolError> {
        if bytes.len() != CONTEXT_BYTES {
            return invalid("lifecycle context length is invalid");
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.take::<8>()? != *CONTEXT_MAGIC || decoder.u16()? != CONTEXT_VERSION {
            return invalid("lifecycle context header is invalid");
        }
        let action = decode_action(decoder.byte()?)?;
        let verb = decode_verb(decoder.byte()?)?;
        let sandbox_id = decoder.take()?;
        let preparation_generation = decoder.u64()?;
        let preparation_digest = ObjectDigest::from_bytes(decoder.take()?);
        let kernel_plan_digest = ObjectDigest::from_bytes(decoder.take()?);
        let identity = NetworkNamespaceIdentityV1::new(
            decoder.take()?,
            decoder.take()?,
            decoder.u64()?,
            decoder.u64()?,
        )
        .map_err(|_| NetworkWorkerProtocolError::InvalidWire("invalid target identity"))?;
        let resource_digest = ObjectDigest::from_bytes(decoder.take()?);
        let highest_lease_generation = decoder.u64()?;
        let highest_lease_digest = ObjectDigest::from_bytes(decoder.take()?);
        let observed_state = decode_state(&mut decoder)?;
        let desired_state = decode_state(&mut decoder)?;
        let transport_digest = ObjectDigest::from_bytes(decoder.take()?);
        let semantic_digest = ObjectDigest::from_bytes(decoder.take()?);
        decoder.finish()?;
        let context = Self {
            sandbox_id,
            transport_digest,
            semantic_digest,
            verb,
            action,
            preparation_generation,
            preparation_digest,
            authority: NetworkNamespaceLifecycleAuthorityV1 {
                identity,
                observed_state,
                resource_digest,
                kernel_plan_digest,
                highest_lease_generation,
                highest_lease_digest,
            },
            desired_state,
        };
        context.validate()?;
        if context.encode()? != bytes {
            return invalid("lifecycle context is not canonical");
        }
        Ok(context)
    }

    fn validate(self) -> Result<(), NetworkWorkerProtocolError> {
        let high_water_valid = match self.authority.highest_lease_generation {
            0 => self.authority.highest_lease_digest.as_bytes() == &[0; 32],
            _ => self.authority.highest_lease_digest.as_bytes() != &[0; 32],
        };
        let active_prior_valid = match self.authority.observed_state.kind() {
            NetworkNamespaceObservedStateKindV1::Armed
            | NetworkNamespaceObservedStateKindV1::Fenced => self
                .authority
                .observed_state
                .lease()
                .is_some_and(|(digest, generation, _)| {
                    generation == self.authority.highest_lease_generation
                        && digest == self.authority.highest_lease_digest
                }),
            NetworkNamespaceObservedStateKindV1::DefaultDrop => true,
            NetworkNamespaceObservedStateKindV1::Absent => false,
        };
        let transition_valid = valid_transition(
            self.action,
            self.authority.observed_state,
            self.desired_state,
            self.authority.highest_lease_generation,
        );
        if self.sandbox_id == [0; 16]
            || self.transport_digest.as_bytes() == &[0; 32]
            || self.semantic_digest.as_bytes() == &[0; 32]
            || self.preparation_generation == 0
            || self.preparation_digest.as_bytes() == &[0; 32]
            || self.authority.resource_digest.as_bytes() == &[0; 32]
            || self.authority.kernel_plan_digest.as_bytes() == &[0; 32]
            || !action_matches_verb(self.action, self.verb)
            || !high_water_valid
            || !active_prior_valid
            || !transition_valid
        {
            return Err(NetworkWorkerProtocolError::Authority);
        }
        Ok(())
    }
}

pub(crate) fn issue_lifecycle_dispatch(
    authority: &NetworkAuthorityV1,
    durable: AmbiguousNetworkLifecycleDispatchV1,
    request_body: &[u8],
    catalog: AuthenticatedNetworkPreparationV1,
    kernel_plan: NetworkKernelPlanV1,
) -> Result<NetworkLifecycleWorkerDispatchV1, NetworkWorkerProtocolError> {
    let context = NetworkLifecycleDispatchContextV1::from_durable(&durable)?;
    let assignment = kernel_plan.assignment();
    let resolution = authority
        .validate_catalog(&catalog, assignment)
        .map_err(|_| NetworkWorkerProtocolError::Authority)?;
    let semantics = decode_admitted_semantics(request_body)?;
    let transport_digest = ObjectDigest::from_bytes(Sha256::digest(request_body).into());
    if durable.request_id == [0; 16]
        || durable.effect_digest.as_bytes() == &[0; 32]
        || transport_digest != durable.transport_digest
        || context.authority.kernel_plan_digest != kernel_plan.digest()
        || context.preparation_generation != resolution.binding().generation()
        || context.preparation_digest != resolution.binding().digest()
        || context.authority.identity.network_handle() != *resolution.reserved_network_handle()
        || context.sandbox_id != *assignment.sandbox().as_bytes()
        || !kernel_plan_matches_catalog(&kernel_plan, resolution)
        || !semantics_matches_context(&semantics, durable.request_id, context)
        || durable.effect_digest
            != lifecycle_effect_digest(
                durable.request_id,
                durable.transport_digest,
                durable.semantic_digest,
                durable.action,
                durable.authority,
                durable.desired_state,
            )
    {
        return Err(NetworkWorkerProtocolError::Authority);
    }

    let current_fence = authority
        .open_fence(&durable.sandbox_id, &durable.current_fence)
        .map_err(|_| NetworkWorkerProtocolError::Authority)?;
    let operation_fence = authority
        .open_operation_fence(&durable.request_id, &durable.operation_fence)
        .map_err(|_| NetworkWorkerProtocolError::Authority)?;
    let effect = authority
        .validate_operation_links(
            &durable.sandbox_id,
            &durable.request_id,
            &durable.operation_fence,
            &durable.effect,
        )
        .map_err(|_| NetworkWorkerProtocolError::Authority)?;
    validate_opened_authority(
        durable.request_id,
        durable.effect_digest,
        context,
        assignment,
        &current_fence,
        &operation_fence,
        &effect,
    )?;
    authority
        .check_current_fence(&current_fence)
        .map_err(|_| NetworkWorkerProtocolError::Authority)?;

    let payload = dispatch_payload(
        NetworkLifecycleWorkerRoleV1::Mutation,
        NetworkLifecycleDescriptorRoleV1::TargetNamespace,
        durable.request_id,
        durable.effect_digest,
        request_body,
        &kernel_plan,
        context,
        resolution,
    )?;
    let dispatch = authority
        .seal_local(&durable.request_id, dispatch_domain()?, &payload)
        .map_err(|_| NetworkWorkerProtocolError::Authority)?;
    let message = NetworkLifecycleWorkerDispatchV1 {
        worker_role: NetworkLifecycleWorkerRoleV1::Mutation,
        descriptor_role: NetworkLifecycleDescriptorRoleV1::TargetNamespace,
        request_id: durable.request_id,
        effect_digest: durable.effect_digest,
        request_body: request_body.to_vec(),
        kernel_plan,
        catalog,
        context,
        current_fence: durable.current_fence,
        operation_fence: durable.operation_fence,
        effect: durable.effect,
        dispatch,
    };
    message.validate_shape()?;
    Ok(message)
}

fn authenticate_association(
    authority: &NetworkAuthorityV1,
    request: &NetworkLifecycleWorkerDispatchV1,
) -> Result<(BrokerAuthorizationFenceV1, BrokerEffectIntentV1), NetworkWorkerProtocolError> {
    let semantics = decode_admitted_semantics(&request.request_body)?;
    let assignment = request.kernel_plan.assignment();
    let resolution = authority
        .validate_catalog(&request.catalog, assignment)
        .map_err(|_| NetworkWorkerProtocolError::Authority)?;
    let current_fence = authority
        .open_fence(&request.context.sandbox_id, &request.current_fence)
        .map_err(|_| NetworkWorkerProtocolError::Authority)?;
    let operation_fence = authority
        .open_operation_fence(&request.request_id, &request.operation_fence)
        .map_err(|_| NetworkWorkerProtocolError::Authority)?;
    let effect = authority
        .validate_operation_links(
            &request.context.sandbox_id,
            &request.request_id,
            &request.operation_fence,
            &request.effect,
        )
        .map_err(|_| NetworkWorkerProtocolError::Authority)?;
    let expected_dispatch = dispatch_payload(
        request.worker_role,
        request.descriptor_role,
        request.request_id,
        request.effect_digest,
        &request.request_body,
        &request.kernel_plan,
        request.context,
        resolution,
    )?;
    let opened_dispatch = authority
        .open_local(&request.request_id, dispatch_domain()?, &request.dispatch)
        .map_err(|_| NetworkWorkerProtocolError::Authority)?;
    let transport_digest = ObjectDigest::from_bytes(Sha256::digest(&request.request_body).into());
    if request.worker_role != NetworkLifecycleWorkerRoleV1::Mutation
        || request.descriptor_role != NetworkLifecycleDescriptorRoleV1::TargetNamespace
        || request.request_id == [0; 16]
        || request.effect_digest.as_bytes() == &[0; 32]
        || transport_digest != request.context.transport_digest
        || request.context.preparation_generation != resolution.binding().generation()
        || request.context.preparation_digest != resolution.binding().digest()
        || request.context.authority.identity.network_handle()
            != *resolution.reserved_network_handle()
        || request.context.sandbox_id != *assignment.sandbox().as_bytes()
        || request.context.authority.kernel_plan_digest != request.kernel_plan.digest()
        || !kernel_plan_matches_catalog(&request.kernel_plan, resolution)
        || !semantics_matches_context(&semantics, request.request_id, request.context)
        || request.effect_digest
            != lifecycle_effect_digest(
                request.request_id,
                request.context.transport_digest,
                request.context.semantic_digest,
                request.context.action,
                request.context.authority,
                request.context.desired_state,
            )
        || opened_dispatch != expected_dispatch
    {
        return Err(NetworkWorkerProtocolError::Authority);
    }
    validate_opened_authority(
        request.request_id,
        request.effect_digest,
        request.context,
        assignment,
        &current_fence,
        &operation_fence,
        &effect,
    )?;
    authority
        .check_current_fence(&current_fence)
        .map_err(|_| NetworkWorkerProtocolError::Authority)?;
    Ok((current_fence, effect))
}

#[allow(clippy::too_many_arguments)]
fn validate_opened_authority(
    request_id: [u8; 16],
    effect_digest: ObjectDigest,
    context: NetworkLifecycleDispatchContextV1,
    assignment: aos_sandbox_core::BrokerAssignment,
    current_fence: &BrokerAuthorizationFenceV1,
    operation_fence: &BrokerAuthorizationFenceV1,
    effect: &BrokerEffectIntentV1,
) -> Result<(), NetworkWorkerProtocolError> {
    let expected_target = BrokerGrantTarget::Resource(
        BrokerResourceHandle::from_bytes(context.authority.identity.network_handle())
            .map_err(|_| NetworkWorkerProtocolError::Authority)?,
    );
    if current_fence != operation_fence
        || current_fence.assignment() != assignment
        || effect.request_id() != &request_id
        || effect.transport_request_digest() != context.transport_digest
        || effect.request_digest() != context.semantic_digest
        || effect.verb() != context.verb
        || effect.target() != expected_target
        || effect.status() != BrokerEffectStatusV1::Pending
        || effect.plan_digest() != operation_fence.plan_digest()
        || effect.host_boot_id() != &context.authority.identity.kernel_boot_id()
        || effect_digest
            != lifecycle_effect_digest(
                request_id,
                context.transport_digest,
                context.semantic_digest,
                context.action,
                context.authority,
                context.desired_state,
            )
    {
        return Err(NetworkWorkerProtocolError::Authority);
    }
    Ok(())
}

fn semantics_matches_context(
    semantics: &CanonicalNetworkSemanticsV1,
    request_id: [u8; 16],
    context: NetworkLifecycleDispatchContextV1,
) -> bool {
    let identity = context.authority.identity;
    semantics.header().request_id() == &request_id
        && semantics.argument_commitment().digest() == context.semantic_digest
        && *semantics.fence().sandbox_id() == context.sandbox_id
        && semantics.broker_verb() == context.verb
        && operation_matches_context(
            semantics.operation(),
            context.action,
            identity.network_handle(),
            context.desired_state,
        )
}

fn operation_matches_context(
    operation: &NetworkOperation,
    action: NetworkNamespaceLifecycleActionV1,
    network_handle: [u8; 32],
    desired_state: NetworkNamespaceObservedStateV1,
) -> bool {
    match (operation, action) {
        (
            NetworkOperation::ArmLease {
                network_handle: requested_handle,
                ownership_lease_digest,
                lease_generation,
                fail_stop_boottime_nanoseconds,
            },
            NetworkNamespaceLifecycleActionV1::Arm,
        )
        | (
            NetworkOperation::RenewLease {
                network_handle: requested_handle,
                ownership_lease_digest,
                lease_generation,
                fail_stop_boottime_nanoseconds,
            },
            NetworkNamespaceLifecycleActionV1::Renew,
        ) => {
            requested_handle == &network_handle
                && desired_state
                    .lease()
                    .is_some_and(|(digest, generation, deadline)| {
                        digest.as_bytes() == ownership_lease_digest
                            && generation == *lease_generation
                            && deadline == *fail_stop_boottime_nanoseconds
                    })
        }
        (
            NetworkOperation::Disarm {
                network_handle: requested_handle,
            },
            NetworkNamespaceLifecycleActionV1::Disarm,
        ) => {
            requested_handle == &network_handle
                && desired_state.kind() == NetworkNamespaceObservedStateKindV1::DefaultDrop
        }
        (
            NetworkOperation::Destroy {
                network_handle: requested_handle,
            },
            NetworkNamespaceLifecycleActionV1::Destroy,
        ) => {
            requested_handle == &network_handle
                && desired_state.kind() == NetworkNamespaceObservedStateKindV1::Absent
        }
        _ => false,
    }
}

fn valid_transition(
    action: NetworkNamespaceLifecycleActionV1,
    prior: NetworkNamespaceObservedStateV1,
    desired: NetworkNamespaceObservedStateV1,
    high_water: u64,
) -> bool {
    match action {
        NetworkNamespaceLifecycleActionV1::Arm => {
            prior.kind() == NetworkNamespaceObservedStateKindV1::DefaultDrop
                && desired.kind() == NetworkNamespaceObservedStateKindV1::Armed
                && desired
                    .lease()
                    .is_some_and(|(_, generation, _)| generation > high_water)
        }
        NetworkNamespaceLifecycleActionV1::Renew => {
            prior.kind() == NetworkNamespaceObservedStateKindV1::Armed
                && desired.kind() == NetworkNamespaceObservedStateKindV1::Armed
                && prior.lease().zip(desired.lease()).is_some_and(
                    |((_, _, prior_deadline), (_, generation, desired_deadline))| {
                        generation > high_water && desired_deadline > prior_deadline
                    },
                )
        }
        NetworkNamespaceLifecycleActionV1::Disarm => {
            matches!(
                prior.kind(),
                NetworkNamespaceObservedStateKindV1::Armed
                    | NetworkNamespaceObservedStateKindV1::Fenced
            ) && desired.kind() == NetworkNamespaceObservedStateKindV1::DefaultDrop
        }
        NetworkNamespaceLifecycleActionV1::Destroy => {
            matches!(
                prior.kind(),
                NetworkNamespaceObservedStateKindV1::DefaultDrop
                    | NetworkNamespaceObservedStateKindV1::Fenced
            ) && desired.kind() == NetworkNamespaceObservedStateKindV1::Absent
        }
        NetworkNamespaceLifecycleActionV1::Fence => false,
    }
}

fn dispatch_payload(
    worker_role: NetworkLifecycleWorkerRoleV1,
    descriptor_role: NetworkLifecycleDescriptorRoleV1,
    request_id: [u8; 16],
    effect_digest: ObjectDigest,
    request_body: &[u8],
    kernel_plan: &NetworkKernelPlanV1,
    context: NetworkLifecycleDispatchContextV1,
    catalog: &ResolvedNetworkPreparationV1,
) -> Result<Vec<u8>, NetworkWorkerProtocolError> {
    let context_digest = Sha256::digest(context.encode()?);
    let mut bytes = Vec::with_capacity(228);
    bytes.extend_from_slice(DISPATCH_MAGIC);
    bytes.extend_from_slice(&DISPATCH_VERSION.to_be_bytes());
    bytes.push(worker_role_code(worker_role));
    bytes.push(descriptor_role_code(descriptor_role));
    bytes.extend_from_slice(&request_id);
    bytes.extend_from_slice(effect_digest.as_bytes());
    bytes.extend_from_slice(&Sha256::digest(request_body));
    bytes.extend_from_slice(kernel_plan.digest().as_bytes());
    bytes.extend_from_slice(&context_digest);
    bytes.extend_from_slice(&catalog.binding().generation().to_be_bytes());
    bytes.extend_from_slice(catalog.binding().digest().as_bytes());
    bytes.extend_from_slice(catalog.reserved_network_handle());
    Ok(bytes)
}
