//! Joins distinct live holder and publisher channels to one registered request.
//!
//! The borrowed result establishes request possession and current protected
//! issuance/policy consistency. It does not authorize publication: current
//! runtime assignment, source release, root authority, reservations, atomic
//! challenge consumption, and completion permits remain separate admission
//! requirements. Nothing in this module writes a decision or signs a plan.

use aos_sandbox_core::format::decode_publisher_admission_request_v1;
use aos_sandbox_core::{CapabilityId, PublisherAdmissionRequestV1};

use super::*;
use crate::local_sessions::{
    AuthenticatedLocalRecord, LocalSessionError, LocalSessionId, LocalSessionRegistry,
};
use crate::publisher_authority::{
    PublisherAuthorityError, PublisherAuthorityLimits, PublisherCapabilityRegistry,
};
use crate::publisher_ingress::PublisherChallengeRegistrationV1;
use crate::publisher_sessions::LivePublisherExecution;

mod runtime;
pub use runtime::RuntimeJoinedPublisherRequest;

/// Configures protected replay and clock bounds for holder-request joining.
#[derive(Clone, Copy, Debug)]
pub struct PublisherJoinPolicy {
    /// Existing publisher registration and protected policy limits.
    pub control: PublisherControlPolicy,
    /// Complete capability and issuance audit replay bounds.
    pub authority_limits: PublisherAuthorityLimits,
}

/// Reports failed channel joining without granting fallback admission.
#[derive(Debug, thiserror::Error)]
pub enum PublisherJoinError {
    /// The presented bytes differ from the exact registered pending request.
    #[error("holder request does not match a registered publisher challenge")]
    RequestMismatch,
    /// Holder, channel, capability, or installed scope bindings disagree.
    #[error("holder request does not match its authenticated local session")]
    HolderMismatch,
    /// Current local issuance evidence is absent, stale, or inconsistent.
    #[error("holder capability does not match current local issuance")]
    IssuanceMismatch,
    /// A previous failed check permanently invalidated this borrowed join.
    #[error("publisher request join is invalidated")]
    Invalidated,
    /// Fresh runtime acquisition or origin-to-current continuity failed.
    #[error(transparent)]
    Runtime(#[from] crate::runtime_scope::CurrentRuntimeScopeError),
    /// The actual holder record or retained scope failed validation.
    #[error(transparent)]
    Holder(#[from] LocalSessionError),
    /// The original publisher execution or connection is no longer live.
    #[error(transparent)]
    Publisher(#[from] PublisherSessionError),
    /// Protected capability replay, lookup, or individual revocation failed.
    #[error(transparent)]
    Capability(#[from] PublisherAuthorityError),
    /// Registration, current policy, request encoding, or trusted time failed.
    #[error(transparent)]
    Control(#[from] PublisherControlError),
}

/// Holds one authenticated request join under exclusive controller state access.
///
/// Neither this value nor a successful recheck authorizes a publication effect.
/// Runtime fields bind the installed session to its issuance record, not to a
/// current assignment head. Runtime-issued sessions must additionally match
/// their complete historical observation evidence; administrative sessions
/// cannot substitute for that origin. Source release, root registry, reservation state,
/// challenge consumption, signing, and completion remain unverified here.
/// No live proof can be reconstructed from the owned request or an audit receipt.
/// [`Self::bind_current_runtime`] performs a separate fresh Host exchange and
/// origin-continuity check, returning a distinct non-authorizing context.
///
/// A failed recheck permanently poisons the join and closes holder ingress.
/// The closed holder slot can then be removed with `LocalSessionRegistry::invalidate`;
/// a subsequent receive also removes it. Closing does not revoke durable
/// capabilities or cancel outstanding permits.
///
/// ```compile_fail
/// use aos_sandbox::publisher_control::JoinedPublisherRequest;
/// fn duplicate<'a>(join: &JoinedPublisherRequest<'a>) -> JoinedPublisherRequest<'a> {
///     join.clone()
/// }
/// ```
pub struct JoinedPublisherRequest<'a> {
    journal: &'a mut Journal,
    holder: AuthenticatedLocalRecord<'a>,
    publisher: LivePublisherExecution<'a>,
    execution: PublisherExecutionRegistrationV1,
    registration: PublisherChallengeRegistrationV1,
    config: PublisherJoinPolicy,
    boot: [u8; 16],
    observed: RawPairedClockSample,
    valid: bool,
}

impl JoinedPublisherRequest<'_> {
    /// Borrows the exact registered request presented by the authenticated holder.
    #[must_use]
    pub fn request(&self) -> &PublisherAdmissionRequestV1 {
        &self.registration.fields().request
    }

    /// Returns the capability handle installed on the actual holder channel.
    #[must_use]
    pub const fn capability_id(&self) -> CapabilityId {
        self.holder.capability_id()
    }

    /// Revalidates live channels, protected claims, and original time bounds.
    ///
    /// Successful rechecks never refresh the challenge or issuance deadlines.
    /// They are observations, not migration fences or publication authorization.
    ///
    /// # Errors
    /// Rejects an invalidated join, unhealthy journal, changed channel or scope,
    /// inactive capability, inconsistent issuance or policy, and expired or
    /// changed protected time. Any failure permanently closes holder ingress;
    /// a failed publisher observation additionally retires its connection.
    pub fn recheck<T>(&mut self, clock: &mut T) -> Result<(), PublisherJoinError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        if !self.valid {
            return Err(PublisherJoinError::Invalidated);
        }
        let result = self.check_current(clock);
        if result.is_err() {
            self.valid = false;
            self.holder.close_channel();
        }
        result
    }

    fn check_current<T>(&mut self, clock: &mut T) -> Result<(), PublisherJoinError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        if let Err(error) = self.journal.ensure_protected_authority() {
            self.publisher.retire();
            return Err(PublisherControlError::from(error).into());
        }
        self.holder.recheck_execution_scope()?;
        self.bind_live_execution()?;
        let now = clock().map_err(|_| PublisherControlError::Clock)?;
        validate_clock(now, self.boot, self.config.control.clock_provenance)?;
        validate_elapsed(
            self.observed,
            now,
            self.registration.fields().expires_wall_seconds,
            u64::from(self.config.control.maximum_challenge_seconds),
        )?;
        challenge::validate_execution_time(&self.execution, now)?;
        challenge::validate_registration_clock(
            &self.registration,
            now,
            self.boot,
            self.config.control,
        )?;
        let policy = resolve_policy(
            self.journal,
            *self.publisher.scope(),
            self.config.control.policy_limits,
            now.wall_seconds(),
        )?;
        challenge::validate_current_request(
            self.journal,
            &self.registration.fields().request,
            &policy,
            self.config.control,
            now.wall_seconds(),
        )?;
        let holder_validity = self.bind_holder(&policy, now)?;
        self.bind_live_execution()?;
        self.holder.recheck_execution_scope()?;
        let fresh = clock().map_err(|_| PublisherControlError::Clock)?;
        validate_clock(fresh, self.boot, self.config.control.clock_provenance)?;
        validate_elapsed(
            now,
            fresh,
            self.registration.fields().expires_wall_seconds,
            u64::from(self.config.control.maximum_challenge_seconds),
        )?;
        challenge::validate_registration_clock(
            &self.registration,
            fresh,
            self.boot,
            self.config.control,
        )?;
        holder_validity.check(fresh)?;
        self.bind_live_execution()?;
        self.holder.recheck_execution_scope()?;
        // Track monotonic ordering between calls without changing either fixed
        // registration-derived deadline, including under a frozen wall clock.
        self.observed = fresh;
        Ok(())
    }

    fn bind_live_execution(&mut self) -> Result<(), PublisherJoinError> {
        let peer = self.publisher.recheck()?;
        let scope = self.publisher.scope();
        let fields = self.execution.fields();
        if fields.instance != self.publisher.instance()
            || fields.principal != scope.principal
            || fields.node != scope.node
            || fields.project != scope.project
            || fields.cache_resource != scope.cache_resource
            || fields.channel_binding != self.publisher.channel_binding()
            || fields.boot_id != self.boot
            || fields.clock_provenance != self.config.control.clock_provenance
            || fields.peer_pid != peer.pid()
            || fields.peer_tgid != peer.thread_group_id()
            || Some(fields.peer_cgroup_id) != peer.cgroup_id()
        {
            self.publisher.retire();
            return Err(
                PublisherControlError::Ingress(PublisherIngressError::ExecutionMismatch).into(),
            );
        }
        challenge::bind_request(&self.registration.fields().request, &self.execution)?;
        Ok(())
    }

    fn bind_holder(
        &mut self,
        policy: &ResolvedPolicy,
        now: RawPairedClockSample,
    ) -> Result<HolderValidity, PublisherJoinError> {
        let request = &self.registration.fields().request;
        let plan = request.plan().fields();
        let scope = self.holder.scope();
        if request.capability() != self.holder.capability_id()
            || request.cache_resource() != scope.cache_resource
            || plan.target.project != scope.project
            || plan.request.holder != scope.holder
            || plan.request.channel != self.holder.channel_binding()
        {
            return Err(PublisherJoinError::HolderMismatch);
        }

        let registry =
            PublisherCapabilityRegistry::load(self.journal, self.config.authority_limits)?;
        let capability = registry.resolve_current(self.holder.capability_id())?;
        let issuance = registry
            .resolve_issuance(self.holder.capability_id())?
            .ok_or(PublisherJoinError::IssuanceMismatch)?;
        let claims = capability.claims();
        let metadata = issuance.metadata();
        if issuance.runtime() != self.holder.runtime_issuance().as_ref() {
            return Err(PublisherJoinError::IssuanceMismatch);
        }
        // These runtime comparisons establish only immutable issuance/session
        // consistency. Feeding them to CapabilityRecord::authorize as current
        // assignment state would silently elevate an old scope snapshot.
        if issuance.is_revoked()
            || claims.holder != scope.holder
            || claims.channel_binding != self.holder.channel_binding()
            || claims.project != scope.project
            || claims.sandbox != Some(scope.sandbox)
            || claims.incarnation != Some(scope.incarnation)
            || claims.assignment_epoch != Some(scope.epoch)
            || claims.issuer != policy.controller.principal
            || claims.audience != policy.controller.principal
            || claims.policy_digest != plan.authority.policy
            || claims.revocation_scope != plan.authority.revocation_scope
            || claims.revocation_generation.get() != plan.authority.revocation_generation
            || metadata.session_id() != *self.holder.session_id().as_bytes()
            || metadata.boot_id() != self.boot
            || metadata.clock_provenance() != self.config.control.clock_provenance
            || metadata.policy_generation() != plan.authority.policy_generation
            || metadata.controller_generation() != plan.authority.controller_generation
            || metadata.cache_resource() != scope.cache_resource
            || metadata.isolation_policy() != policy.resource.isolation_policy()
        {
            return Err(PublisherJoinError::IssuanceMismatch);
        }
        let lifetime = claims
            .expires_at
            .checked_sub(metadata.observed_wall_seconds())
            .and_then(|seconds| u64::try_from(seconds).ok())
            .and_then(|seconds| seconds.checked_mul(1_000_000_000))
            .ok_or(PublisherControlError::Clock)?;
        let elapsed = now
            .boottime_nanoseconds()
            .checked_sub(metadata.observed_boottime_nanoseconds())
            .ok_or(PublisherControlError::Clock)?;
        if now.wall_seconds() < claims.not_before
            || now.wall_seconds() < metadata.observed_wall_seconds()
            || now.wall_seconds() >= claims.expires_at
            || elapsed >= lifetime
        {
            return Err(PublisherControlError::Clock.into());
        }
        let validity = HolderValidity {
            expires_wall_seconds: claims.expires_at,
            expires_boottime_nanoseconds: metadata
                .observed_boottime_nanoseconds()
                .checked_add(lifetime)
                .ok_or(PublisherControlError::Clock)?,
        };
        validity.check(now)?;
        Ok(validity)
    }
}

/// Preserves the original capability's independent wall and boottime expiry.
struct HolderValidity {
    expires_wall_seconds: i64,
    expires_boottime_nanoseconds: u64,
}

impl HolderValidity {
    fn check(&self, now: RawPairedClockSample) -> Result<(), PublisherJoinError> {
        if now.wall_seconds() >= self.expires_wall_seconds
            || now.boottime_nanoseconds() >= self.expires_boottime_nanoseconds
        {
            return Err(PublisherControlError::Clock.into());
        }
        Ok(())
    }
}

pub(crate) fn join_holder_request<'a, T>(
    journal: &'a mut Journal,
    holders: &'a mut LocalSessionRegistry,
    publishers: &'a mut PublisherSessionRegistry,
    holder_session: LocalSessionId,
    config: PublisherJoinPolicy,
    clock: &mut T,
) -> Result<JoinedPublisherRequest<'a>, PublisherJoinError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    validate_config(config.control)?;
    journal
        .ensure_protected_authority()
        .map_err(PublisherControlError::from)?;
    let mut holder = holders.receive(holder_session)?;
    let prepared = (|| {
        let request =
            decode_publisher_admission_request_v1(holder.payload(), challenge::request_limits())
                .map_err(PublisherControlError::from)?;
        let instance = request.plan().fields().target.instance;
        let store = PublisherIngressStore::load(journal, config.control.ingress_limits)
            .map_err(PublisherControlError::from)?;
        let registration = store
            .challenge(instance, request.challenge())
            .map_err(PublisherControlError::from)?
            .ok_or(PublisherJoinError::RequestMismatch)?;
        if registration.fields().request != request {
            return Err(PublisherJoinError::RequestMismatch);
        }
        let execution = store
            .execution(instance)
            .map_err(PublisherControlError::from)?
            .ok_or(PublisherJoinError::RequestMismatch)?;
        let boot = KernelBootId::current()
            .map_err(PublisherControlError::from)?
            .into_bytes();
        let observed = clock().map_err(|_| PublisherControlError::Clock)?;
        validate_clock(observed, boot, config.control.clock_provenance)?;
        Ok((registration, execution, boot, observed))
    })();
    let (registration, execution, boot, observed) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            holder.close_channel();
            return Err(error);
        }
    };
    let publisher = match publishers.retain_execution(execution.fields().instance) {
        Ok(publisher) => publisher,
        Err(error) => {
            holder.close_channel();
            return Err(error.into());
        }
    };
    let mut joined = JoinedPublisherRequest {
        journal,
        holder,
        publisher,
        execution,
        registration,
        config,
        boot,
        observed,
        valid: true,
    };
    joined.recheck(clock)?;
    Ok(joined)
}
