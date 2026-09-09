//! Pure admission model for privileged lifecycle-worker namespace inspection.
//!
//! This module defines the bounded request and response records for a future
//! fixed namespace-inspector process. It deliberately does not launch that
//! process, acquire a namespace, persist policy, or advertise effect readiness.
//! In the eventual runtime, the authenticated broker is the sole writer of an
//! immutable expected-attempt record after validating `READY`. The inspector
//! receives only lookup access to those records and may mutate only a separate,
//! one-shot spent-nonce ledger protected by the deployment's MAC policy.
//!
//! Neither canonical decoding nor a response produced by the inspector is
//! evidence. Only broker-side completion, after independently authenticating
//! the fixed inspector and correlating the response with the retained pending
//! attempt, creates [`ProvenLifecycleWorkerBootstrapNamespaceV1`].
//! The numeric namespace identity reported in worker `READY` is not included in
//! expected-attempt policy and supplies no authority; it remains correlation or
//! diagnostic input only. The inspector's pidfd observation is the sole source
//! of the response namespace identity.
//!
//! ```text
//! request:
//!   AOSNIQ01 | version:u16 | kind:u8 | fd-role:u8 | total:u32 | reserved:u32
//!   nonce:32 | boot-id:16 | not-before-ns:u64 | deadline-ns:u64
//!   request-id:16 | effect-digest:32 | dispatch-digest:32 | policy-digest:32
//!   pid:u32 | tgid:u32 | ppid:u32 | cgroup-id:u64
//!   launch-contract-digest:32 | exact-unit-len:u16 | reserved:u16
//!   forbidden-host-dev:u64 | forbidden-host-ino:u64
//!   forbidden-target-dev:u64 | forbidden-target-ino:u64
//!   cgroup-len:u16 | reserved:u16 | exact-unit:exact-unit-len
//!   lifecycle-worker-cgroup:cgroup-len
//!   SCM_RIGHTS: exactly one WorkerLeaderPidfd
//!
//! response:
//!   AOSNIR01 | version:u16 | kind:u8 | fd-role:u8 | total:u32 | reserved:u32
//!   nonce:32 | boot-id:16 | request-id:16 | effect-digest:32
//!   dispatch-digest:32 | policy-digest:32
//!   pid:u32 | tgid:u32 | ppid:u32 | cgroup-id:u64
//!   namespace-dev:u64 | namespace-ino:u64
//!   SCM_RIGHTS: exactly one WorkerBootstrapNetworkNamespace
//! ```

use std::collections::BTreeMap;

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_linux::pidfd::NamespaceIdentity;
use sha2::{Digest as _, Sha256};

use crate::systemd_socket_instance::validate_systemd_socket_instance_fields;

mod store;

const REQUEST_MAGIC: &[u8; 8] = b"AOSNIQ01";
const RESPONSE_MAGIC: &[u8; 8] = b"AOSNIR01";
const VERSION: u16 = 1;
const REQUEST_KIND: u8 = 1;
const RESPONSE_KIND: u8 = 2;
const HEADER_BYTES: usize = 20;
const REQUEST_FIXED_BYTES: usize = 288;
const RESPONSE_BYTES: usize = 216;
const MAXIMUM_UNIT_NAME_BYTES: usize = 192;
const MAXIMUM_CGROUP_BYTES: usize = 512;
const MAXIMUM_REQUEST_BYTES: usize =
    REQUEST_FIXED_BYTES + MAXIMUM_UNIT_NAME_BYTES + MAXIMUM_CGROUP_BYTES;
const CONTROL_SLICE_CGROUP: &str = "aos.slice/aos-control.slice";
const LIFECYCLE_WORKER_CGROUP_PREFIX: &str =
    "aos.slice/aos-control.slice/aos-sandbox-network-lifecycle-worker@";
const WORKER_CGROUP_SUFFIX: &str = ".service";

/// Identifies one descriptor role in the closed inspector protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NetworkNamespaceInspectorDescriptorRoleV1 {
    /// The request transfers the broker-retained lifecycle-worker leader pidfd.
    WorkerLeaderPidfd,
    /// The response transfers the inspector-observed bootstrap Network namespace.
    WorkerBootstrapNetworkNamespace,
}

impl NetworkNamespaceInspectorDescriptorRoleV1 {
    const fn code(self) -> u8 {
        match self {
            Self::WorkerLeaderPidfd => 1,
            Self::WorkerBootstrapNetworkNamespace => 2,
        }
    }

    fn decode(code: u8) -> Result<Self, NetworkNamespaceInspectorError> {
        match code {
            1 => Ok(Self::WorkerLeaderPidfd),
            2 => Ok(Self::WorkerBootstrapNetworkNamespace),
            _ => protocol("unknown namespace-inspector descriptor role"),
        }
    }
}

/// Reports fail-closed rejection by the namespace-inspector model.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum NetworkNamespaceInspectorError {
    /// Canonical framing, bounds, or descriptor shape was invalid.
    #[error("namespace-inspector protocol is invalid: {0}")]
    Protocol(&'static str),
    /// Independently provisioned deployment identity did not match.
    #[error("namespace-inspector deployment identity did not match")]
    DeploymentMismatch,
    /// The fixed connection or record subject did not match policy.
    #[error("namespace-inspector peer identity did not match")]
    PeerMismatch,
    /// The immutable expected-attempt policy was absent or inconsistent.
    #[error("namespace-inspector expected-attempt policy did not match")]
    PolicyMismatch,
    /// The attempt was not valid at the independently observed boot-time instant.
    #[error("namespace-inspector attempt is stale")]
    Stale,
    /// The one-shot nonce had already been spent.
    #[error("namespace-inspector attempt was replayed")]
    Replay,
    /// Protected expected-policy lookup failed without being collapsed to absence.
    #[error("namespace-inspector protected policy lookup failed")]
    ProtectedPolicy,
    /// The pidfd, cgroup, or namespace observation differed from policy.
    #[error("namespace-inspector kernel observation did not match")]
    ObservationMismatch,
    /// A prior error permanently closed this one-record session.
    #[error("namespace-inspector session is terminal")]
    Terminal,
}

/// Preserves model rejection or backend-specific spent-claim recovery evidence.
///
/// The protected filesystem ledger returns a lifetime-bound error containing
/// its pinned private inode on publication failure. Keeping that error generic
/// prevents admission from erasing ambiguous rename evidence merely to fit the
/// pure model's copyable error type.
#[derive(Debug, thiserror::Error)]
pub(crate) enum NetworkNamespaceInspectorAdmissionError<SpentError> {
    /// Pure protocol, identity, policy, clock, or observation admission failed.
    #[error("{0}")]
    Model(NetworkNamespaceInspectorError),
    /// The configured replay ledger failed and retained its backend evidence.
    #[error("namespace-inspector spent claim failed: {0}")]
    Spent(SpentError),
}

impl<SpentError> From<NetworkNamespaceInspectorError>
    for NetworkNamespaceInspectorAdmissionError<SpentError>
{
    fn from(error: NetworkNamespaceInspectorError) -> Self {
        Self::Model(error)
    }
}

/// Names one exact process and cgroup identity observed through a pidfd.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InspectorProcessIdentityV1 {
    pid: u32,
    thread_group_id: u32,
    parent_pid: u32,
    cgroup_id: u64,
}

impl InspectorProcessIdentityV1 {
    fn validate(self) -> Result<(), NetworkNamespaceInspectorError> {
        if self.pid == 0
            || self.thread_group_id != self.pid
            || self.parent_pid == 0
            || self.cgroup_id == 0
        {
            return protocol("invalid namespace-inspector process identity");
        }
        Ok(())
    }
}

/// Models the kernel-authenticated identity for one connection or record.
///
/// The future transport adapter must create this value only after retaining the
/// peer pidfd, validating exact cgroup membership, and checking kernel-provided
/// credentials. There is intentionally no general constructor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KernelAuthenticatedInspectorPeerV1 {
    process: InspectorProcessIdentityV1,
    uid: u32,
    gid: u32,
}

/// Models the separately authenticated system manager identity.
///
/// PID 1 is the sole permitted zero-parent subject. Keeping this role distinct
/// prevents the broker, inspector, or worker validation from accidentally
/// accepting a non-manager process with parent PID zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KernelAuthenticatedSystemdManagerV1 {
    pid: u32,
    thread_group_id: u32,
    parent_pid: u32,
    cgroup_id: u64,
    uid: u32,
    gid: u32,
}

impl KernelAuthenticatedSystemdManagerV1 {
    fn validate(self) -> Result<(), NetworkNamespaceInspectorError> {
        if self.pid != 1
            || self.thread_group_id != 1
            || self.parent_pid != 0
            || self.cgroup_id == 0
            || self.uid != 0
            || self.gid != 0
        {
            return Err(NetworkNamespaceInspectorError::PeerMismatch);
        }
        Ok(())
    }
}

/// Holds the fixed identities supplied by protected deployment provisioning.
///
/// This value cannot be decoded from caller wire. Its production constructor is
/// intentionally pending alongside root-owned policy provisioning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProvisionedNetworkNamespaceInspectorV1 {
    boot_id: [u8; 16],
    broker: KernelAuthenticatedInspectorPeerV1,
    inspector: KernelAuthenticatedInspectorPeerV1,
    systemd_manager: KernelAuthenticatedSystemdManagerV1,
    launch_contract_digest: ObjectDigest,
}

/// Models an independently authenticated live systemd launch observation.
///
/// The future inspector adapter must obtain this from the fixed manager and
/// validate the complete protected property allowlist. No caller-wire field can
/// construct this observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuthenticatedLifecycleWorkerLaunchObservationV1 {
    manager: KernelAuthenticatedSystemdManagerV1,
    unit_name: String,
    cgroup: String,
    process: InspectorProcessIdentityV1,
    launch_contract_digest: ObjectDigest,
}

/// Captures one validated lifecycle-worker `READY` admission.
///
/// A future broker adapter constructs this only while retaining the exact
/// worker-leader pidfd and resolved cgroup anchor. The identity is copied into
/// policy, but this pure model does not replace those retained kernel objects.
#[derive(Debug)]
pub(crate) struct ValidatedLifecycleWorkerLeaderV1 {
    process: InspectorProcessIdentityV1,
    cgroup: String,
    request_id: [u8; 16],
    effect_digest: ObjectDigest,
    dispatch_digest: ObjectDigest,
}

/// Binds broker-retained custody to the protected worker launch contract.
///
/// The host and target identities come from the broker's retained descriptors,
/// not worker input. The launch digest comes from independently provisioned
/// policy for the fixed, admission-only systemd unit. Unlike a fresh bootstrap
/// inode, all three values have concrete broker-side sources before inspection.
#[derive(Debug)]
pub(crate) struct BrokerLifecycleWorkerInspectionContextV1 {
    forbidden_host: NamespaceIdentity,
    forbidden_target: NamespaceIdentity,
}

/// Keeps the exact worker leader associated with one not-yet-completed request.
///
/// The eventual transport must obtain its sole `WorkerLeaderPidfd` from the
/// retained kernel object represented by this token, never from worker input.
#[derive(Debug)]
pub(crate) struct PendingLifecycleWorkerInspectionV1 {
    expected: ExpectedInspectorAttemptV1,
}

impl PendingLifecycleWorkerInspectionV1 {
    /// Creates an expected attempt from authenticated broker admission.
    ///
    /// This constructor is crate-private and accepts the move-only validated
    /// leader token rather than caller bytes. The production adapter that mints
    /// that token and retains its pidfd remains intentionally unimplemented.
    fn from_validated_ready(
        leader: ValidatedLifecycleWorkerLeaderV1,
        context: BrokerLifecycleWorkerInspectionContextV1,
        deployment: &ProvisionedNetworkNamespaceInspectorV1,
        nonce: [u8; 32],
        boot_id: [u8; 16],
        not_before_boottime_ns: u64,
        deadline_boottime_ns: u64,
    ) -> Result<Self, NetworkNamespaceInspectorError> {
        validate_nonce(nonce)?;
        validate_boot_id(boot_id)?;
        leader.process.validate()?;
        validate_lifecycle_worker_cgroup(&leader.cgroup)?;
        validate_namespace(context.forbidden_host)?;
        validate_namespace(context.forbidden_target)?;
        if leader.request_id == [0; 16]
            || leader.effect_digest.as_bytes() == &[0; 32]
            || leader.dispatch_digest.as_bytes() == &[0; 32]
            || deployment.launch_contract_digest.as_bytes() == &[0; 32]
            || deployment.boot_id != boot_id
            || context.forbidden_host == context.forbidden_target
            || not_before_boottime_ns >= deadline_boottime_ns
        {
            return protocol("invalid namespace-inspector attempt identity");
        }

        let mut expected = ExpectedInspectorAttemptV1 {
            nonce,
            boot_id,
            not_before_boottime_ns,
            deadline_boottime_ns,
            request_id: leader.request_id,
            effect_digest: leader.effect_digest,
            dispatch_digest: leader.dispatch_digest,
            policy_digest: ObjectDigest::from_bytes([0; 32]),
            process: leader.process,
            unit_name: lifecycle_worker_unit_name(&leader.cgroup)?.to_owned(),
            cgroup: leader.cgroup,
            launch_contract_digest: deployment.launch_contract_digest,
            forbidden_host: context.forbidden_host,
            forbidden_target: context.forbidden_target,
        };
        expected.policy_digest = expected.compute_digest()?;
        Ok(Self { expected })
    }

    /// Encodes the untrusted request bytes correlated with this pending attempt.
    fn encode_request(&self) -> Result<Vec<u8>, NetworkNamespaceInspectorError> {
        NetworkNamespaceInspectionRequestV1::from_expected(&self.expected).encode()
    }
}

/// Stores immutable expected-attempt records written by authenticated admission.
///
/// This in-memory type is only a pure ownership model. It is not durable policy
/// storage and must not be wired into effect readiness. The eventual broker is
/// the only component permitted to call [`Self::record_from_admission`].
#[derive(Debug, Default)]
pub(crate) struct InspectorExpectedAttemptCatalogV1 {
    records: BTreeMap<[u8; 32], ExpectedInspectorAttemptV1>,
}

impl InspectorExpectedAttemptCatalogV1 {
    /// Records one immutable expected attempt after authenticated admission.
    fn record_from_admission(
        &mut self,
        pending: &PendingLifecycleWorkerInspectionV1,
    ) -> Result<(), NetworkNamespaceInspectorError> {
        if self.records.contains_key(&pending.expected.nonce) {
            return Err(NetworkNamespaceInspectorError::PolicyMismatch);
        }
        self.records
            .insert(pending.expected.nonce, pending.expected.clone());
        Ok(())
    }
}

/// Provides read-only access to broker-written expected-attempt policy.
pub(crate) trait InspectorAttemptPolicyLookupV1 {
    /// Looks up one owned immutable expected attempt by its fresh nonce.
    ///
    /// Only exact initial absence returns `Ok(None)`; observation and decoding
    /// failures remain distinguishable errors.
    fn lookup(
        &self,
        nonce: &[u8; 32],
    ) -> Result<Option<ExpectedInspectorAttemptV1>, NetworkNamespaceInspectorError>;
}

impl InspectorAttemptPolicyLookupV1 for InspectorExpectedAttemptCatalogV1 {
    fn lookup(
        &self,
        nonce: &[u8; 32],
    ) -> Result<Option<ExpectedInspectorAttemptV1>, NetworkNamespaceInspectorError> {
        Ok(self.records.get(nonce).cloned())
    }
}

/// Claims nonces in storage separate from immutable expected-attempt policy.
pub(crate) trait InspectorSpentNonceLedgerV1 {
    /// Error returned by one claim while the ledger remains borrowed.
    type Error<'ledger>: std::fmt::Debug + std::fmt::Display
    where
        Self: 'ledger;

    /// Atomically marks `nonce` spent and reports whether this call claimed it.
    ///
    /// The eventual implementation must be root-owned, persistent for the
    /// deployment's replay horizon, and writable by the inspector only through
    /// its MAC-confined one-shot claim operation.
    fn claim_once<'ledger>(
        &'ledger mut self,
        expected: &ExpectedInspectorAttemptV1,
    ) -> Result<bool, Self::Error<'ledger>>;
}

/// Captures one trusted monotonic clock observation in the current boot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InspectorTrustedTimeV1 {
    boot_id: [u8; 16],
    boottime_ns: u64,
}

/// Supplies fresh boot identity and `CLOCK_BOOTTIME` observations.
pub(crate) trait InspectorTrustedClockV1 {
    /// Reads the protected current boot identity and monotonic boot time.
    fn observe(&mut self) -> Result<InspectorTrustedTimeV1, NetworkNamespaceInspectorError>;
}

/// Represents descriptor and ancillary shape already parsed by the transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InspectorDescriptorEnvelopeV1 {
    count: usize,
    ancillary_is_canonical: bool,
}

/// Carries a canonical request whose fields remain wholly untrusted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NetworkNamespaceInspectionRequestV1 {
    expected: ExpectedInspectorAttemptV1,
}

impl NetworkNamespaceInspectionRequestV1 {
    fn from_expected(expected: &ExpectedInspectorAttemptV1) -> Self {
        Self {
            expected: expected.clone(),
        }
    }

    /// Decodes bounded request framing without granting authority.
    fn decode(bytes: &[u8]) -> Result<Self, NetworkNamespaceInspectorError> {
        if bytes.len() < REQUEST_FIXED_BYTES || bytes.len() > MAXIMUM_REQUEST_BYTES {
            return protocol("namespace-inspector request length is invalid");
        }
        validate_header(
            bytes,
            REQUEST_MAGIC,
            REQUEST_KIND,
            NetworkNamespaceInspectorDescriptorRoleV1::WorkerLeaderPidfd,
        )?;

        let unit_length = usize::from(u16::from_be_bytes(copy_array(&bytes[248..250])?));
        let cgroup_length = usize::from(u16::from_be_bytes(copy_array(&bytes[284..286])?));
        if bytes[250..252] != [0; 2]
            || bytes[286..288] != [0; 2]
            || unit_length == 0
            || unit_length > MAXIMUM_UNIT_NAME_BYTES
            || cgroup_length == 0
            || cgroup_length > MAXIMUM_CGROUP_BYTES
            || bytes.len() != REQUEST_FIXED_BYTES + unit_length + cgroup_length
        {
            return protocol("namespace-inspector unit or cgroup length is invalid");
        }
        let unit_end = REQUEST_FIXED_BYTES + unit_length;
        let unit_name = std::str::from_utf8(&bytes[REQUEST_FIXED_BYTES..unit_end])
            .map_err(|_| {
                NetworkNamespaceInspectorError::Protocol("namespace-inspector unit is not UTF-8")
            })?
            .to_owned();
        let cgroup = std::str::from_utf8(&bytes[unit_end..])
            .map_err(|_| {
                NetworkNamespaceInspectorError::Protocol("namespace-inspector cgroup is not UTF-8")
            })?
            .to_owned();
        let request = Self {
            expected: ExpectedInspectorAttemptV1 {
                nonce: copy_array(&bytes[20..52])?,
                boot_id: copy_array(&bytes[52..68])?,
                not_before_boottime_ns: u64::from_be_bytes(copy_array(&bytes[68..76])?),
                deadline_boottime_ns: u64::from_be_bytes(copy_array(&bytes[76..84])?),
                request_id: copy_array(&bytes[84..100])?,
                effect_digest: ObjectDigest::from_bytes(copy_array(&bytes[100..132])?),
                dispatch_digest: ObjectDigest::from_bytes(copy_array(&bytes[132..164])?),
                policy_digest: ObjectDigest::from_bytes(copy_array(&bytes[164..196])?),
                process: InspectorProcessIdentityV1 {
                    pid: u32::from_be_bytes(copy_array(&bytes[196..200])?),
                    thread_group_id: u32::from_be_bytes(copy_array(&bytes[200..204])?),
                    parent_pid: u32::from_be_bytes(copy_array(&bytes[204..208])?),
                    cgroup_id: u64::from_be_bytes(copy_array(&bytes[208..216])?),
                },
                launch_contract_digest: ObjectDigest::from_bytes(copy_array(&bytes[216..248])?),
                unit_name,
                forbidden_host: NamespaceIdentity {
                    device: u64::from_be_bytes(copy_array(&bytes[252..260])?),
                    inode: u64::from_be_bytes(copy_array(&bytes[260..268])?),
                },
                forbidden_target: NamespaceIdentity {
                    device: u64::from_be_bytes(copy_array(&bytes[268..276])?),
                    inode: u64::from_be_bytes(copy_array(&bytes[276..284])?),
                },
                cgroup,
            },
        };
        request.expected.validate()?;
        if request.encode()? != bytes {
            return protocol("namespace-inspector request is not canonical");
        }
        Ok(request)
    }

    fn encode(&self) -> Result<Vec<u8>, NetworkNamespaceInspectorError> {
        self.expected.validate()?;
        let unit_name = self.expected.unit_name.as_bytes();
        let cgroup = self.expected.cgroup.as_bytes();
        let unit_length = u16::try_from(unit_name.len()).map_err(|_| {
            NetworkNamespaceInspectorError::Protocol("namespace-inspector unit is too long")
        })?;
        let cgroup_length = u16::try_from(cgroup.len()).map_err(|_| {
            NetworkNamespaceInspectorError::Protocol("namespace-inspector cgroup is too long")
        })?;
        let total = REQUEST_FIXED_BYTES
            .checked_add(unit_name.len())
            .and_then(|length| length.checked_add(cgroup.len()))
            .ok_or(NetworkNamespaceInspectorError::Protocol(
                "namespace-inspector request length overflowed",
            ))?;
        if total > MAXIMUM_REQUEST_BYTES {
            return protocol("namespace-inspector request is too large");
        }

        let mut bytes = vec![0_u8; total];
        encode_header(
            &mut bytes,
            REQUEST_MAGIC,
            REQUEST_KIND,
            NetworkNamespaceInspectorDescriptorRoleV1::WorkerLeaderPidfd,
        );
        bytes[20..52].copy_from_slice(&self.expected.nonce);
        bytes[52..68].copy_from_slice(&self.expected.boot_id);
        bytes[68..76].copy_from_slice(&self.expected.not_before_boottime_ns.to_be_bytes());
        bytes[76..84].copy_from_slice(&self.expected.deadline_boottime_ns.to_be_bytes());
        bytes[84..100].copy_from_slice(&self.expected.request_id);
        bytes[100..132].copy_from_slice(self.expected.effect_digest.as_bytes());
        bytes[132..164].copy_from_slice(self.expected.dispatch_digest.as_bytes());
        bytes[164..196].copy_from_slice(self.expected.policy_digest.as_bytes());
        encode_process(&mut bytes[196..216], self.expected.process);
        bytes[216..248].copy_from_slice(self.expected.launch_contract_digest.as_bytes());
        bytes[248..250].copy_from_slice(&unit_length.to_be_bytes());
        bytes[252..260].copy_from_slice(&self.expected.forbidden_host.device.to_be_bytes());
        bytes[260..268].copy_from_slice(&self.expected.forbidden_host.inode.to_be_bytes());
        bytes[268..276].copy_from_slice(&self.expected.forbidden_target.device.to_be_bytes());
        bytes[276..284].copy_from_slice(&self.expected.forbidden_target.inode.to_be_bytes());
        bytes[284..286].copy_from_slice(&cgroup_length.to_be_bytes());
        let unit_end = REQUEST_FIXED_BYTES + unit_name.len();
        bytes[REQUEST_FIXED_BYTES..unit_end].copy_from_slice(unit_name);
        bytes[unit_end..].copy_from_slice(cgroup);
        Ok(bytes)
    }
}

/// Authorizes one namespace observation after policy lookup and replay claim.
///
/// This token is deliberately neither cloneable nor constructible from wire.
#[derive(Debug)]
pub(crate) struct AuthorizedNamespaceInspectionV1 {
    expected: ExpectedInspectorAttemptV1,
}

impl AuthorizedNamespaceInspectionV1 {
    /// Produces an untrusted response bound to a fresh kernel observation.
    fn respond(
        self,
        clock: &mut impl InspectorTrustedClockV1,
        process_after_inspection: InspectorProcessIdentityV1,
        namespace: NamespaceIdentity,
    ) -> Result<NetworkNamespaceInspectionResponseV1, NetworkNamespaceInspectorError> {
        validate_fresh_time(&self.expected, clock.observe()?)?;
        process_after_inspection.validate()?;
        validate_namespace(namespace)?;
        if process_after_inspection != self.expected.process
            || namespace == self.expected.forbidden_host
            || namespace == self.expected.forbidden_target
        {
            return Err(NetworkNamespaceInspectorError::ObservationMismatch);
        }
        Ok(NetworkNamespaceInspectionResponseV1 {
            nonce: self.expected.nonce,
            boot_id: self.expected.boot_id,
            request_id: self.expected.request_id,
            effect_digest: self.expected.effect_digest,
            dispatch_digest: self.expected.dispatch_digest,
            policy_digest: self.expected.policy_digest,
            process: self.expected.process,
            namespace,
        })
    }
}

/// Enforces terminal, one-record inspector request admission.
#[derive(Debug, Default)]
pub(crate) struct NetworkNamespaceInspectorAdmissionV1 {
    terminal: bool,
}

impl NetworkNamespaceInspectorAdmissionV1 {
    /// Authenticates one request against provisioned identity and protected policy.
    ///
    /// Policy lookup and spent-nonce claim are separate authorities. An error at
    /// any boundary permanently closes this admission object.
    fn authenticate_and_claim<'ledger, SpentLedger>(
        &mut self,
        deployment: &ProvisionedNetworkNamespaceInspectorV1,
        connection_peer: KernelAuthenticatedInspectorPeerV1,
        record_subject: KernelAuthenticatedInspectorPeerV1,
        launch: &AuthenticatedLifecycleWorkerLaunchObservationV1,
        policy: &impl InspectorAttemptPolicyLookupV1,
        spent: &'ledger mut SpentLedger,
        clock: &mut impl InspectorTrustedClockV1,
        request: NetworkNamespaceInspectionRequestV1,
        envelope: InspectorDescriptorEnvelopeV1,
        observed_worker: InspectorProcessIdentityV1,
    ) -> Result<
        AuthorizedNamespaceInspectionV1,
        NetworkNamespaceInspectorAdmissionError<SpentLedger::Error<'ledger>>,
    >
    where
        SpentLedger: InspectorSpentNonceLedgerV1,
    {
        if self.terminal {
            return Err(NetworkNamespaceInspectorError::Terminal.into());
        }
        self.terminal = true;

        validate_descriptor_envelope(envelope)?;
        validate_provisioned_peer(deployment.broker, connection_peer)?;
        validate_provisioned_peer(deployment.broker, record_subject)?;

        let expected = policy
            .lookup(&request.expected.nonce)?
            .ok_or(NetworkNamespaceInspectorError::PolicyMismatch)?;
        if expected != request.expected || expected.policy_digest != expected.compute_digest()? {
            return Err(NetworkNamespaceInspectorError::PolicyMismatch.into());
        }
        validate_launch_observation(deployment, launch, &expected)?;
        validate_fresh_time(&expected, clock.observe()?)?;
        if observed_worker != expected.process {
            return Err(NetworkNamespaceInspectorError::ObservationMismatch.into());
        }
        if !spent
            .claim_once(&expected)
            .map_err(NetworkNamespaceInspectorAdmissionError::Spent)?
        {
            return Err(NetworkNamespaceInspectorError::Replay.into());
        }
        validate_fresh_time(&expected, clock.observe()?)?;
        Ok(AuthorizedNamespaceInspectionV1 { expected })
    }
}

/// Carries canonical response fields that remain untrusted until completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NetworkNamespaceInspectionResponseV1 {
    nonce: [u8; 32],
    boot_id: [u8; 16],
    request_id: [u8; 16],
    effect_digest: ObjectDigest,
    dispatch_digest: ObjectDigest,
    policy_digest: ObjectDigest,
    process: InspectorProcessIdentityV1,
    namespace: NamespaceIdentity,
}

impl NetworkNamespaceInspectionResponseV1 {
    /// Decodes canonical response framing without constructing evidence.
    fn decode(bytes: &[u8]) -> Result<Self, NetworkNamespaceInspectorError> {
        if bytes.len() != RESPONSE_BYTES {
            return protocol("namespace-inspector response length is invalid");
        }
        validate_header(
            bytes,
            RESPONSE_MAGIC,
            RESPONSE_KIND,
            NetworkNamespaceInspectorDescriptorRoleV1::WorkerBootstrapNetworkNamespace,
        )?;
        let response = Self {
            nonce: copy_array(&bytes[20..52])?,
            boot_id: copy_array(&bytes[52..68])?,
            request_id: copy_array(&bytes[68..84])?,
            effect_digest: ObjectDigest::from_bytes(copy_array(&bytes[84..116])?),
            dispatch_digest: ObjectDigest::from_bytes(copy_array(&bytes[116..148])?),
            policy_digest: ObjectDigest::from_bytes(copy_array(&bytes[148..180])?),
            process: InspectorProcessIdentityV1 {
                pid: u32::from_be_bytes(copy_array(&bytes[180..184])?),
                thread_group_id: u32::from_be_bytes(copy_array(&bytes[184..188])?),
                parent_pid: u32::from_be_bytes(copy_array(&bytes[188..192])?),
                cgroup_id: u64::from_be_bytes(copy_array(&bytes[192..200])?),
            },
            namespace: NamespaceIdentity {
                device: u64::from_be_bytes(copy_array(&bytes[200..208])?),
                inode: u64::from_be_bytes(copy_array(&bytes[208..216])?),
            },
        };
        response.validate()?;
        if response.encode().as_slice() != bytes {
            return protocol("namespace-inspector response is not canonical");
        }
        Ok(response)
    }

    fn encode(self) -> [u8; RESPONSE_BYTES] {
        let mut bytes = [0_u8; RESPONSE_BYTES];
        encode_header(
            &mut bytes,
            RESPONSE_MAGIC,
            RESPONSE_KIND,
            NetworkNamespaceInspectorDescriptorRoleV1::WorkerBootstrapNetworkNamespace,
        );
        bytes[20..52].copy_from_slice(&self.nonce);
        bytes[52..68].copy_from_slice(&self.boot_id);
        bytes[68..84].copy_from_slice(&self.request_id);
        bytes[84..116].copy_from_slice(self.effect_digest.as_bytes());
        bytes[116..148].copy_from_slice(self.dispatch_digest.as_bytes());
        bytes[148..180].copy_from_slice(self.policy_digest.as_bytes());
        encode_process(&mut bytes[180..200], self.process);
        bytes[200..208].copy_from_slice(&self.namespace.device.to_be_bytes());
        bytes[208..216].copy_from_slice(&self.namespace.inode.to_be_bytes());
        bytes
    }

    fn validate(self) -> Result<(), NetworkNamespaceInspectorError> {
        validate_nonce(self.nonce)?;
        validate_boot_id(self.boot_id)?;
        self.process.validate()?;
        validate_namespace(self.namespace)?;
        if self.request_id == [0; 16]
            || self.effect_digest.as_bytes() == &[0; 32]
            || self.dispatch_digest.as_bytes() == &[0; 32]
            || self.policy_digest.as_bytes() == &[0; 32]
        {
            return protocol("invalid namespace-inspector response identity");
        }
        Ok(())
    }
}

/// Proves broker-side correlation of an inspector namespace response.
///
/// Fields are private and no constructor accepts wire or caller values. The
/// future runtime will additionally retain the type-checked namespace FD in
/// this evidence object before exposing it to the lifecycle admission flow.
#[derive(Debug)]
pub(crate) struct ProvenLifecycleWorkerBootstrapNamespaceV1 {
    process: InspectorProcessIdentityV1,
    namespace: NamespaceIdentity,
    policy_digest: ObjectDigest,
}

/// Enforces terminal, one-record broker completion.
#[derive(Debug, Default)]
pub(crate) struct NetworkNamespaceInspectorCompletionV1 {
    terminal: bool,
}

impl NetworkNamespaceInspectorCompletionV1 {
    /// Correlates an untrusted response with pending broker state.
    fn complete_inspection(
        &mut self,
        deployment: &ProvisionedNetworkNamespaceInspectorV1,
        connection_peer: KernelAuthenticatedInspectorPeerV1,
        record_subject: KernelAuthenticatedInspectorPeerV1,
        pending: PendingLifecycleWorkerInspectionV1,
        clock: &mut impl InspectorTrustedClockV1,
        response: NetworkNamespaceInspectionResponseV1,
        envelope: InspectorDescriptorEnvelopeV1,
        reobserved_worker: InspectorProcessIdentityV1,
        received_namespace: NamespaceIdentity,
    ) -> Result<ProvenLifecycleWorkerBootstrapNamespaceV1, NetworkNamespaceInspectorError> {
        if self.terminal {
            return Err(NetworkNamespaceInspectorError::Terminal);
        }
        self.terminal = true;

        validate_descriptor_envelope(envelope)?;
        validate_provisioned_peer(deployment.inspector, connection_peer)?;
        validate_provisioned_peer(deployment.inspector, record_subject)?;
        validate_fresh_time(&pending.expected, clock.observe()?)?;
        if pending.expected.boot_id != deployment.boot_id
            || !response.matches(&pending.expected)
            || reobserved_worker != pending.expected.process
            || received_namespace != response.namespace
            || received_namespace == pending.expected.forbidden_host
            || received_namespace == pending.expected.forbidden_target
        {
            return Err(NetworkNamespaceInspectorError::ObservationMismatch);
        }
        Ok(ProvenLifecycleWorkerBootstrapNamespaceV1 {
            process: response.process,
            namespace: received_namespace,
            policy_digest: response.policy_digest,
        })
    }
}

impl NetworkNamespaceInspectionResponseV1 {
    fn matches(self, expected: &ExpectedInspectorAttemptV1) -> bool {
        self.nonce == expected.nonce
            && self.boot_id == expected.boot_id
            && self.request_id == expected.request_id
            && self.effect_digest == expected.effect_digest
            && self.dispatch_digest == expected.dispatch_digest
            && self.policy_digest == expected.policy_digest
            && self.process == expected.process
            && self.namespace != expected.forbidden_host
            && self.namespace != expected.forbidden_target
    }
}

/// Holds one broker-written immutable expected-attempt policy record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExpectedInspectorAttemptV1 {
    nonce: [u8; 32],
    boot_id: [u8; 16],
    not_before_boottime_ns: u64,
    deadline_boottime_ns: u64,
    request_id: [u8; 16],
    effect_digest: ObjectDigest,
    dispatch_digest: ObjectDigest,
    policy_digest: ObjectDigest,
    process: InspectorProcessIdentityV1,
    unit_name: String,
    cgroup: String,
    launch_contract_digest: ObjectDigest,
    forbidden_host: NamespaceIdentity,
    forbidden_target: NamespaceIdentity,
}

impl ExpectedInspectorAttemptV1 {
    fn validate(&self) -> Result<(), NetworkNamespaceInspectorError> {
        validate_nonce(self.nonce)?;
        validate_boot_id(self.boot_id)?;
        self.process.validate()?;
        validate_lifecycle_worker_cgroup(&self.cgroup)?;
        validate_lifecycle_worker_unit(&self.unit_name)?;
        validate_namespace(self.forbidden_host)?;
        validate_namespace(self.forbidden_target)?;
        if self.request_id == [0; 16]
            || self.effect_digest.as_bytes() == &[0; 32]
            || self.dispatch_digest.as_bytes() == &[0; 32]
            || self.policy_digest.as_bytes() == &[0; 32]
            || self.launch_contract_digest.as_bytes() == &[0; 32]
            || self.unit_name != lifecycle_worker_unit_name(&self.cgroup)?
            || self.forbidden_host == self.forbidden_target
            || self.not_before_boottime_ns >= self.deadline_boottime_ns
        {
            return protocol("invalid namespace-inspector expected-attempt policy");
        }
        Ok(())
    }

    fn compute_digest(&self) -> Result<ObjectDigest, NetworkNamespaceInspectorError> {
        validate_nonce(self.nonce)?;
        validate_boot_id(self.boot_id)?;
        self.process.validate()?;
        validate_lifecycle_worker_cgroup(&self.cgroup)?;
        validate_lifecycle_worker_unit(&self.unit_name)?;
        validate_namespace(self.forbidden_host)?;
        validate_namespace(self.forbidden_target)?;

        let mut digest = Sha256::new();
        digest.update(b"AOS-NETWORK-NAMESPACE-INSPECTOR-POLICY-V1\0");
        digest.update(self.nonce);
        digest.update(self.boot_id);
        digest.update(self.not_before_boottime_ns.to_be_bytes());
        digest.update(self.deadline_boottime_ns.to_be_bytes());
        digest.update(self.request_id);
        digest.update(self.effect_digest.as_bytes());
        digest.update(self.dispatch_digest.as_bytes());
        digest.update(self.process.pid.to_be_bytes());
        digest.update(self.process.thread_group_id.to_be_bytes());
        digest.update(self.process.parent_pid.to_be_bytes());
        digest.update(self.process.cgroup_id.to_be_bytes());
        digest.update(self.launch_contract_digest.as_bytes());
        let unit_length = u16::try_from(self.unit_name.len()).map_err(|_| {
            NetworkNamespaceInspectorError::Protocol("namespace-inspector unit is too long")
        })?;
        digest.update(unit_length.to_be_bytes());
        digest.update(self.unit_name.as_bytes());
        digest.update(self.forbidden_host.device.to_be_bytes());
        digest.update(self.forbidden_host.inode.to_be_bytes());
        digest.update(self.forbidden_target.device.to_be_bytes());
        digest.update(self.forbidden_target.inode.to_be_bytes());
        let cgroup_length = u16::try_from(self.cgroup.len()).map_err(|_| {
            NetworkNamespaceInspectorError::Protocol("namespace-inspector cgroup is too long")
        })?;
        digest.update(cgroup_length.to_be_bytes());
        digest.update(self.cgroup.as_bytes());
        Ok(ObjectDigest::from_bytes(digest.finalize().into()))
    }
}

fn validate_provisioned_peer(
    expected: KernelAuthenticatedInspectorPeerV1,
    actual: KernelAuthenticatedInspectorPeerV1,
) -> Result<(), NetworkNamespaceInspectorError> {
    expected.process.validate()?;
    actual.process.validate()?;
    if expected.uid != 0 || expected.gid != 0 || actual != expected {
        return Err(NetworkNamespaceInspectorError::PeerMismatch);
    }
    Ok(())
}

fn validate_launch_observation(
    deployment: &ProvisionedNetworkNamespaceInspectorV1,
    launch: &AuthenticatedLifecycleWorkerLaunchObservationV1,
    expected: &ExpectedInspectorAttemptV1,
) -> Result<(), NetworkNamespaceInspectorError> {
    deployment.systemd_manager.validate()?;
    launch.manager.validate()?;
    if launch.manager != deployment.systemd_manager
        || deployment.boot_id != expected.boot_id
        || deployment.launch_contract_digest.as_bytes() == &[0; 32]
        || launch.launch_contract_digest != deployment.launch_contract_digest
        || launch.launch_contract_digest != expected.launch_contract_digest
        || launch.unit_name != expected.unit_name
        || launch.cgroup != expected.cgroup
        || launch.process != expected.process
    {
        return Err(NetworkNamespaceInspectorError::DeploymentMismatch);
    }
    Ok(())
}

fn validate_fresh_time(
    expected: &ExpectedInspectorAttemptV1,
    observed: InspectorTrustedTimeV1,
) -> Result<(), NetworkNamespaceInspectorError> {
    if observed.boot_id != expected.boot_id
        || observed.boottime_ns < expected.not_before_boottime_ns
        || observed.boottime_ns >= expected.deadline_boottime_ns
    {
        return Err(NetworkNamespaceInspectorError::Stale);
    }
    Ok(())
}

fn validate_descriptor_envelope(
    envelope: InspectorDescriptorEnvelopeV1,
) -> Result<(), NetworkNamespaceInspectorError> {
    if !envelope.ancillary_is_canonical || envelope.count != 1 {
        return protocol("namespace-inspector descriptor envelope is invalid");
    }
    Ok(())
}

fn validate_lifecycle_worker_cgroup(cgroup: &str) -> Result<(), NetworkNamespaceInspectorError> {
    if cgroup.is_empty()
        || cgroup.len() > MAXIMUM_CGROUP_BYTES
        || cgroup.as_bytes().contains(&0)
        || !cgroup.starts_with(LIFECYCLE_WORKER_CGROUP_PREFIX)
        || !cgroup.ends_with(WORKER_CGROUP_SUFFIX)
        || !cgroup.starts_with(CONTROL_SLICE_CGROUP)
    {
        return Err(NetworkNamespaceInspectorError::PolicyMismatch);
    }
    let instance =
        &cgroup[LIFECYCLE_WORKER_CGROUP_PREFIX.len()..cgroup.len() - WORKER_CGROUP_SUFFIX.len()];
    validate_systemd_socket_instance_fields(instance)
        .map_err(|_| NetworkNamespaceInspectorError::PolicyMismatch)
}

fn lifecycle_worker_unit_name(cgroup: &str) -> Result<&str, NetworkNamespaceInspectorError> {
    validate_lifecycle_worker_cgroup(cgroup)?;
    cgroup
        .rsplit_once('/')
        .map(|(_, unit)| unit)
        .ok_or(NetworkNamespaceInspectorError::PolicyMismatch)
}

fn validate_lifecycle_worker_unit(unit: &str) -> Result<(), NetworkNamespaceInspectorError> {
    if unit.is_empty()
        || unit.len() > MAXIMUM_UNIT_NAME_BYTES
        || unit.as_bytes().contains(&0)
        || !unit.starts_with("aos-sandbox-network-lifecycle-worker@")
        || !unit.ends_with(WORKER_CGROUP_SUFFIX)
    {
        return Err(NetworkNamespaceInspectorError::PolicyMismatch);
    }
    Ok(())
}

fn validate_nonce(nonce: [u8; 32]) -> Result<(), NetworkNamespaceInspectorError> {
    if nonce == [0; 32] {
        protocol("namespace-inspector nonce is zero")
    } else {
        Ok(())
    }
}

fn validate_boot_id(boot_id: [u8; 16]) -> Result<(), NetworkNamespaceInspectorError> {
    if boot_id == [0; 16] {
        protocol("namespace-inspector boot identity is zero")
    } else {
        Ok(())
    }
}

fn validate_namespace(namespace: NamespaceIdentity) -> Result<(), NetworkNamespaceInspectorError> {
    if namespace.device == 0 || namespace.inode == 0 {
        protocol("namespace-inspector namespace identity is zero")
    } else {
        Ok(())
    }
}

fn encode_header(
    bytes: &mut [u8],
    magic: &[u8; 8],
    kind: u8,
    role: NetworkNamespaceInspectorDescriptorRoleV1,
) {
    let total = bytes.len() as u32;
    bytes[..8].copy_from_slice(magic);
    bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
    bytes[10] = kind;
    bytes[11] = role.code();
    bytes[12..16].copy_from_slice(&total.to_be_bytes());
}

fn validate_header(
    bytes: &[u8],
    magic: &[u8; 8],
    kind: u8,
    role: NetworkNamespaceInspectorDescriptorRoleV1,
) -> Result<(), NetworkNamespaceInspectorError> {
    if bytes.len() < HEADER_BYTES
        || bytes.get(..8) != Some(magic.as_slice())
        || bytes.get(8..10) != Some(VERSION.to_be_bytes().as_slice())
        || bytes.get(10) != Some(&kind)
        || NetworkNamespaceInspectorDescriptorRoleV1::decode(bytes[11])? != role
        || bytes.get(12..16) != Some((bytes.len() as u32).to_be_bytes().as_slice())
        || bytes.get(16..20) != Some([0; 4].as_slice())
    {
        return protocol("namespace-inspector header is invalid");
    }
    Ok(())
}

fn encode_process(bytes: &mut [u8], process: InspectorProcessIdentityV1) {
    bytes[..4].copy_from_slice(&process.pid.to_be_bytes());
    bytes[4..8].copy_from_slice(&process.thread_group_id.to_be_bytes());
    bytes[8..12].copy_from_slice(&process.parent_pid.to_be_bytes());
    bytes[12..20].copy_from_slice(&process.cgroup_id.to_be_bytes());
}

fn copy_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], NetworkNamespaceInspectorError> {
    bytes.try_into().map_err(|_| {
        NetworkNamespaceInspectorError::Protocol("namespace-inspector record is truncated")
    })
}

fn protocol<T>(message: &'static str) -> Result<T, NetworkNamespaceInspectorError> {
    Err(NetworkNamespaceInspectorError::Protocol(message))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::collections::{BTreeSet, VecDeque};

    use super::*;

    #[derive(Default)]
    struct SpentLedger {
        nonces: BTreeSet<[u8; 32]>,
    }

    impl InspectorSpentNonceLedgerV1 for SpentLedger {
        type Error<'ledger> = NetworkNamespaceInspectorError;

        fn claim_once<'ledger>(
            &'ledger mut self,
            expected: &ExpectedInspectorAttemptV1,
        ) -> Result<bool, Self::Error<'ledger>> {
            Ok(self.nonces.insert(expected.nonce))
        }
    }

    struct FailingPolicy;

    impl InspectorAttemptPolicyLookupV1 for FailingPolicy {
        fn lookup(
            &self,
            _nonce: &[u8; 32],
        ) -> Result<Option<ExpectedInspectorAttemptV1>, NetworkNamespaceInspectorError> {
            Err(NetworkNamespaceInspectorError::ProtectedPolicy)
        }
    }

    struct UnreachableSpentLedger;

    impl InspectorSpentNonceLedgerV1 for UnreachableSpentLedger {
        type Error<'ledger> = NetworkNamespaceInspectorError;

        fn claim_once<'ledger>(
            &'ledger mut self,
            _expected: &ExpectedInspectorAttemptV1,
        ) -> Result<bool, Self::Error<'ledger>> {
            panic!("spent claim must not run after protected lookup failure")
        }
    }

    struct UnreachableClock;

    impl InspectorTrustedClockV1 for UnreachableClock {
        fn observe(&mut self) -> Result<InspectorTrustedTimeV1, NetworkNamespaceInspectorError> {
            panic!("clock observation must not run after protected lookup failure")
        }
    }

    struct Clock {
        observations: VecDeque<InspectorTrustedTimeV1>,
        last: InspectorTrustedTimeV1,
    }

    impl Clock {
        fn fixed(boot_id: [u8; 16], boottime_ns: u64) -> Self {
            let last = InspectorTrustedTimeV1 {
                boot_id,
                boottime_ns,
            };
            Self {
                observations: VecDeque::new(),
                last,
            }
        }

        fn scripted(observations: impl IntoIterator<Item = InspectorTrustedTimeV1>) -> Self {
            let observations = observations.into_iter().collect::<VecDeque<_>>();
            let last = observations.back().copied().unwrap();
            Self { observations, last }
        }
    }

    impl InspectorTrustedClockV1 for Clock {
        fn observe(&mut self) -> Result<InspectorTrustedTimeV1, NetworkNamespaceInspectorError> {
            Ok(self.observations.pop_front().unwrap_or(self.last))
        }
    }

    fn process(seed: u32) -> InspectorProcessIdentityV1 {
        InspectorProcessIdentityV1 {
            pid: seed,
            thread_group_id: seed,
            parent_pid: seed - 1,
            cgroup_id: u64::from(seed) * 17,
        }
    }

    fn peer(seed: u32) -> KernelAuthenticatedInspectorPeerV1 {
        KernelAuthenticatedInspectorPeerV1 {
            process: process(seed),
            uid: 0,
            gid: 0,
        }
    }

    fn manager() -> KernelAuthenticatedSystemdManagerV1 {
        KernelAuthenticatedSystemdManagerV1 {
            pid: 1,
            thread_group_id: 1,
            parent_pid: 0,
            cgroup_id: 17,
            uid: 0,
            gid: 0,
        }
    }

    fn deployment() -> ProvisionedNetworkNamespaceInspectorV1 {
        ProvisionedNetworkNamespaceInspectorV1 {
            boot_id: [7; 16],
            broker: peer(100),
            inspector: peer(200),
            systemd_manager: manager(),
            launch_contract_digest: ObjectDigest::from_bytes([6; 32]),
        }
    }

    fn namespace(seed: u64) -> NamespaceIdentity {
        NamespaceIdentity {
            device: seed,
            inode: seed * 100,
        }
    }

    pub(super) fn pending(nonce: u8) -> PendingLifecycleWorkerInspectionV1 {
        let deployment = deployment();
        PendingLifecycleWorkerInspectionV1::from_validated_ready(
            ValidatedLifecycleWorkerLeaderV1 {
                process: process(300),
                cgroup: "aos.slice/aos-control.slice/aos-sandbox-network-lifecycle-worker@0-984321-543_876-0.service".to_owned(),
                request_id: [3; 16],
                effect_digest: ObjectDigest::from_bytes([4; 32]),
                dispatch_digest: ObjectDigest::from_bytes([5; 32]),
            },
            BrokerLifecycleWorkerInspectionContextV1 {
                forbidden_host: namespace(1),
                forbidden_target: namespace(2),
            },
            &deployment,
            [nonce; 32],
            [7; 16],
            10,
            20,
        )
        .unwrap()
    }

    fn launch(
        pending: &PendingLifecycleWorkerInspectionV1,
    ) -> AuthenticatedLifecycleWorkerLaunchObservationV1 {
        AuthenticatedLifecycleWorkerLaunchObservationV1 {
            manager: manager(),
            unit_name: pending.expected.unit_name.clone(),
            cgroup: pending.expected.cgroup.clone(),
            process: pending.expected.process,
            launch_contract_digest: ObjectDigest::from_bytes([6; 32]),
        }
    }

    fn envelope() -> InspectorDescriptorEnvelopeV1 {
        InspectorDescriptorEnvelopeV1 {
            count: 1,
            ancillary_is_canonical: true,
        }
    }

    fn flatten_admission<T>(
        result: Result<T, NetworkNamespaceInspectorAdmissionError<NetworkNamespaceInspectorError>>,
    ) -> Result<T, NetworkNamespaceInspectorError> {
        match result {
            Ok(value) => Ok(value),
            Err(
                NetworkNamespaceInspectorAdmissionError::Model(error)
                | NetworkNamespaceInspectorAdmissionError::Spent(error),
            ) => Err(error),
        }
    }

    fn authorize(
        pending: &PendingLifecycleWorkerInspectionV1,
        catalog: &InspectorExpectedAttemptCatalogV1,
        spent: &mut SpentLedger,
    ) -> Result<AuthorizedNamespaceInspectionV1, NetworkNamespaceInspectorError> {
        let request =
            NetworkNamespaceInspectionRequestV1::decode(&pending.encode_request().unwrap())?;
        let mut clock = Clock::fixed([7; 16], 15);
        flatten_admission(
            NetworkNamespaceInspectorAdmissionV1::default().authenticate_and_claim(
                &deployment(),
                peer(100),
                peer(100),
                &launch(pending),
                catalog,
                spent,
                &mut clock,
                request,
                envelope(),
                process(300),
            ),
        )
    }

    #[test]
    fn request_and_response_round_trip_as_untrusted_wire() {
        let pending = pending(1);
        let request = pending.encode_request().unwrap();
        assert_eq!(
            NetworkNamespaceInspectionRequestV1::decode(&request)
                .unwrap()
                .encode()
                .unwrap(),
            request
        );

        let mut catalog = InspectorExpectedAttemptCatalogV1::default();
        catalog.record_from_admission(&pending).unwrap();
        let authorized = authorize(&pending, &catalog, &mut SpentLedger::default()).unwrap();
        let mut clock = Clock::fixed([7; 16], 15);
        let response = authorized
            .respond(&mut clock, process(300), namespace(3))
            .unwrap();
        assert_eq!(
            NetworkNamespaceInspectionResponseV1::decode(&response.encode()).unwrap(),
            response
        );
    }

    #[test]
    fn every_request_header_field_and_reserved_identity_fails_closed() {
        let valid = pending(1).encode_request().unwrap();
        for offset in 0..HEADER_BYTES {
            let mut changed = valid.clone();
            changed[offset] ^= 0x80;
            assert!(NetworkNamespaceInspectionRequestV1::decode(&changed).is_err());
        }
        for range in [20..52, 52..68, 84..100, 100..132, 132..164, 164..196] {
            let mut changed = valid.clone();
            changed[range].fill(0);
            assert!(NetworkNamespaceInspectionRequestV1::decode(&changed).is_err());
        }
    }

    #[test]
    fn every_truncated_or_oversized_self_consistent_record_fails_without_panicking() {
        let request = pending(1).encode_request().unwrap();
        for length in 0..request.len() {
            let mut truncated = request[..length].to_vec();
            if length >= 16 {
                truncated[12..16].copy_from_slice(&(length as u32).to_be_bytes());
            }
            assert!(NetworkNamespaceInspectionRequestV1::decode(&truncated).is_err());
        }
        let mut oversized_request = vec![0_u8; MAXIMUM_REQUEST_BYTES + 1];
        oversized_request[..16].copy_from_slice(&request[..16]);
        let oversized_length = oversized_request.len() as u32;
        oversized_request[12..16].copy_from_slice(&oversized_length.to_be_bytes());
        assert!(NetworkNamespaceInspectionRequestV1::decode(&oversized_request).is_err());

        let pending = pending(2);
        let mut catalog = InspectorExpectedAttemptCatalogV1::default();
        catalog.record_from_admission(&pending).unwrap();
        let mut response_clock = Clock::fixed([7; 16], 15);
        let response = authorize(&pending, &catalog, &mut SpentLedger::default())
            .unwrap()
            .respond(&mut response_clock, process(300), namespace(3))
            .unwrap()
            .encode();
        for offset in 0..HEADER_BYTES {
            let mut changed = response;
            changed[offset] ^= 0x80;
            assert!(NetworkNamespaceInspectionResponseV1::decode(&changed).is_err());
        }
        for length in 0..RESPONSE_BYTES {
            let mut truncated = response[..length].to_vec();
            if length >= 16 {
                truncated[12..16].copy_from_slice(&(length as u32).to_be_bytes());
            }
            assert!(NetworkNamespaceInspectionResponseV1::decode(&truncated).is_err());
        }
        let mut oversized_response = response.to_vec();
        oversized_response.push(0);
        let oversized_length = oversized_response.len() as u32;
        oversized_response[12..16].copy_from_slice(&oversized_length.to_be_bytes());
        assert!(NetworkNamespaceInspectionResponseV1::decode(&oversized_response).is_err());
    }

    #[test]
    fn policy_lookup_is_not_replaced_by_canonical_caller_bytes() {
        let expected = pending(1);
        let mut attacker = pending(1);
        attacker.expected.forbidden_target = namespace(9);
        attacker.expected.policy_digest = attacker.expected.compute_digest().unwrap();
        let mut catalog = InspectorExpectedAttemptCatalogV1::default();
        catalog.record_from_admission(&expected).unwrap();

        let request =
            NetworkNamespaceInspectionRequestV1::decode(&attacker.encode_request().unwrap())
                .unwrap();
        let mut clock = Clock::fixed([7; 16], 15);
        let result = flatten_admission(
            NetworkNamespaceInspectorAdmissionV1::default().authenticate_and_claim(
                &deployment(),
                peer(100),
                peer(100),
                &launch(&attacker),
                &catalog,
                &mut SpentLedger::default(),
                &mut clock,
                request,
                envelope(),
                process(300),
            ),
        );
        assert!(matches!(
            result,
            Err(NetworkNamespaceInspectorError::PolicyMismatch)
        ));
    }

    #[test]
    fn protected_lookup_error_is_not_absence_and_precedes_claim_or_clock() {
        let pending = pending(1);
        let request =
            NetworkNamespaceInspectionRequestV1::decode(&pending.encode_request().unwrap())
                .unwrap();
        let mut admission = NetworkNamespaceInspectorAdmissionV1::default();
        let result = admission.authenticate_and_claim(
            &deployment(),
            peer(100),
            peer(100),
            &launch(&pending),
            &FailingPolicy,
            &mut UnreachableSpentLedger,
            &mut UnreachableClock,
            request,
            envelope(),
            process(300),
        );

        assert!(matches!(
            result,
            Err(NetworkNamespaceInspectorAdmissionError::Model(
                NetworkNamespaceInspectorError::ProtectedPolicy
            ))
        ));
        assert!(admission.terminal);
    }

    #[test]
    fn replay_stale_and_foreign_peer_fail_terminally() {
        let pending = pending(1);
        let mut catalog = InspectorExpectedAttemptCatalogV1::default();
        catalog.record_from_admission(&pending).unwrap();
        let mut spent = SpentLedger::default();
        authorize(&pending, &catalog, &mut spent).unwrap();
        assert!(matches!(
            authorize(&pending, &catalog, &mut spent),
            Err(NetworkNamespaceInspectorError::Replay)
        ));

        let request =
            NetworkNamespaceInspectionRequestV1::decode(&pending.encode_request().unwrap())
                .unwrap();
        let mut stale = NetworkNamespaceInspectorAdmissionV1::default();
        let mut stale_clock = Clock::fixed([7; 16], 20);
        assert!(matches!(
            flatten_admission(stale.authenticate_and_claim(
                &deployment(),
                peer(100),
                peer(100),
                &launch(&pending),
                &catalog,
                &mut SpentLedger::default(),
                &mut stale_clock,
                request.clone(),
                envelope(),
                process(300),
            )),
            Err(NetworkNamespaceInspectorError::Stale)
        ));
        let mut current_clock = Clock::fixed([7; 16], 15);
        assert!(matches!(
            flatten_admission(stale.authenticate_and_claim(
                &deployment(),
                peer(100),
                peer(100),
                &launch(&pending),
                &catalog,
                &mut SpentLedger::default(),
                &mut current_clock,
                request.clone(),
                envelope(),
                process(300),
            )),
            Err(NetworkNamespaceInspectorError::Terminal)
        ));

        let mut foreign = NetworkNamespaceInspectorAdmissionV1::default();
        let mut clock = Clock::fixed([7; 16], 15);
        assert!(matches!(
            flatten_admission(foreign.authenticate_and_claim(
                &deployment(),
                peer(101),
                peer(100),
                &launch(&pending),
                &catalog,
                &mut SpentLedger::default(),
                &mut clock,
                request,
                envelope(),
                process(300),
            )),
            Err(NetworkNamespaceInspectorError::PeerMismatch)
        ));
    }

    #[test]
    fn expiry_or_boot_change_after_nonce_claim_fails_and_spends_attempt() {
        for after_claim in [
            InspectorTrustedTimeV1 {
                boot_id: [7; 16],
                boottime_ns: 20,
            },
            InspectorTrustedTimeV1 {
                boot_id: [8; 16],
                boottime_ns: 15,
            },
        ] {
            let pending = pending(1);
            let mut catalog = InspectorExpectedAttemptCatalogV1::default();
            catalog.record_from_admission(&pending).unwrap();
            let request =
                NetworkNamespaceInspectionRequestV1::decode(&pending.encode_request().unwrap())
                    .unwrap();
            let mut clock = Clock::scripted([
                InspectorTrustedTimeV1 {
                    boot_id: [7; 16],
                    boottime_ns: 15,
                },
                after_claim,
            ]);
            let mut spent = SpentLedger::default();
            let result = flatten_admission(
                NetworkNamespaceInspectorAdmissionV1::default().authenticate_and_claim(
                    &deployment(),
                    peer(100),
                    peer(100),
                    &launch(&pending),
                    &catalog,
                    &mut spent,
                    &mut clock,
                    request,
                    envelope(),
                    process(300),
                ),
            );
            assert!(matches!(result, Err(NetworkNamespaceInspectorError::Stale)));
            assert!(spent.nonces.contains(&[1; 32]));
        }
    }

    #[test]
    fn independent_launch_contract_unit_leader_and_cgroup_must_match() {
        let pending = pending(1);
        let mut catalog = InspectorExpectedAttemptCatalogV1::default();
        catalog.record_from_admission(&pending).unwrap();

        let mut wrong_observations = Vec::new();
        let mut wrong = launch(&pending);
        wrong.manager.cgroup_id = 18;
        wrong_observations.push(wrong);
        let mut wrong = launch(&pending);
        wrong.launch_contract_digest = ObjectDigest::from_bytes([9; 32]);
        wrong_observations.push(wrong);
        let mut wrong = launch(&pending);
        wrong.unit_name = "aos-sandbox-network-lifecycle-worker@foreign.service".to_owned();
        wrong_observations.push(wrong);
        let mut wrong = launch(&pending);
        wrong.cgroup =
            "aos.slice/aos-control.slice/aos-sandbox-network-lifecycle-worker@foreign.service"
                .to_owned();
        wrong_observations.push(wrong);
        let mut wrong = launch(&pending);
        wrong.process = process(301);
        wrong_observations.push(wrong);

        for wrong in wrong_observations {
            let request =
                NetworkNamespaceInspectionRequestV1::decode(&pending.encode_request().unwrap())
                    .unwrap();
            let mut clock = Clock::fixed([7; 16], 15);
            let result = flatten_admission(
                NetworkNamespaceInspectorAdmissionV1::default().authenticate_and_claim(
                    &deployment(),
                    peer(100),
                    peer(100),
                    &wrong,
                    &catalog,
                    &mut SpentLedger::default(),
                    &mut clock,
                    request,
                    envelope(),
                    process(300),
                ),
            );
            assert!(matches!(
                result,
                Err(NetworkNamespaceInspectorError::DeploymentMismatch
                    | NetworkNamespaceInspectorError::PeerMismatch)
            ));
        }
    }

    #[test]
    fn only_the_exact_pid_one_manager_may_have_zero_parent() {
        assert!(manager().validate().is_ok());

        let zero_parent_peer = InspectorProcessIdentityV1 {
            parent_pid: 0,
            ..process(100)
        };
        assert!(zero_parent_peer.validate().is_err());

        let mut not_pid_one = manager();
        not_pid_one.pid = 2;
        not_pid_one.thread_group_id = 2;
        assert!(not_pid_one.validate().is_err());
    }

    #[test]
    fn foreign_boot_deployment_cannot_authorize_matching_attempt_bytes() {
        let pending = pending(1);
        let mut catalog = InspectorExpectedAttemptCatalogV1::default();
        catalog.record_from_admission(&pending).unwrap();
        let request =
            NetworkNamespaceInspectionRequestV1::decode(&pending.encode_request().unwrap())
                .unwrap();
        let mut foreign_deployment = deployment();
        foreign_deployment.boot_id = [8; 16];
        let mut clock = Clock::fixed([7; 16], 15);

        let result = flatten_admission(
            NetworkNamespaceInspectorAdmissionV1::default().authenticate_and_claim(
                &foreign_deployment,
                peer(100),
                peer(100),
                &launch(&pending),
                &catalog,
                &mut SpentLedger::default(),
                &mut clock,
                request,
                envelope(),
                process(300),
            ),
        );
        assert!(matches!(
            result,
            Err(NetworkNamespaceInspectorError::DeploymentMismatch)
        ));
    }

    #[test]
    fn multi_fd_and_malformed_ancillary_fail_terminally() {
        let pending = pending(1);
        let mut catalog = InspectorExpectedAttemptCatalogV1::default();
        catalog.record_from_admission(&pending).unwrap();
        for bad_envelope in [
            InspectorDescriptorEnvelopeV1 {
                count: 2,
                ancillary_is_canonical: true,
            },
            InspectorDescriptorEnvelopeV1 {
                count: 1,
                ancillary_is_canonical: false,
            },
        ] {
            let request =
                NetworkNamespaceInspectionRequestV1::decode(&pending.encode_request().unwrap())
                    .unwrap();
            let mut admission = NetworkNamespaceInspectorAdmissionV1::default();
            let mut clock = Clock::fixed([7; 16], 15);
            assert!(matches!(
                flatten_admission(admission.authenticate_and_claim(
                    &deployment(),
                    peer(100),
                    peer(100),
                    &launch(&pending),
                    &catalog,
                    &mut SpentLedger::default(),
                    &mut clock,
                    request,
                    bad_envelope,
                    process(300),
                )),
                Err(NetworkNamespaceInspectorError::Protocol(_))
            ));
            assert!(admission.terminal);
        }
    }

    #[test]
    fn response_rechecks_freshness_and_rejects_forbidden_namespaces() {
        for (clock, namespace, expected_error) in [
            (
                Clock::fixed([7; 16], 20),
                namespace(3),
                NetworkNamespaceInspectorError::Stale,
            ),
            (
                Clock::fixed([8; 16], 15),
                namespace(3),
                NetworkNamespaceInspectorError::Stale,
            ),
            (
                Clock::fixed([7; 16], 15),
                namespace(1),
                NetworkNamespaceInspectorError::ObservationMismatch,
            ),
            (
                Clock::fixed([7; 16], 15),
                namespace(2),
                NetworkNamespaceInspectorError::ObservationMismatch,
            ),
        ] {
            let pending = pending(1);
            let mut catalog = InspectorExpectedAttemptCatalogV1::default();
            catalog.record_from_admission(&pending).unwrap();
            let authorized = authorize(&pending, &catalog, &mut SpentLedger::default()).unwrap();
            let mut clock = clock;
            assert_eq!(
                authorized.respond(&mut clock, process(300), namespace),
                Err(expected_error)
            );
        }
    }

    #[test]
    fn broker_completion_binds_inspector_pidfd_cgroup_and_namespace() {
        let pending = pending(1);
        let mut catalog = InspectorExpectedAttemptCatalogV1::default();
        catalog.record_from_admission(&pending).unwrap();
        let response = authorize(&pending, &catalog, &mut SpentLedger::default())
            .unwrap()
            .respond(&mut Clock::fixed([7; 16], 15), process(300), namespace(3))
            .unwrap();

        let proof = NetworkNamespaceInspectorCompletionV1::default()
            .complete_inspection(
                &deployment(),
                peer(200),
                peer(200),
                pending,
                &mut Clock::fixed([7; 16], 15),
                NetworkNamespaceInspectionResponseV1::decode(&response.encode()).unwrap(),
                envelope(),
                process(300),
                namespace(3),
            )
            .unwrap();
        assert_eq!(proof.process, process(300));
        assert_eq!(proof.namespace, namespace(3));
        assert_eq!(proof.policy_digest, response.policy_digest);
    }

    #[test]
    fn broker_completion_rejects_substituted_inspector_or_namespace() {
        let expected_pending = pending(1);
        let mut catalog = InspectorExpectedAttemptCatalogV1::default();
        catalog.record_from_admission(&expected_pending).unwrap();
        let response = authorize(&expected_pending, &catalog, &mut SpentLedger::default())
            .unwrap()
            .respond(&mut Clock::fixed([7; 16], 15), process(300), namespace(3))
            .unwrap();

        let result = NetworkNamespaceInspectorCompletionV1::default().complete_inspection(
            &deployment(),
            peer(201),
            peer(200),
            pending(1),
            &mut Clock::fixed([7; 16], 15),
            response,
            envelope(),
            process(300),
            namespace(3),
        );
        assert!(matches!(
            result,
            Err(NetworkNamespaceInspectorError::PeerMismatch)
        ));

        let result = NetworkNamespaceInspectorCompletionV1::default().complete_inspection(
            &deployment(),
            peer(200),
            peer(200),
            expected_pending,
            &mut Clock::fixed([7; 16], 15),
            response,
            envelope(),
            process(300),
            NamespaceIdentity {
                device: 41,
                inode: 99,
            },
        );
        assert!(matches!(
            result,
            Err(NetworkNamespaceInspectorError::ObservationMismatch)
        ));
    }

    #[test]
    fn broker_completion_rechecks_deadline_and_boot_before_consuming_proof() {
        for mut clock in [Clock::fixed([7; 16], 20), Clock::fixed([8; 16], 15)] {
            let pending = pending(1);
            let mut catalog = InspectorExpectedAttemptCatalogV1::default();
            catalog.record_from_admission(&pending).unwrap();
            let response = authorize(&pending, &catalog, &mut SpentLedger::default())
                .unwrap()
                .respond(&mut Clock::fixed([7; 16], 15), process(300), namespace(3))
                .unwrap();
            let result = NetworkNamespaceInspectorCompletionV1::default().complete_inspection(
                &deployment(),
                peer(200),
                peer(200),
                pending,
                &mut clock,
                response,
                envelope(),
                process(300),
                namespace(3),
            );
            assert!(matches!(result, Err(NetworkNamespaceInspectorError::Stale)));
        }
    }

    #[test]
    fn broker_completion_rejects_host_and_target_namespace_responses() {
        for forbidden in [namespace(1), namespace(2)] {
            let pending = pending(1);
            let mut catalog = InspectorExpectedAttemptCatalogV1::default();
            catalog.record_from_admission(&pending).unwrap();
            let mut response = authorize(&pending, &catalog, &mut SpentLedger::default())
                .unwrap()
                .respond(&mut Clock::fixed([7; 16], 15), process(300), namespace(3))
                .unwrap();
            response.namespace = forbidden;

            let result = NetworkNamespaceInspectorCompletionV1::default().complete_inspection(
                &deployment(),
                peer(200),
                peer(200),
                pending,
                &mut Clock::fixed([7; 16], 15),
                response,
                envelope(),
                process(300),
                forbidden,
            );
            assert!(matches!(
                result,
                Err(NetworkNamespaceInspectorError::ObservationMismatch)
            ));
        }
    }
}
