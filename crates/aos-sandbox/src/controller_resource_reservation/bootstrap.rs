//! Admits original PID1 bootstrap custody into the one native resource bank.
//!
//! Image policy pays the finite trusted bootstrap interval. The bank verifies
//! those same bytes with the sole resource arithmetic before recording the
//! node and two inclusive envelopes. A capsule alone cannot enter this path:
//! the original closed Controller table and current fixed launch are required.
//! Original enrollment commits fixed Controller and Components demand, with
//! only their explicit subdivisions retained as separate reserved claims.
//! Native uncertainty retains the entire transaction and original descriptors.

use std::os::unix::fs::{FileExt as _, MetadataExt as _};

use aos_sandbox_core::{ResourceAccount, ResourceCeilings, ResourceVector};
use aos_sandbox_linux::boot::{KernelBootId, RootOriginalKernelBootIdAttemptV1};
use rustix::fs::{OFlags, SealFlags, fcntl_get_seals, fcntl_getfl, fstatfs};
use sha2::{Digest as _, Sha256};

use super::{
    AccountHead, AccountKind, Claim, ClaimCut, ClaimPurpose, ClaimState,
    ControllerResourceEnrollmentCaptureV1, EnrollmentIdentity, ImageBootstrapPolicy,
    ResourceReservationErrorV1, Transition, TransitionOriginal, codec, matches_record, replay,
};
use crate::{Journal, JournalError, JournalRecord, JournalTransaction, RecordNamespace};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct OriginalEnrollment {
    pub(super) identity: EnrollmentIdentity,
    pub(super) policy: ImageBootstrapPolicy,
    pub(super) recipient_invocation: [u8; 16],
}

impl ControllerResourceEnrollmentCaptureV1 {
    fn observe(
        &self,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<OriginalEnrollment, ResourceReservationErrorV1> {
        if self.process != std::process::id() {
            return Err(ResourceReservationErrorV1::EnrollmentUnavailable);
        }
        let (invocation, producer) = profile.require_resource_producer()?;
        let original = observe_original_pair(&self.policy, &self.enrollment)?;
        if original.recipient_invocation != invocation || original.identity.invocation != producer
            || profile.require_resource_producer()? != (invocation, producer)
        {
            return Err(ResourceReservationErrorV1::EnrollmentUnavailable);
        }
        Ok(original)
    }
}

// These fixed file and canonical DATA checks do not issue enrollment. Each
// purpose-closed caller independently rejoins its actual PID1 recipient.
pub(super) fn observe_original_pair(
    policy_file: &std::fs::File,
    enrollment_file: &std::fs::File,
) -> Result<OriginalEnrollment, ResourceReservationErrorV1> {
    let mut observations = OriginalPairObservations::default();
    observe_original_pair_into::<false>(policy_file, enrollment_file, &mut observations, None, None)
}

/// Retains the reached original pair observations without issuing a loan.
///
/// The caller holds both original files and this destination through any
/// refusal. The six established image widths remain exact; the fixed buffer
/// provides custody, not a funded receiving or physical-fit declaration.
pub(super) struct OriginalEnrollmentPairAttemptV1 {
    observations: OriginalPairObservations,
    bytes: OriginalPairBytes,
    boot: RootOriginalKernelBootIdAttemptV1,
    entered: bool,
    closed: Option<ResourceReservationErrorV1>,
}

impl OriginalEnrollmentPairAttemptV1 {
    pub(super) fn new() -> Self {
        Self {
            observations: OriginalPairObservations::default(),
            bytes: OriginalPairBytes {
                policy: [0; codec::ROOT_IMAGE_POLICY_BYTES],
                delivery: [0; 152],
            },
            boot: RootOriginalKernelBootIdAttemptV1::new(),
            entered: false,
            closed: None,
        }
    }

    /// Observes the original pair once and borrows its earliest actual refusal.
    ///
    /// # Errors
    ///
    /// Retains failed native observations, partial reads and canonical causes.
    /// A repeated entry closes the attempt without replacing earlier debt.
    pub(super) fn observe_once(
        &mut self,
        policy: &std::fs::File,
        delivery: &std::fs::File,
    ) -> Result<&OriginalEnrollment, &(dyn std::error::Error + 'static)> {
        if self.entered {
            self.closed = Some(ResourceReservationErrorV1::Conflict);
        } else {
            self.entered = true;
            self.observations.completion = Some(observe_original_pair_into::<true>(
                policy,
                delivery,
                &mut self.observations,
                Some(&mut self.bytes),
                Some(&mut self.boot),
            ));
        }

        if let Some(error) = self.failure() {
            return Err(error);
        }
        self.observations
            .completion
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(&PAIR_UNAVAILABLE as &(dyn std::error::Error + 'static))
    }

    /// Borrows the earliest reached native or canonical cause without retry.
    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.observations.failure()
            .or_else(|| self.boot.failure())
            .or_else(|| pair_failure(&self.observations.completion))
            .or_else(|| self.closed.as_ref().map(|error| error as _))
    }
}

struct OriginalPairBytes {
    policy: [u8; codec::ROOT_IMAGE_POLICY_BYTES],
    delivery: [u8; 152],
}

#[derive(Default)]
struct OriginalPairObservations {
    policy_metadata: Option<std::io::Result<std::fs::Metadata>>,
    delivery_metadata: Option<std::io::Result<std::fs::Metadata>>,
    delivery_seals: Option<Result<SealFlags, rustix::io::Errno>>,
    policy_filesystem: Option<Result<rustix::fs::StatFs, rustix::io::Errno>>,
    policy_flags: Option<Result<OFlags, rustix::io::Errno>>,
    delivery_flags: Option<Result<OFlags, rustix::io::Errno>>,
    shape: Option<Result<(), ResourceReservationErrorV1>>,
    policy_read: Option<std::io::Result<()>>,
    delivery_read: Option<std::io::Result<()>>,
    policy_decode: Option<Result<ImageBootstrapPolicy, ResourceReservationErrorV1>>,
    delivery_decode: Option<Result<(EnrollmentIdentity, [u8; 16]), ResourceReservationErrorV1>>,
    manifest: Option<[u8; 32]>,
    // Ordinary acquisition keeps its original returned-result contract. Only
    // the actual retained Root pair installs bounded original boot custody.
    boot: Option<Result<KernelBootId, aos_sandbox_linux::Error>>,
    completion: Option<Result<OriginalEnrollment, ResourceReservationErrorV1>>,
}

impl OriginalPairObservations {
    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        // Vacant slots were never entered. The shape marker follows its native
        // inputs; it must not replace their original IO or descriptor cause.
        let causes: [Option<&(dyn std::error::Error + 'static)>; 12] = [
            pair_failure(&self.policy_metadata),
            pair_failure(&self.delivery_metadata),
            pair_failure(&self.delivery_seals),
            pair_failure(&self.policy_filesystem),
            pair_failure(&self.policy_flags),
            pair_failure(&self.delivery_flags),
            pair_failure(&self.shape),
            pair_failure(&self.policy_read),
            pair_failure(&self.delivery_read),
            pair_failure(&self.policy_decode),
            pair_failure(&self.delivery_decode),
            pair_failure(&self.boot),
        ];
        causes.into_iter().flatten().next()
    }
}

fn pair_failure<T, E: std::error::Error + 'static>(
    result: &Option<Result<T, E>>,
) -> Option<&(dyn std::error::Error + 'static)> {
    result.as_ref()?.as_ref().err().map(|error| error as _)
}

#[derive(Debug)]
struct PairUnavailable;

impl std::fmt::Display for PairUnavailable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("original enrollment pair observation is unavailable")
    }
}

impl std::error::Error for PairUnavailable {}

static PAIR_UNAVAILABLE: PairUnavailable = PairUnavailable;

// Both facades enter this one native/canonical schedule. The ordinary arm moves
// an error out unchanged; the retained arm leaves the actual Result in its slot
// and returns only a stopping marker. Successful metadata is borrowed in place.
macro_rules! original_pair_outcome {
    ($retained:expr, $slot:expr, $native:expr) => {{
        let slot = &mut $slot;
        *slot = Some($native);
        if slot.as_ref().is_some_and(Result::is_err) {
            if $retained {
                return Err(ResourceReservationErrorV1::EnrollmentUnavailable);
            }
            if let Some(Err(error)) = slot.take() {
                return Err(error.into());
            }
        }
        slot.as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?
    }};
}

fn observe_original_pair_into<const RETAINED: bool>(
    policy_file: &std::fs::File,
    enrollment_file: &std::fs::File,
    observations: &mut OriginalPairObservations,
    bytes: Option<&mut OriginalPairBytes>,
    retained_boot: Option<&mut RootOriginalKernelBootIdAttemptV1>,
) -> Result<OriginalEnrollment, ResourceReservationErrorV1> {
    let policy_metadata = original_pair_outcome!(
        RETAINED, observations.policy_metadata, policy_file.metadata()
    );
    let delivery_metadata = original_pair_outcome!(
        RETAINED, observations.delivery_metadata, enrollment_file.metadata()
    );
    let seals = *original_pair_outcome!(
        RETAINED, observations.delivery_seals, fcntl_get_seals(enrollment_file)
    );
    let policy_length = policy_metadata.len();

    let shape = (|| {
        if !policy_metadata.is_file()
            || ![
                codec::IMAGE_POLICY_BYTES as u64,
                codec::HOST_IMAGE_POLICY_BYTES as u64,
                codec::FIRST_GLOBAL_IMAGE_POLICY_BYTES as u64,
                codec::NIX_INTAKE_IMAGE_POLICY_BYTES as u64,
                codec::Q04_INTAKE_IMAGE_POLICY_BYTES as u64,
                codec::ROOT_IMAGE_POLICY_BYTES as u64,
            ].contains(&policy_length)
            || policy_metadata.uid() != 0 || policy_metadata.gid() != 0
            || policy_metadata.mode() & 0o222 != 0
            || original_pair_outcome!(
                RETAINED, observations.policy_filesystem, fstatfs(policy_file)
            ).f_type as u64 != 0xe0f5_e1e2
            || *original_pair_outcome!(
                RETAINED, observations.policy_flags, fcntl_getfl(policy_file)
            ) & OFlags::ACCMODE != OFlags::RDONLY
            || !delivery_metadata.is_file() || delivery_metadata.len() != 152
            || delivery_metadata.nlink() != 0 || delivery_metadata.uid() != 0
            || *original_pair_outcome!(
                RETAINED, observations.delivery_flags, fcntl_getfl(enrollment_file)
            ) & OFlags::ACCMODE != OFlags::RDONLY
            || !seals.contains(SealFlags::SEAL | SealFlags::GROW | SealFlags::SHRINK | SealFlags::WRITE)
        {
            return Err(ResourceReservationErrorV1::EnrollmentUnavailable);
        }
        Ok(())
    })();
    original_pair_outcome!(RETAINED, observations.shape, shape);

    let (policy, identity, recipient_invocation, manifest) =
        if policy_length == codec::IMAGE_POLICY_BYTES as u64 {
            read_original_pair::<{ codec::IMAGE_POLICY_BYTES }, RETAINED>(
                policy_file, enrollment_file, observations, bytes,
            )?
        } else if policy_length == codec::HOST_IMAGE_POLICY_BYTES as u64 {
            read_original_pair::<{ codec::HOST_IMAGE_POLICY_BYTES }, RETAINED>(
                policy_file, enrollment_file, observations, bytes,
            )?
        } else if policy_length == codec::FIRST_GLOBAL_IMAGE_POLICY_BYTES as u64 {
            read_original_pair::<{ codec::FIRST_GLOBAL_IMAGE_POLICY_BYTES }, RETAINED>(
                policy_file, enrollment_file, observations, bytes,
            )?
        } else if policy_length == codec::NIX_INTAKE_IMAGE_POLICY_BYTES as u64 {
            read_original_pair::<{ codec::NIX_INTAKE_IMAGE_POLICY_BYTES }, RETAINED>(
                policy_file, enrollment_file, observations, bytes,
            )?
        } else if policy_length == codec::Q04_INTAKE_IMAGE_POLICY_BYTES as u64 {
            read_original_pair::<{ codec::Q04_INTAKE_IMAGE_POLICY_BYTES }, RETAINED>(
                policy_file, enrollment_file, observations, bytes,
            )?
        } else {
            read_original_pair::<{ codec::ROOT_IMAGE_POLICY_BYTES }, RETAINED>(
                policy_file, enrollment_file, observations, bytes,
            )?
        };
    if identity.node != policy.node || identity.epoch != policy.epoch
        || identity.manifest != manifest
        || identity.boot != original_pair_boot::<RETAINED>(observations, retained_boot)?
    {
        return Err(ResourceReservationErrorV1::EnrollmentUnavailable);
    }
    Ok(OriginalEnrollment { identity, policy, recipient_invocation })
}

// Both arms enter only after the same node/epoch/manifest short-circuit checks.
// No ordinary caller constructs or enters the retained original boot attempt.
fn original_pair_boot<const RETAINED: bool>(
    observations: &mut OriginalPairObservations,
    retained_boot: Option<&mut RootOriginalKernelBootIdAttemptV1>,
) -> Result<[u8; 16], ResourceReservationErrorV1> {
    if RETAINED {
        let attempt = retained_boot.ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        return attempt.observe_once()
            .map(|boot| boot.into_bytes())
            .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable);
    }

    Ok(original_pair_outcome!(
        false, observations.boot, KernelBootId::current()
    ).into_bytes())
}

// Reads both fixed-width records before decoding either, then hashes the policy.
fn read_original_pair<const N: usize, const RETAINED: bool>(
    policy_file: &std::fs::File,
    enrollment_file: &std::fs::File,
    observations: &mut OriginalPairObservations,
    retained_bytes: Option<&mut OriginalPairBytes>,
) -> Result<
    (ImageBootstrapPolicy, EnrollmentIdentity, [u8; 16], [u8; 32]),
    ResourceReservationErrorV1,
> {
    match retained_bytes {
        Some(bytes) => read_original_pair_buffers::<RETAINED>(
            policy_file, enrollment_file, observations,
            &mut bytes.policy[..N], &mut bytes.delivery,
        ),
        None => {
            let mut policy_bytes = [0; N];
            let mut delivery_bytes = [0; 152];
            read_original_pair_buffers::<RETAINED>(
                policy_file, enrollment_file, observations,
                &mut policy_bytes, &mut delivery_bytes,
            )
        }
    }
}

fn read_original_pair_buffers<const RETAINED: bool>(
    policy_file: &std::fs::File,
    enrollment_file: &std::fs::File,
    observations: &mut OriginalPairObservations,
    policy_bytes: &mut [u8],
    delivery_bytes: &mut [u8; 152],
) -> Result<
    (ImageBootstrapPolicy, EnrollmentIdentity, [u8; 16], [u8; 32]),
    ResourceReservationErrorV1,
> {
    original_pair_outcome!(
        RETAINED, observations.policy_read, policy_file.read_exact_at(policy_bytes, 0)
    );
    original_pair_outcome!(
        RETAINED, observations.delivery_read, enrollment_file.read_exact_at(delivery_bytes, 0)
    );

    let policy = *original_pair_outcome!(
        RETAINED, observations.policy_decode, codec::decode_image_policy(policy_bytes)
    );
    let (identity, recipient_invocation) = *original_pair_outcome!(
        RETAINED, observations.delivery_decode, codec::decode_pid1_delivery(delivery_bytes)
    );
    let manifest = <[u8; 32]>::from(Sha256::digest(policy_bytes));
    observations.manifest = Some(manifest);
    Ok((policy, identity, recipient_invocation, manifest))
}

pub(super) struct EnrollmentTransition {
    transaction_id: [u8; 16],
    heads: [AccountHead; 3],
    claims: [Claim; 2],
    host: Option<(AccountHead, [Claim; 2])>,
    first_global: Option<Claim>,
    nix_intake: Option<Claim>,
    q04_intake: Option<Claim>,
    root_receiving: Option<Claim>,
}

impl EnrollmentTransition {
    fn prepare(original: &OriginalEnrollment) -> Result<Self, ResourceReservationErrorV1> {
        let identity = original.identity;
        let policy = original.policy;
        policy.validate()?;
        let node = policy.node;
        let controller = account_id(identity, b"controller");
        let components = account_id(identity, b"components");
        let root_account = ResourceAccount::from_usage(
            ResourceCeilings::bounded(policy.capacity), policy.baseline, ResourceVector::ZERO,
        )?.reserve(policy.controller)?.reserve(policy.components)?;
        let head = |id, parent, kind, account, baseline| AccountHead {
            enrollment: identity, id, parent, kind, generation: 1,
            project: [0; 16], sandbox: [0; 16], tree_revision: [0; 32], account, baseline,
        };

        // Fixed aggregate demand stays committed inside the once-paid grant;
        // only the explicit Host and Root subdivisions remain reserved.
        let components_baseline = match policy.host {
            Some(host) => policy.components
                .checked_sub(host.service)?.checked_sub(host.control)?,
            None => policy.components,
        }
        .checked_sub(policy.root_receiving.unwrap_or(ResourceVector::ZERO))?;
        let child_account = |amount, baseline| ResourceAccount::from_usage(
            ResourceCeilings::bounded(amount), baseline, ResourceVector::ZERO,
        );

        let mut heads = [
            head(node, [0; 16], AccountKind::Node, root_account, policy.baseline),
            head(
                controller, node, AccountKind::Controller,
                child_account(policy.controller, policy.controller)?, policy.controller,
            ),
            head(
                components, node, AccountKind::Components,
                child_account(policy.components, components_baseline)?, components_baseline,
            ),
        ];
        let claim = |child, amount, purpose| Claim {
            enrollment: identity, id: account_id(identity, &child), account: node, child,
            owner: identity.manifest, purpose, operation: [0; 16], project: [0; 16],
            sandbox: [0; 16], tree_revision: [0; 32], cut: ClaimCut::BootLifetime,
            genesis_instance: [0; 32],
            amount, state: ClaimState::Reserved,
        };
        let first_global = if let Some(prefix) = policy.first_global_prefix {
            let retained_service = policy.controller.checked_sub(prefix)?
                .checked_sub(policy.nix_original_start_intake.unwrap_or(ResourceVector::ZERO))?
                .checked_sub(policy.q04_original_intake.unwrap_or(ResourceVector::ZERO))?;
            heads[1].baseline = retained_service;
            heads[1].account = ResourceAccount::from_usage(
                ResourceCeilings::bounded(policy.controller),
                retained_service,
                ResourceVector::ZERO,
            )?.reserve(prefix)?
                .reserve(policy.nix_original_start_intake.unwrap_or(ResourceVector::ZERO))?
                .reserve(policy.q04_original_intake.unwrap_or(ResourceVector::ZERO))?;
            Some(Claim {
                id: account_id(identity, b"controller-first-global-prefix-v1"),
                account: controller,
                ..claim([0; 16], prefix, ClaimPurpose::ControllerFirstGlobalPrefix)
            })
        } else {
            None
        };
        let nix_intake = policy.nix_original_start_intake.map(|amount| Claim {
            id: account_id(identity, b"controller-nix-original-start-intake-v1"),
            account: controller,
            ..claim([0; 16], amount, ClaimPurpose::NixOriginalStartIntake)
        });
        let q04_intake = policy.q04_original_intake.map(|amount| Claim {
            id: account_id(identity, b"controller-q04-original-intake-v1"),
            account: controller,
            ..claim([0; 16], amount, ClaimPurpose::Q04OriginalIntake)
        });
        let host = if let Some(host_policy) = policy.host {
            let host_id = account_id(identity, b"host-component-v2");
            let amount = host_policy.service.checked_add(host_policy.control)?;
            heads[2].account = heads[2].account.reserve(amount)?;
            let host_account = ResourceAccount::from_usage(
                ResourceCeilings::bounded(amount),
                host_policy.service,
                ResourceVector::ZERO,
            )?.reserve(host_policy.control)?;
            let host_head = head(
                host_id, components, AccountKind::Operation,
                host_account, host_policy.service,
            );
            let host_claim = Claim {
                account: components,
                ..claim(host_id, amount, ClaimPurpose::HostComponentBootstrap)
            };
            let control_claim = Claim {
                id: account_id(identity, b"host-control-v2"),
                account: host_id,
                ..claim([0; 16], host_policy.control, ClaimPurpose::HostControlInterval)
            };
            Some((host_head, [host_claim, control_claim]))
        } else {
            None
        };
        let root_receiving = if let Some(amount) = policy.root_receiving {
            heads[2].account = heads[2].account.reserve(amount)?;
            Some(Claim {
                id: account_id(identity, b"root-receiving-v1"),
                account: components,
                ..claim([0; 16], amount, ClaimPurpose::RootReceiving)
            })
        } else {
            None
        };

        Ok(Self {
            transaction_id: aos_sandbox_core::OperationId::new().into_bytes(),
            heads,
            claims: [
                claim(controller, policy.controller, ClaimPurpose::ControllerBootstrap),
                claim(components, policy.components, ClaimPurpose::ComponentEnvelope),
            ],
            host,
            first_global,
            nix_intake,
            q04_intake,
            root_receiving,
        })
    }

    fn transaction(&self) -> Result<JournalTransaction, ResourceReservationErrorV1> {
        let members = if self.root_receiving.is_some() { 12 } else if self.q04_intake.is_some() { 11 } else if self.nix_intake.is_some() { 10 }
            else if self.first_global.is_some() { 9 } else if self.host.is_some() { 8 } else { 5 };
        let mut records = Vec::with_capacity(members);
        for head in self.heads {
            records.push(JournalRecord::put(
                RecordNamespace::ControllerResourceReservation,
                replay::key(replay::HEAD_PREFIX, head.id).to_vec(),
                codec::encode_head(head)?.to_vec(),
            ));
        }
        if let Some((head, _)) = self.host {
            records.push(JournalRecord::put(
                RecordNamespace::ControllerResourceReservation,
                replay::key(replay::HEAD_PREFIX, head.id).to_vec(),
                codec::encode_head(head)?.to_vec(),
            ));
        }
        for claim in self.claims {
            records.push(JournalRecord::put(
                RecordNamespace::ControllerResourceReservation,
                replay::key(replay::CLAIM_PREFIX, claim.id).to_vec(),
                codec::encode_claim(claim)?.to_vec(),
            ));
        }
        if let Some((_, claims)) = self.host {
            for claim in claims {
                records.push(JournalRecord::put(
                    RecordNamespace::ControllerResourceReservation,
                    replay::key(replay::CLAIM_PREFIX, claim.id).to_vec(),
                    codec::encode_claim(claim)?.to_vec(),
                ));
            }
        }
        if let Some(claim) = self.first_global {
            records.push(JournalRecord::put(
                RecordNamespace::ControllerResourceReservation,
                replay::key(replay::CLAIM_PREFIX, claim.id).to_vec(),
                codec::encode_claim(claim)?.to_vec(),
            ));
        }
        if let Some(claim) = self.nix_intake {
            records.push(JournalRecord::put(
                RecordNamespace::ControllerResourceReservation,
                replay::key(replay::CLAIM_PREFIX, claim.id).to_vec(),
                codec::encode_claim(claim)?.to_vec(),
            ));
        }
        if let Some(claim) = self.q04_intake {
            records.push(JournalRecord::put(
                RecordNamespace::ControllerResourceReservation,
                replay::key(replay::CLAIM_PREFIX, claim.id).to_vec(),
                codec::encode_claim(claim)?.to_vec(),
            ));
        }
        if let Some(claim) = self.root_receiving {
            records.push(JournalRecord::put(
                RecordNamespace::ControllerResourceReservation,
                replay::key(replay::CLAIM_PREFIX, claim.id).to_vec(),
                codec::encode_claim(claim)?.to_vec(),
            ));
        }
        Ok(JournalTransaction::new(self.transaction_id, records)?)
    }

    pub(super) fn require_current(
        &self,
        state: &replay::State,
        transaction: &JournalTransaction,
    ) -> Result<(), JournalError> {
        self.require_exact(state, transaction).map_err(|_| JournalError::ProtectedBoundary)
    }

    fn require_exact(
        &self,
        state: &replay::State,
        transaction: &JournalTransaction,
    ) -> Result<(), ResourceReservationErrorV1> {
        if replay::validate(state)?.is_some()
            || transaction.id() != &self.transaction_id
            || transaction.records().len() != if self.root_receiving.is_some() { 12 }
                else if self.q04_intake.is_some() { 11 }
                else if self.nix_intake.is_some() { 10 }
                else if self.first_global.is_some() { 9 }
                else if self.host.is_some() { 8 } else { 5 }
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        for (record, head) in transaction.records()[..3].iter().zip(self.heads) {
            if !matches_record(record, replay::HEAD_PREFIX, head.id, &codec::encode_head(head)?) {
                return Err(ResourceReservationErrorV1::Conflict);
            }
        }
        let claim_offset = if self.host.is_some() { 4 } else { 3 };
        if let Some((head, claims)) = self.host {
            if !matches_record(
                &transaction.records()[3], replay::HEAD_PREFIX, head.id,
                &codec::encode_head(head)?,
            ) {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            for (record, claim) in transaction.records()[6..].iter().zip(claims) {
                if !matches_record(record, replay::CLAIM_PREFIX, claim.id, &codec::encode_claim(claim)?) {
                    return Err(ResourceReservationErrorV1::Conflict);
                }
            }
        }
        for (record, claim) in transaction.records()[claim_offset..claim_offset + 2].iter().zip(self.claims) {
            if !matches_record(record, replay::CLAIM_PREFIX, claim.id, &codec::encode_claim(claim)?) {
                return Err(ResourceReservationErrorV1::Conflict);
            }
        }
        if let Some(claim) = self.first_global {
            if !matches_record(
                &transaction.records()[8], replay::CLAIM_PREFIX, claim.id,
                &codec::encode_claim(claim)?,
            ) {
                return Err(ResourceReservationErrorV1::Conflict);
            }
        }
        if let Some(claim) = self.nix_intake {
            if !matches_record(
                &transaction.records()[9], replay::CLAIM_PREFIX, claim.id,
                &codec::encode_claim(claim)?,
            ) {
                return Err(ResourceReservationErrorV1::Conflict);
            }
        }
        if let Some(claim) = self.q04_intake {
            if !matches_record(
                &transaction.records()[10], replay::CLAIM_PREFIX, claim.id,
                &codec::encode_claim(claim)?,
            ) {
                return Err(ResourceReservationErrorV1::Conflict);
            }
        }
        if let Some(claim) = self.root_receiving {
            if !matches_record(
                &transaction.records()[11], replay::CLAIM_PREFIX, claim.id,
                &codec::encode_claim(claim)?,
            ) {
                return Err(ResourceReservationErrorV1::Conflict);
            }
        }
        Ok(())
    }

    fn require_returned(&self, journal: &Journal) -> Result<(), ResourceReservationErrorV1> {
        let state = journal.controller_resource_state_v1()?;
        if replay::validate(state)? != Some(self.heads[0].enrollment)
            || !journal.controller_resource_contains_transaction_v1(&self.transaction_id)?
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        for expected in self.heads {
            if replay::find_head(state, expected.id)? != expected {
                return Err(ResourceReservationErrorV1::Conflict);
            }
        }
        for expected in self.claims {
            let actual = replay::record_bytes(state, replay::CLAIM_PREFIX, expected.id)
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            if codec::decode_claim(actual)? != expected {
                return Err(ResourceReservationErrorV1::Conflict);
            }
        }
        if let Some((head, claims)) = self.host {
            if replay::find_head(state, head.id)? != head {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            for expected in claims {
                let actual = replay::record_bytes(state, replay::CLAIM_PREFIX, expected.id)
                    .ok_or(ResourceReservationErrorV1::Conflict)?;
                if codec::decode_claim(actual)? != expected {
                    return Err(ResourceReservationErrorV1::Conflict);
                }
            }
        }
        if let Some(expected) = self.first_global {
            let actual = replay::record_bytes(state, replay::CLAIM_PREFIX, expected.id)
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            if codec::decode_claim(actual)? != expected {
                return Err(ResourceReservationErrorV1::Conflict);
            }
        }
        if let Some(expected) = self.nix_intake {
            let actual = replay::record_bytes(state, replay::CLAIM_PREFIX, expected.id)
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            if codec::decode_claim(actual)? != expected {
                return Err(ResourceReservationErrorV1::Conflict);
            }
        }
        if let Some(expected) = self.q04_intake {
            let actual = replay::record_bytes(state, replay::CLAIM_PREFIX, expected.id)
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            if codec::decode_claim(actual)? != expected {
                return Err(ResourceReservationErrorV1::Conflict);
            }
        }
        if let Some(expected) = self.root_receiving {
            let actual = replay::record_bytes(state, replay::CLAIM_PREFIX, expected.id)
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            if codec::decode_claim(actual)? != expected {
                return Err(ResourceReservationErrorV1::Conflict);
            }
        }
        Ok(())
    }
}

pub(super) fn account_id(identity: EnrollmentIdentity, role: &[u8]) -> [u8; 16] {
    let mut hash = Sha256::new();
    hash.update(b"AOS-resource-account-v1\0");
    hash.update(identity.node);
    hash.update(identity.epoch);
    hash.update(role);
    let hash = hash.finalize();
    let mut id = [0; 16];
    id.copy_from_slice(&hash[..16]);
    id
}

/// Keeps the first bank-open transaction and every native/post result resident.
///
/// A failed opening cannot be retried or turned into a loan by replay DATA.
/// This owner keeps the actual PID1 files for its whole Controller lifetime.
#[must_use]
pub struct ControllerResourceBankOpeningV1 {
    original: ControllerResourceEnrollmentCaptureV1,
    preopen: Option<ControllerResourcePreopenPostV1>,
    preopen_attempted: bool,
    observed: Option<Result<OriginalEnrollment, ResourceReservationErrorV1>>,
    prepared: Option<Result<(EnrollmentTransition, JournalTransaction), ResourceReservationErrorV1>>,
    names: Option<Result<crate::journal::ProtectedJournalNamesV1, JournalError>>,
    native: Option<Result<crate::journal::CommitResult, JournalError>>,
    readback: Option<Result<(), ResourceReservationErrorV1>>,
    journal_post: Option<Result<(), JournalError>>,
    profile_post: Option<Result<[u8; 16], crate::normal_root::NormalRootStartupErrorV1>>,
    attempted: bool,
    nix_intake_attempted: bool,
    q04_intake_attempted: bool,
}

impl ControllerResourceBankOpeningV1 {
    pub(super) fn begin_q04_intake_once(
        &mut self,
    ) -> Result<OriginalEnrollment, ResourceReservationErrorV1> {
        if self.q04_intake_attempted {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.q04_intake_attempted = true;
        if self.failure().is_some() || !matches!(self.native, Some(Ok(_)))
            || !matches!(self.readback, Some(Ok(())))
        {
            return Err(ResourceReservationErrorV1::EnrollmentUnavailable);
        }
        let original = self.observed.as_ref().and_then(|result| result.as_ref().ok())
            .copied().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        if original.policy.q04_original_intake.is_none() {
            return Err(ResourceReservationErrorV1::EnrollmentUnavailable);
        }
        // This first short borrow uses the actual already-enrolled owner.
        // It grants no fresh replay currentness. Full replay (including cold
        // input decode) and fixed-file/profile proof run only after pricing.
        Ok(original)
    }

    pub(super) fn begin_nix_intake_once(&mut self) -> Result<OriginalEnrollment, ResourceReservationErrorV1> {
        if self.nix_intake_attempted {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        // Arm in the actual bank owner, not only a disposable caller attempt.
        // Failed intake and dropped attempts cannot retry a Reserved row.
        self.nix_intake_attempted = true;
        if self.failure().is_some() || !matches!(self.native, Some(Ok(_)))
            || !matches!(self.readback, Some(Ok(())))
        {
            return Err(ResourceReservationErrorV1::EnrollmentUnavailable);
        }
        let original = self.observed.as_ref().and_then(|result| result.as_ref().ok())
            .copied().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let provision = original.policy.nix_original_start_intake
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        provision.checked_sub(super::nix_intake::minimum_failure_demand()?)?;

        // This is the held successful enrollment, not fresh replay or PID1
        // currentness. Even the first clock/name observation needs this I.
        Ok(original)
    }

    /// Reports only the already-held image family's prefix selection DATA.
    ///
    /// This allocation-free selector does not observe PID1, construct a loan,
    /// rearm first use or authorize a native effect.
    #[must_use]
    pub fn selects_first_global_prefix(&self) -> bool {
        self.observed.as_ref().and_then(|result| result.as_ref().ok())
            .is_some_and(|original| original.policy.first_global_prefix.is_some())
    }

    // Only the entered FirstGlobal constructor uses this genuine held origin
    // before its newly bounded property observations. The returned DATA never
    // escapes the private bank children or substitutes for their current join.
    pub(super) fn first_global_original(
        &self,
        journal: &Journal,
    ) -> Result<OriginalEnrollment, ResourceReservationErrorV1> {
        if self.failure().is_some() || !matches!(self.native, Some(Ok(_)))
            || !matches!(self.readback, Some(Ok(())))
        {
            return Err(ResourceReservationErrorV1::EnrollmentUnavailable);
        }
        let original = self.observed.as_ref().and_then(|result| result.as_ref().ok())
            .copied().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let names = self.names.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let actual = observe_original_pair(&self.original.policy, &self.original.enrollment)?;
        if actual != original || journal.protected_writer_physical_names_v1()? != *names
            || replay::validate(journal.controller_resource_state_v1()?)? != Some(original.identity)
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(original)
    }

    // Rechecks the original producer, not a decoded capsule or a new opener.
    pub(super) fn require_enrolled(
        &self,
        journal: &Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<EnrollmentIdentity, ResourceReservationErrorV1> {
        if self.failure().is_some() || !matches!(self.native, Some(Ok(_)))
            || !matches!(self.readback, Some(Ok(())))
        {
            return Err(ResourceReservationErrorV1::EnrollmentUnavailable);
        }
        let original = self.observed.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let current = self.original.observe(profile)?;
        let names = self.names.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        if current.identity != original.identity || current.policy != original.policy
            || current.recipient_invocation != original.recipient_invocation
            || journal.protected_writer_physical_names_v1()? != *names
            || replay::validate(journal.controller_resource_state_v1()?)? != Some(original.identity)
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(original.identity)
    }

    /// Parks the same original startup pair without observations or allocation.
    pub fn begin(original: ControllerResourceEnrollmentCaptureV1) -> Self {
        Self {
            original, preopen: None, preopen_attempted: false,
            nix_intake_attempted: false,
            q04_intake_attempted: false,
            observed: None, prepared: None, names: None, native: None, readback: None,
            journal_post: None, profile_post: None, attempted: false,
        }
    }

    /// Admits the original PID1-paid bootstrap interval before a Journal opens.
    ///
    /// This once-only admission retains independent observations even after
    /// an earlier failure. It issues neither native Bank enrollment nor an
    /// operation/read reservation, and creates no construction deadline.
    ///
    /// # Errors
    /// Borrows the first retained original recipient, file, or binding cause.
    /// Reentry and failed or interrupted admission never create another loan.
    pub fn admit_preopen_once(
        &mut self,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<(), &(dyn std::error::Error + 'static)> {
        if self.preopen_attempted || self.attempted {
            return Err(&CLOSED);
        }
        self.preopen_attempted = true;
        self.preopen = Some(ControllerResourcePreopenPostV1::new());
        let post = self.preopen.as_mut().ok_or(
            &CLOSED as &(dyn std::error::Error + 'static),
        )?;
        post.observe(&self.original, profile, None);
        post.require_success()
    }

    /// Borrows the same live bootstrap owner without issuing native enrollment.
    ///
    /// The loan is non-Clone and remains tied to the original files/profile.
    /// It cannot expose amounts, descriptors, a new epoch, or a refund.
    ///
    /// # Errors
    /// Rejects absent, failed or spent pre-opening admission and foreign
    /// processes. Its independent current observations must precede effects.
    pub fn borrow_preopen<'owner>(
        &'owner self,
        profile: &'owner crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<ControllerResourcePreopenLoanV1<'owner>, &(dyn std::error::Error + 'static)> {
        if self.attempted || self.original.process != std::process::id() {
            return Err(&CLOSED);
        }
        let post = self.preopen.as_ref().ok_or(
            &CLOSED as &(dyn std::error::Error + 'static),
        )?;
        post.require_success()?;
        Ok(ControllerResourcePreopenLoanV1 { opening: self, profile })
    }

    /// Enrolls the finite bootstrap accounts once on the original protected writer.
    ///
    /// # Errors
    /// Borrows the original observation, preparation, commit or independent
    /// post refusal. Ambiguous commits stay resident and never expose a bank.
    pub fn open_once(
        &mut self,
        journal: &mut Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
        node: [u8; 16],
    ) -> Result<(), &(dyn std::error::Error + 'static)> {
        if self.attempted {
            return Err(&CLOSED);
        }
        self.attempted = true;
        if self.preopen_attempted
            && self.preopen.as_ref().is_none_or(|post| post.require_success().is_err())
        {
            // Failed admission cannot reach enrollment, but the supplied
            // writer/profile still lend their independent negative posts.
            self.journal_post = Some(journal.validate_held_protected_names());
            self.profile_post = Some(profile.require_resource_delivery());
            return Err(self.failure().unwrap_or(&CLOSED));
        }
        self.observed = Some(self.original.observe(profile).and_then(|original| {
            if original.identity.node != node {
                return Err(ResourceReservationErrorV1::EnrollmentUnavailable);
            }
            Ok(original)
        }));
        self.names = Some(journal.protected_writer_physical_names_v1());
        if let Some(Ok(original)) = self.observed.as_ref() {
            self.prepared = Some((|| {
                let transition = EnrollmentTransition::prepare(original)?;
                let transaction = transition.transaction()?;
                transition.require_exact(journal.controller_resource_state_v1()?, &transaction)?;
                Ok((transition, transaction))
            })());
        }
        if self.names.as_ref().is_some_and(Result::is_ok) {
            if let Some(Ok((transition, transaction))) = self.prepared.as_ref() {
                self.native = Some(journal.commit_controller_resource_transition_v1(
                    transaction,
                    &Transition { original: TransitionOriginal::Enrollment(transition), crossing: None },
                ));
            }
        }

        if let Some(Ok((transition, _))) = self.prepared.as_ref() {
            // A commit Err does not suppress same-writer negative readback.
            self.readback = Some(transition.require_returned(journal));
        }
        // Both independent posts run after native Err and observation Err.
        self.journal_post = Some(journal.validate_held_protected_names());
        self.profile_post = Some(profile.require_resource_delivery());
        if let Some(cause) = self.failure() {
            return Err(cause);
        }
        if !matches!(self.native, Some(Ok(_))) {
            return Err(&CLOSED);
        }
        Ok(())
    }

    /// Borrows the earliest original cause in the fixed opening schedule.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.preopen.as_ref().and_then(ControllerResourcePreopenPostV1::failure)
            .or_else(|| self.observed.as_ref().and_then(|result| result.as_ref().err())
            .map(|error| error as &(dyn std::error::Error + 'static))
            )
            .or_else(|| self.names.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.prepared.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.native.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.readback.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.journal_post.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.profile_post.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
    }
}

/// Borrows only the original Controller's PID1 bootstrap obligation.
///
/// This owner-bound short loan is not an operation/read permit or native
/// enrollment. Dropping it refunds nothing and cannot replace the originals.
pub struct ControllerResourcePreopenLoanV1<'owner> {
    opening: &'owner ControllerResourceBankOpeningV1,
    profile: &'owner crate::normal_root::ProductionControllerNormalRootProfileV1,
}

impl ControllerResourcePreopenLoanV1<'_> {
    pub(crate) fn require_node(&self, node: [u8; 16]) -> Result<(), ResourceReservationErrorV1> {
        let original = self.opening.preopen.as_ref()
            .and_then(|post| post.pair.as_ref())
            .and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        if original.identity.node != node {
            return Err(ResourceReservationErrorV1::EnrollmentUnavailable);
        }
        Ok(())
    }

    pub(crate) fn observe_into(&self, post: &mut ControllerResourcePreopenPostV1) {
        let admitted = self.opening.preopen.as_ref()
            .and_then(|post| post.pair.as_ref())
            .and_then(|result| result.as_ref().ok());
        post.observe(&self.opening.original, self.profile, admitted);
    }
}

/// Retains whole independent original recipient, file and binding observations.
///
/// A vacant or successful report is never independently payment authority.
/// Only the original opening's closed loan can populate a construction post.
pub struct ControllerResourcePreopenPostV1 {
    before: Option<Result<([u8; 16], [u8; 16]), crate::normal_root::NormalRootStartupErrorV1>>,
    pair: Option<Result<OriginalEnrollment, ResourceReservationErrorV1>>,
    after: Option<Result<([u8; 16], [u8; 16]), crate::normal_root::NormalRootStartupErrorV1>>,
    binding: Option<Result<(), ResourceReservationErrorV1>>,
    attempted: bool,
}

impl ControllerResourcePreopenPostV1 {
    pub(crate) const fn new() -> Self {
        Self { before: None, pair: None, after: None, binding: None, attempted: false }
    }

    fn observe(
        &mut self,
        original: &ControllerResourceEnrollmentCaptureV1,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
        admitted: Option<&OriginalEnrollment>,
    ) {
        if self.attempted {
            return;
        }
        self.attempted = true;
        self.before = Some(profile.require_resource_producer());
        self.pair = Some(observe_original_pair(&original.policy, &original.enrollment));
        // A native/profile Err does not suppress the independent negative post.
        self.after = Some(profile.require_resource_producer());
        self.binding = Some((|| {
            let before = self.before.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
            let pair = self.pair.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
            let after = self.after.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
            if original.process != std::process::id() || before != after
                || pair.recipient_invocation != before.0 || pair.identity.invocation != before.1
                || admitted.is_some_and(|previous| {
                    previous.identity != pair.identity || previous.policy != pair.policy
                        || previous.recipient_invocation != pair.recipient_invocation
                })
            {
                return Err(ResourceReservationErrorV1::EnrollmentUnavailable);
            }
            Ok(())
        })());
    }

    pub(crate) fn require_success(&self) -> Result<(), &(dyn std::error::Error + 'static)> {
        if let Some(cause) = self.failure() {
            return Err(cause);
        }
        if !matches!(self.binding, Some(Ok(()))) {
            return Err(&CLOSED);
        }
        Ok(())
    }

    /// Borrows the earliest cause without taking any result or original.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.before.as_ref().and_then(|result| result.as_ref().err())
            .map(|error| error as &(dyn std::error::Error + 'static))
            .or_else(|| self.pair.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.after.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.binding.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
    }
}

static CLOSED: ResourceReservationErrorV1 = ResourceReservationErrorV1::EnrollmentUnavailable;
