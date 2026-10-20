//! Captures the actual shared image/PID1 pair without issuing role grants.
//!
//! Controller callers additionally validate their actual native Q/J layouts;
//! independent F recipients validate canonical/static image policy and their
//! own genuine role's held Parent/financial/native construction separately.

use std::os::unix::fs::{FileExt as _, MetadataExt as _};
use aos_sandbox_linux::boot::{KernelBootId, RootOriginalKernelBootIdAttemptV1};
use aos_sandbox_protocol::domain_ledger::resource_bank::{self as bank, EnrollmentIdentity, ImageBootstrapPolicy};
use rustix::fs::{OFlags, SealFlags, fcntl_get_seals, fcntl_getfl, fstatfs};
use sha2::{Digest as _, Sha256};

/// Preserves original pair IO, descriptor, canonical or fixed refusal causes.
#[derive(Debug, thiserror::Error)]
pub enum OriginalPairErrorV1 {
    /// An actual positional file read or metadata observation failed.
    #[error(transparent)] Io(#[from] std::io::Error),
    /// An actual descriptor operation failed.
    #[error(transparent)] Descriptor(#[from] rustix::io::Errno),
    /// The original kernel boot observation failed.
    #[error(transparent)] Kernel(#[from] aos_sandbox_linux::Error),
    /// Canonical identity, vector or subdivision validation failed.
    #[error(transparent)] Data(#[from] bank::ResourceBankDataError),
    /// The actual original files or producer identity are unavailable.
    #[error("original image/PID1 pair is unavailable")] EnrollmentUnavailable,
    /// A once-only original destination was entered again.
    #[error("original image/PID1 pair was already entered")] Conflict,
}

/// Borrows copied canonical identity DATA from an actual pair observation.
///
/// Copying this DATA cannot enroll a bank or create a role-specific original.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OriginalEnrollment {
    /// Carries the observed canonical producer identity.
    pub identity: EnrollmentIdentity,
    /// Carries the fully canonical/static-validated image policy DATA.
    pub policy: ImageBootstrapPolicy,
    /// Carries the delivery recipient invocation DATA.
    pub recipient_invocation: [u8; 16],
    /// Carries the Controller delivery's actual consumed ordinal DATA.
    pub controller_generation_v1: Option<u64>,
    /// Carries the actual versioned delivery's prepaid-range commitment DATA.
    pub controller_range_commitment_v2: Option<[u8; 32]>,
}

// These fixed file and canonical DATA checks do not issue enrollment. Each
// purpose-closed caller independently rejoins its actual PID1 recipient.
/// Observes the original pair with the actual Controller native-layout DATA.
///
/// # Errors
/// Preserves original native and canonical failures without issuing enrollment.
pub fn observe_original_pair(
    policy_file: &std::fs::File,
    enrollment_file: &std::fs::File,
    layout: bank::NativeLayoutDemand,
) -> Result<OriginalEnrollment, OriginalPairErrorV1> {
    let mut observations = OriginalPairObservations::default();
    observe_original_pair_into::<false>(policy_file, enrollment_file, &mut observations, None, None, Some(layout))
}

/// Retains the reached original pair observations without issuing a loan.
///
/// The caller holds both original files and this destination through any
/// refusal. Every accepted image width remains exact, including the 3248-byte
/// AOSRSB11 policy and 192-byte Controller AOSRSE03 delivery. Other roles retain
/// their separate delivery grammar. Native-layout DATA does not select a role;
/// genuine Root also uses layout validation. These buffers provide custody,
/// not a funded receiving or physical-fit declaration.
pub struct OriginalEnrollmentPairAttemptV1 {
    observations: OriginalPairObservations,
    bytes: OriginalPairBytes,
    boot: RootOriginalKernelBootIdAttemptV1,
    entered: bool,
    closed: Option<OriginalPairErrorV1>,
    layout: Option<bank::NativeLayoutDemand>,
}

impl OriginalEnrollmentPairAttemptV1 {
    /// Creates empty retained destinations with the actual Controller layout.
    pub fn new_controller(layout: bank::NativeLayoutDemand) -> Self {
        Self::with_layout(Some(layout))
    }

    /// Describes this same retained pair's added dynamic/native destinations.
    ///
    /// The enclosing owner separately includes this inline attempt in its
    /// compiled layout. This is passive DATA: it supplies no account, admission
    /// or original observation. One boot File and its exact lower result census
    /// coexist with the original pair, current SHA state and return carrier.
    #[must_use]
    pub fn additional_receiving_demand_v1() -> Option<aos_sandbox_core::ResourceVector> {
        use aos_sandbox_core::{ResourceDimension as D, ResourceVector};

        let boot = RootOriginalKernelBootIdAttemptV1::dominant_requested_bytes_v1()?;
        let bytes = std::mem::size_of::<Self>()
            .checked_add(std::mem::size_of::<OriginalEnrollment>())?
            .checked_add(std::mem::size_of::<Sha256>())?
            // The actual boot owner is already inside Self; only its named
            // bounded parser/diagnostic backing remains additional here.
            .checked_add(boot.checked_sub(std::mem::size_of::<RootOriginalKernelBootIdAttemptV1>())?)?;
        Some(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
            .with(D::OpenFiles, u64::try_from(RootOriginalKernelBootIdAttemptV1::MAXIMUM_RETAINED_FILES_V1).ok()?))
    }

    pub(crate) fn new_component() -> Self { Self::with_layout(None) }

    /// Creates inert component pair DATA custody without a Controller layout.
    ///
    /// This constructor opens nothing and creates no role, payer, enrollment,
    /// Host original or completion token. A genuine enclosing component owner
    /// prepays this destination and independently checks its fixed native joins.
    #[must_use]
    pub fn new_component_data_v2() -> Self {
        Self::with_layout(None)
    }

    /// Reports this bounded pair destination and construction temporary in bytes.
    ///
    /// The embedded boot reader supplies its bounded diagnostic backing. Held
    /// policy/delivery files belong to the enclosing original; observing this
    /// pair can additionally retain one actual boot-ID file on failure.
    #[must_use]
    pub fn receiving_memory_bytes_v2() -> Option<usize> {
        std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(RootOriginalKernelBootIdAttemptV1::dominant_requested_bytes_v1()?
                .checked_sub(std::mem::size_of::<RootOriginalKernelBootIdAttemptV1>())?)
    }

    fn with_layout(layout: Option<bank::NativeLayoutDemand>) -> Self {
        Self {
            observations: OriginalPairObservations::default(),
            bytes: OriginalPairBytes {
                policy: [0; bank::CONTROLLER_RECIPIENT_RANGE_IMAGE_POLICY_BYTES],
                delivery: [0; 192],
            },
            boot: RootOriginalKernelBootIdAttemptV1::new(),
            entered: false,
            closed: None,
            layout,
        }
    }

    /// Observes the original pair once and borrows its earliest actual refusal.
    ///
    /// # Errors
    ///
    /// Retains failed native observations, partial reads and canonical causes.
    /// A repeated entry closes the attempt without replacing earlier debt.
    pub fn observe_once(
        &mut self,
        policy: &std::fs::File,
        delivery: &std::fs::File,
    ) -> Result<&OriginalEnrollment, &(dyn std::error::Error + 'static)> {
        if self.entered {
            self.closed = Some(OriginalPairErrorV1::Conflict);
        } else {
            self.entered = true;
            self.observations.completion = Some(observe_original_pair_into::<true>(
                policy,
                delivery,
                &mut self.observations,
                Some(&mut self.bytes),
                Some(&mut self.boot),
                self.layout,
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

    /// Borrows the same successful observation's immutable policy commitment.
    pub fn policy_commitment(&self) -> Option<[u8; 32]> {
        self.observations.completion.as_ref()?.as_ref().ok()?;
        self.observations.manifest
    }

    // Only an enclosing fully positive fixed observation can retire this
    // temporary boot input. The original startup pair never uses this route.
    pub(crate) fn retire_positive_boot_file_once(&mut self) -> Result<(), OriginalPairErrorV1> {
        if self.failure().is_some()
            || self.observations.completion.as_ref().is_none_or(Result::is_err)
        {
            return Err(OriginalPairErrorV1::Conflict);
        }
        self.boot.retire_positive_file_once().map_err(|_| OriginalPairErrorV1::Conflict)
    }

    /// Borrows the earliest reached native or canonical cause without retry.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.observations.failure()
            .or_else(|| self.boot.failure())
            .or_else(|| pair_failure(&self.observations.completion))
            .or_else(|| self.closed.as_ref().map(|error| error as _))
    }
}

struct OriginalPairBytes {
    policy: [u8; bank::CONTROLLER_RECIPIENT_RANGE_IMAGE_POLICY_BYTES],
    delivery: [u8; 192],
}

#[derive(Default)]
struct OriginalPairObservations {
    policy_metadata: Option<std::io::Result<std::fs::Metadata>>,
    delivery_metadata: Option<std::io::Result<std::fs::Metadata>>,
    delivery_seals: Option<Result<SealFlags, rustix::io::Errno>>,
    policy_filesystem: Option<Result<rustix::fs::StatFs, rustix::io::Errno>>,
    policy_flags: Option<Result<OFlags, rustix::io::Errno>>,
    delivery_flags: Option<Result<OFlags, rustix::io::Errno>>,
    shape: Option<Result<(), OriginalPairErrorV1>>,
    policy_read: Option<std::io::Result<()>>,
    delivery_read: Option<std::io::Result<()>>,
    policy_decode: Option<Result<ImageBootstrapPolicy, OriginalPairErrorV1>>,
    delivery_decode: Option<Result<(EnrollmentIdentity, [u8; 16]), OriginalPairErrorV1>>,
    controller_generation: Option<Result<Option<u64>, OriginalPairErrorV1>>,
    controller_range: Option<Result<Option<[u8; 32]>, OriginalPairErrorV1>>,
    manifest: Option<[u8; 32]>,
    // Ordinary acquisition keeps its original returned-result contract. Only
    // the actual retained Root pair installs bounded original boot custody.
    boot: Option<Result<KernelBootId, aos_sandbox_linux::Error>>,
    completion: Option<Result<OriginalEnrollment, OriginalPairErrorV1>>,
}

impl OriginalPairObservations {
    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        // Vacant slots were never entered. The shape marker follows its native
        // inputs; it must not replace their original IO or descriptor cause.
        let causes: [Option<&(dyn std::error::Error + 'static)>; 14] = [
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
            pair_failure(&self.controller_generation),
            pair_failure(&self.controller_range),
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
                return Err(OriginalPairErrorV1::EnrollmentUnavailable);
            }
            if let Some(Err(error)) = slot.take() {
                return Err(error.into());
            }
        }
        slot.as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(OriginalPairErrorV1::EnrollmentUnavailable)?
    }};
}

fn observe_original_pair_into<const RETAINED: bool>(
    policy_file: &std::fs::File,
    enrollment_file: &std::fs::File,
    observations: &mut OriginalPairObservations,
    bytes: Option<&mut OriginalPairBytes>,
    retained_boot: Option<&mut RootOriginalKernelBootIdAttemptV1>,
    layout: Option<bank::NativeLayoutDemand>,
) -> Result<OriginalEnrollment, OriginalPairErrorV1> {
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
                bank::IMAGE_POLICY_BYTES as u64,
                bank::HOST_IMAGE_POLICY_BYTES as u64,
                bank::FIRST_GLOBAL_IMAGE_POLICY_BYTES as u64,
                bank::NIX_INTAKE_IMAGE_POLICY_BYTES as u64,
                bank::Q04_INTAKE_IMAGE_POLICY_BYTES as u64,
                bank::ROOT_IMAGE_POLICY_BYTES as u64,
                bank::CREATE_STORAGE_IMAGE_POLICY_BYTES as u64,
                bank::OPERATION_INTAKE_IMAGE_POLICY_BYTES as u64,
                bank::HOST_EXECUTION_IMAGE_POLICY_BYTES as u64,
                bank::CONTROLLER_RECOVERY_IMAGE_POLICY_BYTES as u64,
                bank::CONTROLLER_RECIPIENT_RANGE_IMAGE_POLICY_BYTES as u64,
            ].contains(&policy_length)
            || policy_metadata.uid() != 0 || policy_metadata.gid() != 0
            || policy_metadata.mode() & 0o222 != 0
            || original_pair_outcome!(
                RETAINED, observations.policy_filesystem, fstatfs(policy_file)
            ).f_type as u64 != 0xe0f5_e1e2
            || *original_pair_outcome!(
                RETAINED, observations.policy_flags, fcntl_getfl(policy_file)
            ) & OFlags::ACCMODE != OFlags::RDONLY
            || !delivery_metadata.is_file() || ![152, 160, 192].contains(&delivery_metadata.len())
            || delivery_metadata.nlink() != 0 || delivery_metadata.uid() != 0
            || *original_pair_outcome!(
                RETAINED, observations.delivery_flags, fcntl_getfl(enrollment_file)
            ) & OFlags::ACCMODE != OFlags::RDONLY
            || !seals.contains(SealFlags::SEAL | SealFlags::GROW | SealFlags::SHRINK | SealFlags::WRITE)
        {
            return Err(OriginalPairErrorV1::EnrollmentUnavailable);
        }
        Ok(())
    })();
    original_pair_outcome!(RETAINED, observations.shape, shape);

    let (policy, identity, recipient_invocation, manifest, controller_generation_v1, controller_range_commitment_v2) =
        if policy_length == bank::IMAGE_POLICY_BYTES as u64 {
            read_original_pair::<{ bank::IMAGE_POLICY_BYTES }, RETAINED>(
                policy_file, enrollment_file, observations, bytes, layout,
            )?
        } else if policy_length == bank::HOST_IMAGE_POLICY_BYTES as u64 {
            read_original_pair::<{ bank::HOST_IMAGE_POLICY_BYTES }, RETAINED>(
                policy_file, enrollment_file, observations, bytes, layout,
            )?
        } else if policy_length == bank::FIRST_GLOBAL_IMAGE_POLICY_BYTES as u64 {
            read_original_pair::<{ bank::FIRST_GLOBAL_IMAGE_POLICY_BYTES }, RETAINED>(
                policy_file, enrollment_file, observations, bytes, layout,
            )?
        } else if policy_length == bank::NIX_INTAKE_IMAGE_POLICY_BYTES as u64 {
            read_original_pair::<{ bank::NIX_INTAKE_IMAGE_POLICY_BYTES }, RETAINED>(
                policy_file, enrollment_file, observations, bytes, layout,
            )?
        } else if policy_length == bank::Q04_INTAKE_IMAGE_POLICY_BYTES as u64 {
            read_original_pair::<{ bank::Q04_INTAKE_IMAGE_POLICY_BYTES }, RETAINED>(
                policy_file, enrollment_file, observations, bytes, layout,
            )?
        } else if policy_length == bank::ROOT_IMAGE_POLICY_BYTES as u64 {
            read_original_pair::<{ bank::ROOT_IMAGE_POLICY_BYTES }, RETAINED>(
                policy_file, enrollment_file, observations, bytes, layout,
            )?
        } else if policy_length == bank::CREATE_STORAGE_IMAGE_POLICY_BYTES as u64 {
            read_original_pair::<{ bank::CREATE_STORAGE_IMAGE_POLICY_BYTES }, RETAINED>(
                policy_file, enrollment_file, observations, bytes, layout,
            )?
        } else if policy_length == bank::OPERATION_INTAKE_IMAGE_POLICY_BYTES as u64 {
            read_original_pair::<{ bank::OPERATION_INTAKE_IMAGE_POLICY_BYTES }, RETAINED>(
                policy_file, enrollment_file, observations, bytes, layout,
            )?
        } else if policy_length == bank::HOST_EXECUTION_IMAGE_POLICY_BYTES as u64 {
            read_original_pair::<{ bank::HOST_EXECUTION_IMAGE_POLICY_BYTES }, RETAINED>(
                policy_file, enrollment_file, observations, bytes, layout,
            )?
        } else if policy_length == bank::CONTROLLER_RECOVERY_IMAGE_POLICY_BYTES as u64 {
            read_original_pair::<{ bank::CONTROLLER_RECOVERY_IMAGE_POLICY_BYTES }, RETAINED>(
                policy_file, enrollment_file, observations, bytes, layout,
            )?
        } else {
            read_original_pair::<{ bank::CONTROLLER_RECIPIENT_RANGE_IMAGE_POLICY_BYTES }, RETAINED>(
                policy_file, enrollment_file, observations, bytes, layout,
            )?
        };
    if !identity.matches_image(policy, manifest)
        || identity.native_fields().boot
            != original_pair_boot::<RETAINED>(observations, retained_boot)?
    {
        return Err(OriginalPairErrorV1::EnrollmentUnavailable);
    }
    Ok(OriginalEnrollment { identity, policy, recipient_invocation, controller_generation_v1, controller_range_commitment_v2 })
}

// Both arms enter only after the same node/epoch/manifest short-circuit checks.
// No ordinary caller constructs or enters the retained original boot attempt.
fn original_pair_boot<const RETAINED: bool>(
    observations: &mut OriginalPairObservations,
    retained_boot: Option<&mut RootOriginalKernelBootIdAttemptV1>,
) -> Result<[u8; 16], OriginalPairErrorV1> {
    if RETAINED {
        let attempt = retained_boot.ok_or(OriginalPairErrorV1::EnrollmentUnavailable)?;
        return attempt.observe_once()
            .map(|boot| boot.into_bytes())
            .map_err(|_| OriginalPairErrorV1::EnrollmentUnavailable);
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
    layout: Option<bank::NativeLayoutDemand>,
) -> Result<
    (ImageBootstrapPolicy, EnrollmentIdentity, [u8; 16], [u8; 32], Option<u64>, Option<[u8; 32]>),
    OriginalPairErrorV1,
> {
    let delivery_length = observations.delivery_metadata.as_ref().and_then(|result| result.as_ref().ok())
        .map(|metadata| metadata.len() as usize).filter(|length| matches!(length, 152 | 160 | 192))
        .ok_or(OriginalPairErrorV1::EnrollmentUnavailable)?;
    match retained_bytes {
        Some(bytes) => read_original_pair_buffers::<RETAINED>(
            policy_file, enrollment_file, observations,
            &mut bytes.policy[..N], &mut bytes.delivery[..delivery_length], layout,
        ),
        None => {
            let mut policy_bytes = [0; N];
            let mut delivery_bytes = [0; 192];
            read_original_pair_buffers::<RETAINED>(
                policy_file, enrollment_file, observations,
                &mut policy_bytes, &mut delivery_bytes[..delivery_length], layout,
            )
        }
    }
}

fn read_original_pair_buffers<const RETAINED: bool>(
    policy_file: &std::fs::File,
    enrollment_file: &std::fs::File,
    observations: &mut OriginalPairObservations,
    policy_bytes: &mut [u8],
    delivery_bytes: &mut [u8],
    layout: Option<bank::NativeLayoutDemand>,
) -> Result<
    (ImageBootstrapPolicy, EnrollmentIdentity, [u8; 16], [u8; 32], Option<u64>, Option<[u8; 32]>),
    OriginalPairErrorV1,
> {
    original_pair_outcome!(
        RETAINED, observations.policy_read, policy_file.read_exact_at(policy_bytes, 0)
    );
    original_pair_outcome!(
        RETAINED, observations.delivery_read, enrollment_file.read_exact_at(delivery_bytes, 0)
    );

    let policy = *original_pair_outcome!(
        RETAINED,
        observations.policy_decode,
        match layout {
            Some(layout) => bank::decode_image_policy(policy_bytes, layout),
            None => bank::decode_component_image_policy(policy_bytes),
        }.map_err(OriginalPairErrorV1::from)
    );
    let (identity, recipient_invocation) = *original_pair_outcome!(
        RETAINED,
        observations.delivery_decode,
        bank::decode_pid1_delivery(delivery_bytes).map_err(OriginalPairErrorV1::from)
    );
    let controller_generation = *original_pair_outcome!(RETAINED,
        observations.controller_generation,
        bank::decode_controller_delivery_generation_v1(delivery_bytes).map_err(OriginalPairErrorV1::from)
    );
    let controller_range = *original_pair_outcome!(
        RETAINED,
        observations.controller_range,
        (|| {
            if delivery_bytes.len() == 192 {
                let (recipients, _) = policy.controller_recovery_range_v1()
                    .ok_or(OriginalPairErrorV1::EnrollmentUnavailable)?;
                let ordinal = controller_generation
                    .ok_or(OriginalPairErrorV1::EnrollmentUnavailable)?;
                let actual = bank::controller_recipient_range_commitment_v1(identity, policy)?;
                if ordinal > recipients || delivery_bytes[128..160] != actual {
                    return Err(OriginalPairErrorV1::EnrollmentUnavailable);
                }
                return Ok(Some(actual));
            }
            Ok(None)
        })()
    );
    let manifest = <[u8; 32]>::from(Sha256::digest(policy_bytes));
    observations.manifest = Some(manifest);
    Ok((policy, identity, recipient_invocation, manifest, controller_generation, controller_range))
}
