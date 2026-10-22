//! Retains Source host controls beneath the authentic containing Main.
//!
//! A fixed descriptor window borrows the already paid host-table remainder;
//! control storage debits the same original Main counters. No nested allocator
//! or RAM-controller registration supplies this purpose. The actual owned Child
//! records physical reap; a PID, empty cgroup or cancellation cannot replace it.
// SPDX-License-Identifier: Apache-2.0

use std::process::{Child, ExitStatus};
use std::sync::Mutex;

use super::*;

mod retained_control;
use retained_control::RetainedControl;

mod roster_allocation;
pub use roster_allocation::{NativeRosterAllocationFunding, NativeRosterUpgradeGate};

/// Retains one Source launch's actual Main payer and descriptor window.
///
/// Clones and control payers retain one shared charge through the allocation's
/// actual deallocation. The final owner can discharge it only after its real
/// child is reaped, or no process birth was attempted, and all controls return.
#[derive(Clone)]
pub struct AuthenticatedSourceHostPurpose {
    held: RetainedControl<SourceHostState>,
}

/// Retains the existing Source payer while its issued control routes remain.
///
/// Clones keep the same Main reservation live without allocating another control.
/// This observer owns no process and creates no Source, operation or resource
/// credit. It cannot outlive the funding of its shared allocation header.
#[derive(Clone)]
pub struct SourceHostControlPayer {
    purpose: AuthenticatedSourceHostPurpose,
}

impl SourceHostControlPayer {
    /// Reserves actual controls from the same retained Source before birth.
    ///
    /// # Errors
    /// Refuses changed Main custody or exhausted existing control capacity.
    pub fn reserve_controls(
        &self,
        descriptors: u64,
        bytes: u64,
    ) -> Result<SourceHostControlLease, ServiceBirthError> {
        self.purpose.reserve_controls(descriptors, bytes)
    }
}

struct SourceHostState {
    issuer: Arc<AuthenticatedNativeSlotPurpose>,
    window: Option<AuthenticatedNativeNodeHostWindow>,
    child: Mutex<SourceChildState>,
    controls: Mutex<SourceControlState>,
    control_peak: u64,
    descriptor_peak: u64,
    descriptors: Option<HostServiceLease>,
    metadata: Option<HostServiceLeasePair>,
}

/// Owns a disjoint piece of the already admitted Source control peak.
///
/// Physical descriptor and body owners must be destroyed before this lease.
/// This borrows the existing Main reservation; it creates no account or budget.
#[derive(Debug)]
pub struct SourceHostControlLease {
    purpose: AuthenticatedSourceHostPurpose,
    bytes: u64,
    descriptors: u64,
}

#[derive(Default)]
struct SourceControlState {
    bytes: u64,
    descriptors: u64,
}

#[derive(Default)]
struct SourceChildState {
    birth_attempted: bool,
    process: Option<u32>,
    reaped: bool,
}

/// Owns the actual Source child whose wait result proves process retirement.
///
/// Its host purpose remains retained after process reap until every launch
/// control borrower closes. Construction consumes a real Child, not a PID.
#[derive(Debug)]
pub struct AuthenticatedSourceChild {
    child: Child,
    purpose: AuthenticatedSourceHostPurpose,
}

impl std::fmt::Debug for AuthenticatedSourceHostPurpose {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AuthenticatedSourceHostPurpose { .. }")
    }
}

impl AuthenticatedNativeSubdivision {
    /// Prepays Source controls inside the same actual containing Main.
    ///
    /// The requested peak prices the caller's real startup, preexec, cancellation
    /// and error overlap. This reserves no native RAM, new task or replacement
    /// service budget. Both actual Source and Target host windows must fit.
    ///
    /// # Errors
    /// Refuses changed Main custody, an occupied Source window, an invalid peak
    /// or exhausted existing metadata/descriptor capacity.
    pub fn reserve_source_host_purpose(
        &self,
        control_peak: u64,
        descriptor_peak: u64,
        original: &Arc<HostOperationGuard>,
    ) -> Result<AuthenticatedSourceHostPurpose, NativePoolRefusal> {
        let result = (|| {
            self.verify_native_preparation(original)?;
            let node = self.node.as_ref().ok_or_else(|| {
                ServiceBirthError::policy("Source host needs its consumed node claim")
            })?;
            let (layout, _) = std::alloc::Layout::new::<(
                std::sync::atomic::AtomicUsize,
                std::sync::atomic::AtomicUsize,
            )>()
            .extend(std::alloc::Layout::new::<SourceHostState>())
            .map_err(|_| ServiceBirthError::policy("Source host holder layout overflows"))?;
            let extent = u64::try_from(layout.pad_to_align().size())
                .ok()
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<SourceHostState>() as u64))
                .and_then(|bytes| bytes.checked_add(control_peak))
                .and_then(|bytes| bytes.checked_add(host_descriptors::CENSUS_BYTES as u64))
                .and_then(|bytes| bytes.checked_add(2 * HostServiceLease::metadata_bytes()))
                .filter(|_| control_peak != 0 && descriptor_peak != 0)
                .ok_or_else(|| ServiceBirthError::policy("Source host control peak is invalid"))?;
            let prepared = native_pool::PreparedRefusal::reserve(&self.owner)?;
            // The containing counters and table window pay before Arc/body birth.
            let metadata = self
                .owner
                .owner
                .reserve_metadata(extent)
                .map_err(ServiceBirthError::from)?;
            let window = node.occupy_window(native_pool::WindowRole::Source)?;
            let assigned_descriptors = window.descriptor_peak()?;
            if assigned_descriptors < descriptor_peak {
                return Err(ServiceBirthError::policy(
                    "selected Source landing is undersized",
                ));
            }
            let descriptors = self
                .owner
                .host_descriptors
                .lock()
                .map_err(|_| ServiceBirthError::policy("Source host table custody is uncertain"))?
                .as_ref()
                .ok_or_else(|| ServiceBirthError::policy("Source host table payer is absent"))?
                .retain_pool_remainder()?;
            let source = construct_source_host(
                Arc::clone(&self.owner),
                window,
                control_peak,
                assigned_descriptors,
                descriptors,
                metadata,
            );
            Ok((source, prepared))
        })();
        let after = self.verify_native_preparation(original).err();
        native_pool::finish_source(result, after)
    }
}

/// Enters the candidate-body frame only after its same Main peak is held.
fn construct_source_host(
    issuer: Arc<AuthenticatedNativeSlotPurpose>,
    window: AuthenticatedNativeNodeHostWindow,
    control_peak: u64,
    descriptor_peak: u64,
    descriptors: HostServiceLease,
    metadata: HostServiceLeasePair,
) -> AuthenticatedSourceHostPurpose {
    AuthenticatedSourceHostPurpose {
        held: RetainedControl::new(SourceHostState {
            issuer,
            window: Some(window),
            child: Mutex::new(SourceChildState::default()),
            controls: Mutex::new(SourceControlState::default()),
            control_peak,
            descriptor_peak,
            descriptors: Some(descriptors),
            metadata: Some(metadata),
        }),
    }
}

impl AuthenticatedSourceHostPurpose {
    /// Retains this actual Source payer for an already issued control route.
    ///
    /// The observer shares the original allocation and Main charge; it grants
    /// neither process ownership nor a separately spendable resource window.
    #[must_use]
    pub fn retain_control_payer(&self) -> SourceHostControlPayer {
        SourceHostControlPayer {
            purpose: self.clone(),
        }
    }

    /// Borrows controls already priced by the authentic Main Source reservation.
    ///
    /// # Errors
    /// Refuses changed custody, arithmetic overflow or overlapping controls
    /// exceeding the originally admitted metadata and descriptor peaks.
    pub fn reserve_controls(
        &self,
        descriptors: u64,
        bytes: u64,
    ) -> Result<SourceHostControlLease, ServiceBirthError> {
        self.check()?;
        let mut controls = self
            .held
            .controls
            .lock()
            .map_err(|_| ServiceBirthError::policy("Source control custody is uncertain"))?;
        let next_bytes = controls
            .bytes
            .checked_add(bytes)
            .filter(|next| *next <= self.held.control_peak)
            .ok_or_else(|| ServiceBirthError::policy("Source metadata peak is exhausted"))?;
        let next_descriptors = controls
            .descriptors
            .checked_add(descriptors)
            .filter(|next| *next <= self.held.descriptor_peak)
            .ok_or_else(|| ServiceBirthError::policy("Source descriptor peak is exhausted"))?;
        controls.bytes = next_bytes;
        controls.descriptors = next_descriptors;
        Ok(SourceHostControlLease {
            purpose: self.clone(),
            bytes,
            descriptors,
        })
    }

    /// Compares actual shared Source control custody without using wire identity.
    #[must_use]
    pub fn same_owner(&self, other: &Self) -> bool {
        self.held.same_owner(&other.held)
    }

    /// Corroborates this payer against its actual retained native subdivision.
    #[must_use]
    pub fn belongs_to(&self, subdivision: &AuthenticatedNativeSubdivision) -> bool {
        Arc::ptr_eq(&self.held.issuer, &subdivision.owner)
            && self
                .held
                .window
                .as_ref()
                .is_some_and(|window| window.matches(subdivision))
    }

    /// Checks that the actual node supervisor shares this retained Main cap.
    ///
    /// # Errors
    /// Refuses another supervisor or changed/expired physical payer custody.
    pub fn verify_supervisor(
        &self,
        supervisor: &HostOperationSupervisor,
    ) -> Result<(), ServiceBirthError> {
        self.check()?;
        if !self.held.issuer.original.shares_outer_cap(supervisor) {
            return Err(ServiceBirthError::policy(
                "Source supervisor belongs to another Main",
            ));
        }
        Ok(())
    }

    /// Checks unchanged Main and the same retained Source table window.
    ///
    /// # Errors
    /// Refuses Main expiration, changed table limits, or stale/poisoned custody.
    pub fn check(&self) -> Result<(), ServiceBirthError> {
        self.held.issuer.check()?;
        self.held
            .window
            .as_ref()
            .ok_or_else(|| ServiceBirthError::policy("Source host landing is absent"))?
            .descriptor_peak()?;
        Ok(())
    }

    /// Marks the actual Source spawn attempt before invoking process creation.
    ///
    /// An uncertain failed spawn cannot replenish its window. The caller keeps
    /// this same purpose in the already paid failure/cleanup owner.
    ///
    /// # Errors
    /// Refuses repeated birth, changed Main or poisoned retained process state.
    pub fn begin_birth(&self) -> Result<(), ServiceBirthError> {
        self.check()?;
        let mut state = self
            .held
            .child
            .lock()
            .map_err(|_| ServiceBirthError::policy("Source process custody is uncertain"))?;
        if state.birth_attempted {
            return Err(ServiceBirthError::policy(
                "Source birth was already attempted",
            ));
        }
        state.birth_attempted = true;
        Ok(())
    }

    /// Moves the actual spawned Child into its retained physical wait owner.
    ///
    /// # Errors
    /// Returns the same Child on missing/repeated birth or uncertain state. The
    /// caller must retain and contain that real process after refusal.
    pub fn retain_child(
        &self,
        child: Child,
    ) -> Result<AuthenticatedSourceChild, (Child, ServiceBirthError)> {
        let mut state = match self.held.child.lock() {
            Ok(state) => state,
            Err(_) => {
                return Err((
                    child,
                    ServiceBirthError::policy("Source child keeper is uncertain"),
                ));
            }
        };
        if !state.birth_attempted || state.process.is_some() || state.reaped {
            return Err((
                child,
                ServiceBirthError::policy("Source child birth does not match keeper"),
            ));
        }
        state.process = Some(child.id());
        drop(state);
        Ok(AuthenticatedSourceChild {
            child,
            purpose: self.clone(),
        })
    }
}

impl AuthenticatedSourceChild {
    /// Returns the actual owned child process identifier.
    #[must_use]
    pub fn id(&self) -> u32 {
        self.child.id()
    }

    /// Checks actual process exit and records only successful kernel reap.
    ///
    /// # Errors
    /// Returns the real wait error or poisoned same-purpose retirement state.
    pub fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        let result = self.child.try_wait()?;
        if result.is_some() {
            self.record_reap()?;
        }
        Ok(result)
    }

    /// Waits for the actual child and records its successful physical reap.
    ///
    /// # Errors
    /// Returns the real wait error or poisoned same-purpose retirement state.
    pub fn wait(&mut self) -> std::io::Result<ExitStatus> {
        let result = self.child.wait()?;
        self.record_reap()?;
        Ok(result)
    }

    /// Requests termination of this actual owned child.
    ///
    /// # Errors
    /// Returns the kernel termination error; this does not record reap.
    pub fn kill(&mut self) -> std::io::Result<()> {
        self.child.kill()
    }

    fn record_reap(&self) -> std::io::Result<()> {
        let mut state = self
            .purpose
            .held
            .child
            .lock()
            .map_err(|_| std::io::Error::other("Source reap keeper is uncertain"))?;
        if state.process != Some(self.child.id()) {
            return Err(std::io::Error::other(
                "Source reap does not match retained child",
            ));
        }
        state.reaped = true;
        Ok(())
    }
}

impl Drop for SourceHostState {
    fn drop(&mut self) {
        let proven = self
            .child
            .get_mut()
            .is_ok_and(|state| (!state.birth_attempted && state.process.is_none()) || state.reaped);
        let controls_closed = self
            .controls
            .get_mut()
            .is_ok_and(|controls| controls.bytes == 0 && controls.descriptors == 0);
        // Final physical closure does not request new work from an expired
        // issuance clock. The same retained epoch and actual kernel table
        // limits still corroborate the authentic containing owner.
        let closed = proven
            && controls_closed
            && self
                .window
                .as_mut()
                .is_some_and(|window| window.close_after_controls().is_ok());
        if !closed {
            // Preserve the same real payer on unknown process/alias lifetime.
            if let Some(descriptors) = self.descriptors.take() {
                std::mem::forget(descriptors);
            }
            if let Some(metadata) = self.metadata.take() {
                std::mem::forget(metadata);
            }
            std::mem::forget(Arc::clone(&self.issuer));
        }
    }
}

impl SourceHostControlLease {
    /// Compares the already debited metadata extent without issuing authority.
    pub(crate) fn covers_metadata(&self, bytes: usize) -> bool {
        u64::try_from(bytes).is_ok_and(|bytes| self.bytes >= bytes)
    }

    /// Checks that this actual borrower covers an original's required peak.
    ///
    /// # Errors
    /// Refuses an undersized recorded borrower before effects, another Main,
    /// uncertain physical custody or the actual entered original's refusal.
    pub fn verify_original_capacity(
        &self,
        original: &HostOperationGuard,
        descriptors: u64,
        bytes: u64,
    ) -> Result<(), ServiceBirthError> {
        if self.descriptors < descriptors || self.bytes < bytes {
            return Err(ServiceBirthError::policy(
                "Source control borrower is undersized",
            ));
        }
        self.verify_original(original)
    }

    /// Checks a running original under this same authenticated containing Main.
    ///
    /// # Errors
    /// Refuses stale physical custody, another containing cap, or the actual
    /// original's cancellation/deadline before borrowing verifier storage.
    pub fn verify_original(&self, original: &HostOperationGuard) -> Result<(), ServiceBirthError> {
        self.purpose.check()?;
        if !original.shares_outer_cap(&self.purpose.held.issuer.supervisor) {
            return Err(ServiceBirthError::policy(
                "Source original belongs to another Main",
            ));
        }
        original
            .wait_slice()
            .map(|_| ())
            .map_err(ServiceBirthError::from)
    }

    /// Checks that this physical control belongs to the same actual supervisor.
    ///
    /// # Errors
    /// Refuses another Main or changed retained Source custody.
    pub fn verify_supervisor(
        &self,
        supervisor: &HostOperationSupervisor,
    ) -> Result<(), ServiceBirthError> {
        self.purpose.verify_supervisor(supervisor)
    }
}

impl Drop for SourceHostControlLease {
    fn drop(&mut self) {
        let closed = self.purpose.held.controls.lock().is_ok_and(|mut controls| {
            let Some(bytes) = controls.bytes.checked_sub(self.bytes) else {
                return false;
            };
            let Some(descriptors) = controls.descriptors.checked_sub(self.descriptors) else {
                return false;
            };
            controls.bytes = bytes;
            controls.descriptors = descriptors;
            true
        });
        if !closed {
            // Keep the same actual Main charge after uncertain control closure.
            std::mem::forget(self.purpose.clone());
        }
    }
}
