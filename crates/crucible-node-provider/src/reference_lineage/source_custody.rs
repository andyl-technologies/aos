//! Owns the distinct public provider and native-companion process groups.
//!
//! A host reserves the complete capsule before spawning the provider. Cached
//! original wire remains owned during installed read-only adoption callbacks.
//! This capsule grants neither source qualification nor modeled readiness.

use std::path::{Path, PathBuf};
use std::process::{Child, ExitStatus};

use crucible_node_contract::{ContentRef, Id, U64, Validate};
use rustix::process::{Signal, WaitId, WaitIdOptions, kill_process_group, waitid};

use crate::ProviderError;
use crate::bodies::ResponseBody;
use crate::client::{
    LineageWindowRequests, OriginalLineageRealization, OriginalLineageWindow, ReferenceController,
};
use crate::envelope::Method;
use crate::handshake::Handshake;

#[path = "source_kernel.rs"]
mod kernel;

/// Reserves an owning host capsule for both groups before provider spawn.
///
/// The installed actor keeps this reservation across transport loss and shutdown.
/// Its consuming transfer prevents one reservation from accepting two capsules.
/// Implementations must service retained native reclamation on their owning
/// thread; a vector whose owner can disappear is not a supervisor.
pub trait LineageSourceCustodySlot {
    /// Returns the original finite host reservation identity.
    fn identity(&self) -> U64;

    /// Takes complete native handles and original controller custody once.
    fn retain(self: Box<Self>, custody: LineageSourceCustody);
}

/// Owns original provider and companion identities alongside their raw journals.
///
/// This holder cannot be serialized or constructed from a native relation DTO.
/// Its controller remains retained even after actual group reclamation.
pub struct LineageSourceCustody {
    child: Child,
    directory: PathBuf,
    provider: Option<kernel::Identity>,
    expected_provider: ContentRef,
    expected_native: ContentRef,
    controller: Option<ReferenceController>,
    handshake: Option<Handshake>,
    native: NativeCustody,
    provider_signalled: bool,
    reaped: Option<ExitStatus>,
    bootstrap: Option<Vec<u8>>,
    realization: Option<Id>,
}

enum NativeCustody {
    NotStarted,
    Unresolved,
    Original(kernel::Identity),
}

/// Preserves complete native custody when original attachment or control fails.
pub struct LineageSourceFailure {
    /// Reports the refusal without claiming absence of native effects.
    pub error: ProviderError,
    /// Retains the original process, journals and pre-spawn supervision slot.
    pub guard: LineageSourceGuard,
}

/// Keeps a complete two-group source capsule beneath a pre-spawn reservation.
pub struct LineageSourceGuard {
    custody: Option<Box<LineageSourceCustody>>,
    slot: Option<Box<dyn LineageSourceCustodySlot>>,
}

impl LineageSourceGuard {
    /// Takes an original private provider Child under its prior reservation.
    ///
    /// The launcher reserves `slot` before spawn and sets `process_group(0)`.
    /// It calls this function before private bootstrap or any process wait.
    /// Artifact references identify expected byte custody, not source authority.
    /// A failed identity check returns the complete owning guard.
    ///
    /// # Errors
    /// Returns retained custody on invalid references, missing original kernel
    /// identity, foreign provider group or changed measured executable.
    pub fn new(
        child: Child,
        directory: PathBuf,
        expected_provider: ContentRef,
        expected_native: ContentRef,
        slot: Box<dyn LineageSourceCustodySlot>,
    ) -> Result<Self, LineageSourceFailure> {
        let mut guard = Self {
            custody: Some(Box::new(LineageSourceCustody {
                child,
                directory,
                provider: None,
                expected_provider,
                expected_native,
                controller: None,
                handshake: None,
                native: NativeCustody::NotStarted,
                provider_signalled: false,
                reaped: None,
                bootstrap: None,
                realization: None,
            })),
            slot: Some(slot),
        };
        let result = (|| {
            let custody = guard.custody_mut()?;
            custody.expected_provider.validate()?;
            custody.expected_native.validate()?;
            let original = kernel::identity(custody.child.id())?;
            custody.provider = Some(original);
            kernel::verify_executable(original.pid, &custody.expected_provider)
        })();
        match result {
            Ok(()) => Ok(guard),
            Err(error) => Err(LineageSourceFailure { error, guard }),
        }
    }

    /// Attaches the exact authenticated public controller without releasing its registrar.
    ///
    /// Both handles enter the capsule before validation, so attachment failure
    /// retains their original journals and authority lifetime alongside Child.
    ///
    /// # Errors
    /// Returns complete owned failure on duplicate attachment, foreign peer,
    /// legacy profile or changed provider bytes/kernel identity.
    pub fn attach(
        mut self,
        controller: ReferenceController,
        handshake: Handshake,
    ) -> Result<Self, LineageSourceFailure> {
        let result = (|| {
            let custody = self.custody_mut()?;
            if custody.controller.is_some() || custody.handshake.is_some() {
                return Err(ProviderError::Correlation(
                    "lineage source already attached",
                ));
            }
            custody.controller = Some(controller);
            custody.handshake = Some(handshake);
            let controller = custody
                .controller
                .as_ref()
                .ok_or(ProviderError::Correlation(
                    "lineage source controller omitted",
                ))?;
            if controller.peer_pid() != custody.child.id()
                || controller.peer_executable() != &custody.expected_provider
                || !controller.profile.is_lineage()
            {
                return Err(ProviderError::Correlation(
                    "lineage source attached peer differs",
                ));
            }
            custody.verify_provider()
        })();
        match result {
            Ok(()) => Ok(self),
            Err(error) => Err(LineageSourceFailure { error, guard: self }),
        }
    }

    /// Writes and retains one complete original private launch document.
    ///
    /// The original bytes enter capsule custody before the first pipe write.
    /// Launch uncertainty cannot be classified as an absent native companion.
    ///
    /// # Errors
    /// Refuses duplicate, empty or over-16-MiB launch bytes, missing original
    /// stdin, changed provider identity or actual pipe errors.
    pub fn write_private_bootstrap(&mut self, bytes: Vec<u8>) -> Result<(), ProviderError> {
        use std::io::Write;

        let custody = self.custody_mut()?;
        custody.verify_provider()?;
        if custody.bootstrap.is_some() || bytes.is_empty() || bytes.len() > 16 * 1024 * 1024 {
            return Err(ProviderError::ResourceExhausted(
                "lineage source bootstrap custody",
            ));
        }
        let length = u32::try_from(bytes.len())
            .map_err(|_| ProviderError::ResourceExhausted("lineage source bootstrap extent"))?;
        custody.bootstrap = Some(bytes);
        custody.native = NativeCustody::Unresolved;
        let mut stdin = custody
            .child
            .stdin
            .take()
            .ok_or(ProviderError::Correlation(
                "lineage source private bootstrap pipe unavailable",
            ))?;
        let original = custody
            .bootstrap
            .as_deref()
            .ok_or(ProviderError::Correlation(
                "lineage source bootstrap omitted",
            ))?;
        stdin.write_all(&length.to_be_bytes())?;
        stdin.write_all(original)?;
        stdin.flush()?;
        Ok(())
    }

    /// Borrows a verified original body from the owning public byte registry.
    ///
    /// # Errors
    /// Refuses transferred custody or an absent/altered full typed reference.
    pub fn content(&self, reference: &ContentRef) -> Result<&[u8], ProviderError> {
        self.custody
            .as_ref()
            .and_then(|custody| custody.controller.as_ref())
            .ok_or(ProviderError::Correlation(
                "lineage source controller omitted",
            ))?
            .content(reference)
    }

    /// Sends one original public request while retaining unresolved native custody.
    ///
    /// Realize marks native custody unresolved before socket I/O. Only the actual
    /// cached realization and current direct-child kernel identity can pin the
    /// second group. Later controls require that original native identity.
    ///
    /// # Errors
    /// Refuses transferred custody, foreign kernel scope, effects before native
    /// realization or SDK/transport/evidence failures. An uncertain Realize keeps
    /// the complete capsule unresolved; it cannot be reclaimed as never spawned.
    pub fn call(
        &mut self,
        request_id: Id,
        operation_id: Option<Id>,
        method: Method,
        owned: bool,
        body: impl serde::Serialize,
    ) -> Result<ResponseBody, ProviderError> {
        let custody = self.custody_mut()?;
        custody.verify_provider()?;
        if method == Method::Realize {
            if custody
                .realization
                .as_ref()
                .is_some_and(|original| original != &request_id)
            {
                return Err(ProviderError::Correlation(
                    "lineage source realization identity changed",
                ));
            }
            custody.realization = Some(request_id.clone());
            if !matches!(custody.native, NativeCustody::Original(_)) {
                custody.native = NativeCustody::Unresolved;
            }
        } else if matches!(
            method,
            Method::Input | Method::Begin | Method::QuantumClose | Method::Retire
        ) {
            let NativeCustody::Original(native) = custody.native else {
                return Err(ProviderError::Correlation(
                    "lineage source native scope not pinned",
                ));
            };
            kernel::verify_identity(native)?;
        }
        let result =
            custody
                .controller_mut()?
                .call(request_id.clone(), operation_id, method, owned, body);
        if method == Method::Realize && result.is_ok() {
            custody.pin_native(&request_id)?;
        }
        result
    }

    /// Retains and transfers exact typed body bytes through the owning controller.
    ///
    /// # Errors
    /// Refuses transferred/foreign custody or an original SDK content failure.
    pub fn upload(&mut self, reference: &ContentRef, bytes: &[u8]) -> Result<(), ProviderError> {
        let custody = self.custody_mut()?;
        custody.verify_provider()?;
        custody.controller_mut()?.upload(reference, bytes)
    }

    /// Returns the retained original provider PID without asserting current readiness.
    pub fn provider_pid(&self) -> Option<u32> {
        self.custody.as_ref().map(|custody| custody.child.id())
    }

    /// Borrows original initialized readiness inside the installed read-only adopter.
    ///
    /// Both original private groups and the exact source-owned Ready wire remain
    /// outside the callback's unwind boundary. This does not grant source class.
    ///
    /// # Errors
    /// Refuses changed live original identities, unknown realization, altered
    /// original Ready scope or the installed callback's refusal.
    pub fn with_original_realization<T>(
        &self,
        request: &Id,
        adopt: impl FnOnce(OriginalLineageRealization<'_>) -> Result<T, ProviderError>,
    ) -> Result<T, ProviderError> {
        let custody = self.custody.as_ref().ok_or(ProviderError::Correlation(
            "lineage source custody transferred",
        ))?;
        custody.verify_provider()?;
        let NativeCustody::Original(native) = custody.native else {
            return Err(ProviderError::Correlation(
                "lineage source native scope not pinned",
            ));
        };
        kernel::verify_identity(native)?;
        let controller = custody
            .controller
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "lineage source controller omitted",
            ))?;
        let original = controller.original_lineage_realization(request)?;
        if custody.realization.as_ref() != Some(request)
            || original.native_pid().get() != u64::from(native.pid)
            || original.native_start_ticks().get() != native.start_ticks
            || original.native_executable() != &custody.expected_native
        {
            return Err(ProviderError::Correlation(
                "lineage source realization origin differs",
            ));
        }
        adopt(original)
    }

    /// Borrows an original closed window only inside the installed adopter callback.
    ///
    /// The controller, registrar, Child and both original kernel identities stay
    /// owned outside the callback, including during unwind. The callback receives
    /// no mutable controller or portable authority constructor. Its return value
    /// obtains authority only from the separately installed host policy.
    ///
    /// # Errors
    /// Refuses unpinned or changed kernel scope and incomplete original SDK
    /// windows, or propagates the installed callback's refusal unchanged.
    pub fn with_original_window<T>(
        &self,
        requests: LineageWindowRequests<'_>,
        adopt: impl FnOnce(OriginalLineageWindow<'_>) -> Result<T, ProviderError>,
    ) -> Result<T, ProviderError> {
        let custody = self.custody.as_ref().ok_or(ProviderError::Correlation(
            "lineage source custody transferred",
        ))?;
        custody.verify_provider()?;
        let NativeCustody::Original(native) = custody.native else {
            return Err(ProviderError::Correlation(
                "lineage source native scope not pinned",
            ));
        };
        kernel::verify_identity(native)?;
        let controller = custody
            .controller
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "lineage source controller omitted",
            ))?;
        let window = controller.original_lineage_window(requests)?;
        if window.native_pid().get() != u64::from(native.pid)
            || window.native_start_ticks().get() != native.start_ticks
            || window.native_executable() != &custody.expected_native
        {
            return Err(ProviderError::Correlation(
                "lineage source window origin differs",
            ));
        }
        adopt(window)
    }

    /// Returns the original reserved capsule identity without servicing native work.
    pub fn supervision_id(&self) -> Option<U64> {
        self.slot.as_ref().map(|slot| slot.identity())
    }

    /// Services original operational reclamation without replacing native custody.
    ///
    /// A live companion must first be reaped by its owning source. Refusal leaves
    /// the original controller and both groups retained. Once that group is
    /// empty, this call can contain and reap the original provider; subsequent
    /// modeled controls then refuse. Reclamation does not discharge output or
    /// evidence obligations beneath the host reservation.
    ///
    /// # Errors
    /// Retains custody on unresolved native preparation, a nonempty native
    /// group, changed original kernel identity or operational probe failure.
    pub fn poll_reclamation(&mut self) -> Result<bool, ProviderError> {
        self.custody_mut()?.poll_reclamation()
    }

    fn custody_mut(&mut self) -> Result<&mut LineageSourceCustody, ProviderError> {
        self.custody
            .as_deref_mut()
            .ok_or(ProviderError::Correlation(
                "lineage source custody transferred",
            ))
    }
}

impl Drop for LineageSourceGuard {
    fn drop(&mut self) {
        if let (Some(slot), Some(custody)) = (self.slot.take(), self.custody.take()) {
            slot.retain(*custody);
        }
    }
}

impl LineageSourceCustody {
    /// Returns the original provider PID even after Child reaping.
    pub fn provider_pid(&self) -> u32 {
        self.child.id()
    }

    /// Returns the exact independently retained native group identity when known.
    pub fn native_pid(&self) -> Option<u32> {
        match self.native {
            NativeCustody::Original(native) => Some(native.pid),
            _ => None,
        }
    }

    /// Returns the original private directory whose closure remains owned.
    pub fn private_directory(&self) -> &Path {
        &self.directory
    }

    /// Reports a pinned original scope or uncertainty, without model authority.
    pub fn native_scope_resolved(&self) -> bool {
        !matches!(self.native, NativeCustody::Unresolved)
    }

    /// Contains the provider after original native-parent reclamation.
    ///
    /// The provider remains an unreaped original kernel anchor while its source
    /// collects the native Child. This host has no wait authority over that child
    /// and does not signal its numeric group through a concurrent source reaper.
    /// Only a complete empty native group census permits the provider group to
    /// be signalled. Success requires actual provider Child wait
    /// and complete empty censuses for both groups, including zombie members.
    /// No post-wait signal ever targets a reused numeric PID.
    ///
    /// # Errors
    /// Retains all journals and handles on unresolved Realize, changed original
    /// kernel identity, a native group not yet reclaimed by its original parent,
    /// provider signal/wait error or malformed/exhausted census.
    pub fn poll_reclamation(&mut self) -> Result<bool, ProviderError> {
        let provider = self.provider.ok_or(ProviderError::Correlation(
            "lineage source original provider scope unavailable",
        ))?;
        let native = match self.native {
            NativeCustody::Unresolved => {
                return Err(ProviderError::Correlation(
                    "lineage source native preparation unresolved",
                ));
            }
            NativeCustody::NotStarted => None,
            NativeCustody::Original(native) => Some(native),
        };
        if let Some(native) = native
            && !kernel::group_empty(native.pid)?
        {
            return Err(ProviderError::Correlation(
                "lineage source requires original native-parent reclamation",
            ));
        }
        // Preserve the provider's original native-parent lifetime until the
        // companion group is genuinely empty. Closing control earlier could
        // remove the only actor able to wait its own native Child.
        if let Some(controller) = &mut self.controller {
            controller.fence();
        }
        if let Some(handshake) = &mut self.handshake {
            handshake.contain();
        }
        if !self.provider_signalled && self.reaped.is_none() {
            // NOWAIT protects the original PID even when the leader has exited.
            waitid(
                WaitId::Pid(kernel::pid(provider.pid)?),
                WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
            )
            .map_err(std::io::Error::from)?;
            kernel::verify_identity(provider)?;
            kill_process_group(kernel::pid(provider.pid)?, Signal::KILL)
                .map_err(std::io::Error::from)?;
            self.provider_signalled = true;
        }
        if self.reaped.is_none() {
            self.reaped = self.child.try_wait()?;
        }
        Ok(self.reaped.is_some()
            && kernel::group_empty(provider.pid)?
            && match native {
                Some(native) => kernel::group_empty(native.pid)?,
                None => true,
            })
    }

    fn verify_provider(&self) -> Result<(), ProviderError> {
        let original = self.provider.ok_or(ProviderError::Correlation(
            "lineage source original provider scope unavailable",
        ))?;
        if self.reaped.is_some() || self.provider_signalled {
            return Err(ProviderError::Correlation(
                "lineage source provider contained",
            ));
        }
        kernel::verify_identity(original)
    }

    fn pin_native(&mut self, request: &Id) -> Result<(), ProviderError> {
        let controller = self.controller.as_ref().ok_or(ProviderError::Correlation(
            "lineage source controller omitted",
        ))?;
        let view = controller.original_lineage_realization(request)?;
        let pid = u32::try_from(view.native_pid().get())
            .map_err(|_| ProviderError::Correlation("lineage source native PID extent"))?;
        let native = kernel::identity(pid)?;
        if native.parent != self.child.id()
            || native.start_ticks != view.native_start_ticks().get()
            || view.native_executable() != &self.expected_native
            || pid == self.child.id()
        {
            return Err(ProviderError::Correlation(
                "lineage source original native scope differs",
            ));
        }
        kernel::verify_executable(pid, &self.expected_native)?;
        self.native = NativeCustody::Original(native);
        Ok(())
    }

    fn controller_mut(&mut self) -> Result<&mut ReferenceController, ProviderError> {
        self.controller.as_mut().ok_or(ProviderError::Correlation(
            "lineage source controller omitted",
        ))
    }
}
