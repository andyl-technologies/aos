//! Retains fixed normal055 root and named-file posts on the original writer.
//!
//! These are inert native destinations. The genuine normal caller prepays
//! their passive demand before a body can owe them; observation uses the same
//! directory/name engines after poison and never restores writer health.

use std::error::Error;
use std::fmt;
use std::path::Path;
use std::sync::Arc;

use aos_sandbox_core::{ResourceDimension as D, ResourceVector};

use super::{Journal, JournalError, ProtectedJournalCurrentnessOriginalsV1};
use crate::runtime_deployment::{MAIN_DIRECTORY_V1, MAIN_NAME, SIDECAR_NAME};

/// Retains a single fixed main or floor root/name observation and native causes.
#[must_use = "prepay and retain this actual original through its owed post"]
pub struct RuntimeDeploymentJournalPostOriginalV1 {
    name: &'static str,
    directory: ProtectedJournalCurrentnessOriginalsV1,
    names: ProtectedJournalCurrentnessOriginalsV1,
    directory_result: Option<Result<(), JournalError>>,
    names_result: Option<Result<(), JournalError>>,
    entered: [bool; 2],
    first: Option<usize>,
    interrupted: bool,
}

impl RuntimeDeploymentJournalPostOriginalV1 {
    /// Creates inert fixed-main destinations, without IO or payment permission.
    #[must_use]
    pub fn main_v1() -> Self {
        Self::new(MAIN_NAME)
    }

    /// Creates inert fixed-floor destinations, without IO or payment permission.
    #[must_use]
    pub fn floor_v1() -> Self {
        Self::new(SIDECAR_NAME)
    }

    fn new(name: &'static str) -> Self {
        Self {
            name,
            directory: ProtectedJournalCurrentnessOriginalsV1::new(),
            names: ProtectedJournalCurrentnessOriginalsV1::new(),
            directory_result: None,
            names_result: None,
            entered: [false; 2],
            first: None,
            interrupted: false,
        }
    }

    /// Quotes the actual fixed root/name recipe and compiled retained carrier.
    ///
    /// This passive DATA supplies no payer, Native permission or healthy owner.
    ///
    /// # Errors
    /// Preserves checked lower native geometry or aggregate overflow.
    pub fn receiving_demand_v1(&self) -> Result<ResourceVector, JournalError> {
        let controls = std::mem::size_of::<Self>()
            .checked_mul(2)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        ProtectedJournalCurrentnessOriginalsV1::fixed_demand_v1(
            Path::new(MAIN_DIRECTORY_V1),
            self.name,
        )?
        .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, controls))
        .map_err(Into::into)
    }

    /// Observes the same held writer's root and names independently once.
    ///
    /// Entry latches also support a negative drain after an interrupted group;
    /// that group is never replayed, while the other group remains owed.
    /// This method neither debits Source nor consults healthy writer admission.
    ///
    /// # Errors
    /// Retains native/path/name refusal or an interrupted entry. A different
    /// fixed writer is refused before any native observation.
    pub fn observe_owed_once_v1(&mut self, journal: &Journal) -> Result<(), JournalError> {
        let location = journal
            .native
            .protected_view()
            .ok_or(JournalError::ProtectedBoundary)?;
        if location.name() != self.name
            || location.expected_uid() != 0
            || journal.native.path().parent() != Some(Path::new(MAIN_DIRECTORY_V1))
            || journal.native.path().file_name() != Some(std::ffi::OsStr::new(self.name))
        {
            return Err(JournalError::ProtectedBoundary);
        }

        if !self.entered[0] {
            self.entered[0] = true;
            self.directory_result = Some((|| {
                self.directory.begin(false)?;
                let result = journal.native.read_view().observe_directory_binding_into(
                    Path::new(MAIN_DIRECTORY_V1),
                    0,
                    &mut self.directory,
                );
                self.directory.finish(result)
            })());
            if !matches!(self.directory_result, Some(Ok(()))) {
                self.first.get_or_insert(0);
            }
        } else if self.directory_result.is_none() {
            self.interrupted = true;
        }
        if !self.entered[1] {
            self.entered[1] = true;
            self.names_result = Some(journal.observe_held_names_post_retaining_v1(&mut self.names));
            if !matches!(self.names_result, Some(Ok(()))) {
                self.first.get_or_insert(1);
            }
        } else if self.names_result.is_none() {
            self.interrupted = true;
        }
        if self.first.is_some() || self.interrupted {
            Err(JournalError::ProtectedBoundary)
        } else {
            Ok(())
        }
    }

    /// Borrows the original earliest native/path/name refusal without IO.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            0 => self
                .directory
                .failure()
                .or_else(|| error(&self.directory_result)),
            _ => self.names.failure().or_else(|| error(&self.names_result)),
        }
    }

    /// Moves this whole failed original into the typed Journal diagnostic.
    #[must_use]
    pub fn into_failure_v1(self: Box<Self>) -> JournalError {
        JournalError::BootJournalPostOriginal(self.into_failure_original_v1())
    }

    /// Shares only the actual whole failed original for permanent diagnostics.
    #[must_use]
    pub fn into_failure_original_v1(self: Box<Self>) -> RuntimeDeploymentJournalPostFailureV1 {
        RuntimeDeploymentJournalPostFailureV1 {
            original: Arc::from(self),
        }
    }
}

/// Retains the whole original fixed-root/name failure beside its diagnostic.
#[derive(Clone)]
pub struct RuntimeDeploymentJournalPostFailureV1 {
    original: Arc<RuntimeDeploymentJournalPostOriginalV1>,
}

impl fmt::Debug for RuntimeDeploymentJournalPostFailureV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeDeploymentJournalPostFailureV1")
            .finish_non_exhaustive()
    }
}

impl fmt::Display for RuntimeDeploymentJournalPostFailureV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("original deployment root/name post failed or was interrupted")
    }
}

impl Error for RuntimeDeploymentJournalPostFailureV1 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original.failure()
    }
}

fn error(value: &Option<Result<(), JournalError>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}
