//! Installs a pinned, unqualified complete scene on its original owning actor.
//!
//! The local operator supplies the independently authenticated manifest identity.
//! Its closed source records are interpreted by the existing complete-source,
//! Host, measured graph and collecting-plan constructors. No decoded manifest
//! supplies Accepted qualification, native readiness or an activation permit.
//! Only the complete producer/relay/sink profile is installed here, with
//! OwnedProtocol11, original Observe12, canonical SDK Blob acknowledgements and
//! the existing post-poll confirmation. Other backends and profiles are refused.
//! The manifest is startup-fixed operator policy; current source-file and owner
//! revision fences continue independently after its bytes have been consumed.
//!
//! ```text
//! {schema:"crucible.complete-scene.installation/1", measurements:[...;3],
//!  participants:[...;3], host:{...}, world:{...}, requirements:{...},
//!  coordinator:{...}, content:[{reference:ContentRef,bytes:Bytes},...],
//!  resources:ResourceLimits, maximum_initial_bytes:integer,
//!  maximum_native_rows:integer, maximum_operations:integer,
//!  maximum_retained_outputs:integer, write_watchdog_ms:integer}
//! ```

mod manifest;
mod source;
pub use source::{InstalledCompleteRestoration, PreparedCompleteRestoration};

use std::{cell::RefCell, path::PathBuf, rc::Rc, task::Poll};

use crucible_node_contract::ContentRef;

use super::{PacketCompleteOriginalSceneInputs, PacketCompleteReportStartupHolder};
use crate::node_qualification::QualificationError;

/// Pins one local complete-scene manifest independently of any portable request.
///
/// This is trusted operator installation data. It grants only source inspection;
/// each subsequent native or lifecycle action retains its own installed gate.
#[derive(Clone)]
pub struct InstalledCompleteSceneManifest {
    path: PathBuf,
    expected: ContentRef,
}

impl InstalledCompleteSceneManifest {
    /// Retains an absolute manifest path and its independently authenticated bytes.
    ///
    /// # Errors
    /// Refuses an invalid reference, nonabsolute path or oversized manifest.
    pub fn new(path: PathBuf, expected: ContentRef) -> Result<Self, QualificationError> {
        manifest::validate_pin(&path, &expected)?;
        Ok(Self { path, expected })
    }
}

/// Retains one installed collecting scene through preparation and reclamation.
///
/// The actor keeps this capsule on failure and unwind. It never returns a
/// controller, ordinary provider, Ready receipt or common activation permit.
/// Private namespace and effect socket names remain reserved after reclamation;
/// retirement proves resource containment, not directory release or replay rights.
#[must_use = "retain the same installed source and supervisor through reclamation"]
pub struct InstalledCompleteScene {
    original: Rc<RefCell<PacketCompleteReportStartupHolder>>,
    incoming: Option<PacketCompleteOriginalSceneInputs>,
    attempted: bool,
    retired: bool,
    reclaimed: bool,
    process: u32,
    thread: std::thread::ThreadId,
}

impl InstalledCompleteScene {
    /// Interprets the pinned package and reserves its original pre-Child inputs.
    ///
    /// The private directory must be newly created by this installation. No
    /// existing process or prior scene is adopted and no Child is constructed.
    ///
    /// # Errors
    /// Refuses changed files, unsupported complete-source declarations, duplicate
    /// content, mismatched full world, invalid resource limits or occupied paths.
    pub fn install(
        manifest: InstalledCompleteSceneManifest,
        directory: PathBuf,
    ) -> Result<Self, QualificationError> {
        let selected = manifest::load(&manifest)?;
        source::install(selected, directory)
    }

    /// Consumes the installed original scene's once-only initial lifecycle.
    ///
    /// # Errors
    /// Refuses a repeated/retired scene or any installed report, native, SDK or
    /// initial-lifecycle gate. A newly started failure retires the same originals;
    /// a refused repeat leaves their existing lifecycle unchanged. All partial
    /// owners remain in this same capsule.
    pub fn prepare(&mut self) -> Result<(), QualificationError> {
        self.authenticate_creator()?;
        if self.attempted || self.retired {
            return Err(refused());
        }
        self.attempted = true;
        let result = self.prepare_started();
        if result.is_err() {
            // Only this call spent the entry. Refused duplicates must not retire
            // originals retained by an earlier attempt.
            let _ = self.retire();
        }
        result
    }

    fn prepare_started(&mut self) -> Result<(), QualificationError> {
        // Use the same driver phases, with an explicit ownership boundary
        // after its into-slot stage and before its first startup action.
        PacketCompleteReportStartupHolder::stage_original_scene_into(
            &self.original,
            &mut self.incoming,
        )
        .map_err(|_| refused())?;
        self.authenticate_transferred_inputs()?;
        PacketCompleteReportStartupHolder::launch_and_complete_original_scene(&self.original)
            .map_err(|_| refused())?;
        // The earlier installation edition remains preparation-only. Only the
        // explicitly installed full mechanism enters the separate Core-priced
        // inactive constructor; this does not Arm or activate the runtime.
        if PacketCompleteReportStartupHolder::has_original_runtime_mechanism_data(&self.original)
            .map_err(|_| refused())?
        {
            PacketCompleteReportStartupHolder::prepare_original_scene_runtime(&self.original)
                .map_err(|_| refused())?;
        }
        Ok(())
    }

    /// Withdraws future actions and transfers originals to their same supervisor.
    ///
    /// # Errors
    /// Refuses a busy or foreign owner without releasing any retained custody.
    pub fn retire(&mut self) -> Result<(), QualificationError> {
        self.authenticate_creator()?;
        if self.reclaimed {
            return Ok(());
        }
        self.retired = true;
        // An unconsumed input capsule contains no guard or Child. Closing its
        // original input descriptors requires no native reclamation claim.
        if self.incoming.take().is_some() {
            self.reclaimed = true;
            return Ok(());
        }
        PacketCompleteReportStartupHolder::retire_original_scene(&self.original)
            .map_err(|_| refused())
    }

    pub(crate) fn is_reclaimed(&self) -> bool {
        self.reclaimed
    }

    fn authenticate_creator(&self) -> Result<(), QualificationError> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(refused());
        }
        self.original
            .try_borrow()
            .map_err(|_| refused())?
            .authenticate_installed_scene_creator_data()
    }

    fn authenticate_transferred_inputs(&self) -> Result<(), QualificationError> {
        // The only potentially nested external input bank is now inside the
        // counted holder. Exhaustiveness makes future owner fields reviewable.
        let Self {
            original: _,
            incoming,
            attempted: _,
            retired: _,
            reclaimed: _,
            process: _,
            thread: _,
        } = self;
        if incoming.is_some() {
            return Err(refused());
        }
        Ok(())
    }

    /// Drives one bounded pass on the original supervisor after retirement.
    ///
    /// # Errors
    /// Refuses cleanup faults or a foreign/busy owner; Pending retains custody.
    pub fn poll_reclamation(&mut self) -> Result<bool, QualificationError> {
        self.authenticate_creator()?;
        if self.reclaimed {
            return Ok(true);
        }
        if !self.retired {
            return Ok(false);
        }
        match PacketCompleteReportStartupHolder::drive_original_scene_reclamation(&self.original, 1)
            .map_err(|_| refused())?
        {
            Poll::Ready(Ok(_)) => {
                self.reclaimed = true;
                Ok(true)
            }
            Poll::Ready(Err(_)) => Err(refused()),
            Poll::Pending => Ok(false),
        }
    }
}

fn refused() -> QualificationError {
    QualificationError::Refused("installed complete collecting scene unavailable")
}

#[cfg(test)]
mod tests;
