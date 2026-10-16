//! Carries one verified historical native owner into a genuine fresh adopter.
//!
//! The archive/source factory authenticates all historical objects before this
//! nonserializable ticket exists. Its old owner identities remain data; a fresh
//! process association and original runtime restoration context are required
//! separately before those bytes can become live state.

use std::rc::Rc;

use crate::node_contract::{NativeStateKey, OriginalLineageRestoration, RuntimeError};
use crate::node_state::VerifiedStateContent;
use crucible_node_contract::ContentRef;

use super::NativeOwnerState;
use super::complete_original_source::{CompleteOriginalRestorationSource, CompleteOriginalSource};

/// Retains one source-verified native owner for a single fresh restoration attempt.
///
/// This type has no public constructor, cloning or decoding implementation.
/// It provides historical source data and identity, never fresh native custody
/// or permission to install, activate, or replay the old process requests.
#[must_use = "retain the original native source ticket through target failure"]
pub struct CompleteOriginalNativeTicket {
    pub(super) source: Rc<CompleteOriginalSource>,
    pub(super) owner_index: usize,
}

impl CompleteOriginalNativeTicket {
    /// Borrows the complete historical owner row from the verified archive.
    ///
    /// # Errors
    /// Refuses foreign process/thread custody or an absent original owner slot.
    pub fn owner(&self) -> Result<&NativeOwnerState, RuntimeError> {
        self.source.authenticate_birth()?;
        self.source
            .archive()
            .owners()
            .get(self.owner_index)
            .ok_or(RuntimeError::ForeignAuthority)
    }

    /// Borrows the exact source-selected native state key.
    ///
    /// # Errors
    /// Refuses foreign custody or an absent original owner slot.
    pub fn key(&self) -> Result<&NativeStateKey, RuntimeError> {
        Ok(&self.owner()?.key)
    }

    /// Borrows the complete already verified object closure without copying it.
    ///
    /// # Errors
    /// Refuses foreign process/thread custody.
    pub fn content(&self) -> Result<&VerifiedStateContent, RuntimeError> {
        self.source.authenticate_birth()?;
        Ok(self.source.content())
    }

    /// Borrows the original captured Runtime7 reference.
    ///
    /// # Errors
    /// Refuses foreign process/thread custody.
    pub fn runtime_object(&self) -> Result<&ContentRef, RuntimeError> {
        self.source.authenticate_birth()?;
        Ok(self.source.runtime_object())
    }

    /// Authenticates the same original verified source allocation.
    ///
    /// Equal archived IDs and bytes from another source cannot pass this check.
    /// Fresh controller/process custody is authenticated by its owning adopter.
    ///
    /// # Errors
    /// Refuses foreign custody or another original source allocation.
    pub fn authenticate_source(
        &self,
        source: &CompleteOriginalRestorationSource,
    ) -> Result<(), RuntimeError> {
        self.source.authenticate_birth()?;
        source.inner.authenticate_birth()?;
        if !Rc::ptr_eq(&self.source, &source.inner) {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    /// Conjoins the same source with its independently issued target context.
    ///
    /// The owning native adopter must still bind its real fresh process and
    /// controller to this ticket. This check grants no installation permission.
    ///
    /// # Errors
    /// Refuses foreign custody, another original target/source, or an absent
    /// original owner slot.
    pub fn authenticate_context(
        &self,
        context: &OriginalLineageRestoration<'_>,
    ) -> Result<(), RuntimeError> {
        self.source.authenticate_birth()?;
        self.source
            .authenticate_target(context.original_runtime_authority())?;
        if context.source_record() != self.source.runtime_object() {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.owner()?;
        Ok(())
    }
}

impl CompleteOriginalNativeTicket {
    pub(crate) fn is_original_restoration_owner_data(&self, other: &Self) -> bool {
        self.owner_index == other.owner_index && Rc::ptr_eq(&self.source, &other.source)
    }

    /// Borrows the actual native-after demand retained by this archive's validator.
    ///
    /// This contains historical DATA only. It cannot reconstruct a native graph,
    /// sign a request or grant memory; the same installed whole-restoration
    /// window must conjoin all fresh and future owners before its first effect.
    ///
    /// # Errors
    /// Refuses another creator or an archive whose actual codec supplied no row.
    pub fn native_restoration_construction_data(
        &self,
    ) -> Result<&super::CompleteOriginalNativeRestorationData, RuntimeError> {
        self.source.authenticate_birth()?;
        self.source
            .native_restoration_construction_data(self.owner_index)
    }

    /// Counts the actual archive while its genuine inactive runtime/ticket agree.
    ///
    /// This raw owning walk is valid during the inactive target phase, unlike the distinct
    /// prebirth observer. It authenticates private original identities only and
    /// performs no currentness callbacks, serializer, hash, formatting or I/O.
    /// The enclosing ticket root and fixed observer scratch remain separate.
    ///
    /// # Errors
    /// Refuses foreign origin/source/runtime/proposal/plan, unavailable actual backing,
    /// overflow or complete archive requested storage above the bound.
    pub fn retained_original_restoration_source_precredit_data(
        &self,
        archive: &CompleteOriginalRestorationSource,
        runtime: &crate::node_contract::ConformanceRuntime,
        plan: &crate::node_admission::InstalledConformancePlan,
        activation: &crate::node_contract::ActivationRecord,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        self.authenticate_source(archive)?;
        runtime.authenticate_original_restoration_target_data(archive, plan, activation)?;
        let bytes = self.source.capture_owned_storage()?;
        if bytes > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(bytes)
    }
}
