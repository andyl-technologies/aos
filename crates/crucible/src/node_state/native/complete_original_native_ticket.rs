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
