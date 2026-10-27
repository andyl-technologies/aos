//! Checks the real pending Runtime original against the same installed Window.
//!
//! This node consumes the opaque synchronous Runtime loan without cloning it.
//! The check grants no recurring Observe or execution effect: complete future
//! per-action rows, SourceRead and the native proof consumer remain mandatory.

use super::*;
use crate::node_contract::OriginalRuntimeOperationDispatch;

impl super::super::super::CnpSemanticNode {
    pub(in crate::node_adapters::cnp::semantic) fn authenticate_installed_suffix_dispatch_data(
        &self,
        dispatch: &OriginalRuntimeOperationDispatch<'_>,
    ) -> Result<(), RuntimeError> {
        let native = self
            .preparation
            .guard
            .custody
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let source = native
            .source
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let controller = native
            .controller
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let selected = native
            .runtime
            .as_ref()
            .and_then(|runtime| runtime.installed_restoration.as_ref())
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if !selected.installed
            || !selected
                .activation
                .as_ref()
                .is_some_and(|world| world.same_authority(dispatch.admission_data().activation()))
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        selected
            .association
            .authenticate_original_suffix_runtime_dispatch_data(
                source.as_ref(),
                controller,
                Rc::as_ptr(&native.read_owner).cast(),
                dispatch,
            )
    }
}

/// Names the actual simultaneous Node loans before the immutable dispatch check.
///
/// The enclosing custody sum materializes twenty-one independent fixed terms.
/// Neither this fixed-layout row nor its early caller grants an action effect.
pub(super) fn counter_scratch_data() -> usize {
    use crate::node_adapters::cnp::{CnpSemanticProcessCustody, CnpSemanticSource};
    use crucible_node_transport::client::CnpController;

    size_of::<Result<&Box<CnpSemanticProcessCustody>, RuntimeError>>()
        + size_of::<Result<&Rc<dyn CnpSemanticSource>, RuntimeError>>()
        + size_of::<Result<&CnpController, RuntimeError>>()
        + size_of::<Result<&InstalledRestorationCustody, RuntimeError>>()
        + size_of::<Option<&Box<CnpSemanticProcessCustody>>>()
        + size_of::<Option<&Rc<dyn CnpSemanticSource>>>()
        + size_of::<Option<&CnpController>>()
        + size_of::<Option<&InstalledRestorationCustody>>()
        + size_of::<(
            &Box<CnpSemanticProcessCustody>,
            &Rc<dyn CnpSemanticSource>,
            &CnpController,
            &InstalledRestorationCustody,
        )>()
        + size_of::<&super::super::super::CnpSemanticNode>()
        + size_of::<&OriginalRuntimeOperationDispatch<'static>>()
        + size_of::<[usize; 21]>()
}
