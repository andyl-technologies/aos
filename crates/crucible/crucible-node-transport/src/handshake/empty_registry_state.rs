//! Counts original empty-registry custody through selection and revocation.
//!
//! These observations describe the actual SDK owners without requiring a live
//! registration. They cannot authorize registration, effects or restoration.

use super::{ConnectionAuthority, ExtensionHandshake, OriginalEmptyExtensionRegistry};
use crate::ProviderError;
use crate::retained_metadata::{MetadataObserver, RetainedProtocolMetadataFacts};
use std::{rc::Rc, sync::Arc};

impl ExtensionHandshake {
    /// Counts the original wrapper and an optional retained connection lease.
    ///
    /// The enclosing process owner must authenticate its creator and include
    /// every retained lease in its complete census. This method covers exactly
    /// this wrapper and the supplied lease; inline headers belong to that owner.
    /// A selected wrapper remains countable after containment or supersession.
    /// The original unselected-only census keeps its stricter phase contract.
    ///
    /// Shared allocations are counted once only after exact Rc/Arc identity
    /// checks. A retired lease's different empty selection is counted separately;
    /// matching contents cannot establish an alias. No currentness, serializer
    /// or verifier callback is used.
    ///
    /// # Errors
    /// Refuses a different concrete registry, owning or nonempty registry,
    /// historical registry-owner variant, nonempty selection, foreign lease
    /// registrar backing, missing lease selection or checked metadata overflow.
    pub(crate) fn original_empty_state_metadata_facts_data<
        R: OriginalEmptyExtensionRegistry + 'static,
    >(
        &self,
        registry: &Rc<R>,
        authority: Option<&ConnectionAuthority>,
    ) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        let Self {
            handshake,
            installed,
            selected,
            original_registry,
        } = self;
        if std::mem::size_of::<R>() != 0
            || !std::ptr::addr_eq(Rc::as_ptr(installed), Rc::as_ptr(registry))
            || original_registry.is_some()
            || !registry.supported().is_empty()
            || !registry.required().is_empty()
            || selected.as_ref().is_some_and(|value| !value.is_empty())
        {
            return Err(super::registry_refused());
        }
        let lease_selection = match authority {
            Some(authority) => {
                if selected.is_none() {
                    return Err(ProviderError::Correlation(
                        "retained wrapper selection absent",
                    ));
                }
                let actual = authority
                    .extensions
                    .as_ref()
                    .ok_or(ProviderError::Correlation(
                        "retained authority selection absent",
                    ))?;
                if !actual.is_empty() {
                    return Err(super::registry_refused());
                }
                Some(actual)
            }
            None => None,
        };

        let mut observer = MetadataObserver::new();
        match authority {
            Some(authority) => {
                handshake.observe_retained_authority_pair_data(authority, &mut observer)?;
            }
            None => handshake.observe_retained_metadata_data(&mut observer)?,
        }

        observer.shared_value(registry.as_ref())?;
        if let Some(selected) = selected {
            observer.shared_value(selected.as_ref())?;
        }
        if let Some(actual) = lease_selection
            && selected
                .as_ref()
                .is_none_or(|original| !Arc::ptr_eq(original, actual))
        {
            // Resumption installs a new Arc even for an empty roster. A retained
            // older lease still owns its former allocation after revocation.
            observer.shared_value(actual.as_ref())?;
        }
        Ok(observer.finish())
    }
}
