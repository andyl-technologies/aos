//! Canonical archive source reads through the same selected owning request.
//!
//! Only a sender's explicit operation retains a paid last-pack manifest. Every
//! request still executes Graph admission, physical supervision and fresh path
//! checks. Terminal closure retires that metadata before its acceptance cut.

use super::*;

impl BoundedReadRequest<'_, '_> {
    /// Executes one source turn through a freshly checked Packed lookup.
    ///
    /// # Errors
    /// Returns request reuse, Graph, physical, original, integrity or quota refusal.
    pub(super) fn execute_packed_canonical(
        &mut self,
        backend: &crate::content_store::PackedBlobBackend,
    ) -> Result<(), StoreError> {
        match self.state.phase {
            ReadPhase::Ready => {}
            ReadPhase::Failed => return Err(self.first_failure()),
            _ => {
                return Err(StoreError::Unsupported {
                    capability: "bounded-read-request-already-used",
                });
            }
        }
        if let Some(first) = self.work.account.read_failure() {
            self.state.phase = ReadPhase::Failed;
            return Err(first);
        }
        let ReadTask::Canonical { id, expected, .. } = self.task else {
            return Err(StoreError::Unsupported {
                capability: "not-canonical-source-read",
            });
        };
        self.state.phase = ReadPhase::Active;
        let physical = self.physical;
        let admission = self.inventory_admission;
        let mut session = self.work.canonical_session.take();
        let result = (|| {
            let prepared = super::super::codec::prepare_envelope_read(id, self.work)?;
            if session.is_none() {
                session = Some(self.work.checked(|original, boundary| {
                    if let Some(admit) = admission {
                        admit(id)?;
                    }
                    crate::content_store::checked_reader::check(original, boundary)?;
                    verify_physical(original, physical)?;
                    crate::content_store::PackedCanonicalSession::new(backend, original)
                })?);
            }
            let retained = session
                .as_mut()
                .ok_or(RamStoreError::Invalid("missing canonical source session"))?;
            let mut source =
                |original: &crate::owned_decode::DecodeBudget,
                 selected,
                 boundary: &mut dyn FnMut() -> Result<(), StoreError>| {
                    if let Some(admit) = admission {
                        admit(selected)?;
                    }
                    retained.lookup(
                        backend,
                        original,
                        selected,
                        selected_physical(physical),
                        boundary,
                    )
                };
            let mut verify = |original: &crate::owned_decode::DecodeBudget| {
                if let Some(admit) = admission {
                    admit(id)?;
                }
                verify_physical(original, physical)
            };
            match super::super::codec::read_prepared_envelope_using(
                prepared,
                self.work,
                true,
                &mut source,
                &mut verify,
            ) {
                Ok(envelope) => {
                    if let Some(expected) = expected {
                        validate_tree(&envelope, expected)?;
                    }
                    Ok(ReadValue::Canonical(Some(envelope.canonical_bytes())))
                }
                Err(error) if super::super::store_boundary::confirmed_absence(&error, id) => {
                    Ok(ReadValue::Canonical(None))
                }
                Err(error) => Err(error),
            }
        })();
        match result {
            Ok(value) => {
                self.work.canonical_session = session;
                self.state.pending.set(Some(Ok(value)));
                self.state.phase = ReadPhase::Completed;
                Ok(())
            }
            Err(error) => {
                // Keep the original failure before releasing its paid metadata.
                let error = self.work.account.fail_read(error);
                drop(session);
                self.state.phase = ReadPhase::Failed;
                Err(error)
            }
        }
    }

    /// Retires source metadata before the same original and physical cut.
    ///
    /// # Errors
    /// Returns request reuse or final Graph, physical and original refusal.
    pub(super) fn execute_close_canonical(&mut self) -> Result<(), StoreError> {
        match self.state.phase {
            ReadPhase::Ready => {}
            ReadPhase::Failed => return Err(self.first_failure()),
            _ => {
                return Err(StoreError::Unsupported {
                    capability: "bounded-read-request-already-used",
                });
            }
        }
        if let Some(first) = self.work.account.read_failure() {
            self.state.phase = ReadPhase::Failed;
            return Err(first);
        }
        let ReadTask::CloseCanonical(root) = self.task else {
            return Err(StoreError::Unsupported {
                capability: "not-canonical-source-close",
            });
        };
        self.state.phase = ReadPhase::Active;
        drop(self.work.canonical_session.take());
        let physical = self.physical;
        let admission = self.inventory_admission;
        let result = self.work.checked(|original, boundary| {
            if let Some(admit) = admission {
                admit(root)?;
            }
            crate::content_store::checked_reader::check(original, boundary)?;
            verify_physical(original, physical)
        });
        match result {
            Ok(()) => {
                self.state.pending.set(Some(Ok(ReadValue::CanonicalClosed)));
                self.state.phase = ReadPhase::Completed;
                Ok(())
            }
            Err(error) => {
                self.state.phase = ReadPhase::Failed;
                Err(self.work.account.fail_read(error))
            }
        }
    }
}

/// Closes the source session through its selected backend facade.
///
/// # Errors
/// Returns the retained original failure or terminal provider/authority refusal.
pub(in crate::ram) fn close(
    store: &super::super::RamStore,
    root: crate::content_store::ContentId,
    work: &mut Work<'_>,
) -> Result<(), RamStoreError> {
    let mut state = ReadState {
        phase: ReadPhase::Ready,
        pending: Cell::new(None),
    };
    let mut request = BoundedReadRequest {
        work,
        task: ReadTask::CloseCanonical(root),
        state: &mut state,
        physical: None,
        inventory_admission: None,
    };
    let provider = store.backend.read_bounded_with_boundary(&mut request);
    match request.finish(provider).map_err(RamStoreError::from)? {
        ReadValue::CanonicalClosed => Ok(()),
        _ => unreachable!("canonical source closure keeps its own terminal result"),
    }
}
