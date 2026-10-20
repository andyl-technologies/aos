//! Owns an authenticated complete small-object lineage closure across source deletion.
//!
//! Ownership is transferred from the already verified typed closure. The private
//! constructor authenticates every role against the signed archive first. Later
//! views share those immutable original bytes and never reread a vanished source
//! namespace. This pins historical evidence only, without native or Ready grants.

use super::*;

/// Retains complete original typed bodies independently of source archive paths.
///
/// No public DTO constructor exists. The archive metadata is retained solely for
/// exact historical identity; all small-object reads use the owned authenticated
/// closure. Native artifact preservation is unsupported by this model-only pin.
pub struct PinnedOriginalLineageSource {
    archive: Rc<NativeArchiveRecord>,
    owner: NativeOwnerState,
    runtime_reference: ContentRef,
    runtime: Rc<OriginalLineageRuntimeRecord>,
    scheduling: Rc<SchedulingSnapshot>,
    repeatability: Repeatability,
    content: Rc<VerifiedStateContent>,
}

impl PinnedOriginalLineageSource {
    /// Borrows a source seal backed by the same immutable owned original bodies.
    ///
    /// This is historical evidence, not independently qualified native authority.
    /// Creating the view does not clone large body or journal inventories.
    pub fn source(&self) -> AuthenticatedOriginalLineageSource<'_> {
        AuthenticatedOriginalLineageSource {
            archive: &self.archive,
            owner: &self.owner,
            runtime_reference: self.runtime_reference.clone(),
            runtime: Rc::clone(&self.runtime),
            scheduling: Rc::clone(&self.scheduling),
            repeatability: self.repeatability,
            content: &self.content,
        }
    }

    /// Borrows this owner's exact original native model state reference.
    pub fn native_state_reference(&self) -> &ContentRef {
        &self.owner.state
    }

    /// Borrows complete original source-capture runtime without recreating tokens.
    pub fn runtime(&self) -> &OriginalLineageRuntimeRecord {
        &self.runtime
    }

    /// Borrows the exact original Runtime7 role in the signed typed inventory.
    pub fn runtime_reference(&self) -> &ContentRef {
        &self.runtime_reference
    }

    /// Borrows complete original scheduling/transfer custody without reexecution.
    pub fn scheduling(&self) -> &SchedulingSnapshot {
        &self.scheduling
    }

    /// Borrows every original verified typed body independently of source paths.
    pub fn content(&self) -> &VerifiedStateContent {
        &self.content
    }

    /// Borrows the original authenticated archive identity without opening its path.
    pub fn source_artifact(&self) -> &ContentRef {
        self.archive.artifact()
    }

    /// Borrows an original role only by its exact complete typed reference.
    pub fn original_body(&self, reference: &ContentRef) -> Option<&[u8]> {
        self.content.get(reference)
    }

    /// Borrows every complete typed reference and its authenticated original bytes.
    ///
    /// Distinct typed aliases retain their full identities even when they share
    /// physical bytes. Iteration neither allocates nor opens source paths, and
    /// grants no execution, restoration or native authority.
    pub fn original_objects(&self) -> impl Iterator<Item = (&ContentRef, &[u8])> {
        self.content.entries()
    }
}

/// Retains the complete supplied original body closure when pinning refuses.
///
/// A refused transfer never discards original proof/body custody. The caller can
/// keep it beside the owning source world or recover both parts for retirement.
pub struct OriginalLineageSourcePinFailure {
    error: StateError,
    content: VerifiedStateContent,
}

impl OriginalLineageSourcePinFailure {
    /// Borrows the authentic source validation or finite-credit refusal.
    pub fn error(&self) -> &StateError {
        &self.error
    }

    /// Returns the refusal together with complete original body ownership.
    pub fn into_parts(self) -> (StateError, VerifiedStateContent) {
        (self.error, self.content)
    }
}

impl NativeArchiveRecord {
    /// Transfers one complete authenticated body closure into all original owner pins.
    ///
    /// Immutable body and archive metadata custody are shared. Every owner is
    /// independently authenticated before transfer; no body is deep-cloned for
    /// another peer. Physical artifacts remain unsupported and failures return
    /// the entire original supplied closure.
    ///
    /// # Errors
    /// Returns complete original content on finite metadata/body excess, missing
    /// owner/source scope, installed codec refusal or unavailable reservation.
    pub fn pin_original_lineage_world(
        &self,
        content: VerifiedStateContent,
        limits: OriginalInputLineageLimits,
        graph: &crate::node_admission::AdmittedGraph,
        factory: &dyn super::NativeWorldFactory,
    ) -> Result<Vec<PinnedOriginalLineageSource>, OriginalLineageSourcePinFailure> {
        let checked = (|| -> Result<_, StateError> {
            // Installed code is immutable graph content, not an input lineage
            // body or physical native artifact. Its declared archive credit is
            // independent of the smaller original-input closure allowance.
            pin_archive_credit(&content, self.limits.state)?;
            super::super::super::closure::bounded_record(
                &self.index,
                self.limits
                    .state
                    .maximum_record_bytes
                    .min(limits.maximum_bytes / 2),
            )?;
            if self.index.schema_version != 2
                || self.owners().is_empty()
                || self
                    .owners()
                    .iter()
                    .any(|owner| !owner.artifacts.is_empty())
                || self.owners().len() != graph.ownership_policy().capture_owners.len()
            {
                return Err(refused(
                    "complete Tape2 pin has unsupported owner/artifact inventory",
                ));
            }
            let mut sources = Vec::new();
            sources
                .try_reserve_exact(self.owners().len())
                .map_err(|_| refused("complete Tape2 owner reservation failed"))?;
            super::super::extensions::archive::authenticate_archive(self, graph, factory)?;
            super::super::super::validation::validate_manifest(
                graph,
                &self.manifest,
                &crate::node_state::StateRequirements {
                    preservation_contract: Id::new(
                        crate::node_adapters::transcript::TRANSCRIPT_ORIGINAL_LINEAGE_CONTINUATION_PROFILE,
                    )
                    .map_err(super::super::super::schema)?,
                    exact_model_continuation: true,
                    deterministic: false,
                    restore_mode: crate::node_state::StateRestoreMode::DurableRestart,
                },
                self.limits.state,
            )?;
            self.validate_lineage_owner_receipts(graph, &content)?;
            if graph.world_binding_hash() != &self.manifest.world_binding_hash {
                return Err(refused("complete Tape2 pin world differs"));
            }
            let first_owner = self
                .owners()
                .first()
                .ok_or_else(|| refused("complete Tape2 source owner absent"))?;
            let first =
                self.decode_original_lineage_source(&first_owner.owner, &content, limits)?;
            for owner in self.owners() {
                if owner.cut != first.runtime.capture_cut
                    || owner.participants.is_empty()
                    || owner.participants.iter().any(|node| {
                        !first
                            .runtime
                            .operations
                            .iter()
                            .any(|operation| &operation.route.node == node)
                    })
                    || owner
                        .evidence
                        .iter()
                        .any(|reference| content.get(reference).is_none())
                    || content.get(&owner.state).is_none()
                {
                    return Err(refused("complete Tape2 native journal roster differs"));
                }
                let source = AuthenticatedOriginalLineageSource {
                    archive: self,
                    owner,
                    runtime_reference: first.runtime_reference.clone(),
                    runtime: Rc::clone(&first.runtime),
                    scheduling: Rc::clone(&first.scheduling),
                    repeatability: first.repeatability,
                    content: &content,
                };
                factory.authenticate_original_lineage_source(graph, &source)?;
                sources.push((
                    owner.clone(),
                    source.runtime_reference.clone(),
                    Rc::clone(&source.runtime),
                    Rc::clone(&source.scheduling),
                    source.repeatability,
                ));
            }
            Ok(sources)
        })();
        let sources = match checked {
            Ok(sources) => sources,
            Err(error) => return Err(OriginalLineageSourcePinFailure { error, content }),
        };
        let mut pins = Vec::new();
        if pins.try_reserve_exact(sources.len()).is_err() {
            return Err(OriginalLineageSourcePinFailure {
                error: refused("complete Tape2 pin reservation failed"),
                content,
            });
        }
        let archive = Rc::new(self.clone());
        let content = Rc::new(content);
        for (owner, runtime_reference, runtime, scheduling, repeatability) in sources {
            pins.push(PinnedOriginalLineageSource {
                archive: Rc::clone(&archive),
                owner,
                runtime_reference,
                runtime,
                scheduling,
                repeatability,
                content: Rc::clone(&content),
            });
        }
        Ok(pins)
    }

    /// Transfers authenticated original lineage bodies into path-independent custody.
    ///
    /// Every exact role/body is authenticated against the signed archive before
    /// ownership transfer. The existing source decoder validates complete Runtime7,
    /// scheduler and native owner scope. No new body inventory is allocated or
    /// copied: the supplied immutable verified closure is moved into the pin.
    /// The small owner metadata copy is precredited by the archive record ceiling.
    ///
    /// # Errors
    /// Returns complete supplied content on unsupported physical artifacts, changed
    /// signed roles, foreign source/owner, malformed original journals or exhausted
    /// original metadata/body credit. Selected-extension combinations stay refused.
    pub fn pin_original_lineage_source(
        &self,
        owner: &Id,
        content: VerifiedStateContent,
        limits: OriginalInputLineageLimits,
    ) -> Result<PinnedOriginalLineageSource, OriginalLineageSourcePinFailure> {
        self.pin_original_lineage_source_with_selection(owner, content, limits, None)
    }

    /// Pins a complete selected source only after installed graph/native authentication.
    ///
    /// The exact original selected graph and factory remain conjuncts of signed
    /// source verification. This transfers no native image or execution permission.
    ///
    /// # Errors
    /// Returns all original content on unsupported selection, physical artifacts,
    /// foreign native journals or exceeded original metadata/body credits.
    pub fn pin_selected_original_lineage_source(
        &self,
        owner: &Id,
        content: VerifiedStateContent,
        limits: OriginalInputLineageLimits,
        graph: &crate::node_admission::AdmittedGraph,
        factory: &dyn super::NativeWorldFactory,
    ) -> Result<PinnedOriginalLineageSource, OriginalLineageSourcePinFailure> {
        self.pin_original_lineage_source_with_selection(
            owner,
            content,
            limits,
            Some((graph, factory)),
        )
    }

    fn pin_original_lineage_source_with_selection(
        &self,
        owner: &Id,
        content: VerifiedStateContent,
        limits: OriginalInputLineageLimits,
        selected: Option<(
            &crate::node_admission::AdmittedGraph,
            &dyn super::NativeWorldFactory,
        )>,
    ) -> Result<PinnedOriginalLineageSource, OriginalLineageSourcePinFailure> {
        let checked = (|| -> Result<_, StateError> {
            pin_credit(&content, limits)?;
            // This pin has no native-image lease. A physical closure must remain
            // with a separately qualified whole native artifact custody path.
            if self
                .owners()
                .iter()
                .any(|owner| !owner.artifacts.is_empty())
            {
                return Err(refused(
                    "physical native artifacts cannot enter a Tape2 source pin",
                ));
            }
            let source = if let Some((graph, factory)) = selected {
                self.authenticated_selected_original_lineage_source(
                    owner, &content, limits, graph, factory,
                )?
            } else {
                self.authenticated_original_lineage_source(owner, &content, limits)?
            };
            super::super::super::closure::bounded_record(
                source.owner(),
                self.limits.state.maximum_record_bytes,
            )?;
            Ok((
                source.owner().clone(),
                source.runtime_reference.clone(),
                Rc::clone(&source.runtime),
                Rc::clone(&source.scheduling),
                source.repeatability,
            ))
        })();
        let (owner, runtime_reference, runtime, scheduling, repeatability) = match checked {
            Ok(source) => source,
            Err(error) => return Err(OriginalLineageSourcePinFailure { error, content }),
        };
        Ok(PinnedOriginalLineageSource {
            archive: Rc::new(self.clone()),
            owner,
            runtime_reference,
            runtime,
            scheduling,
            repeatability,
            content: Rc::new(content),
        })
    }
}

pub(super) fn pin_archive_credit(
    content: &VerifiedStateContent,
    limits: crate::node_state::StateLimits,
) -> Result<(), StateError> {
    archive_pin_geometry(content.entries().map(|(reference, _)| reference), limits)?;
    for (reference, body) in content.entries() {
        if reference.length.get() != body.len() as u64 {
            return Err(refused("complete Tape2 source role extent differs"));
        }
    }
    Ok(())
}

fn archive_pin_geometry<'a>(
    references: impl Iterator<Item = &'a ContentRef>,
    limits: crate::node_state::StateLimits,
) -> Result<(), StateError> {
    let mut count = 0usize;
    let mut total = 0usize;
    for reference in references {
        reference
            .validate()
            .map_err(|_| refused("complete Tape2 source role is malformed"))?;
        let extent = usize::try_from(reference.length.get())
            .map_err(|_| refused("complete Tape2 source role extent overflows"))?;
        count = count
            .checked_add(1)
            .filter(|count| *count <= limits.maximum_content_objects)
            .ok_or_else(|| super::super::super::closure::limit("complete Tape2 source roles"))?;
        if extent > limits.maximum_content_bytes {
            return Err(super::super::super::closure::limit(
                "complete Tape2 source object bytes",
            ));
        }
        // Charge each full typed role before transfer, even when the CAS backing
        // shares identical bytes. No source read or body clone occurs here.
        total = total
            .checked_add(extent)
            .filter(|total| *total <= limits.maximum_total_content_bytes)
            .ok_or_else(|| super::super::super::closure::limit("complete Tape2 source bytes"))?;
    }
    Ok(())
}

pub(super) fn pin_credit(
    content: &VerifiedStateContent,
    limits: OriginalInputLineageLimits,
) -> Result<(), StateError> {
    let hard = OriginalInputLineageLimits::default();
    if content.object_count() > limits.maximum_objects.min(hard.maximum_objects) {
        return Err(super::super::super::closure::limit(
            "Tape2 source role count",
        ));
    }
    let mut total = 0usize;
    for (reference, body) in content.entries() {
        reference
            .validate()
            .map_err(|_| refused("Tape2 source role is malformed"))?;
        if reference.length.get() != body.len() as u64 {
            return Err(refused("Tape2 source role extent differs"));
        }
        // Typed aliases each consume an original role extent, although backing
        // CAS bytes remain shared. No body read or clone precedes this charge.
        total = total
            .checked_add(body.len())
            .filter(|total| *total <= limits.maximum_bytes.min(hard.maximum_bytes))
            .ok_or_else(|| super::super::super::closure::limit("Tape2 source role bytes"))?;
    }
    Ok(())
}

#[cfg(test)]
mod models {
    use super::*;

    #[test]
    fn complete_archive_pin_uses_declared_code_credit_without_expanding_input_lineage()
    -> Result<(), StateError> {
        let lineage = OriginalInputLineageLimits::default();
        let mut installed =
            canonical::content_ref(b"synthetic installed code", "application/octet-stream")
                .map_err(|_| refused("synthetic installed reference failed"))?;
        installed.length = ((lineage.maximum_bytes as u64) + 1).into();
        let extent = usize::try_from(installed.length.get())
            .map_err(|_| refused("synthetic installed extent failed"))?;
        let archive = crate::node_state::StateLimits {
            maximum_content_bytes: extent,
            maximum_total_content_bytes: extent,
            ..crate::node_state::StateLimits::default()
        };

        // The metadata control never allocates the declared executable body.
        archive_pin_geometry(std::iter::once(&installed), archive)?;
        assert!(
            archive_pin_geometry(
                std::iter::once(&installed),
                crate::node_state::StateLimits {
                    maximum_content_bytes: extent - 1,
                    ..archive
                }
            )
            .is_err()
        );
        assert_eq!(
            OriginalInputLineageLimits::default().maximum_bytes,
            lineage.maximum_bytes
        );
        Ok(())
    }

    #[test]
    fn complete_archive_pin_charges_full_typed_roles_before_transfer() -> Result<(), StateError> {
        let first = canonical::content_ref(b"same installed bytes", "application/octet-stream")
            .map_err(|_| refused("synthetic code reference failed"))?;
        let mut second = first.clone();
        second.media_type = "application/x-installed-source".into();
        let extent = usize::try_from(first.length.get())
            .map_err(|_| refused("synthetic code extent failed"))?;
        let archive = crate::node_state::StateLimits {
            maximum_content_bytes: extent,
            maximum_total_content_bytes: extent * 2,
            maximum_content_objects: 2,
            ..crate::node_state::StateLimits::default()
        };

        archive_pin_geometry([&first, &second].into_iter(), archive)?;
        assert!(
            archive_pin_geometry(
                [&first, &second].into_iter(),
                crate::node_state::StateLimits {
                    maximum_content_objects: 1,
                    ..archive
                }
            )
            .is_err()
        );
        assert!(
            archive_pin_geometry(
                [&first, &second].into_iter(),
                crate::node_state::StateLimits {
                    maximum_total_content_bytes: extent * 2 - 1,
                    ..archive
                }
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn owned_lineage_pin_charges_each_full_typed_alias_before_source_reads()
    -> Result<(), StateError> {
        let body = b"original shared bytes";
        let mut objects = Vec::new();
        for media in ["application/json", "application/octet-stream"] {
            objects.push(crate::node_scheduling::InputPayload {
                reference: canonical::content_ref(body, media)
                    .map_err(|_| refused("synthetic pin reference failed"))?,
                bytes: body.to_vec(),
            });
        }
        let content = super::super::super::super::closure::synthetic_typed_content(&objects)?;
        assert_eq!(content.total_bytes(), body.len());
        let hard = OriginalInputLineageLimits::default();
        assert!(
            pin_credit(
                &content,
                OriginalInputLineageLimits {
                    maximum_objects: 1,
                    ..hard
                }
            )
            .is_err()
        );
        assert!(
            pin_credit(
                &content,
                OriginalInputLineageLimits {
                    maximum_bytes: body.len(),
                    ..hard
                }
            )
            .is_err()
        );
        pin_credit(
            &content,
            OriginalInputLineageLimits {
                maximum_bytes: body.len() * 2,
                ..hard
            },
        )?;
        assert_eq!(content.object_count(), 2);
        for object in &objects {
            assert_eq!(content.get(&object.reference), Some(body.as_slice()));
        }
        Ok(())
    }
}
