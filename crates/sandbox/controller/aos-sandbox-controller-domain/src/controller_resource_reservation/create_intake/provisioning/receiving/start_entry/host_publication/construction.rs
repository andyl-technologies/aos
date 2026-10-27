//! Constructs and retains the private Host child inside its paired signing turn.
//!
//! Whole pure results and the actual chronological native selection remain held
//! until both independently owed posts complete. The successful action then
//! moves into the same Start native owner without late growth or allocation.

use super::*;

impl StartHostPublicationConstructionOriginalV2 {
    pub(crate) fn new() -> Self {
        Self {
            parent: None,
            root_reply: None,
            construction_turn: None,
            funding: None,
            clock: None,
            current: None,
            host_signature: None,
            guardian_signature: None,
            template: None,
            draft: None,
            prepared: None,
            plan: None,
            comparison_geometry: None,
            comparison_funding: None,
            comparison: None,
            catalog_association: None,
            action: None,
            after: None,
            original_selected: false,
            first: None,
        }
    }

    // This constructor is entered only after both genuine paired signing
    // borrows; it repeats their exact Root/native comparison before mutation.
    pub(crate) fn construct_once_v2(
        &mut self,
        original: &mut OriginalStartHostRootLoanV1<'_, '_>,
        controller: &mut Journal,
        admission: &RootStartResourcePrepareAdmissionOriginalV2<'_>,
        construction: &RootStartResourceConstructionTurnV2<'_>,
        catalog: &crate::StartHostCatalogProjectionOriginalV2,
        body: &[u8],
        host_preparation: &BrokerPlanPreparation,
        guardian_preparation: &BrokerPlanPreparation,
        host: &SignedBrokerPlan,
        guardian: &SignedBrokerPlan,
    ) -> Result<(), StartHostPublicationClosedV2> {
        if self.funding.is_some() || self.first.is_some() {
            self.first.get_or_insert(First::Reentry);
            return Err(CLOSED);
        }
        self.parent = Some(original.parent_operation_v1());
        self.construction_turn = Some(original.native_turn_v1());
        self.funding = Some((|| {
            construction.require_admission_v2(admission, original, controller, true)?;
            if admission.purpose_data_v2()? != HostResourcePurposeDataV1::HostLaunch
                || host_preparation.canonical_plan() != admission.reply_v1()
                    .map_err(|_| ResourceReservationErrorV1::Conflict)?.canonical_plan
                || host_preparation.signing_request().canonical_statement()
                    != admission.reply_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?.canonical_statement
            {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            let reply = admission.reply_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
            self.root_reply = Some(reply.digest_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?);
            let (manifest, _) = original.start_assignment_v2(controller)?;
            let lease = original.fresh_ownership_lease_v1()?;
            let encoded = aos_sandbox_protocol::publication::publication_construction_encoded_bound_v1(
                manifest.canonical_bytes().len(), [lease.canonical_lease().len(),
                    lease.canonical_signature().len(), lease.canonical_receipt().len(),
                    lease.canonical_receipt_signature().len()],
                [(host.canonical_plan().len(), host.canonical_signature().len(), body.len(), 0)],
            ).map_err(|_| ResourceReservationErrorV1::Conflict)?;
            let models = aos_sandbox_protocol::publication::decoding_receiving_bytes_v1(encoded)
                .and_then(|bytes| bytes.checked_mul(6))
                .and_then(|bytes| bytes.checked_add(size_of::<Self>().checked_mul(2)?))
                .and_then(|bytes| bytes.checked_add(size_of::<StartHostPublicationContractV2>().checked_mul(2)?))
                .and_then(|bytes| bytes.checked_add(size_of::<StartHostPublicationActionOriginalV2>().checked_mul(2)?))
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            // Full current C validation includes foreign schemas and the real
            // predecessor RuntimeAuthority CAS, using the existing selector.
            let state = controller.historical_read_view_v1().materialized_state_v1();
            let current = crate::cold_launch_publication::completion::controller_selector_model_bytes_v1(state)
                .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(ResourceReservationErrorV1::Conflict)?;
            let names = crate::cold_launch_publication::completion::controller_selector_namespace_entries_v1(state)
                .and_then(|names| u64::try_from(names).ok()).ok_or(ResourceReservationErrorV1::Conflict)?;
            let demand = ResourceVector::ZERO.with(D::MemoryBytes,
                models.checked_add(current).ok_or(ResourceReservationErrorV1::Conflict)?)
                .with(D::MetadataEntries, names);
            let returned = original.require_complete_v1(controller, demand);
            self.original_selected = returned.is_err() && original.failure_v1().is_some();
            if returned.is_ok() {
                original.native.resources.host_publication_resident = demand;
            }
            returned
        })());
        if !matches!(self.funding, Some(Ok(()))) {
            self.first = Some(First::Funding);
            return Err(CLOSED);
        }

        self.clock = Some(construction.actual_before_clock_v2());
        let sample = match self.clock.as_ref() {
            Some(Ok(sample)) => *sample,
            _ => {
                self.first = Some(First::Clock);
                return Err(CLOSED);
            }
        };
        self.current = Some((|| -> Result<_, Cause> {
            let (manifest, _) = original.start_assignment_v2(controller)?;
            let sandbox = manifest.manifest().sandbox();
            RuntimeAuthorityStore::load(controller, RuntimeAuthorityLimits::default())?
                .current(sandbox)?.ok_or_else(|| Box::new(CLOSED) as Cause)
        })());
        if !matches!(self.current, Some(Ok(_))) {
            self.first = Some(First::Current);
            return Err(CLOSED);
        }
        self.host_signature = Some(check_signed(host_preparation, host, sample.wall_seconds()));
        if !matches!(self.host_signature, Some(Ok(_))) {
            self.first = Some(First::HostSignature);
            return Err(CLOSED);
        }
        self.guardian_signature = Some(check_signed(guardian_preparation, guardian, sample.wall_seconds()));
        if !matches!(self.guardian_signature, Some(Ok(_))) {
            self.first = Some(First::GuardianSignature);
            return Err(CLOSED);
        }
        self.template = Some((|| -> Result<_, Cause> {
            let signed = positive(&self.host_signature)?;
            let [grant] = signed.plan().grants() else { return Err(Box::new(CLOSED)); };
            Ok(crate::BrokerDispatchTemplateV1::new(signed.clone(),
                aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME,
                body.to_vec(), Vec::new(), crate::BrokerDispatchSemanticIdentityV1::new(
                    BrokerVerb::HostLaunch, BrokerGrantTarget::Assignment, grant.argument_commitment(),
                ))?)
        })());
        if !matches!(self.template, Some(Ok(_))) {
            self.first = Some(First::Template);
            return Err(CLOSED);
        }
        self.draft = Some((|| -> Result<_, Cause> {
            let (manifest, _) = original.start_assignment_v2(controller)?;
            Ok(AuthorityPublicationDraftV1::new(manifest.clone(), vec![BrokerAudience::Host],
                vec![positive(&self.template)?.clone()])?)
        })());
        if !matches!(self.draft, Some(Ok(_))) {
            self.first = Some(First::Draft);
            return Err(CLOSED);
        }
        self.prepared = Some((|| -> Result<_, Cause> {
            Ok(crate::publication::bind_authority_publication_lease(
                positive(&self.draft)?.clone(), original.fresh_ownership_claim_v1()?,
                original.fresh_ownership_lease_v1()?.clone(),
            )?)
        })());
        if !matches!(self.prepared, Some(Ok(_))) {
            self.first = Some(First::Prepared);
            return Err(CLOSED);
        }
        self.plan = Some((|| -> Result<_, Cause> {
            let parent = original.parent_operation_v1();
            let mut hash = Sha256::new();
            hash.update(b"aos.original-start.host-publication.v2\0");
            hash.update(parent.as_bytes());
            hash.update(self.root_reply.ok_or(CLOSED)?);
            hash.update(positive(&self.prepared)?.digest().as_bytes());
            let digest: [u8; 32] = hash.finalize().into();
            let operation = OperationId::from_bytes(digest[..16].try_into()?);
            let (manifest, _) = original.start_assignment_v2(controller)?;
            let key = aos_sandbox_protocol::public_api::projection::projection_key(
                aos_sandbox_protocol::public_api::projection::PublicProjectionKindV1::Sandbox,
                manifest.manifest().sandbox().into_bytes(),
            );
            let value = controller.get(crate::RecordNamespace::DesiredState, &key).ok_or(CLOSED)?.to_vec();
            let draft = positive(&self.draft)?;
            let effect = aos_sandbox_protocol::publication::bind_authority_publication_effect(draft, positive(&self.template)?.digest())?;
            let context = original.original_start_plan_v1().original_start_context_v1()?;
            Ok(crate::OperationPlan::ownership_gated(operation,
                crate::IdempotencyKey::new(operation.as_bytes().to_vec())?,
                *positive(&self.prepared)?.digest().as_bytes(),
                key, value, vec![effect], original.fresh_ownership_claim_v1()?.clone(), draft.clone(),
            )?.with_runtime_authority(RuntimeAuthorityIntentV1::bind_holder(context.caller(),
                Some(positive(&self.current)?.revision()))?)?)
        })());
        if !matches!(self.plan, Some(Ok(_))) {
            self.first = Some(First::Plan);
            return Err(CLOSED);
        }
        self.comparison_geometry = Some((|| -> Result<_, Cause> {
            let predecessor = positive(&self.current)?;
            let plan = positive(&self.plan)?;
            let namespace = aos_sandbox_protocol::domain_ledger::runtime_authority_history::CURRENT_PREFIX;
            let sandbox = predecessor.manifest().manifest().sandbox();
            let head = controller.records(crate::RecordNamespace::RuntimeAuthority)
                .find(|(key, _)| key.len() == namespace.len() + sandbox.as_bytes().len()
                    && key.starts_with(namespace) && &key[namespace.len()..] == sandbox.as_bytes())
                .ok_or(ResourceReservationErrorV1::Conflict)?.1;
            let gate = plan.pending_ownership_gate_receiving_bytes_v2()?;
            // Each tuple buffer remains beside the same contract's exact clone.
            // Source row backing itself is already paid by the current C owner.
            let bytes = namespace.len().checked_add(sandbox.as_bytes().len())
                .and_then(|bytes| bytes.checked_add(head.len()))
                .and_then(|bytes| bytes.checked_add(gate))
                .and_then(|bytes| bytes.checked_mul(2))
                .and_then(|bytes| bytes.checked_add(size_of::<usize>().checked_mul(2)?))
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
        })());
        let additional = match self.comparison_geometry.as_ref() {
            Some(Ok(additional)) => *additional,
            _ => {
                self.first = Some(First::ComparisonGeometry);
                return Err(CLOSED);
            }
        };
        self.comparison_funding = Some((|| {
            let complete = original.native.resources.host_publication_resident.checked_add(additional)?;
            let returned = original.require_complete_v1(controller, additional);
            self.original_selected = returned.is_err() && original.failure_v1().is_some();
            if returned.is_ok() {
                original.native.resources.host_publication_resident = complete;
            }
            returned
        })());
        if !matches!(self.comparison_funding, Some(Ok(()))) {
            self.first = Some(First::ComparisonFunding);
            return Err(CLOSED);
        }
        self.comparison = Some((|| -> Result<_, Cause> {
            let predecessor = positive(&self.current)?;
            let key = aos_sandbox_protocol::domain_ledger::runtime_authority_history::ledger_read::
                current_key(predecessor.manifest().manifest().sandbox());
            let head = controller.get(crate::RecordNamespace::RuntimeAuthority, &key)
                .ok_or(CLOSED)?.to_vec();
            let gate = positive(&self.plan)?.pending_ownership_gate_bytes_v2()?;
            Ok((key, head, gate))
        })());
        if !matches!(self.comparison, Some(Ok(_))) {
            self.first = Some(First::Comparison);
            return Err(CLOSED);
        }
        self.catalog_association = Some((|| {
            let snapshot = catalog.catalog_data_v2(original, controller)?;
            let encoded = catalog.canonical_catalog_data_v2(original, controller)?;
            Ok((snapshot.generation(), Sha256::digest(encoded).into()))
        })());
        let (catalog_generation, catalog_digest) = match self.catalog_association.as_ref() {
            Some(Ok(association)) => *association,
            _ => {
                self.first = Some(First::CatalogAssociation);
                return Err(CLOSED);
            }
        };
        // Move the same verified pair into long-lived native action custody.
        // SDK representation disposal cannot discard the signed Source anchor,
        // and this transfer allocates no new plan or signature backing.
        let host = take_signature_v2(&mut self.host_signature)?;
        let guardian = take_signature_v2(&mut self.guardian_signature)?;
        self.action = Some(StartHostPublicationActionOriginalV2 {
            contract: Arc::new(StartHostPublicationContractV2 {
                identity: original.retained_resource_identity_v2(), parent: original.parent_operation_v1(),
                origin: original.start_origin_data_v1(), root_reply: self.root_reply.ok_or(CLOSED)?,
                catalog_generation, catalog_digest,
                predecessor: positive(&self.current).map_err(|_| CLOSED)?.clone(),
                predecessor_head_key: positive(&self.comparison).map_err(|_| CLOSED)?.0.clone(),
                predecessor_head: positive(&self.comparison).map_err(|_| CLOSED)?.1.clone(),
                pending_gate: positive(&self.comparison).map_err(|_| CLOSED)?.2.clone(),
                plan: positive(&self.plan).map_err(|_| CLOSED)?.clone(),
                draft: positive(&self.draft).map_err(|_| CLOSED)?.clone(),
                prepared: positive(&self.prepared).map_err(|_| CLOSED)?.clone(),
                host,
                guardian,
            }),
            admission_geometry: None, admission_funding: None, admission_native_selected: false,
            admission_scope: None,
            admission_turn: None, admission: None, admission_after: None,
            activation_preparation: None,
            activation_original: activation::StartHostActivationOriginalV2::new(),
            effect_original: effect::StartHostEffectOriginalV2::new(),
            activation: None, activation_after: None,
        });
        Ok(())
    }
}

fn positive<T>(value: &Option<Result<T, Cause>>) -> Result<&T, StartHostPublicationClosedV2> {
    value.as_ref().and_then(|value| value.as_ref().ok()).ok_or(CLOSED)
}

fn check_signed(preparation: &BrokerPlanPreparation, signed: &SignedBrokerPlan,
    wall_seconds: i64,
) -> Result<SignedBrokerPlan, Cause> {
    if signed.canonical_plan() != preparation.canonical_plan()
        || signed.plan() != preparation.plan_data_v1()
    {
        return Err(Box::new(CLOSED));
    }
    Ok(preparation.clone().complete(
        aos_sandbox_protocol::authorization_artifact::ReturnedSignature::Envelope(signed.canonical_signature()),
        wall_seconds,
    )?)
}

impl StartHostPublicationConstructionOriginalV2 {
    pub(crate) fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Reentry => Some(&CLOSED as &(dyn Error + 'static)),
            First::Funding => resource_cause_v2(&self.funding),
            First::Clock => self.clock.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Current => self.current.as_ref()?.as_ref().err().map(|cause| cause.as_ref() as _),
            First::HostSignature => self.host_signature.as_ref()?.as_ref().err().map(|cause| cause.as_ref() as _),
            First::GuardianSignature => self.guardian_signature.as_ref()?.as_ref().err().map(|cause| cause.as_ref() as _),
            First::Template => self.template.as_ref()?.as_ref().err().map(|cause| cause.as_ref() as _),
            First::Draft => self.draft.as_ref()?.as_ref().err().map(|cause| cause.as_ref() as _),
            First::Prepared => self.prepared.as_ref()?.as_ref().err().map(|cause| cause.as_ref() as _),
            First::Plan => self.plan.as_ref()?.as_ref().err().map(|cause| cause.as_ref() as _),
            First::ComparisonGeometry => self.comparison_geometry.as_ref()?.as_ref().err().map(|cause| cause.as_ref() as _),
            First::ComparisonFunding => resource_cause_v2(&self.comparison_funding),
            First::Comparison => self.comparison.as_ref()?.as_ref().err().map(|cause| cause.as_ref() as _),
            First::Posts => resource_cause_v2(&self.after),
            First::CatalogAssociation => self.catalog_association.as_ref()?.as_ref().err().map(|cause| cause as _),
        }.or(Some(&CLOSED))
    }

    pub(crate) fn finish_after_posts_once_v2(&mut self,
        client: &RootHostLaunchClientOriginalV1,
        entry: &mut AcceptedStartEntryOriginalV1,
        controller: &Journal,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.after.is_some() {
            self.first.get_or_insert(First::Reentry);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.after = Some((|| {
            if self.first.is_some() || self.action.is_none() {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            client.require_completed_resource_construction_v2(entry, controller,
                HostResourcePurposeDataV1::HostLaunch,
                self.parent.ok_or(ResourceReservationErrorV1::Conflict)?,
                self.root_reply.ok_or(ResourceReservationErrorV1::Conflict)?,
                self.construction_turn.ok_or(ResourceReservationErrorV1::Conflict)?)?;
            let native = entry.native_state.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
            if native.host_publication_action.is_some() {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            Ok(())
        })());
        if !matches!(self.after, Some(Ok(()))) {
            self.first.get_or_insert(First::Posts);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        // All allocations occurred inside the paid construction turn. The same
        // successful original moves into C custody only after both owed posts.
        let action = self.action.take().ok_or(ResourceReservationErrorV1::Conflict)?;
        entry.native_state.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?
            .host_publication_action = Some(action);
        Ok(())
    }
}

impl StartHostPublicationConstructionOriginalV2 {
    pub(crate) fn original_selected_v2(&self) -> bool {
        self.original_selected
    }
}

fn resource_cause_v2(value: &Option<Result<(), ResourceReservationErrorV1>>)
    -> Option<&(dyn Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}

fn take_signature_v2(slot: &mut Option<Result<SignedBrokerPlan, Cause>>)
    -> Result<SignedBrokerPlan, StartHostPublicationClosedV2> {
    match slot.take() {
        Some(Ok(signed)) => Ok(signed),
        Some(Err(cause)) => {
            *slot = Some(Err(cause));
            Err(CLOSED)
        }
        None => Err(CLOSED),
    }
}
