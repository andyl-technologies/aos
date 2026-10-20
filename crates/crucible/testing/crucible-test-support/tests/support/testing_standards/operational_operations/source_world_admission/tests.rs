//! Rejects foreign admission, premature publication and lost original custody.

use super::*;
use super::super::{
    Companion, Contract, mask_contract, read_companions, replace_one_obligation, source_pattern,
};

struct Fixture {
    contract: &'static Contract,
    code: String,
    companions: Vec<String>,
}

impl Fixture {
    fn load(contract: &'static Contract) -> Result<Self, Box<dyn std::error::Error>> {
        let path = crate::workspace::package_path(
            &crate::workspace_root().join("crates"),
            contract.package,
        )
        .join(format!("{}.rs", contract.target));
        let code = crate::scrub_comments_and_strings(&std::fs::read_to_string(path)?);
        let companions = read_companions(contract)?;
        assert!(
            mask_contract(contract, &code, &companions) != code,
            "reviewed World admission changed: {}",
            contract.target,
        );
        assert!(
            crate::flaky_escape_failures(
                "unreviewed",
                "unreviewed",
                &mask_contract(contract, &code, &companions)
            )
            .is_empty()
        );
        Ok(Self {
            contract,
            code,
            companions,
        })
    }

    fn rejects(&self, fact: &Companion, before: &str, after: &str) {
        let index = self
            .contract
            .companions
            .iter()
            .position(|binding| binding.path == fact.path && binding.required == fact.required)
            .expect("same shared World fact is bound to the actual contract");
        let clause = fact
            .required
            .iter()
            .find_map(|(clause, _)| {
                source_pattern(clause)
                    .contains(&source_pattern(before))
                    .then_some(*clause)
            })
            .expect("the exact causal mutation is anchored in a reviewed clause");
        let evidence = crate::scrub_comments_and_strings(&self.companions[index]);
        let altered_clause = replace_one_obligation(
            &crate::scrub_comments_and_strings(clause),
            &source_pattern(before),
            after,
        );
        let changed = replace_one_obligation(&evidence, &source_pattern(clause), &altered_clause);
        assert_ne!(changed, evidence, "mutation missed {}: {before}", fact.path);
        let mut companions = self.companions.clone();
        companions[index] = changed;
        assert_eq!(
            mask_contract(self.contract, &self.code, &companions),
            self.code,
            "{} masked changed World provenance {}: {before}",
            self.contract.target,
            fact.path
        );
        assert!(!crate::flaky_escape_failures("unreviewed", "unreviewed", &self.code).is_empty());
    }
}

#[test]
fn source_world_admission_preserves_actual_publication_and_initial_custody()
-> Result<(), Box<dyn std::error::Error>> {
    let cases: &[(&Companion, &str, &str)] = &[
        (
            &PREPARED_WORLD,
            r#"let selected_checkpoint = self.selected_checkpoint.take();"#,
            r#"drop(self.not_started.take()); let selected_checkpoint = self.selected_checkpoint.take();"#,
        ),
        (
            &PREPARED_WORLD,
            r#"self.world_admission = Some(admission);"#,
            r#"drop(admission); self.world_admission = None;"#,
        ),
        (
            &PREPARED_WORLD,
            r#"factory.prepare_world_admission(selection.clone(), registration.as_ref())"#,
            r#"factory.prepare_world_admission(foreign_selection, registration.as_ref())"#,
        ),
        (
            &PREPARED_WORLD,
            r#"not_started: &mut self.not_started,"#,
            r#"not_started: &mut foreign.not_started,"#,
        ),
        (
            &PREPARED_WORLD,
            r#"first_failure: &mut self.history.native,"#,
            r#"first_failure: &mut foreign.history.native,"#,
        ),
        (
            &PREPARED_WORLD,
            r#"self.history.admission = admission.take_history();"#,
            r#"drop(admission.take_history());"#,
        ),
        (
            &PREPARED_WORLD,
            r#"admission_post: self.admission.post(),"#,
            r#"admission_post: None,"#,
        ),
        (
            &PREPARED_WORLD,
            r#"fn source_selection(&self) -> &crate::PreparedSourceSelector { &self.selection }"#,
            r#"fn source_selection(&self) -> &crate::PreparedSourceSelector { &foreign.selection }"#,
        ),
        (
            &PREPARED_WORLD,
            r#"fn entered_world(&mut self) { drop(self.not_started.take()); }"#,
            r#"fn entered_world(&mut self) {}"#,
        ),
        (
            &FACADE,
            r#"self.host.world_origin().cloned()"#,
            r#"self.host.try_lock()?.world_preparation_origin()"#,
        ),
        (
            &FACADE,
            r#"if !admission.matches(before_effects)"#,
            r#"if false"#,
        ),
        (
            &FACADE,
            r#"let mut host = match admission.lock_host(&self.host)"#,
            r#"let mut host = match foreign.lock_host(&self.host)"#,
        ),
        (
            &FACADE,
            r#"owner: identity.owner, selection: identity.selection,"#,
            r#"owner: identity.owner, selection: foreign.selection,"#,
        ),
        (
            &FACADE,
            r#"&mut admission.preparation,"#,
            r#"&mut foreign.preparation,"#,
        ),
        (
            &FACADE,
            r#"admission, resources, selected_checkpoint, consumer_control_bytes, registration, before_effects,"#,
            r#"foreign_admission, resources, selected_checkpoint, consumer_control_bytes, registration, before_effects,"#,
        ),
        (
            &ADMISSION,
            r#"self.selection.same_role(receiver.source_selection())"#,
            r#"true"#,
        ),
        (
            &ADMISSION,
            r#"acquire_host(host, self.preparation.operation())"#,
            r#"acquire_host(host, foreign.operation())"#,
        ),
        (
            &ADMISSION,
            r#"self.history.first.get_or_insert(first);"#,
            r#"drop(first);"#,
        ),
        (
            &ADMISSION,
            r#"self.history.post.get_or_insert(post);"#,
            r#"drop(post);"#,
        ),
        (
            &ADMISSION,
            r#"if let Err(refusal) = original.wait_slice()"#,
            r#"if let Err(refusal) = renewed.wait_slice()"#,
        ),
        (
            &ADMISSION,
            r#"match host.try_lock()"#,
            r#"match host.lock()"#,
        ),
        (
            &ADMISSION,
            r#"original.wait_for_change()"#,
            r#"renewed.wait_for_change()"#,
        ),
        (
            &ADMISSION,
            r#"let post = original.wait_slice().map(|_| ());"#,
            r#"let post = Ok(());"#,
        ),
        (
            &ADMISSION,
            r#"drop(host);"#,
            r#"return HostAcquisition { host: Ok(host), first, post };"#,
        ),
        (
            &TOKEN,
            r#"!same_pool || self.identity != identity || self.entry != PreparationEntry::Ready"#,
            r#"self.identity != identity || self.entry != PreparationEntry::Ready"#,
        ),
        (&TOKEN, r#"self.identity != identity"#, r#"false"#),
        (
            &TOKEN,
            r#"self.entry != PreparationEntry::Ready"#,
            r#"false"#,
        ),
        (
            &TOKEN,
            r#"self.entry = PreparationEntry::Attempted;"#,
            r#"self.entry = PreparationEntry::Ready;"#,
        ),
        (
            &TOKEN,
            r#"self.entry = PreparationEntry::Committed; entered();"#,
            r#"self.entry = PreparationEntry::Committed;"#,
        ),
        (&TOKEN, r#"purpose.same_pool(&self.purpose)"#, r#"true"#),
        (
            &TOKEN,
            r#"Ok(Arc::clone(&self.original))"#,
            r#"Ok(Arc::new(self.purpose.begin_native_preparation()?))"#,
        ),
        (
            &TOKEN,
            r#".extend(std::alloc::Layout::new::<HostOperationGuard>())"#,
            r#".extend(std::alloc::Layout::new::<()>())"#,
        ),
        (
            &NATIVE_WORLD,
            r#"preparation.begin_attempt(purpose, identity)?"#,
            r#"preparation.begin_attempt(foreign_purpose, identity)?"#,
        ),
        (
            &NATIVE_WORLD,
            r#"|| preparation.commit_world(|| before_effects.entered_world())"#,
            r#"|| preparation.commit_world(|| {})"#,
        ),
        (
            &NATIVE_WORLD,
            r#"|| preparation.commit_world(|| before_effects.entered_world())"#,
            r#"|| before_effects.entered_world()"#,
        ),
        (
            &NATIVE_WORLD,
            r#"original, entered, populate,"#,
            r#"original, || {}, populate,"#,
        ),
        (
            &NATIVE_WORLD,
            r#"let custody = claim.take_initial_custody();"#,
            r#"let custody = foreign_claim.take_initial_custody();"#,
        ),
        (
            &NATIVE_WORLD,
            r#"first.retain_world_delivery_error(delivery);"#,
            r#"drop(delivery);"#,
        ),
        (
            &NATIVE_WORLD,
            r#"first.retain_world_receiver_refusal(receiver);"#,
            r#"drop(receiver);"#,
        ),
        (
            &POOL_CLAIM,
            r#"Arc::ptr_eq(&self.held, &other.held)"#,
            r#"true"#,
        ),
        (
            &POOL_CLAIM,
            r#"self.held.root.verify_world_preparation(original)?;"#,
            r#"Ok::<(), ServiceBirthError>(())?;"#,
        ),
        (
            &POOL_CLAIM,
            r#"consumer_control_bytes, original, entered,"#,
            r#"consumer_control_bytes, original, || {},"#,
        ),
        (
            &POOL_CLAIM,
            r#"after: self.held.root.verify_world_preparation(original).err(),"#,
            r#"after: None,"#,
        ),
        (
            &POOL_CLAIM,
            r#"&self.held.ledger,"#,
            r#"&foreign.held.ledger,"#,
        ),
        (&POOL_CLAIM, r#"ledger.assign_source("#, r#"ledger.assign("#),
        (&POOL_CLAIM, r#"born = Some(claim);"#, r#"drop(claim);"#),
        (
            &POOL_CLAIM,
            r#"controls: AuthenticatedNativeWorldControlLease { held: Arc::clone(&self.held), epoch, closed: false, }"#,
            r#"controls: AuthenticatedNativeWorldControlLease { held: Arc::clone(&foreign.held), epoch, closed: false, }"#,
        ),
        (
            &POOL_CLAIM,
            r#".reserve_pool_windows(peak, tables, original)?;"#,
            r#".reserve_pool_windows(peak, tables, renewed)?;"#,
        ),
        (
            &POOL_CLAIM,
            r#"_retained: born.map(RetainedClaim::world),"#,
            r#"_retained: None,"#,
        ),
        (
            &POOL_CLAIM,
            r#"self.initial_custody.take()"#,
            r#"self.initial_custody.as_ref()"#,
        ),
        (&LEDGER, r#"if consumer_control_bytes == 0"#, r#"if false"#),
        (
            &LEDGER,
            r#"original, true, entered,"#,
            r#"original, false, entered,"#,
        ),
        (
            &LEDGER,
            r#"let (used, peak) = checked_selection(self.ceiling, self.used, requests)?;"#,
            r#"let (used, peak) = (self.used, 0);"#,
        ),
        (
            &LEDGER,
            r#"charge_world_controls(self.ceiling, used, consumer_control_bytes)?"#,
            r#"used"#,
        ),
        (
            &LEDGER,
            r#"self.next_world.checked_add(1)"#,
            r#"self.next_world.checked_add(0)"#,
        ),
        (
            &LEDGER,
            r#"entered(); self.used = used;"#,
            r#"self.used = used; entered();"#,
        ),
        (
            &LEDGER,
            r#"entered(); self.used = used;"#,
            r#"entered(); additional_effect()?; self.used = used;"#,
        ),
        (
            &LEDGER,
            r#"consumer_issued, node_constructor_entered: false,"#,
            r#"consumer_issued: false, node_constructor_entered: false,"#,
        ),
        (
            &LEDGER,
            r#"_original: Arc::clone(original),"#,
            r#"_original: Arc::clone(foreign_original),"#,
        ),
        (
            &LEDGER,
            r#"consumer_closed: consumer_control_bytes == 0,"#,
            r#"consumer_closed: true,"#,
        ),
        (&MAIN_CHECK, r#"if !self.owner.is_live()"#, r#"if false"#),
        (
            &MAIN_CHECK,
            r#"self.family.check()"#,
            r#"Ok::<(), ServiceBirthError>(())?;"#,
        ),
        (&MAIN_CHECK, r#"if self.node.is_some()"#, r#"if false"#),
        (
            &MAIN_CHECK,
            r#"partition.check()?;"#,
            r#"Ok::<(), ServiceBirthError>(())?;"#,
        ),
        (&MAIN_CHECK, r#"control.try_lock()"#, r#"control.lock()"#),
        (
            &MAIN_CHECK,
            r#"let after = check().err();"#,
            r#"let after = None;"#,
        ),
        (
            &MAIN_CHECK,
            r#"let result = check().and_then(|()| attempt());"#,
            r#"let result = attempt();"#,
        ),
        (
            &PREPARATION_CLASS,
            r#"preparation.shares_outer_cap(supervisor)"#,
            r#"true"#,
        ),
        (
            &PREPARATION_CLASS,
            r#"HostOperationClass::Preparation"#,
            r#"HostOperationClass::Cleanup"#,
        ),
        (
            &LIVE_CLASS,
            r#"decision.require_running(self.id)?;"#,
            r#"Ok::<(), HostSupervisionError>(())?;"#,
        ),
        (
            &PENDING_LAYOUT,
            r#".checked_add(preparation)"#,
            r#".checked_add(0)"#,
        ),
        (
            &PENDING_LAYOUT,
            r#"std::mem::size_of::<Self>()"#,
            r#"0_usize"#,
        ),
        (
            &PENDING_POST_BODY,
            r#"self.world_admission = None;"#,
            r#"retain_extra_guard_alias();"#,
        ),
        (
            &NATIVE_LAYOUT,
            r#"std::alloc::Layout::array::<Option<AuthenticatedNativeWorldClaim>>(capacity)"#,
            r#"std::alloc::Layout::array::<()>(capacity)"#,
        ),
        (
            &NATIVE_WORLD,
            r#"pool.prepare_next(world, &original)"#,
            r#"pool.prepare_next(world, renewed)"#,
        ),
        (
            &NATIVE_WORLD,
            r#"original.complete()"#,
            r#"renewed.complete()"#,
        ),
        (
            &NATIVE_WORLD,
            r#"node.owner.quarantine();"#,
            r#"discard_node_owner();"#,
        ),
        (
            &POOL_CLAIM,
            r#"self.claim_world(identity, &rows, consumer_control_bytes, original, entered)"#,
            r#"self.claim_world(identity, &rows, consumer_control_bytes, original, || {})"#,
        ),
        (
            &POOL_CLAIM,
            r#"ledger.assign_source(identity, nodes, consumer_control_bytes, original, entered,)"#,
            r#"ledger.assign_source(identity, nodes, consumer_control_bytes, original, || {},)"#,
        ),
        (
            &LEDGER,
            r#"self.publish_assignment(identity, requests, consumer_control_bytes, original, true, entered,)"#,
            r#"self.publish_assignment(identity, requests, consumer_control_bytes, original, true, || {},)"#,
        ),
        (
            &MAIN_CHECK,
            r#"verify_preparation(&self.owner.supervisor, original)?;"#,
            r#"self.owner.check_worker_admission()?;"#,
        ),
        (
            &POOL_CLAIM,
            r#"let custody = self.initial_custody.take()"#,
            r#"let retained = self.held.as_ref().unwrap().ledger.lock()?; let custody = self.initial_custody.take()"#,
        ),
        (
            &ADMISSION,
            r#"Some(AdmissionFirst::Original(first)) => { Some(crate::LifecycleFailureRef::Supervision(first)) }"#,
            r#"Some(AdmissionFirst::Original(first)) => None"#,
        ),
        (
            &ADMISSION,
            r#"pub(crate) fn post(&self) -> Option<&HostSupervisionError> { self.post.as_ref() }"#,
            r#"pub(crate) fn post(&self) -> Option<&HostSupervisionError> { None }"#,
        ),
        (
            &ADMISSION,
            r#"acquire_host_with_wait(host, original, || original.wait_for_change())"#,
            r#"acquire_host_with_wait(host, original, || renewed.wait_for_change())"#,
        ),
        (
            &ADMISSION,
            r#"if let Err(refusal) = wait()"#,
            r#"if let Err(refusal) = original.wait_for_change()"#,
        ),
        (
            &ADMISSION,
            r#"observe_acquisition(acquired, first, original)"#,
            r#"observe_acquisition(acquired, first, renewed)"#,
        ),
        (
            &MAIN_CHECK,
            r#"self.require_world_root()?; self.owner.check_world_origin()?;"#,
            r#"self.owner.check_world_origin()?;"#,
        ),
        (
            &MAIN_CHECK,
            r#"self.require_world_root()?; self.owner.check_world_origin()?;"#,
            r#"self.require_world_root()?; self.owner.check_world_admission()?;"#,
        ),
        (
            &MAIN_CHECK,
            r#"self.check_world_origin()?; if let Some(partition)"#,
            r#"if let Some(partition)"#,
        ),
        (
            &FACADE,
            r#"let origin = host.world_preparation_origin()?;"#,
            r#"let origin = foreign.world_preparation_origin()?;"#,
        ),
        (
            &FACADE,
            r#"host: Arc::new(shared_host::SharedHostBody::with_origin(host, origin)),"#,
            r#"host: Arc::new(shared_host::SharedHostBody::ordinary(host)),"#,
        ),
        (
            &FACADE,
            r#"host: Arc::new(shared_host::SharedHostBody::ordinary(host)),"#,
            r#"host: Arc::new(shared_host::SharedHostBody::with_origin(host, replacement_origin)),"#,
        ),
        (
            &FACADE,
            r#"shared_host::shared_body_extent::<Self>()"#,
            r#"std::mem::size_of::<Mutex<Self>>().into()"#,
        ),
        (
            &FACADE,
            r#"Arc::get_mut(&mut self.host)"#,
            r#"Arc::make_mut(&mut self.host)"#,
        ),
        (
            &FACADE,
            r#"Arc::clone(&self.host)"#,
            r#"Arc::new(shared_host::SharedHostBody::ordinary(replacement_host))"#,
        ),
        (&ORIGIN_BODY, r#"if self.host.is_poisoned()"#, r#"if false"#),
        (
            &ORIGIN_BODY,
            r#"self.origin.as_ref().ok_or_else"#,
            r#"self.origin.as_ref().or(Some(&replacement_origin)).ok_or_else"#,
        ),
        (
            &ORIGIN_BODY,
            r#"origin: None,"#,
            r#"origin: Some(replacement_origin),"#,
        ),
        (&ORIGIN_BODY, r#"origin: Some(origin),"#, r#"origin: None,"#),
        (
            &ORIGIN_BODY,
            r#"std::alloc::Layout::new::<SharedHostBody<H>>()"#,
            r#"std::alloc::Layout::new::<Mutex<H>>()"#,
        ),
        (
            &ORIGIN_BODY,
            r#"std::alloc::Layout::new::<(AtomicUsize, AtomicUsize)>()"#,
            r#"std::alloc::Layout::new::<()>()"#,
        ),
        (
            &ORIGIN_BODY,
            r#"self.origin.as_ref()"#,
            r#"self.host.try_lock()?; self.origin.as_ref()"#,
        ),
        (
            &ORIGIN_PUBLICATION,
            r#"let controls = factory_bytes.checked_add(queue_bytes)"#,
            r#"let controls = queue_bytes.checked_add(0)"#,
        ),
        (
            &ORIGIN_PUBLICATION,
            r#"request, controls,"#,
            r#"request, 0,"#,
        ),
        (
            &ORIGIN_PUBLICATION,
            r#"concrete_host.bind_normal_pool(purpose)"#,
            r#"foreign_host.bind_normal_pool(purpose)"#,
        ),
        (
            &ORIGIN_PUBLICATION,
            r#"let bound = host.bind_original_accounts(binding); let after = original.boundary();"#,
            r#"let bound = host.bind_original_accounts(binding); let after = Ok(());"#,
        ),
        (
            &ORIGIN_PUBLICATION,
            r#"original.verify_factory_binding(&binding)"#,
            r#"foreign.verify_factory_binding(&binding)"#,
        ),
        (
            &ORIGIN_PUBLICATION,
            r#"if let Err(source) = after"#,
            r#"if let Err(source) = Ok(())"#,
        ),
        (
            &ORIGIN_PUBLICATION,
            r#"SharedQemuAttemptHostResourceFactory::try_with_world_origin( concrete_host, Some(cleanup), )?"#,
            r#"SharedQemuAttemptHostResourceFactory::new(concrete_host)"#,
        ),
        (&ORIGIN_PUBLICATION, r#"Some(queue.handle())"#, r#"None"#),
        (
            &ORIGIN_RUNNERS,
            r#"host: SharedQemuAttemptHostResourceFactory<H>,"#,
            r#"host: H,"#,
        ),
        (
            &ORIGIN_RUNNERS,
            r#"let lifecycle = lifecycle.into(); let production"#,
            r#"let host = SharedQemuAttemptHostResourceFactory::new(host); let lifecycle = lifecycle.into(); let production"#,
        ),
        (
            &ORIGIN_RUNNERS,
            r#"let lifecycle = lifecycle.into(); let production"#,
            r#"let host = SharedQemuAttemptHostResourceFactory::try_with_world_origin(host, None)?; let lifecycle = lifecycle.into(); let production"#,
        ),
        (
            &ORIGIN_RUNNERS,
            r#"ComposedQemuAttemptResourceGuardFactory::new(host.clone())"#,
            r#"ComposedQemuAttemptResourceGuardFactory::new(foreign.clone())"#,
        ),
        (
            &ORIGIN_RUNNERS,
            r#"ComposedQemuAttemptResourceGuardFactory::new(host),"#,
            r#"ComposedQemuAttemptResourceGuardFactory::new(foreign),"#,
        ),
        (
            &ORIGIN_RUNNERS,
            r#"(runner, execution_evidence)"#,
            r#"(runner, replacement_evidence)"#,
        ),
        (
            &ORIGIN_RUNNERS,
            r#"run_guarded_default_campaign_with_host(request, host)"#,
            r#"run_guarded_default_campaign_with_host(request, replacement_host)"#,
        ),
        (
            &ORIGIN_FINDING,
            r#"lifecycle, owner.inner.host.clone(),"#,
            r#"lifecycle, replacement_host,"#,
        ),
        (
            &ORIGIN_OWNER,
            r#"pub(crate) host: SharedQemuAttemptHostResourceFactory<LinuxQemuAttemptHostResourceFactory>,"#,
            r#"pub(crate) host: LinuxQemuAttemptHostResourceFactory,"#,
        ),
        (
            &ORIGIN_PUBLICATION,
            r#"let mut concrete_host = opened?;"#,
            r#"let mut concrete_host = opened?; let early = SharedQemuAttemptHostResourceFactory::try_with_world_origin(concrete_host, None)?;"#,
        ),
    ];
    for contract in [
        &super::super::production_publication::CONTRACTS[0],
        &super::super::constructor_continuations::CONTRACTS[4],
    ] {
        let fixture = Fixture::load(contract)?;
        for (fact, before, after) in cases {
            fixture.rejects(fact, before, after);
        }
        // A second publication outside the reviewed contiguous birth span
        // must also refuse; matching the original span alone is insufficient.
        let index = contract
            .companions
            .iter()
            .position(|binding| {
                binding.path == ORIGIN_PUBLICATION.path
                    && binding.required == ORIGIN_PUBLICATION.required
            })
            .expect("the actual Main publisher is required");
        let mut added = fixture.companions.clone();
        added[index].push_str(
            "\nSharedQemuAttemptHostResourceFactory::try_with_world_origin(foreign, None);",
        );
        assert_eq!(mask_contract(contract, &fixture.code, &added), fixture.code);
    }
    Ok(())
}
