//! Resolver-driven refusal diagnostics; these controls do not execute QEMU.

use super::*;

use crucible_campaign::{AlternativeId, DiscreteAlternative, DiscreteDomain};

fn recorded_choice(
    source: &ScenarioDefForm,
    node: &NodeId,
    pending: &SelectablePlanPendingRequest,
) -> Result<(Configuration, GuardedCampaignReplayClosure), Box<dyn std::error::Error>> {
    let scenario = ScenarioDefId::from_hash(CampaignHash::from_bytes(source.id().bytes));
    let discovery = resolve_guest_selectable(scenario, source, node, pending)?;
    let selection = Selection::new(
        discovery.opportunity(),
        discovery.domain(),
        discovery.declaration().default().clone(),
        SelectionOrigin::Default,
    )?;
    let target = crucible::try_step(
        &Configuration::genesis(source.scenario_def()),
        Decision::Selection(SelectionDecision::new(&selection)),
    )?;
    let discoveries = BTreeMap::from([(discovery.opportunity().id()?, discovery)]);
    let closure = GuardedCampaignReplayClosure::from_owned_discoveries(
        source,
        &target.schedule,
        &discoveries,
    )?;
    Ok((target, closure))
}

fn refusal_message(
    source: &ScenarioDefForm,
    node: &NodeId,
    target: &Configuration,
    closure: &GuardedCampaignReplayClosure,
    pending: &SelectablePlanPendingRequest,
) -> Result<String, Box<dyn std::error::Error>> {
    let record = closure
        .selection_for_decision(0, &target.schedule)?
        .ok_or("recorded choice absent")?;
    let current = Configuration::genesis(source.scenario_def());
    match recorded_guest_reply(source, node, &current, record, pending) {
        Err(QemuVmRealizationError::InvalidCheckpoint { role, message }) => {
            assert_eq!(role, "guarded replay guest selection");
            assert!(message.starts_with(
                "physical guest request differs from the authenticated replay choice; "
            ));
            Ok(message)
        }
        other => Err(format!("expected original contract refusal, got {other:?}").into()),
    }
}

#[test]
fn matching_contract_preserves_original_reply() -> Result<(), Box<dyn std::error::Error>> {
    let (source, node, [pending, _]) = replay_choice_fixture()?;
    let (target, closure) = recorded_choice(&source, &node, &pending)?;
    let record = closure
        .selection_for_decision(0, &target.schedule)?
        .ok_or("recorded choice absent")?;
    let current = Configuration::genesis(source.scenario_def());
    let scenario = ScenarioDefId::from_hash(CampaignHash::from_bytes(source.id().bytes));
    let discovery = resolve_guest_selectable(scenario, &source, &node, &pending)?;

    let reply = recorded_guest_reply(&source, &node, &current, record, &pending)?;

    assert_eq!(
        reply,
        selected_guest_reply(&pending, &discovery, record.selection())?
    );
    assert_eq!(reply.sequence(), pending.request().sequence());
    Ok(())
}

#[test]
fn raw_coordinate_refusal_retains_expected_and_actual_contracts()
-> Result<(), Box<dyn std::error::Error>> {
    let (source, node, [pending, _]) = replay_choice_fixture()?;
    let (target, closure) = recorded_choice(&source, &node, &pending)?;
    let changed = SelectablePlanPendingRequest::new(
        pending.request().clone(),
        pending.raw_icount() + 1,
        pending.trap_tick_ps() + 50,
        pending.vcpu_index(),
        pending.guest_virtual_address(),
    );
    let scenario = ScenarioDefId::from_hash(CampaignHash::from_bytes(source.id().bytes));
    let expected = resolve_guest_selectable(scenario, &source, &node, &pending)?;
    let actual = resolve_guest_selectable(scenario, &source, &node, &changed)?;

    let message = refusal_message(&source, &node, &target, &closure, &changed)?;

    assert!(message.contains("eq[d,o,m]=true/false/true"));
    assert!(message.contains("req[q,r,t,v]=1,42,2100,0"));
    assert!(message.contains("instance_eq=true pred=OpportunityIdentity"));
    assert!(message.contains(&expected.opportunity().coordinate().scheduler.to_string()));
    assert!(message.contains(&actual.opportunity().coordinate().scheduler.to_string()));
    assert_ne!(
        expected.opportunity().coordinate().scheduler,
        actual.opportunity().coordinate().scheduler
    );
    assert_eq!(
        expected.opportunity().coordinate().producer,
        actual.opportunity().coordinate().producer
    );
    Ok(())
}

#[test]
fn instance_refusal_does_not_dump_guest_instance_text() -> Result<(), Box<dyn std::error::Error>> {
    let (source, node, [pending, _]) = replay_choice_fixture()?;
    let (target, closure) = recorded_choice(&source, &node, &pending)?;
    let changed = SelectablePlanPendingRequest::new(
        SelectionRequest::new(1, "campaign.recovery-policy", "private-instance", None, 256)?,
        pending.raw_icount(),
        pending.trap_tick_ps(),
        pending.vcpu_index(),
        pending.guest_virtual_address(),
    );

    let message = refusal_message(&source, &node, &target, &closure, &changed)?;

    assert!(message.contains("eq[d,o,m]=true/false/true"));
    assert!(message.contains("instance_eq=false pred=OpportunityIdentity"));
    assert!(!message.contains("private-instance"));
    Ok(())
}

#[test]
fn declaration_refusal_identifies_original_declaration_drift()
-> Result<(), Box<dyn std::error::Error>> {
    let (source, node, [pending, _]) = replay_choice_fixture()?;
    let (target, closure) = recorded_choice(&source, &node, &pending)?;
    let declaration = SelectableDeclaration::new(
        "campaign.recovery-policy",
        ChoiceSource::Guest {
            node: node.name.clone(),
            protocol_version: u32::from(crucible_protocol::SELECTABLE_PROTOCOL_VERSION),
        },
        ChoiceDomain::Boolean(BooleanDomain::new(1)?),
        ChoiceValue::Boolean(true),
        ChoiceClassContext::new(BTreeSet::new())?,
        BTreeSet::from([String::from("recovery")]),
        true,
    )?;
    let selectables = ScenarioSelectables::new(
        source.world(),
        ScenarioSelectableLimits::new(4, 8, 16, 32)?,
        vec![declaration],
    )?;
    let changed_source = source.with_selectables(selectables)?;

    let message = refusal_message(&changed_source, &node, &target, &closure, &pending)?;

    assert!(message.contains("eq[d,o,m]=false/false/true"));
    assert!(message.contains("instance_eq=true"));
    Ok(())
}

#[test]
fn narrowed_domain_refusal_retains_original_domain_identities()
-> Result<(), Box<dyn std::error::Error>> {
    let (source, node, [pending, _]) = replay_choice_fixture()?;
    let first = AlternativeId::from_hash(CampaignHash::derive("guarded-replay-test", b"first"));
    let second = AlternativeId::from_hash(CampaignHash::derive("guarded-replay-test", b"second"));
    let alternatives = BTreeMap::from([
        (first, DiscreteAlternative::new(first, "first", None)?),
        (second, DiscreteAlternative::new(second, "second", None)?),
    ]);
    let narrowed = ChoiceDomain::Discrete(DiscreteDomain::new(
        1,
        BTreeMap::from([(first, alternatives[&first].clone())]),
    )?);
    let declaration = SelectableDeclaration::new(
        "campaign.recovery-policy",
        ChoiceSource::Guest {
            node: node.name.clone(),
            protocol_version: u32::from(crucible_protocol::SELECTABLE_PROTOCOL_VERSION),
        },
        ChoiceDomain::Discrete(DiscreteDomain::new(1, alternatives)?),
        ChoiceValue::Discrete(first),
        ChoiceClassContext::new(BTreeSet::new())?,
        BTreeSet::new(),
        true,
    )?;
    let selectables = ScenarioSelectables::new(
        source.world(),
        ScenarioSelectableLimits::new(4, 8, 16, 32)?,
        vec![declaration],
    )?;
    let source = source.with_selectables(selectables)?;
    let (target, closure) = recorded_choice(&source, &node, &pending)?;
    let changed = SelectablePlanPendingRequest::new(
        SelectionRequest::new(
            1,
            "campaign.recovery-policy",
            "first",
            Some(narrowed.canonical_bytes()),
            256,
        )?,
        pending.raw_icount(),
        pending.trap_tick_ps(),
        pending.vcpu_index(),
        pending.guest_virtual_address(),
    );

    let message = refusal_message(&source, &node, &target, &closure, &changed)?;

    assert!(message.contains("eq[d,o,m]=true/false/false"));
    assert!(
        message
            .contains(&CampaignHash::from_bytes(narrowed.id()?.content_id().digest()).to_string())
    );
    Ok(())
}

#[test]
fn maximum_scalar_context_fits_original_promotion_failure_detail()
-> Result<(), Box<dyn std::error::Error>> {
    let (source, node, [pending, _]) = replay_choice_fixture()?;
    let (target, closure) = recorded_choice(&source, &node, &pending)?;
    let changed = SelectablePlanPendingRequest::new(
        SelectionRequest::new(u64::MAX, "campaign.recovery-policy", "first", None, 256)?,
        u64::MAX,
        u64::MAX,
        0,
        pending.guest_virtual_address(),
    );

    let message = refusal_message(&source, &node, &target, &closure, &changed)?;
    let error = QemuVmRealizationError::InvalidCheckpoint {
        role: "guarded replay guest selection",
        message,
    };
    // This is a rendering bound, not a physical execution. Reserve the extra
    // width of usize::MAX decision index, u32::MAX vCPU and false booleans.
    let rendered = format!("Preparation(Realization({error:?}))");
    assert!(rendered.len() + 31 <= 1024, "{} bytes", rendered.len());
    assert!(rendered.ends_with("pred=OpportunityIdentity\" }))"));
    Ok(())
}
