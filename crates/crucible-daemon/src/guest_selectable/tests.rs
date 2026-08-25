//! Guest selectable semantic-resolution regressions.

use std::collections::BTreeSet;
use std::error::Error;

use crucible::{
    Icount, NodeTemplate, Plan, Properties, ReadyPoint, ScenarioSelectableLimits,
    ScenarioSelectables, Seed, WhiteBoxPolicy, World, WorldNode,
};
use crucible_campaign::{
    BooleanDomain, CampaignHash, ChoiceClassContext, ChoiceDomain, ChoiceSource, ChoiceValue,
    ExactRational, IntegerDomain, IntegerRepresentation, IntegerValue, ScenarioDefId,
    SelectableDeclaration, Selection, SelectionOrigin,
};
use crucible_protocol::SelectionRequest;
use crucible_protocol::selectable_catalog_plan::SelectablePlanPendingRequest;

use super::*;

fn fixture() -> Result<(ScenarioDefForm, NodeId), Box<dyn Error>> {
    let node = NodeId {
        name: String::from("router-a"),
    };
    let world = World::from_nodes(vec![WorldNode {
        id: node.clone(),
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::from("guest-selectable-test"),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 1 },
        },
        white_box: WhiteBoxPolicy::Enabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }])?;
    let declaration = SelectableDeclaration::new(
        "product.recovery",
        ChoiceSource::Guest {
            node: node.name.clone(),
            protocol_version: u32::from(crucible_protocol::SELECTABLE_PROTOCOL_VERSION),
        },
        ChoiceDomain::Boolean(BooleanDomain::new(1)?),
        ChoiceValue::Boolean(false),
        ChoiceClassContext::new(BTreeSet::new())?,
        BTreeSet::from([String::from("recovery")]),
        true,
    )?;
    let selectables = ScenarioSelectables::new(
        &world,
        ScenarioSelectableLimits::new(4, 8, 16, 32)?,
        vec![declaration],
    )?;
    let scenario = ScenarioDefForm::from_components(
        &world,
        &Plan::empty(),
        &Properties::empty(),
        Seed::from_u64(7),
    )?
    .with_selectables(selectables)?;
    Ok((scenario, node))
}

fn pending(
    selectable: &str,
    narrowed: Option<Vec<u8>>,
) -> Result<SelectablePlanPendingRequest, Box<dyn Error>> {
    Ok(SelectablePlanPendingRequest::new(
        SelectionRequest::new(9, selectable, "routing-epoch-7", narrowed, 256)?,
        41,
        2,
        0x1000,
    ))
}

#[test]
fn scenario_request_resolves_and_builds_exact_default_reply() -> Result<(), Box<dyn Error>> {
    let (scenario, node) = fixture()?;
    let scenario_id = ScenarioDefId::from_hash(CampaignHash::from_bytes(scenario.id().bytes));
    let pending = pending("product.recovery", None)?;
    let discovery = resolve_guest_selectable(scenario_id, &scenario, &node, &pending)?;
    let another_transport_incarnation = SelectablePlanPendingRequest::new(
        SelectionRequest::new(10, "product.recovery", "routing-epoch-7", None, 256)?,
        41,
        2,
        0x2000,
    );
    let replayed = resolve_guest_selectable(
        scenario_id,
        &scenario,
        &node,
        &another_transport_incarnation,
    )?;
    assert_eq!(replayed.opportunity(), discovery.opportunity());
    let selection = Selection::new(
        discovery.opportunity(),
        discovery.domain(),
        discovery.opportunity().default().clone(),
        SelectionOrigin::Default,
    )?;
    let reply = selected_guest_reply(&pending, &discovery, &selection)?;

    assert_eq!(reply.sequence(), 9);
    assert_eq!(
        *reply.opportunity_id(),
        discovery.opportunity().id()?.content_id().digest()
    );
    assert_eq!(
        *reply.domain_id(),
        discovery.domain().id()?.content_id().digest()
    );
    assert_eq!(
        reply.selected_value(),
        Some(ChoiceValue::Boolean(false).canonical_bytes().as_slice())
    );
    Ok(())
}

#[test]
fn request_rejects_unknown_source_and_broadened_domain() -> Result<(), Box<dyn Error>> {
    let (scenario, node) = fixture()?;
    let scenario_id = ScenarioDefId::from_hash(CampaignHash::from_bytes(scenario.id().bytes));
    assert!(matches!(
        resolve_guest_selectable(
            scenario_id,
            &scenario,
            &node,
            &pending("product.missing", None)?,
        ),
        Err(GuestSelectableError::UnknownSelectable(_))
    ));
    assert!(matches!(
        resolve_guest_selectable(
            scenario_id,
            &scenario,
            &NodeId {
                name: String::from("router-b")
            },
            &pending("product.recovery", None)?,
        ),
        Err(GuestSelectableError::SourceMismatch { .. })
    ));
    let changed_version = ChoiceDomain::Boolean(BooleanDomain::new(2)?).canonical_bytes();
    assert!(matches!(
        resolve_guest_selectable(
            scenario_id,
            &scenario,
            &node,
            &pending("product.recovery", Some(changed_version))?,
        ),
        Err(GuestSelectableError::Campaign(_))
    ));
    Ok(())
}

#[test]
fn integer_runtime_offer_may_narrow_but_never_broaden_scenario_domain() -> Result<(), Box<dyn Error>>
{
    let (base, node) = fixture()?;
    let declared = ChoiceDomain::Integer(IntegerDomain::new(
        1,
        IntegerRepresentation::Unsigned64,
        IntegerValue::Unsigned(0),
        IntegerValue::Unsigned(10),
        1,
        Some(String::from("ms")),
        ExactRational::new(1, 1)?,
        vec![IntegerValue::Unsigned(0), IntegerValue::Unsigned(10)],
    )?);
    let declaration = SelectableDeclaration::new(
        "product.retry-delay",
        ChoiceSource::Guest {
            node: node.name.clone(),
            protocol_version: u32::from(crucible_protocol::SELECTABLE_PROTOCOL_VERSION),
        },
        declared,
        ChoiceValue::Integer(IntegerValue::Unsigned(0)),
        ChoiceClassContext::new(BTreeSet::new())?,
        BTreeSet::new(),
        true,
    )?;
    let selectables = ScenarioSelectables::new(
        base.world(),
        ScenarioSelectableLimits::new(4, 8, 16, 32)?,
        vec![declaration],
    )?;
    let scenario = ScenarioDefForm::from_components(
        base.world(),
        &Plan::empty(),
        &Properties::empty(),
        Seed::from_u64(8),
    )?
    .with_selectables(selectables)?;
    let scenario_id = ScenarioDefId::from_hash(CampaignHash::from_bytes(scenario.id().bytes));
    let narrowed = ChoiceDomain::Integer(IntegerDomain::new(
        1,
        IntegerRepresentation::Unsigned64,
        IntegerValue::Unsigned(0),
        IntegerValue::Unsigned(5),
        1,
        Some(String::from("ms")),
        ExactRational::new(1, 1)?,
        vec![IntegerValue::Unsigned(0), IntegerValue::Unsigned(5)],
    )?);
    let request = pending("product.retry-delay", Some(narrowed.canonical_bytes()))?;
    let discovery = resolve_guest_selectable(scenario_id, &scenario, &node, &request)?;
    assert_eq!(discovery.domain(), &narrowed);

    let broadened = ChoiceDomain::Integer(IntegerDomain::new(
        1,
        IntegerRepresentation::Unsigned64,
        IntegerValue::Unsigned(0),
        IntegerValue::Unsigned(11),
        1,
        Some(String::from("ms")),
        ExactRational::new(1, 1)?,
        vec![IntegerValue::Unsigned(0), IntegerValue::Unsigned(11)],
    )?);
    assert!(matches!(
        resolve_guest_selectable(
            scenario_id,
            &scenario,
            &node,
            &pending("product.retry-delay", Some(broadened.canonical_bytes()))?,
        ),
        Err(GuestSelectableError::Campaign(_))
    ));
    Ok(())
}
