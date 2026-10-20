//! Requires actual node-stage storage and physical-first error propagation.

use super::*;
use super::super::super::{mask_contract, read_companions, replace_one_obligation, source_pattern};

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
        let masked = mask_contract(contract, &code, &companions);
        assert_ne!(masked, code);
        assert!(crate::flaky_escape_failures("unreviewed", "unreviewed", &masked).is_empty());
        Ok(Self {
            contract,
            code,
            companions,
        })
    }

    fn rejects(&self, fact: &Companion, before: &str, after: &str) {
        let clause = fact
            .required
            .iter()
            .find_map(|(text, _)| {
                source_pattern(text)
                    .contains(&source_pattern(before))
                    .then_some(*text)
            })
            .expect("mutation must alter an exact reviewed owner or return clause");
        let changed_clause = replace_one_obligation(
            &crate::scrub_comments_and_strings(clause),
            &source_pattern(before),
            after,
        );
        let mut code = self.code.clone();
        let mut companions = self.companions.clone();
        let local_path = format!("{}/{}.rs", self.contract.package, self.contract.target);
        let mut applied = false;
        if fact.path.ends_with(&local_path) && self.contract.required == fact.required {
            code = replace_one_obligation(&code, &source_pattern(clause), &changed_clause);
            assert_ne!(code, self.code);
            applied = true;
        }
        for (index, binding) in self.contract.companions.iter().enumerate() {
            if binding.path == fact.path && binding.required == fact.required {
                let evidence = crate::scrub_comments_and_strings(&self.companions[index]);
                companions[index] =
                    replace_one_obligation(&evidence, &source_pattern(clause), &changed_clause);
                assert_ne!(companions[index], evidence);
                applied = true;
            }
        }
        assert!(
            applied,
            "same actual shared node fact is required: {}",
            fact.path
        );
        assert_eq!(
            mask_contract(self.contract, &code, &companions),
            code,
            "{} concealed changed node custody: {before}",
            self.contract.target
        );
        assert!(!crate::flaky_escape_failures("unreviewed", "unreviewed", &code).is_empty());
    }
}

#[test]
fn node_construction_contracts_preserve_stages_physical_return_and_independent_posts()
-> Result<(), Box<dyn std::error::Error>> {
    let cases: &[(&Companion, &str, &str)] = &[
        (
            &NODE_BIRTH,
            r#"node.world == world && node.is_constructing()"#,
            r#"false"#,
        ),
        (
            &NODE_BIRTH,
            r#"self.nodes[index] = Some(NormalNode::constructing(world));"#,
            r#"self.nodes[index] = None;"#,
        ),
        (
            &NODE_BIRTH,
            r#"node.prepare(claim, request.node, original, controls)?;"#,
            r#"node.prepare(claim, foreign_node, original, controls)?;"#,
        ),
        (
            &NODE_BIRTH,
            r#"OriginalNativeAccountRoster::shared_allocation_extent()?"#,
            r#"0"#,
        ),
        (
            &NODE_BIRTH,
            r#"let closed = node.try_close(); let returned = node.can_remove();"#,
            r#"let returned = true; let closed = node.try_close();"#,
        ),
        (
            &NODE_BIRTH,
            r#"if returned { *entry = None; }"#,
            r#"*entry = None;"#,
        ),
        (
            &NODE_BIRTH,
            r#"if self.nodes.iter().flatten().any(|node| node.world == index)"#,
            r#"if false"#,
        ),
        (
            &NODE_BIRTH,
            r#"let returned = claim.is_physically_returned();"#,
            r#"let returned = result.is_ok();"#,
        ),
        (
            &NODE_OWNER,
            r#"if self.attempted || !self.is_empty()"#,
            r#"if false"#,
        ),
        (
            &NODE_OWNER,
            r#"self.attempted = true; claim.take_node_into(node, &mut self.node)?;"#,
            r#"claim.take_node_into(node, &mut self.node)?; self.attempted = true;"#,
        ),
        (
            &NODE_OWNER,
            r#"claim.take_node_into(node, &mut self.node)?;"#,
            r#"claim.take_node_into(node, &mut foreign.node)?;"#,
        ),
        (
            &NODE_OWNER,
            r#"&mut self.node, &mut self.subdivision, original,"#,
            r#"&mut self.node, &mut foreign.subdivision, original,"#,
        ),
        (
            &NODE_OWNER,
            r#"&mut self.subdivision, &mut self.credit, original, controls,"#,
            r#"&mut self.subdivision, &mut foreign.credit, original, controls,"#,
        ),
        (
            &NODE_OWNER,
            r#"let (roster, binding) = construction.prepare(claim, node, original, controls)?;"#,
            r#"let (roster, binding) = foreign.prepare(claim, node, original, controls)?;"#,
        ),
        (
            &NODE_OWNER,
            r#"NormalNodeState::Constructing(_) => None"#,
            r#"NormalNodeState::Constructing(_) => foreign.binding()"#,
        ),
        (
            &NODE_OWNER,
            r#"if owners > 1 || (!self.attempted && owners != 0)"#,
            r#"if false"#,
        ),
        (
            &NODE_OWNER,
            r#"drop(binding.take()); roster.try_close()"#,
            r#"roster.try_close()"#,
        ),
        (
            &NODE_OWNER,
            r#"NormalNodeState::Published { roster, .. } => roster.is_physically_returned()"#,
            r#"NormalNodeState::Published { roster, .. } => true"#,
        ),
        (
            &NODE_OWNER,
            r#"if node.is_physically_returned() { self.node = None; } result?;"#,
            r#"self.node = None; result?;"#,
        ),
        (
            &NODE_OWNER,
            r#"if purpose.is_physically_returned() { self.subdivision = None; } result?;"#,
            r#"result?; self.subdivision = None;"#,
        ),
        (
            &NODE_OWNER,
            r#"if credit.is_physically_returned() { self.credit = None; } result?;"#,
            r#"self.credit = None; result?;"#,
        ),
        (
            &NODE_OWNER,
            r#"let cleanup = purpose.retained_world_cleanup()?;"#,
            r#"let cleanup = renewed_cleanup()?;"#,
        ),
        (&NODE_ISSUE, r#"if destination.is_some()"#, r#"if false"#),
        (
            &NODE_ISSUE,
            r#"held.root.verify_native_preparation(&self.original)?;"#,
            r#"Ok::<(), ServiceBirthError>(())?;"#,
        ),
        (
            &NODE_ISSUE,
            r#"*destination = Some(AuthenticatedNativeNodeClaim {"#,
            r#"*foreign_destination = Some(AuthenticatedNativeNodeClaim {"#,
        ),
        (
            &NODE_ISSUE,
            r#"world_epoch: self.epoch,"#,
            r#"world_epoch: foreign_epoch,"#,
        ),
        (
            &NODE_ISSUE,
            r#"let after = postcut(self.held.as_ref(), &self.original);"#,
            r#"let after = None;"#,
        ),
        (
            &NODE_CONVERSION,
            r#"if destination.is_some()"#,
            r#"if false"#,
        ),
        (
            &NODE_CONVERSION,
            r#"let bounds = node.bounds()?; let node = source.take()"#,
            r#"let node = source.take(); let bounds = node.bounds()?; let node = node"#,
        ),
        (
            &NODE_CONVERSION,
            r#"*destination = Some(AuthenticatedNativeSubdivision {"#,
            r#"*foreign_destination = Some(AuthenticatedNativeSubdivision {"#,
        ),
        (
            &NODE_CONVERSION,
            r#"let after = postcut(held.as_ref(), original);"#,
            r#"let after = None;"#,
        ),
        (
            &NODE_CONVERSION,
            r#"ledger.node_bounds(self.world_epoch, self.assignment_epoch, self.node_index)?;"#,
            r#"ledger.node_bounds(foreign_epoch, self.assignment_epoch, self.node_index)?;"#,
        ),
        (
            &NODE_CONVERSION,
            r#"if !Arc::ptr_eq(&saved, cleanup)"#,
            r#"if false"#,
        ),
        (
            &NODE_CONVERSION,
            r#"self.verify_world_cleanup(&saved)?;"#,
            r#"Ok::<(), ServiceBirthError>(())?;"#,
        ),
        (
            &NODE_CONVERSION,
            r#"ledger.commit_node_return(prepared);"#,
            r#"discard_return_receipt(prepared);"#,
        ),
        (
            &NODE_CONVERSION,
            r#"drop(self.held.take());"#,
            r#"retain_returned_holder();"#,
        ),
        (
            &NODE_CONVERSION,
            r#"saved.verify_operation_class(crate::host_supervision::HostOperationClass::Cleanup)"#,
            r#"Ok(())"#,
        ),
        (&NODE_CONVERSION, r#"self.held.is_none()"#, r#"true"#),
        (
            &NODE_SUBDIVISION,
            r#"node.retire_after_control_free(cleanup)"#,
            r#"foreign.retire_after_control_free(cleanup)"#,
        ),
        (
            &NODE_SUBDIVISION,
            r#"is_some_and(|node| node.is_physically_returned())"#,
            r#"is_some_and(|node| true)"#,
        ),
        (
            &NODE_CREDIT_BIRTH,
            r#"if destination.is_some()"#,
            r#"if false"#,
        ),
        (
            &NODE_CREDIT_BIRTH,
            r#"purpose.verify_native_preparation(preparation)?;"#,
            r#"Ok::<(), ServiceBirthError>(())?;"#,
        ),
        (
            &NODE_CREDIT_BIRTH,
            r#"if bounds.cpu_slots == 0 || controls > bounds.metadata_bytes"#,
            r#"if false"#,
        ),
        (
            &NODE_CREDIT_BIRTH,
            r#"normal: Some(purpose),"#,
            r#"normal: None,"#,
        ),
        (
            &NODE_CREDIT_BIRTH,
            r#"preparation: Arc::clone(preparation),"#,
            r#"preparation: Arc::clone(foreign_preparation),"#,
        ),
        (
            &NODE_CREDIT_BIRTH,
            r#"normal_controls_bytes: controls,"#,
            r#"normal_controls_bytes: 0,"#,
        ),
        (
            &NODE_PUBLISHER,
            r#"retained.normal_controls_bytes != controls"#,
            r#"false"#,
        ),
        (
            &NODE_PUBLISHER,
            r#"retained.original.as_ref().and_then(|original| original.normal.as_ref()).is_none()"#,
            r#"false"#,
        ),
        (
            &NODE_PUBLISHER,
            r#"let credit = credit.take().ok_or(OriginalActorAccountError::Unavailable)?;"#,
            r#"let credit = foreign_credit.take().ok_or(OriginalActorAccountError::Unavailable)?;"#,
        ),
        (
            &NODE_PUBLISHER,
            r#"credits.iter().take(width).any(Option::is_none)"#,
            r#"false"#,
        ),
        (
            &NODE_PUBLISHER,
            r#"credits.iter().skip(width).any(Option::is_some)"#,
            r#"false"#,
        ),
        (
            &NODE_PUBLISHER,
            r#"next_generation: 1,"#,
            r#"next_generation: 0,"#,
        ),
        (
            &NODE_PUBLISHER,
            r#"launch_in_flight: false,"#,
            r#"launch_in_flight: true,"#,
        ),
        (
            &NODE_PUBLISHER,
            r#"retiring_credits: std::array::from_fn(|_| None),"#,
            r#"retiring_credits: foreign_credits,"#,
        ),
        (
            &NODE_LEDGER,
            r#"world.epoch == epoch && world.window.is_some()"#,
            r#"world.epoch == epoch"#,
        ),
        (
            &NODE_LEDGER,
            r#"slot.world_epoch == epoch && slot.request.node == node && !slot.issued"#,
            r#"slot.request.node == node"#,
        ),
        (
            &NODE_LEDGER,
            r#"world.node_constructor_entered = true;"#,
            r#"world.node_constructor_entered = false;"#,
        ),
        (
            &NODE_RETURN_HISTORY,
            r#"first: result.err(),"#,
            r#"first: None,"#,
        ),
        (
            &NODE_RETURN_HISTORY,
            r#"post: post.err(),"#,
            r#"post: None,"#,
        ),
        (
            &NODE_LAYOUT,
            r#"std::alloc::Layout::array::<Option<NormalNode>>(capacity)"#,
            r#"std::alloc::Layout::array::<()>(capacity)"#,
        ),
        (
            &NODE_ROSTER_RETURN,
            r#"Arc::get_mut(held)"#,
            r#"Arc::make_mut(held)"#,
        ),
        (
            &NODE_ROSTER_RETURN,
            r#"*retained = slot.credit.take();"#,
            r#"drop(slot.credit.take());"#,
        ),
        (
            &NODE_ROSTER_RETURN,
            r#"if credit.is_physically_returned()"#,
            r#"if true"#,
        ),
        (
            &NODE_ROSTER_RETURN,
            r#"drop(self.held.take()); post_free();"#,
            r#"post_free(); drop(self.held.take());"#,
        ),
        (
            &NODE_CREDIT_RETURN,
            r#"let cleanup = normal.retained_world_cleanup()?;"#,
            r#"let cleanup = renewed_cleanup()?;"#,
        ),
        (
            &NODE_CREDIT_RETURN,
            r#"if normal.is_physically_returned()"#,
            r#"if true"#,
        ),
    ];
    for contract in [
        &CONTRACT,
        super::super::NORMAL_WORLD,
        &super::super::super::retained_continuations::CONTRACTS[0],
        &super::super::super::retained_continuations::CONTRACTS[1],
        &super::super::super::constructor_continuations::CONTRACTS[4],
        &super::super::super::constructor_continuations::CONTRACTS[5],
    ] {
        let fixture = Fixture::load(contract)?;
        for (fact, before, after) in cases {
            fixture.rejects(fact, before, after);
        }
    }
    Ok(())
}
