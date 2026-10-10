//! Imports the exact canonical creation closure before authorized head creation.
//!
//! The request and generators remain inside the same artifact owner through
//! service effects and postcuts. The repository checks the request lineage
//! against the actual imported configuration and scenario closure. This does
//! not certify a native executor's build identity or attach an executor.

use crucible_campaign::{
    CandidateGeneratorAlgorithm, CandidateGeneratorSpec, CandidateGeneratorSpecId,
    CreateCampaignRequest,
};

use super::*;

pub(super) struct LoadedGenerator {
    spec: Option<CandidateGeneratorSpec>,
    imported: Option<CandidateGeneratorSpecId>,
}

pub(super) fn load_and_create(
    model: &mut LoadedAttempt,
    files: &mut Vec<PinnedInput>,
    attempt: &projection::Attempt,
    budget: &DecodeBudget,
    service: &OriginalPreparedCampaignServiceOwner,
    check: &ArtifactWork<'_, '_>,
) -> Result<(), ArtifactRefusal> {
    let creation = &attempt.campaign_creation;
    let request_index = pin_compact(
        files,
        &creation.request_file,
        &creation.request_blake3,
        budget,
        check,
    )?;
    let work = (|| {
        budget.verify_live()?;
        let _scope = budget.enter();
        let bytes = files[request_index]
            .bytes
            .as_deref()
            .ok_or(ArtifactCause::Identity)?;
        if bytes.len() as u64 != creation.request_bytes {
            return Err(ArtifactCause::Identity);
        }
        model.request = Some(CreateCampaignRequest::from_canonical_bytes(bytes)?);
        let request = model.request.as_ref().ok_or(ArtifactCause::Identity)?;
        if request.campaign().as_str() != attempt.campaign
            || request.request_digest() != creation.request_digest
            || request.lineage().id()? != creation.lineage_id
            || request.policy().id()? != creation.policy_id
            || request.lineage().scenario() != attempt.scenario_id
            || Some(request.lineage().genesis_content()) != model.imported
            || request.lineage().crucible_version() != env!("CARGO_PKG_VERSION")
            || request.lineage().protocol_versions().len() != 2
            || request.lineage().protocol_versions().get("control")
                != Some(&crucible_protocol::CONTROL_PROTOCOL_VERSION)
            || request.lineage().protocol_versions().get("shared-memory")
                != Some(&crucible_shmem::ABI_VERSION)
            || request.lineage().scenario_schema() != crate::CRUCIBLE_SCENARIO_PAYLOAD_SCHEMA_V5
            || request.lineage().exact_closure_schema()
                != crate::EXACT_CHECKPOINT_ROOT_SCHEMA_VERSION
            || request.policy().statistical_sampling_design().is_some()
            || request.policy().sequential_monte_carlo_design().is_some()
        {
            return Err(ArtifactCause::Identity);
        }
        budget.charge_array::<LoadedGenerator>(creation.generators.len())?;
        model
            .generators
            .try_reserve_exact(creation.generators.len())?;
        budget.check()?;
        Ok(())
    })();
    checked(check, work)?;

    for record in &creation.generators {
        let index = pin_compact(files, &record.file, &record.blake3, budget, check)?;
        model.generators.push(LoadedGenerator {
            spec: None,
            imported: None,
        });
        let generator = model
            .generators
            .last_mut()
            .ok_or_else(|| check.error(ArtifactCause::Identity))?;
        let work = (|| {
            budget.verify_live()?;
            let _scope = budget.enter();
            let bytes = files[index]
                .bytes
                .as_deref()
                .ok_or(ArtifactCause::Identity)?;
            if bytes.len() as u64 != record.bytes {
                return Err(ArtifactCause::Identity);
            }
            generator.spec = Some(CandidateGeneratorSpec::from_canonical_bytes(bytes)?);
            if generator
                .spec
                .as_ref()
                .ok_or(ArtifactCause::Identity)?
                .id()?
                != record.id
            {
                return Err(ArtifactCause::Identity);
            }
            budget.check()?;
            Ok(())
        })();
        checked(check, work)?;
    }
    checked(check, validate_closure(model, creation, budget, check))?;

    for (generator, record) in model.generators.iter_mut().zip(&creation.generators) {
        let imported = service.import_generator(
            generator
                .spec
                .as_ref()
                .ok_or_else(|| check.error(ArtifactCause::Identity))?,
        );
        let work = imported
            .inspect(|&id| {
                generator.imported = Some(id);
            })
            .map_err(Into::into);
        if checked(check, work)? != record.id {
            return checked(check, Err(ArtifactCause::Identity));
        }
    }
    let request = model
        .request
        .as_ref()
        .ok_or_else(|| check.error(ArtifactCause::Identity))?;
    let work = service
        .create_campaign(request)
        .map(|response| {
            model.response = Some(response);
        })
        .map_err(Into::into);
    checked(check, work)?;
    checked(
        check,
        model
            .response
            .as_ref()
            .ok_or(ArtifactCause::Identity)
            .and_then(|response| response.validate_for(request).map_err(Into::into)),
    )
}

fn validate_closure(
    model: &LoadedAttempt,
    creation: &projection::CampaignCreation,
    budget: &DecodeBudget,
    check: &ArtifactWork<'_, '_>,
) -> Result<(), ArtifactCause> {
    let count = creation.generators.len();
    // A single prepaid visited array replaces allocating maps and a pending
    // stack. Each pass adds a new reachable record or terminates within count.
    let credit = budget.reserve_scratch_array::<bool>(count)?;
    let mut reached = Vec::new();
    reached.try_reserve_exact(count)?;
    reached.resize(count, false);
    let index = |id| {
        creation
            .generators
            .binary_search_by_key(&id, |record| record.id)
            .map_err(|_| ArtifactCause::Identity)
    };
    let request = model.request.as_ref().ok_or(ArtifactCause::Identity)?;
    for choice in request.policy().choice_policies().values() {
        reached[index(choice.generator())?] = true;
    }
    for _ in 0..=count {
        check.verify_original()?;
        budget.verify_live()?;
        let mut changed = false;
        for (position, generator) in model.generators.iter().enumerate() {
            if !reached[position] {
                continue;
            }
            if let CandidateGeneratorAlgorithm::OrderedMixture { components } = generator
                .spec
                .as_ref()
                .ok_or(ArtifactCause::Identity)?
                .algorithm()
            {
                for component in components {
                    let child = index(component.generator())?;
                    changed |= !reached[child];
                    reached[child] = true;
                }
            }
        }
        if !changed {
            if reached.iter().any(|reached| !reached) {
                return Err(ArtifactCause::Identity);
            }
            drop(reached);
            drop(credit);
            return Ok(());
        }
    }
    Err(ArtifactCause::Identity)
}
