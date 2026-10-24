//! Checks the actual independent response owners used by preparation storage.
//!
//! These typed data fixtures create no controller, process, Source or admission.

use crucible_node_format::{ContentRef, canonical};
use crucible_node_transport::{
    bodies::*, envelope::Nullable, retained_metadata::RetainedCommonProtocolData,
};

use super::super::{
    PacketCompleteSemanticSource,
    retained_storage::preparation::{PreparationCounter, charge_responses},
};
use super::{packet_definition::Definition, packet_protocol::Bootstrap};
use crate::node_contract::RuntimeError;

fn responses() -> Result<(DiscoverResult, RealizeResult), Box<dyn std::error::Error>> {
    let executable = canonical::content_ref(b"typed storage fixture", "application/octet-stream")?;
    let definition = Definition::new(executable);
    let bootstrap = Bootstrap::new(&definition);
    Ok((
        DiscoverResult {
            provider_manifest: bootstrap.manifest,
            profiles: Vec::with_capacity(17),
            facet_schemas: Vec::with_capacity(23),
            complete: true,
            next_cursor: Nullable(None),
        },
        RealizeResult {
            realization_manifest: bootstrap.realization,
            prepared_token: crucible_node_format::Id::new("actual-typed-response")?,
            closed_gate_receipt: canonical::content_ref(b"closed", "application/octet-stream")?,
        },
    ))
}

fn bytes(discovery: &DiscoverResult, realization: &RealizeResult) -> Result<usize, RuntimeError> {
    let mut counter = PreparationCounter::new(usize::MAX);
    charge_responses(discovery, realization, &mut counter)?;
    Ok(counter.finish().known_requested_bytes())
}

#[test]
fn actual_independent_responses_admit_exact_and_refuse_one_short()
-> Result<(), Box<dyn std::error::Error>> {
    let (discovery, realization) = responses()?;
    let total = bytes(&discovery, &realization)?;
    let mut exact = PreparationCounter::new(total);
    charge_responses(&discovery, &realization, &mut exact)?;
    assert_eq!(exact.finish().known_requested_bytes(), total);

    let mut short = PreparationCounter::new(total - 1);
    assert_eq!(
        charge_responses(&discovery, &realization, &mut short),
        Err(RuntimeError::ResourceLimit)
    );
    Ok(())
}

#[test]
fn actual_empty_spare_vectors_and_string_growth_are_independent_terms()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut discovery, mut realization) = responses()?;
    let before = bytes(&discovery, &realization)?;
    let profile_capacity = discovery.profiles.capacity();
    let string_capacity = realization.closed_gate_receipt.media_type.capacity();

    discovery.profiles.reserve_exact(37);
    realization
        .closed_gate_receipt
        .media_type
        .reserve_exact(4096);
    let expected_growth = (discovery.profiles.capacity() - profile_capacity)
        * std::mem::size_of::<crucible_node_format::NodeManifest>()
        + realization.closed_gate_receipt.media_type.capacity()
        - string_capacity;

    assert!(discovery.profiles.is_empty());
    assert!(expected_growth > 0);
    assert_eq!(bytes(&discovery, &realization)? - before, expected_growth);
    Ok(())
}

#[test]
fn independent_response_backing_matches_both_typed_rosters()
-> Result<(), Box<dyn std::error::Error>> {
    let (discovery, realization) = responses()?;
    let mut expected = 0usize;
    for view in [
        RetainedCommonProtocolData::Discover(&discovery),
        RetainedCommonProtocolData::Realize(&realization),
    ] {
        let facts = view.observe_retained_metadata()?;
        expected +=
            PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(
                &facts,
                usize::MAX,
            )?;
    }

    assert_eq!(bytes(&discovery, &realization)?, expected);
    Ok(())
}

#[test]
fn bound_refusal_preserves_actual_response_banks_and_content()
-> Result<(), Box<dyn std::error::Error>> {
    let (discovery, realization) = responses()?;
    let before = serde_json::to_vec(&(&discovery, &realization))?;
    let pointer = discovery.profiles.as_ptr();
    let capacity = discovery.profiles.capacity();
    let reference: &ContentRef = &realization.closed_gate_receipt;
    let media_pointer = reference.media_type.as_ptr();
    let media_capacity = reference.media_type.capacity();
    let mut counter = PreparationCounter::new(0);

    assert_eq!(
        charge_responses(&discovery, &realization, &mut counter),
        Err(RuntimeError::ResourceLimit)
    );
    assert_eq!(discovery.profiles.as_ptr(), pointer);
    assert_eq!(discovery.profiles.capacity(), capacity);
    assert_eq!(reference.media_type.as_ptr(), media_pointer);
    assert_eq!(reference.media_type.capacity(), media_capacity);
    assert_eq!(serde_json::to_vec(&(&discovery, &realization))?, before);
    Ok(())
}
