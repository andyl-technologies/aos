//! Checks normalization/native correspondence over actual inherited input banks.
//!
//! Structured fixtures prove framing and exact historical DATA joins only. Their
//! inert graph/lineage cannot construct a sealed native owner or a live model.

use super::*;
use crate::protocol_snapshot::restored_settled17::{
    NativeCold17Admission, NativeCold17ConstructionData, NativeCold17PrewalkData, NativeCold17Work,
};
use crate::reference_packet::service::ack_emitter::native_boot::bootstrap_import18::normalization::OriginalImport18NormalizationAdmission;
use crate::reference_packet::service::complete_restore::import18::{
    OriginalImport18NormalizationAttempt, native_import18_reference_identity_data,
};
use crucible_node_format::{ContentRef, U64};
use std::cell::Cell;

fn roles(case: &str) -> [(ContentRef, Vec<u8>); 7] {
    let mut roles = native_framing::roles("initial_framing_complete");
    let mut snapshot = canonical::parse_json(&roles[3].1, usize::MAX).unwrap();
    let before_capacity = snapshot["protocol"][2].as_u64().unwrap();
    if matches!(
        case,
        "initial_context_before_spare_short" | "initial_context_before_spare_exact"
    ) {
        snapshot["protocol"][2] = json!(before_capacity + 7);
        roles[3].1 = canonical::canonical_json(&snapshot).unwrap();
        roles[3].0 = canonical::content_ref(&roles[3].1, "application/json").unwrap();
    }
    let source = canonical::content_ref(
        br#"{"inert":"semantic"}"#,
        "application/vnd.source-owned.packet-semantic-custody.v17+json",
    )
    .unwrap();
    let mut journal = canonical::parse_json(&roles[4].1, usize::MAX).unwrap();
    journal["objects"]["semantic"] = json!(source);
    journal["objects"]["snapshot"] = json!(roles[3].0);
    roles[4].1 = canonical::canonical_json(&journal).unwrap();
    roles[4].0 = canonical::content_ref(&roles[4].1, "application/json").unwrap();

    let mut normal = normalization::normalization("initial_normalization_complete");
    for (field, index) in [
        ("native_after", 0),
        ("native_control", 1),
        ("native_anchor", 2),
        ("native_snapshot", 3),
        ("native_journal", 4),
    ] {
        normal[field] = json!(roles[index].0);
    }
    normal["native_before"] = snapshot["protocol"][1].clone();
    normal["semantic_spend"] = json!(roles[6].0);
    normal["semantic_spend_maximum"] = json!(roles[6].0.length);
    normal["source17"] = json!(source);
    normal["source_runtime"] = journal["objects"]["runtime_object"].clone();
    normal["limits"]["role_maximums"] = json!([
        roles[3].0.length,
        roles[0].0.length,
        roles[1].0.length,
        roles[2].0.length,
        roles[4].0.length,
    ]);
    match case {
        "initial_context_before_capacity_short" => {
            normal["limits"]["maximum_before_bytes"] = json!(U64::new(before_capacity - 1))
        }
        "initial_context_before_capacity_exact" | "initial_context_before_spare_short" => {
            normal["limits"]["maximum_before_bytes"] = json!(U64::new(before_capacity))
        }
        "initial_context_before_spare_exact" => {
            normal["limits"]["maximum_before_bytes"] = json!(U64::new(before_capacity + 7))
        }
        "initial_context_before" => normal["native_before"] = json!(roles[0].0),
        "initial_context_before_media" => {
            normal["native_before"]["media_type"] = json!("text/plain")
        }
        "initial_context_semantic" => normal["source17"]["hash"]["digest"] = json!("a".repeat(64)),
        "initial_context_runtime" => normal["source_runtime"] = json!(roles[1].0),
        "initial_context_runtime_media" => {
            normal["source_runtime"]["media_type"] = json!("text/plain")
        }
        _ => {}
    }
    roles[5].1 = canonical::canonical_json(&normal).unwrap();
    roles[5].0 = canonical::content_ref(&roles[5].1, "application/json").unwrap();
    roles
}

pub(super) fn commit_recipe(case: &str, recipe: &mut Value) {
    let roles = roles(case);
    let archive = [3, 0, 1, 2, 4].map(|index| &roles[index].0);
    recipe["archived_reference_identities"] =
        json!(archive.map(|reference| native_import18_reference_identity_data(reference).unwrap()));
    recipe["archived_lengths"] = json!(archive.map(|reference| reference.length));
    recipe["semantic_reference_identity"] =
        json!(native_import18_reference_identity_data(&roles[6].0).unwrap());
    recipe["semantic_length"] = json!(roles[6].0.length);
    recipe["semantic_spend_maximum"] = json!(roles[6].0.length);
    for (index, reference) in archive.into_iter().enumerate() {
        recipe["decoder_limits"][index] = json!(reference.length);
    }
    let normal = canonical::parse_json(&roles[5].1, usize::MAX).unwrap();
    for (index, name) in [
        "immutable_objects",
        "immutable_bytes",
        "immutable_depth",
        "maximum_nodes",
        "maximum_requested_bytes",
    ]
    .into_iter()
    .enumerate()
    {
        recipe["decoder_limits"][index + 5] = normal["limits"][name].clone();
    }
    recipe["maximum_target_requested_bytes"] =
        normal["limits"]["maximum_target_requested_bytes"].clone();
    recipe["maximum_before_bytes"] = normal["limits"]["maximum_before_bytes"].clone();
    recipe["normalization_projection_bytes"] = json!(roles[5].0.length);
    recipe["normalization_maximum"] = json!("65536");
}

struct Admission<'a> {
    case: &'a str,
    normalization_calls: Cell<usize>,
    framing_calls: Cell<usize>,
}

impl OriginalImport18NormalizationAdmission for Admission<'_> {
    fn construct_data(
        &self,
        attempt: &OriginalImport18NormalizationAttempt,
        row: [usize; 3],
    ) -> Result<(), ProviderError> {
        assert_eq!(self.normalization_calls.replace(1), 0);
        assert!(attempt.decoded.is_none());
        assert!(row.into_iter().all(|axis| axis > 0));
        Ok(())
    }

    fn finish_data(
        &self,
        attempt: &OriginalImport18NormalizationAttempt,
        actual: usize,
    ) -> Result<(), ProviderError> {
        assert_eq!(self.normalization_calls.replace(2), 1);
        assert_eq!(attempt.retained_backing_data().unwrap(), actual);
        Ok(())
    }
}

impl Admission<'_> {
    fn framing_step(&self) -> Result<(), ProviderError> {
        let call = self.framing_calls.get() + 1;
        self.framing_calls.set(call);
        let stop = match self.case {
            "initial_context_stop_begin" => 1,
            "initial_context_stop_construct" => 2,
            "initial_context_stop_finish" => 3,
            _ => 0,
        };
        if call == stop {
            return Err(ProviderError::ResourceExhausted(
                "actual context framing admission",
            ));
        }
        Ok(())
    }
}

impl NativeCold17Admission for Admission<'_> {
    fn begin_data(&self, row: NativeCold17PrewalkData) -> Result<(), ProviderError> {
        assert_eq!(row.work_data(), NativeCold17Work::Framing);
        self.framing_step()
    }

    fn construct_data(&self, row: NativeCold17ConstructionData) -> Result<(), ProviderError> {
        assert_eq!(row.work_data(), NativeCold17Work::Framing);
        self.framing_step()
    }

    fn finish_data(&self, work: NativeCold17Work, actual: usize) -> Result<(), ProviderError> {
        assert_eq!(work, NativeCold17Work::Framing);
        assert_eq!(actual, 0);
        self.framing_step()
    }
}

pub(super) fn assert_child(case: &str, owner: &mut OriginalImport18RawBootstrap) {
    native_framing::fill(owner, &roles(case));
    let retained = owner.retained_requested_bytes().unwrap();
    let pointers = owner.inputs.bodies_data().unwrap().map(<[u8]>::as_ptr);
    let admission = Admission {
        case,
        normalization_calls: Cell::new(0),
        framing_calls: Cell::new(0),
    };
    let mut attempt = OriginalImport18NormalizationAttempt::empty();
    if case != "initial_context_incomplete" {
        owner
            .decode_normalization_data(&mut attempt, &admission)
            .unwrap();
        assert!(attempt.completed_data());
    }
    match case {
        "initial_context_refused" => attempt.refuse_data(),
        "initial_context_host_changed" => {
            attempt.decoded.as_mut().unwrap().host_registration = json!({"other":"Host"})
        }
        "initial_context_recipe_changed" => {
            attempt.decoded.as_mut().unwrap().lease_generation = U64::new(2)
        }
        "initial_context_foreign_raw" => {
            let mut foreign = canonical::parse_json(&roles(case)[5].1, usize::MAX).unwrap();
            foreign["lease_generation"] = json!("2");
            let raw = canonical::canonical_json(&foreign).unwrap();
            attempt = OriginalImport18NormalizationAttempt::empty();
            attempt.quote_data(&raw, 268_435_456).unwrap();
            attempt.decode_data(&raw).unwrap();
            attempt.complete_data().unwrap();
        }
        _ => {}
    }
    let backing = attempt.retained_backing_data().unwrap();
    let mut inspected = false;
    let result = owner.with_normalized_native17_framing_data(&attempt, &admission, |_, decoded| {
        inspected = true;
        assert!(std::ptr::eq(decoded, attempt.decoded.as_ref().unwrap()));
        if case == "initial_context_callback_refused" {
            return Err(ProviderError::Conflict("actual context callback"));
        }
        if case == "initial_context_terminal_expired" {
            std::thread::sleep(Duration::from_secs(5));
        }
        Ok(())
    });
    let success = matches!(
        case,
        "initial_context_complete"
            | "initial_context_before_capacity_exact"
            | "initial_context_before_spare_exact"
    );
    assert_eq!(result.is_ok(), success);
    assert_eq!(
        inspected,
        matches!(
            case,
            "initial_context_complete"
                | "initial_context_before_capacity_exact"
                | "initial_context_before_spare_exact"
                | "initial_context_callback_refused"
                | "initial_context_terminal_expired"
        )
    );
    assert_eq!(owner.retained_requested_bytes().unwrap(), retained);
    assert_eq!(
        owner.inputs.bodies_data().unwrap().map(<[u8]>::as_ptr),
        pointers
    );
    assert_eq!(attempt.retained_backing_data().unwrap(), backing);
    if matches!(
        case,
        "initial_context_complete"
            | "initial_context_incomplete"
            | "initial_context_terminal_expired"
    ) {
        assert_native_graph_prefix(owner, &attempt, case == "initial_context_complete");
    }

    assert_eq!(
        admission.framing_calls.get(),
        match case {
            "initial_context_incomplete"
            | "initial_context_refused"
            | "initial_context_host_changed"
            | "initial_context_recipe_changed"
            | "initial_context_foreign_raw" => 0,
            "initial_context_stop_begin" => 1,
            "initial_context_stop_construct" => 2,
            _ => 3,
        }
    );
}

#[test]
fn normalized_native_framing_joins_actual_history_before_callback() {
    assert!(
        OriginalImport18RawBootstrap::normalized_native17_framing_counter_scratch_data::<()>()
            > OriginalImport18RawBootstrap::native17_framing_counter_scratch_data::<()>()
    );
    for case in [
        "initial_context_complete",
        "initial_context_before",
        "initial_context_before_capacity_short",
        "initial_context_before_capacity_exact",
        "initial_context_before_spare_short",
        "initial_context_before_spare_exact",
        "initial_context_before_media",
        "initial_context_semantic",
        "initial_context_runtime",
        "initial_context_runtime_media",
        "initial_context_incomplete",
        "initial_context_refused",
        "initial_context_host_changed",
        "initial_context_recipe_changed",
        "initial_context_foreign_raw",
        "initial_context_stop_begin",
        "initial_context_stop_construct",
        "initial_context_stop_finish",
        "initial_context_callback_refused",
        "initial_context_terminal_expired",
    ] {
        flight(case);
    }
}

// This component admission observes rows only. It cannot issue genuine native
// phase funding; the inert graph must still refuse its semantic reader.
struct GraphAdmission {
    calls: Cell<usize>,
    observations: Cell<usize>,
}

impl NativeCold17Admission for GraphAdmission {
    fn begin_data(&self, _: NativeCold17PrewalkData) -> Result<(), ProviderError> {
        self.calls.set(self.calls.get() + 1);
        Ok(())
    }

    fn construct_data(&self, _: NativeCold17ConstructionData) -> Result<(), ProviderError> {
        self.calls.set(self.calls.get() + 1);
        Ok(())
    }

    fn finish_data(&self, _: NativeCold17Work, _: usize) -> Result<(), ProviderError> {
        self.calls.set(self.calls.get() + 1);
        Ok(())
    }
}

impl crate::reference_packet::service::ack_emitter::native_boot::bootstrap_import18::native_framing::OriginalImport18NativeGraphAdmission for GraphAdmission {
    fn finish_attempt_data(
        &self,
        attempt: &crate::protocol_snapshot::restored_settled17::RestoredSettledNative18GraphAttempt,
        actual: usize,
    ) -> Result<(), ProviderError> {
        assert!(!attempt.graphs_decoded_data());
        assert_eq!(attempt.retained_requested_storage_data(usize::MAX).unwrap(), actual);
        assert_eq!(self.observations.replace(1), 0);
        self.calls.set(self.calls.get() + 1);
        Ok(())
    }
}

fn assert_native_graph_prefix(
    owner: &OriginalImport18RawBootstrap,
    normalization: &OriginalImport18NormalizationAttempt,
    expect_backing: bool,
) {
    let pointers = owner.inputs.bodies_data().unwrap().map(<[u8]>::as_ptr);
    let retained = owner.retained_requested_bytes().unwrap();
    let admission = GraphAdmission {
        calls: Cell::new(0),
        observations: Cell::new(0),
    };
    let mut graphs = None;

    assert!(
        owner
            .decode_native17_graphs_into_data(normalization, &mut graphs, &admission)
            .is_err()
    );
    let attempt = graphs.as_ref().expect("actual graph attempt retained");
    assert!(!attempt.graphs_decoded_data());
    let graph_backing = attempt.retained_requested_storage_data(usize::MAX).unwrap();
    assert_eq!(graph_backing > 0, expect_backing);
    assert_eq!(admission.observations.get(), 1);
    let calls = admission.calls.get();
    if expect_backing {
        assert!(calls > 3, "framing alone cannot retain native raw roles");
    } else {
        assert_eq!(
            calls, 1,
            "only final observation runs after a guard refusal"
        );
    }

    assert!(
        owner
            .decode_native17_graphs_into_data(normalization, &mut graphs, &admission)
            .is_err()
    );
    assert_eq!(admission.calls.get(), calls);
    assert_eq!(
        graphs
            .as_ref()
            .unwrap()
            .retained_requested_storage_data(usize::MAX)
            .unwrap(),
        graph_backing
    );
    assert_eq!(owner.retained_requested_bytes().unwrap(), retained);
    assert_eq!(
        owner.inputs.bodies_data().unwrap().map(<[u8]>::as_ptr),
        pointers
    );
    assert!(
        OriginalImport18RawBootstrap::native17_graph_decode_counter_scratch_data()
            > OriginalImport18RawBootstrap::normalized_native17_framing_counter_scratch_data::<()>(
            )
    );
}
