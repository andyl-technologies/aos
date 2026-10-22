//! Exercises actual retained MAC verification on independent inherited flights.

use super::*;
use std::cell::Cell;

const PREFIX: &str = "initial_policy_kernel_normalizations_host_proof_";

#[path = "fixture.rs"]
mod fixture;
pub(in super::super::super) use fixture::{
    prepare_wire_data, write_parent_frame, write_parent_publication_frame,
};

struct Model<'a> {
    suffix: &'a str,
    retained: [usize; 6],
    calls: Cell<usize>,
}

impl Model<'_> {
    fn census(&self, inputs: Inputs<'_>) {
        let prior = inputs.prior;
        assert_eq!(
            [
                prior.original.retained_requested_bytes().unwrap(),
                prior
                    .normalizations
                    .retained_requested_bytes_data(prior.original)
                    .unwrap(),
                prior
                    .literal
                    .retained_requested_bytes_data(prior.original)
                    .unwrap(),
                prior
                    .parsed
                    .retained_requested_bytes_data(prior.original)
                    .unwrap(),
                prior
                    .codec
                    .retained_requested_bytes_data(prior.original)
                    .unwrap(),
                inputs
                    .correlation
                    .retained_requested_bytes_data(prior.original)
                    .unwrap(),
            ],
            self.retained
        );
    }

    fn action(&self, inputs: Inputs<'_>, label: &str) -> Result<(), ProviderError> {
        if self.suffix == format!("expire_{label}") {
            std::thread::sleep(Duration::from_secs(5));
        }
        if self.suffix == format!("revoke_{label}") {
            inputs
                .prior
                .original
                .hello_registrar
                .retained_authority_fixture_data()
                .unwrap()
                .revoke_epoch_fixture_data();
        }
        if self.suffix == format!("reject_{label}") {
            return Err(ProviderError::Conflict("bootstrap proof admission model"));
        }
        Ok(())
    }
}

impl Admission for Model<'_> {
    fn construct_data(
        &self,
        inputs: Inputs<'_>,
        attempt: &Attempt,
        row: [usize; 3],
    ) -> Result<(), ProviderError> {
        assert_eq!(self.calls.replace(1), 0);
        self.census(inputs);
        assert!(attempt.started && inputs.prior.original.bootstrap_proof_started);
        assert_eq!(attempt.row, Some(row));
        assert!(
            attempt.context.is_none() && attempt.assigned.is_none() && attempt.digest.is_none()
        );
        assert_eq!(
            attempt
                .retained_requested_bytes_data(inputs.prior.original)
                .unwrap(),
            size_of::<Attempt>()
        );
        self.action(inputs, "construction")
    }

    fn step_data(
        &self,
        inputs: Inputs<'_>,
        attempt: &Attempt,
        step: Step,
    ) -> Result<(), ProviderError> {
        // Construction and each preceding observation already census these
        // immutable predecessors. Each newly retained output is still observed.
        let (index, label) = match step {
            Step::Assigned => (1, "assignment"),
            Step::Context => (3, "context"),
            Step::ContextDigest => (5, "digest"),
            Step::Verify => (7, "verification"),
        };
        assert_eq!(self.calls.replace(index + 1), index);
        assert_eq!(attempt.assigned.is_some(), index >= 3);
        assert_eq!(attempt.context.is_some(), index >= 5);
        assert_eq!(attempt.digest.is_some(), index >= 7);
        assert!(!attempt.verified);
        self.action(inputs, label)
    }

    fn observe_data(
        &self,
        inputs: Inputs<'_>,
        attempt: &Attempt,
        step: Step,
        actual: usize,
    ) -> Result<(), ProviderError> {
        self.census(inputs);
        assert_eq!(
            attempt
                .retained_requested_bytes_data(inputs.prior.original)
                .unwrap(),
            actual
        );
        assert!(actual <= attempt.row.unwrap()[0]);
        let (index, label) = match step {
            Step::Assigned => (2, "assigned"),
            Step::Context => (4, "constructed"),
            Step::ContextDigest => (6, "hashed"),
            Step::Verify => (8, "verified"),
        };
        assert_eq!(self.calls.replace(index + 1), index);
        assert!(attempt.assigned.is_some());
        assert_eq!(attempt.context.is_some(), index >= 4);
        assert_eq!(attempt.digest.is_some(), index >= 6);
        if let Some(context) = &attempt.context {
            assert_eq!(
                context.assigned_request.as_slice(),
                attempt.assigned.unwrap()
            );
        }
        self.action(inputs, label)
    }
}

/// Preserves all predecessors, accepted requests and proof outputs on refusal.
pub(in super::super::super) fn assert_child(
    case: &str,
    original: &mut OriginalImport18RawBootstrap,
) {
    let suffix = case.strip_prefix(PREFIX).unwrap();
    let (normalizations, literal, parsed, codec, mut correlation) =
        super::super::bootstrap_correlation::tests::complete_for_proof(
            original,
            suffix != "missing_correlation",
        );
    let mut attempt = Attempt::empty_data();
    let model = Model {
        suffix,
        calls: Cell::new(0),
        retained: [
            original.retained_requested_bytes().unwrap(),
            normalizations
                .retained_requested_bytes_data(original)
                .unwrap(),
            literal.retained_requested_bytes_data(original).unwrap(),
            parsed.retained_requested_bytes_data(original).unwrap(),
            codec.retained_requested_bytes_data(original).unwrap(),
            correlation.retained_requested_bytes_data(original).unwrap(),
        ],
    };
    let pointers = original.bodies.each_ref().map(Vec::as_ptr);
    let launch = Rc::as_ptr(original.parsed.shared_launch_data().unwrap());
    let cut = original.cut;
    if suffix == "changed_cut" {
        original.cut = OperationalDeadline::after(Duration::from_secs(3)).unwrap();
    }
    let result = original.verify_bootstrap_proof_data(
        &normalizations,
        &literal,
        &parsed,
        &codec,
        &mut correlation,
        &mut attempt,
        &model,
    );
    let success = matches!(
        suffix,
        "complete" | "reactive" | "callback_refused" | "loan_expired"
    );
    assert_eq!(
        result.is_ok(),
        success,
        "{case}: {result:?}; step={:?}; expired={}",
        attempt.step,
        original.cut.is_expired()
    );
    assert_eq!(attempt.complete, success);
    assert_eq!(attempt.failed, !success);
    assert!(attempt.started && original.bootstrap_proof_started);
    let inputs = Inputs {
        prior: correlation::Inputs {
            original,
            normalizations: &normalizations,
            literal: &literal,
            parsed: &parsed,
            codec: &codec,
        },
        correlation: correlation.view_data(),
    };
    assert_eq!(original.bodies.each_ref().map(Vec::as_ptr), pointers);
    assert_eq!(
        Rc::as_ptr(original.parsed.shared_launch_data().unwrap()),
        launch
    );
    if success {
        assert_eq!(model.calls.get(), 9);
        assert!(attempt.verified);
        let result = attempt.with_verified_context_data(inputs, |context| {
            context.validate_data()?;
            assert_eq!(
                native_import18_bootstrap_ack_context_digest_data(context).unwrap(),
                attempt.digest.unwrap()
            );
            if suffix == "loan_expired" {
                std::thread::sleep(Duration::from_secs(5));
            }
            if suffix == "callback_refused" {
                return Err(ProviderError::Conflict("verified context loan model"));
            }
            Ok(())
        });
        assert_eq!(
            result.is_ok(),
            matches!(suffix, "complete" | "reactive"),
            "{case}: completed context inspection {result:?}; expired={}",
            original.cut.is_expired(),
        );
    } else {
        assert!(
            attempt
                .with_verified_context_data::<()>(inputs, |_| panic!("refused proof loan entered"))
                .is_err()
        );
        assert!(
            correlation
                .with_received_data::<()>(inputs.prior, |_, _| panic!(
                    "failed proof correlation entered"
                ))
                .is_err()
        );
    }

    // The final immutable predecessor census follows the separately guarded
    // inspection. Construction and each output already observed the complete
    // owners; repeating that census before inspection spends its finite cut.
    model.census(inputs);

    if !success && suffix != "missing_correlation" {
        super::super::bootstrap_correlation::tests::assert_fenced_record(&mut correlation);
    }
    let retained = attempt.retained_requested_bytes_data(original).unwrap();
    let context = attempt.context.as_ref().map(std::ptr::from_ref);
    original.cut = cut;
    assert!(
        original
            .verify_bootstrap_proof_data(
                &normalizations,
                &literal,
                &parsed,
                &codec,
                &mut correlation,
                &mut attempt,
                &model
            )
            .is_err()
    );
    assert!(
        original
            .verify_bootstrap_proof_data(
                &normalizations,
                &literal,
                &parsed,
                &codec,
                &mut correlation,
                &mut Attempt::empty_data(),
                &model
            )
            .is_err()
    );
    assert_eq!(
        attempt.retained_requested_bytes_data(original).unwrap(),
        retained
    );
    assert_eq!(attempt.context.as_ref().map(std::ptr::from_ref), context);
}

#[test]
fn proof_quote_refuses_short_credit_and_prices_concrete_copy_results() {
    let selected: PacketNativeImport18SelectedLaunchWireData = serde_json::from_value(
        crate::reference_packet::service::complete_restore::import18::inert_bootstrap_fixtures::initial_selected_launch(false)).unwrap();
    let row = construction_data(selected.launch_data(), usize::MAX).unwrap();
    let peak = row.into_iter().sum::<usize>();
    assert_eq!(
        construction_data(selected.launch_data(), peak).unwrap(),
        row
    );
    assert!(construction_data(selected.launch_data(), peak - 1).is_err());
    assert_eq!(
        construction_data(selected.launch_data(), peak + 4096).unwrap(),
        row
    );
    assert!(
        Attempt::verified_loan_counter_scratch_data::<[u8; 4096]>().unwrap()
            >= Attempt::verified_loan_counter_scratch_data::<()>().unwrap() + 4096
    );
}

/// Completes actual correlation while leaving the new verification slot empty.
pub(in super::super::super) fn complete_for_reply(
    original: &mut OriginalImport18RawBootstrap,
) -> (
    super::super::bootstrap_normalizations::Attempt,
    super::super::bootstrap_literal::Attempt,
    super::super::bootstrap_value::Attempt,
    super::super::bootstrap_codec::Attempt,
    super::super::bootstrap_correlation::Attempt,
    Attempt,
) {
    let (normalizations, literal, parsed, codec, correlation) =
        super::super::bootstrap_correlation::tests::complete_for_proof(original, true);
    (
        normalizations,
        literal,
        parsed,
        codec,
        correlation,
        Attempt::empty_data(),
    )
}

/// Runs actual verification/reply construction with its separately observed proof.
pub(in super::super::super) fn verify_and_construct_reply(
    original: &mut OriginalImport18RawBootstrap,
    normalizations: &super::super::bootstrap_normalizations::Attempt,
    literal: &super::super::bootstrap_literal::Attempt,
    parsed: &super::super::bootstrap_value::Attempt,
    codec: &super::super::bootstrap_codec::Attempt,
    correlation: &mut super::super::bootstrap_correlation::Attempt,
    verified: &mut Attempt,
    reply: &mut super::super::bootstrap_reply::Attempt,
    reply_admission: &dyn super::super::bootstrap_reply::Admission,
) -> Result<(), ProviderError> {
    let model = Model {
        suffix: "complete",
        calls: Cell::new(0),
        retained: [
            original.retained_requested_bytes().unwrap(),
            normalizations
                .retained_requested_bytes_data(original)
                .unwrap(),
            literal.retained_requested_bytes_data(original).unwrap(),
            parsed.retained_requested_bytes_data(original).unwrap(),
            codec.retained_requested_bytes_data(original).unwrap(),
            correlation.retained_requested_bytes_data(original).unwrap(),
        ],
    };
    original.verify_and_construct_bootstrap_reply_data(
        normalizations,
        literal,
        parsed,
        codec,
        correlation,
        verified,
        &model,
        reply,
        reply_admission,
    )
}

/// Checks that completed-proof loans stay closed during the enclosing reply work.
pub(in super::super::super) fn assert_reply_verification_pending(proof: &Attempt) {
    assert!(proof.started && proof.verified && !proof.complete && !proof.failed);
}

/// Checks that aggregate completion was withheld on either operation's refusal.
pub(in super::super::super) fn assert_reply_aggregate_outcome(proof: &Attempt, success: bool) {
    assert!(proof.started);
    assert_eq!(proof.complete, success);
    assert_eq!(proof.failed, !success);
}

/// Checks the actual reply receipt against this retained verified context.
pub(in super::super::super) fn assert_reply_receipt(
    proof: &Attempt,
    original: &OriginalImport18RawBootstrap,
    assigned: &[u8; 32],
    receipt: &crate::reference_packet::service::complete_restore::import18::bootstrap_ack::PacketNativeImport18BootstrapAckReceipt,
) {
    assert!(proof.started && proof.verified && !proof.failed);
    let expected = original
        .parsed
        .bodies_data()
        .unwrap()
        .boot
        .bootstrap_ack_receipt_data(proof.context.as_ref().unwrap(), assigned)
        .unwrap();
    assert_eq!(receipt, &expected);
}

/// Runs all bootstrap effects under one original guard with observed proof work.
pub(in super::super::super) fn verify_prepare_publish_reply(
    original: &mut OriginalImport18RawBootstrap,
    normalizations: &super::super::bootstrap_normalizations::Attempt,
    literal: &super::super::bootstrap_literal::Attempt,
    parsed: &super::super::bootstrap_value::Attempt,
    codec: &super::super::bootstrap_codec::Attempt,
    correlation: &mut super::super::bootstrap_correlation::Attempt,
    verified: &mut Attempt,
    reply: &mut super::super::bootstrap_reply::Attempt,
    preparation: &dyn super::super::bootstrap_reply::Admission,
    publication: &dyn super::super::bootstrap_reply::publication::Admission,
) -> Result<(), ProviderError> {
    let model = Model {
        suffix: "complete",
        calls: Cell::new(0),
        retained: [
            original.retained_requested_bytes().unwrap(),
            normalizations
                .retained_requested_bytes_data(original)
                .unwrap(),
            literal.retained_requested_bytes_data(original).unwrap(),
            parsed.retained_requested_bytes_data(original).unwrap(),
            codec.retained_requested_bytes_data(original).unwrap(),
            correlation.retained_requested_bytes_data(original).unwrap(),
        ],
    };
    original.verify_prepare_and_publish_bootstrap_reply_data(
        normalizations,
        literal,
        parsed,
        codec,
        correlation,
        verified,
        &model,
        reply,
        preparation,
        publication,
    )
}
