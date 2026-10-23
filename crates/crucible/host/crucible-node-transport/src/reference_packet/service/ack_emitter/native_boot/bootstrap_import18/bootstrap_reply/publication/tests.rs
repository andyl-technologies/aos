//! Exercises the exact original stream, actual SDK records and spent publication.

use super::*;
use std::cell::Cell;

const PREFIX: &str = "initial_policy_kernel_normalizations_host_publication_";

struct Model<'a> {
    suffix: &'a str,
    calls: Cell<usize>,
}

impl Model<'_> {
    fn action(&self, current: Current<'_>, label: &str) -> Result<(), ProviderError> {
        if self.suffix == format!("expire_{label}") {
            std::thread::sleep(Duration::from_secs(5));
        }
        if self.suffix == format!("revoke_{label}") {
            current
                .inputs
                .prior
                .original
                .hello_registrar
                .retained_authority_fixture_data()
                .unwrap()
                .revoke_epoch_fixture_data();
        }
        if self.suffix == format!("reject_{label}") {
            return Err(ProviderError::Conflict(
                "bootstrap publication admission model",
            ));
        }
        Ok(())
    }
}

impl Admission for Model<'_> {
    fn construct_data(&self, current: Current<'_>, row: [usize; 3]) -> Result<(), ProviderError> {
        assert_eq!(self.calls.replace(1), 0);
        let root = current.inputs.prior.original;
        assert_eq!(current.reply.publication.row, Some(row));
        assert!(current.reply.publication.started && root.bootstrap_publication_started);
        assert_eq!(current.reply.complete, !current.inputs.pending);
        assert!(!current.reply.publication.complete);
        assert_eq!(current.reply.publication.phase, Some(Phase::Received));
        assert_eq!(current.guard.incoming_requests().count(), 1);
        assert!(current.retained_data()? > current.reply.retained_requested_bytes_data(root)?);
        self.action(current, "construction")
    }

    fn step_data(&self, current: Current<'_>, step: Step) -> Result<(), ProviderError> {
        let (index, label, phase) = match step {
            Step::Reserve => (1, "reserve", Phase::Received),
            Step::Write => (3, "write", Phase::Writing),
            Step::Confirm => (5, "confirm", Phase::Writing),
        };
        assert_eq!(self.calls.replace(index + 1), index);
        assert_eq!(current.reply.publication.phase, Some(phase));
        assert!(current.reply.publication.confirmed_request.is_none());
        assert_eq!(current.guard.incoming_requests().count(), 1);
        current.retained_data()?;
        self.action(current, label)
    }

    fn observe_data(
        &self,
        current: Current<'_>,
        step: Step,
        actual: usize,
    ) -> Result<(), ProviderError> {
        assert_eq!(current.retained_data()?, actual);
        let (index, label) = match step {
            Step::Reserve => (2, "reserved"),
            Step::Write => (4, "written"),
            Step::Confirm => (6, "confirmed"),
        };
        assert_eq!(self.calls.replace(index + 1), index);
        assert_eq!(current.reply.publication.step, Some(step));
        assert_eq!(
            current.reply.publication.confirmed_request.is_some(),
            step == Step::Confirm
        );
        assert_eq!(
            current.reply.publication.confirmed_response.is_some(),
            step == Step::Confirm
        );
        assert_eq!(
            current.guard.incoming_requests().count(),
            usize::from(step != Step::Confirm)
        );
        if step != Step::Reserve && self.suffix != "broken_pipe" {
            current.reply.literal.authenticate_written_data()?;
        }
        self.action(current, label)
    }
}

/// Checks success and every admission, terminal refusal and once-only retry.
pub(in super::super::super::super) fn assert_child(
    case: &str,
    original: &mut OriginalImport18RawBootstrap,
) {
    let suffix = case.strip_prefix(PREFIX).unwrap();
    let (normalizations, literal, parsed, codec, mut correlation, mut proof, mut reply) =
        super::super::tests::complete_for_publication(original);
    let cut = original.cut;
    let raw_pointers = original.bodies.each_ref().map(Vec::as_ptr);
    let launch = Rc::as_ptr(original.parsed.shared_launch_data().unwrap());
    let reply_pointer = reply.envelope.as_ref().map(std::ptr::from_ref);
    let before = original.retained_requested_bytes().unwrap();
    let model = Model {
        suffix,
        calls: Cell::new(0),
    };
    if suffix == "changed_cut" {
        original.cut = OperationalDeadline::after(Duration::from_secs(3)).unwrap();
    }
    if suffix == "missing_preparation" {
        reply.complete = false;
    }
    let outcome = if suffix == "missing_preparation" {
        original.publish_bootstrap_reply_data(
            correlation::Predecessors {
                normalizations: &normalizations,
                literal: &literal,
                parsed: &parsed,
                codec: &codec,
            },
            &mut correlation,
            &proof,
            &mut reply,
            &model,
        )
    } else {
        super::super::tests::verify_prepare_publish_reply(
            original,
            &normalizations,
            &literal,
            &parsed,
            &codec,
            &mut correlation,
            &mut proof,
            &mut reply,
            &model,
        )
    };
    let success = matches!(suffix, "complete" | "reactive");
    assert_eq!(
        outcome.is_ok(),
        success,
        "{case}: {outcome:?}; step={:?}; expired={}",
        reply.publication.step,
        original.cut.is_expired()
    );
    assert!(reply.publication.started && original.bootstrap_publication_started);
    assert_eq!(reply.publication.complete, success);
    assert_eq!(reply.publication.failed, !success);
    assert_eq!(original.bodies.each_ref().map(Vec::as_ptr), raw_pointers);
    assert_eq!(
        Rc::as_ptr(original.parsed.shared_launch_data().unwrap()),
        launch
    );
    if reply_pointer.is_some() {
        assert_eq!(
            reply.envelope.as_ref().map(std::ptr::from_ref),
            reply_pointer
        );
    }
    assert_eq!(original.retained_requested_bytes().unwrap(), before);
    let row = construction_data(
        original.parsed.bodies_data().unwrap().launch.launch_data(),
        usize::MAX,
    )
    .unwrap();
    assert!(reply.retained_requested_bytes_data(original).unwrap() <= row[0]);
    if success {
        assert_eq!(model.calls.get(), 7);
        reply.literal.authenticate_written_data().unwrap();
        assert_eq!(reply.publication.phase, Some(Phase::Confirmed));
        assert_eq!(
            reply.publication.confirmed_response.as_ref(),
            reply.envelope.as_ref()
        );
    }
    // The old received-request loans refuse after confirmation, and on every
    // failed publication. Actual accepted records must not be reconstructed.
    let inputs = correlation::Inputs {
        original,
        normalizations: &normalizations,
        literal: &literal,
        parsed: &parsed,
        codec: &codec,
    };
    assert!(
        correlation
            .with_received_data::<()>(inputs, |_, _| panic!("spent incoming loan entered"))
            .is_err()
    );
    if suffix == "broken_pipe" {
        assert!(matches!(
            reply.publication.failure,
            Some(ProviderError::Io(_))
        ));
    }
    original.cut = cut;
    let retained = reply.retained_requested_bytes_data(original).unwrap();
    let calls = model.calls.get();
    assert!(
        original
            .publish_bootstrap_reply_data(
                correlation::Predecessors {
                    normalizations: &normalizations,
                    literal: &literal,
                    parsed: &parsed,
                    codec: &codec,
                },
                &mut correlation,
                &proof,
                &mut reply,
                &model
            )
            .is_err()
    );
    assert!(
        original
            .publish_bootstrap_reply_data(
                correlation::Predecessors {
                    normalizations: &normalizations,
                    literal: &literal,
                    parsed: &parsed,
                    codec: &codec,
                },
                &mut correlation,
                &proof,
                &mut super::super::Attempt::empty_data(),
                &model
            )
            .is_err()
    );
    assert_eq!(model.calls.get(), calls);
    assert_eq!(
        reply.retained_requested_bytes_data(original).unwrap(),
        retained
    );
}

/// Verifies the actual second public frame and refuses any trailing publication.
pub(in super::super::super::super) fn assert_parent_bytes(case: &str, bytes: &[u8]) {
    let suffix = case.strip_prefix(PREFIX).unwrap();
    let hello_len = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize + 4;
    let rest = &bytes[hello_len..];
    let written = matches!(suffix, "complete" | "reactive")
        || suffix.ends_with("_written")
        || suffix.ends_with("_confirm")
        || suffix.ends_with("_confirmed");
    if !written {
        assert!(rest.is_empty(), "unexpected bootstrap publication: {case}");
        return;
    }
    let length = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
    assert_eq!(rest.len(), length + 4, "{case}");
    let response: Envelope = serde_json::from_slice(&rest[4..]).unwrap();
    assert_eq!(
        response.method,
        crate::envelope::Method::NativeImport18Bootstrap
    );
    assert_eq!(response.message, crate::envelope::MessageKind::Response);
    assert_eq!(response.sequence.get(), 2);
    assert_eq!(
        response.request_id.0.as_ref().unwrap().as_str(),
        "bootstrap"
    );
    assert_eq!(response.body["status"], "completed");
    assert_eq!(response.body["operation_state"], "completed");
    assert_eq!(response.body["result"]["state"], "bootstrap_only");
    assert_eq!(response.extensions.len(), 1);
    let receipt: Receipt =
        serde_json::from_value(response.extensions[NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT].clone())
            .unwrap();
    receipt.validate_data().unwrap();
    assert_eq!(
        receipt.state,
        PacketNativeImport18BootstrapAckState::BootstrapOnly
    );
    assert_eq!(
        crucible_node_format::canonical::canonical_json(&serde_json::to_value(response).unwrap())
            .unwrap(),
        &rest[4..]
    );
}

/// Checks actual SDK-owned buffers are moved rather than reconstructed or cloned.
pub(in super::super::super) fn assert_original_sdk_move(
    publication: &mut Publication,
    guard: &mut CorrelationGuard,
    original: &Envelope,
    reply: &Envelope,
    original_schema: *const u8,
) {
    guard
        .original_bootstrap_confirm_into_data(
            original,
            reply,
            &mut publication.confirmed_request,
            &mut publication.confirmed_response,
        )
        .unwrap();
    let request = publication.confirmed_request.as_ref().unwrap();
    let response = publication.confirmed_response.as_ref().unwrap();
    assert_eq!(
        request.body["schema"].as_str().unwrap().as_ptr(),
        original_schema
    );
    assert_eq!(request, original);
    assert_eq!(response, reply);
    guard
        .original_bootstrap_confirmed_data(request, response)
        .unwrap();
    assert!(
        guard
            .original_bootstrap_writing_data(original, reply)
            .is_err()
    );
    assert!(
        guard
            .original_bootstrap_confirm_into_data(original, reply, &mut None, &mut None)
            .is_err()
    );
}
