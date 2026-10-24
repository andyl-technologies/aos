//! Exercises actual five-role output custody over independent inherited flights.
//!
//! Callback admissions are explicit models. Every census inspects the original
//! receiver and external attempt; no callback mints genuine Source funding.

use super::*;
use serde_json::json;
use std::cell::Cell;

struct Model<'a> {
    case: &'a str,
    original_retained: usize,
    constructed: Cell<bool>,
    entered: Cell<usize>,
    observed: Cell<usize>,
    digests: Cell<[Option<[u8; 32]>; 5]>,
}

impl Model<'_> {
    fn observe_retained(
        &self,
        original: &OriginalImport18RawBootstrap,
        attempt: &Attempt,
        role: Role,
        actual: usize,
    ) {
        self.observed.set(self.observed.get() | (1 << role.index()));
        assert_eq!(
            actual,
            attempt.retained_requested_bytes_data(original).unwrap()
        );
        assert_eq!(
            actual > size_of::<Attempt>(),
            role != Role::HostRegistration
        );
        assert!(actual <= attempt.row.unwrap()[0]);
        assert_eq!(
            original.retained_requested_bytes().unwrap(),
            self.original_retained
        );
    }

    fn selected(&self, prefix: &str, role: Role) -> bool {
        self.case
            .strip_prefix("initial_policy_kernel_normalizations_")
            == Some(match (prefix, role) {
                ("retain", Role::Birth) => "retain_birth",
                ("retain", Role::Kernel) => "retain_kernel",
                ("retain", Role::Policy) => "retain_policy",
                ("retain", Role::NativeRegistration) => "retain_native",
                ("retain", Role::HostRegistration) => "retain_host",
                ("reject", Role::Policy) => "reject_policy",
                ("expire", Role::Policy) => "expire_policy",
                ("revoke", Role::NativeRegistration) => "revoke_native",
                _ => "",
            })
    }
}

impl Admission for Model<'_> {
    fn construct_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        attempt: &Attempt,
        row: [usize; 3],
    ) -> Result<(), ProviderError> {
        assert!(!self.constructed.replace(true));
        assert!(original.bootstrap_normalizations_started && attempt.started);
        assert_eq!(
            original.retained_requested_bytes().unwrap(),
            self.original_retained
        );
        assert_eq!(
            attempt.retained_requested_bytes_data(original).unwrap(),
            size_of::<Attempt>()
        );
        assert_eq!(attempt.row, Some(row));
        assert_eq!(attempt.finished, 0);
        assert!(attempt.value.is_none() && attempt.hash.written == 0);
        if self.case.ends_with("reject_construction") {
            return Err(ProviderError::Conflict("normalization admission model"));
        }
        Ok(())
    }

    fn role_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        attempt: &Attempt,
        role: Role,
    ) -> Result<(), ProviderError> {
        self.entered.set(self.entered.get() | (1 << role.index()));
        assert_eq!(attempt.finished, role.index());
        assert_eq!(attempt.digests, self.digests.get());
        assert!(attempt.value.is_none() && attempt.hash.written == 0);
        assert_eq!(
            original.retained_requested_bytes().unwrap(),
            self.original_retained
        );
        if self.selected("reject", role) {
            return Err(ProviderError::Conflict(
                "normalization role admission model",
            ));
        }
        Ok(())
    }

    fn finish_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        attempt: &Attempt,
        role: Role,
        actual: usize,
    ) -> Result<(), ProviderError> {
        self.observe_retained(original, attempt, role, actual);
        let value = if role == Role::HostRegistration {
            assert!(attempt.value.is_none());
            original
                .typed_bodies_data()?
                .boot
                .expected_host_registration_data()
        } else {
            attempt.value.as_ref().unwrap()
        };
        let bytes = canonical::canonical_json(value).unwrap();
        assert_eq!(attempt.hash.written, bytes.len());
        assert_eq!(attempt.hash.hasher.finalize(), blake3::hash(&bytes));
        let expected_digest = *blake3::hash(&bytes).as_bytes();
        assert_eq!(attempt.digests[role.index()], Some(expected_digest));
        let mut digests = self.digests.get();
        digests[role.index()] = Some(expected_digest);
        self.digests.set(digests);

        // The complete older individual-view controls remain independent field
        // oracles. This owner additionally joins actual raw Birth/Host inputs.
        match role {
            Role::Birth => {
                let boot: Value = serde_json::from_slice(&original.bodies[2]).unwrap();
                assert_eq!(
                    *value,
                    json!({
                        "schema": "source-owned.packet-native-import-bootstrap-birth-association/18",
                        "birth_id": boot["birth_id"], "private_launch": boot["private_launch"],
                        "host_executable": boot["host_executable"], "source_binding": boot["source_birth"],
                        "expected_host_registration": boot["expected_host_registration"],
                    })
                );
            }
            Role::Kernel => assert_eq!(
                value["native"]["executable"],
                json!(original.bootstrap_kernel.executable.as_ref().unwrap())
            ),
            Role::Policy => {
                let boot: Value = serde_json::from_slice(&original.bodies[2]).unwrap();
                assert_eq!(value["source_binding"], boot["source_birth"]);
                assert_eq!(value.as_object().unwrap().len(), 5);
            }
            Role::NativeRegistration => {
                assert_eq!(value["role"], "native");
                assert_eq!(value.as_object().unwrap().len(), 9);
            }
            Role::HostRegistration => {
                let boot: Value = serde_json::from_slice(&original.bodies[2]).unwrap();
                assert_eq!(*value, boot["expected_host_registration"]);
            }
        }
        if self.selected("expire", role) {
            std::thread::sleep(Duration::from_secs(5));
        }
        if self.selected("revoke", role) {
            original
                .hello_registrar
                .retained_authority_fixture_data()
                .unwrap()
                .revoke_epoch_fixture_data();
        }
        if self.selected("retain", role) {
            return Err(ProviderError::Conflict("normalization output census model"));
        }
        Ok(())
    }
}

pub(in super::super) fn assert_child(case: &str, original: &mut OriginalImport18RawBootstrap) {
    let retained = original.retained_requested_bytes().unwrap();
    let raw = original.bodies.each_ref().map(Vec::as_ptr);
    let launch = Rc::as_ptr(original.parsed.shared_launch_data().unwrap());
    let model = Model {
        case,
        original_retained: retained,
        constructed: Cell::new(false),
        entered: Cell::new(0),
        observed: Cell::new(0),
        digests: Cell::new([None; 5]),
    };
    let mut attempt = Attempt::empty_data();
    assert!(attempt.digests_data(original).is_err());
    let cut = original.cut;
    if case.ends_with("changed_cut") {
        original.cut = OperationalDeadline::after(Duration::from_secs(3)).unwrap();
    }
    let outcome = original.construct_bootstrap_normalizations_data(&mut attempt, &model);
    let success = case.ends_with("complete") || case.ends_with("reactive");
    assert_eq!(
        outcome.is_ok(),
        success,
        "{case}: {outcome:?}, expired={}",
        original.cut.is_expired()
    );
    assert!(original.bootstrap_normalizations_started && attempt.started);
    assert_eq!(attempt.complete, success);
    assert_eq!(attempt.failed, !success);
    assert_eq!(original.retained_requested_bytes().unwrap(), retained);
    assert_eq!(original.bodies.each_ref().map(Vec::as_ptr), raw);
    assert_eq!(
        Rc::as_ptr(original.parsed.shared_launch_data().unwrap()),
        launch
    );
    assert_eq!(attempt.digests, model.digests.get());

    if success {
        assert_eq!(model.entered.get(), 31);
        assert_eq!(model.observed.get(), 31);
        assert_eq!(attempt.finished, 5);
        assert!(attempt.value.is_none() && attempt.hash.written == 0);
        assert_eq!(
            attempt.retained_requested_bytes_data(original).unwrap(),
            size_of::<Attempt>()
        );
        let digests = attempt.digests_data(original).unwrap();
        let actual = [
            digests.birth,
            digests.kernel,
            digests.policy,
            digests.native_registration,
            digests.host_registration,
        ];
        assert_eq!(actual.map(Some), model.digests.get());
        for (index, digest) in actual.iter().enumerate() {
            assert!(!actual[..index].contains(digest));
        }
        if case.ends_with("complete") {
            original.hello_registrar.contain_admission_data().unwrap();
            assert!(attempt.digests_data(original).is_err());
        }
    } else {
        assert!(attempt.digests_data(original).is_err());
        assert!(original.with_hello_authority_data(|_| Ok(())).is_err());
        if case.contains("_retain_")
            || case.ends_with("expire_policy")
            || case.ends_with("revoke_native")
        {
            let role = attempt.role.unwrap();
            assert_eq!(attempt.finished, role.index());
            assert!(attempt.hash.written > 0);
            assert_eq!(attempt.value.is_some(), role != Role::HostRegistration);
            assert_eq!(model.observed.get(), (1 << (role.index() + 1)) - 1);
        }
        if case.ends_with("missing_kernel") || case.ends_with("changed_cut") {
            assert!(!model.constructed.get());
            assert_eq!(model.entered.get(), 0);
            assert_eq!(
                attempt.retained_requested_bytes_data(original).unwrap(),
                size_of::<Attempt>()
            );
        }
    }
    let before_retry = attempt.retained_requested_bytes_data(original).unwrap();
    let hash = (
        attempt.hash.hasher.finalize(),
        attempt.hash.written,
        attempt.hash.refused,
    );
    let calls = (
        model.constructed.get(),
        model.entered.get(),
        model.observed.get(),
    );
    original.cut = cut;
    assert!(
        original
            .construct_bootstrap_normalizations_data(&mut attempt, &model)
            .is_err()
    );
    assert!(
        original
            .construct_bootstrap_normalizations_data(&mut Attempt::empty_data(), &model)
            .is_err()
    );
    assert_eq!(
        (
            model.constructed.get(),
            model.entered.get(),
            model.observed.get()
        ),
        calls
    );
    assert_eq!(
        attempt.retained_requested_bytes_data(original).unwrap(),
        before_retry
    );
    assert_eq!(
        (
            attempt.hash.hasher.finalize(),
            attempt.hash.written,
            attempt.hash.refused
        ),
        hash
    );
    assert_eq!(attempt.digests, model.digests.get());
}

#[test]
fn complete_schedule_prices_actual_banks_and_refuses_short_or_overflowing_rows() {
    use crate::retained_metadata::serialization_storage::actual_serialization_storage_data;
    let values = [
        json!({"birth": ["original", "birth"]}),
        json!({"kernel": "both roles"}),
        json!({"policy": [1, 2, 3]}),
        json!({"registration": {"role": "native"}}),
        json!({"host": "already owned"}),
    ];
    let shapes = values.each_ref().map(|value| {
        actual_serialization_storage_data(value, MetadataObserver::new().finish(), usize::MAX)
            .unwrap()
    });
    let row = construction_data(&shapes, usize::MAX).unwrap();
    let peak = row.into_iter().sum::<usize>();
    assert_eq!(construction_data(&shapes, peak).unwrap(), row);
    assert_eq!(construction_data(&shapes, peak + 4096).unwrap(), row);
    assert!(construction_data(&shapes, peak - 1).is_err());
    let mut overflowing = shapes;
    overflowing[0].maximum_encoded_bytes = usize::MAX;
    assert!(construction_data(&overflowing, usize::MAX).is_err());
    assert!(
        row[2]
            > OriginalImport18RawBootstrap::bootstrap_ack_operands_counter_scratch_data::<Digests>(
            )
            .unwrap()
    );
}

#[test]
fn retained_value_bound_covers_actual_strings_empty_maps_and_unhinted_arrays() {
    use crate::retained_metadata::serialization_storage::actual_serialization_storage_data;
    use serde::ser::SerializeSeq;

    struct Unhinted<'a>(&'a [Value]);

    impl Serialize for Unhinted<'_> {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let mut sequence = serializer.serialize_seq(None)?;
            for value in self.0 {
                sequence.serialize_element(value)?;
            }
            sequence.end()
        }
    }

    for length in [0, 1, 3, 4, 7, 8, 9, 127, 1025] {
        let values = (0..length).map(|index| json!({
            "index": index, "text": "a\u{0}\n\u{1f642}", "empty": {}, "array": [1, true, null],
        })).collect::<Vec<_>>();
        let input = Unhinted(&values);
        let shape =
            actual_serialization_storage_data(&input, MetadataObserver::new().finish(), usize::MAX)
                .unwrap();
        let value = serde_json::to_value(&input).unwrap();
        let mut observer = MetadataObserver::new();
        observer.observe(&value).unwrap();
        let actual = requested_metadata_backing_storage_data(&observer.finish()).unwrap()
            + size_of::<Value>();
        assert!(
            value_backing::requested_data(&shape).unwrap() >= actual,
            "length={length}, actual={actual}"
        );
    }
}

/// Checks downstream setup without repeating the independent serialization oracle.
///
/// Dedicated normalization flights use `Model` directly and retain every raw
/// field and canonical hash comparison. Downstream flights still execute the
/// complete production normalization, phase checks and retained-output census
/// under their original cut before testing their own operation.
struct Preparation(Model<'static>);

impl Admission for Preparation {
    fn construct_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        attempt: &Attempt,
        row: [usize; 3],
    ) -> Result<(), ProviderError> {
        self.0.construct_data(original, attempt, row)
    }

    fn role_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        attempt: &Attempt,
        role: Role,
    ) -> Result<(), ProviderError> {
        self.0.role_data(original, attempt, role)
    }

    fn finish_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        attempt: &Attempt,
        role: Role,
        actual: usize,
    ) -> Result<(), ProviderError> {
        self.0.observe_retained(original, attempt, role, actual);
        assert!(attempt.digests[role.index()].is_some());
        assert!(attempt.hash.written > 0);

        let mut digests = self.0.digests.get();
        digests[role.index()] = attempt.digests[role.index()];
        self.0.digests.set(digests);
        Ok(())
    }
}

/// Retains genuine normalization outputs for a downstream operation's fixture.
pub(in super::super) fn complete_for_host(original: &mut OriginalImport18RawBootstrap) -> Attempt {
    println!(
        "bootstrap fixture normalizations begin: remaining={:?}",
        original.cut.remaining()
    );
    let model = Preparation(Model {
        case: "initial_policy_kernel_normalizations_complete",
        original_retained: original.retained_requested_bytes().unwrap(),
        constructed: Cell::new(false),
        entered: Cell::new(0),
        observed: Cell::new(0),
        digests: Cell::new([None; 5]),
    });
    let mut attempt = Attempt::empty_data();
    original
        .construct_bootstrap_normalizations_data(&mut attempt, &model)
        .unwrap();
    println!(
        "bootstrap fixture normalizations complete: remaining={:?}",
        original.cut.remaining()
    );
    assert_eq!(model.0.entered.get(), 31);
    assert_eq!(model.0.observed.get(), 31);
    assert_eq!(attempt.digests, model.0.digests.get());
    assert_eq!(attempt.finished, 5);
    assert!(attempt.complete && !attempt.failed);
    assert!(attempt.value.is_none() && attempt.hash.written == 0);
    assert_eq!(
        attempt.retained_requested_bytes_data(original).unwrap(),
        size_of::<Attempt>()
    );
    attempt
}
