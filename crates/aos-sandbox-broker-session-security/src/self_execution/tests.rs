//! Deterministic retained-self observation tests.

use std::collections::VecDeque;

use super::*;

#[derive(Clone, Copy)]
struct ObservationValues {
    scalars: ScalarObservation,
    information: InformationObservation,
    identity: IdentityObservation,
    alive: bool,
}

impl ObservationValues {
    fn stable() -> Self {
        let credentials = CredentialObservation {
            real_user_id: 11,
            real_group_id: 12,
            effective_user_id: 13,
            effective_group_id: 14,
            saved_user_id: 15,
            saved_group_id: 16,
            filesystem_user_id: 17,
            filesystem_group_id: 18,
        };
        Self {
            scalars: ScalarObservation {
                boot_id: [1; 16],
                process_id: 101,
                effective_user_id: credentials.effective_user_id,
                effective_group_id: credentials.effective_group_id,
            },
            information: InformationObservation {
                process_id: 101,
                thread_group_id: 101,
                parent_process_id: 90,
                credentials: Some(credentials),
                cgroup_id: Some(55),
            },
            identity: IdentityObservation {
                process_id: 101,
                thread_group_id: 101,
                parent_process_id: 90,
                cgroup_id: Some(55),
                start_time_ticks: 777,
            },
            alive: true,
        }
    }

    fn set_process_id(&mut self, process_id: u32) {
        self.scalars.process_id = process_id;
        self.information.process_id = process_id;
        self.information.thread_group_id = process_id;
        self.identity.process_id = process_id;
        self.identity.thread_group_id = process_id;
    }

    fn set_cgroup_id(&mut self, cgroup_id: u64) {
        self.information.cgroup_id = Some(cgroup_id);
        self.identity.cgroup_id = Some(cgroup_id);
    }

    fn credentials_mut(&mut self) -> &mut CredentialObservation {
        self.information
            .credentials
            .as_mut()
            .unwrap_or_else(|| panic!("stable observation omitted credentials"))
    }
}

struct ScriptedSource {
    scalars: VecDeque<Result<ScalarObservation, BrokerSessionSecurityError>>,
    open: Option<Result<(), BrokerSessionSecurityError>>,
    information: VecDeque<Result<InformationObservation, BrokerSessionSecurityError>>,
    identity: VecDeque<Result<IdentityObservation, BrokerSessionSecurityError>>,
    alive: VecDeque<Result<bool, BrokerSessionSecurityError>>,
}

impl ScriptedSource {
    fn stable(values: ObservationValues) -> Self {
        Self {
            scalars: [Ok(values.scalars), Ok(values.scalars)].into(),
            open: Some(Ok(())),
            information: [Ok(values.information), Ok(values.information)].into(),
            identity: [Ok(values.identity)].into(),
            alive: [Ok(values.alive)].into(),
        }
    }

    fn next<T>(
        queue: &mut VecDeque<Result<T, BrokerSessionSecurityError>>,
    ) -> Result<T, BrokerSessionSecurityError> {
        queue
            .pop_front()
            .unwrap_or(Err(BrokerSessionSecurityError::ExecutionChanged))
    }
}

impl ExecutionObservationSource for ScriptedSource {
    type Process = ();

    fn scalars(&mut self) -> Result<ScalarObservation, BrokerSessionSecurityError> {
        Self::next(&mut self.scalars)
    }

    fn open_self(
        &mut self,
        _process_id: NonZeroU32,
    ) -> Result<Self::Process, BrokerSessionSecurityError> {
        self.open
            .take()
            .unwrap_or(Err(BrokerSessionSecurityError::ExecutionChanged))
    }

    fn information(
        &mut self,
        _process: &Self::Process,
    ) -> Result<InformationObservation, BrokerSessionSecurityError> {
        Self::next(&mut self.information)
    }

    fn identity(
        &mut self,
        _process: &Self::Process,
    ) -> Result<IdentityObservation, BrokerSessionSecurityError> {
        Self::next(&mut self.identity)
    }

    fn alive(&mut self, _process: &Self::Process) -> Result<bool, BrokerSessionSecurityError> {
        Self::next(&mut self.alive)
    }
}

fn captured_baseline() -> ExecutionBaseline {
    let (_, baseline) = capture_with(&mut ScriptedSource::stable(ObservationValues::stable()))
        .unwrap_or_else(|error| panic!("stable capture failed: {error}"));
    baseline
}

fn assert_capture_rejected(values: ObservationValues) {
    assert!(capture_with(&mut ScriptedSource::stable(values)).is_err());
}

fn assert_current_rejected(values: ObservationValues) {
    assert!(
        validate_with(
            &mut ScriptedSource::stable(values),
            &(),
            captured_baseline()
        )
        .is_err()
    );
}

#[test]
fn stable_capture_and_revalidation_retain_every_required_field() {
    let values = ObservationValues::stable();
    let (process, baseline) = capture_with(&mut ScriptedSource::stable(values))
        .unwrap_or_else(|error| panic!("stable capture failed: {error}"));
    assert!(validate_with(&mut ScriptedSource::stable(values), &process, baseline).is_ok());

    assert_eq!(baseline.boot_id, [1; 16]);
    assert_eq!(baseline.process_id, 101);
    assert_eq!(baseline.thread_group_id, 101);
    assert_eq!(baseline.start_time_ticks, 777);
    assert_eq!(baseline.cgroup_id, 55);
    assert!(
        baseline.credentials
            == ObservationValues::stable()
                .information
                .credentials
                .unwrap_or_else(|| panic!("missing credentials"))
    );
}

#[test]
fn missing_sentinel_and_cross_source_shapes_fail_closed() {
    let mut zero_pid = ObservationValues::stable();
    zero_pid.set_process_id(0);
    assert_capture_rejected(zero_pid);

    let mut missing_credentials = ObservationValues::stable();
    missing_credentials.information.credentials = None;
    assert_capture_rejected(missing_credentials);

    let mut missing_cgroup = ObservationValues::stable();
    missing_cgroup.information.cgroup_id = None;
    missing_cgroup.identity.cgroup_id = None;
    assert_capture_rejected(missing_cgroup);

    let mut zero_cgroup = ObservationValues::stable();
    zero_cgroup.set_cgroup_id(0);
    assert_capture_rejected(zero_cgroup);

    let mut wrong_tgid = ObservationValues::stable();
    wrong_tgid.information.thread_group_id += 1;
    wrong_tgid.identity.thread_group_id += 1;
    assert_capture_rejected(wrong_tgid);

    let mut wrong_effective_user = ObservationValues::stable();
    wrong_effective_user.credentials_mut().effective_user_id += 1;
    assert_capture_rejected(wrong_effective_user);

    let mut wrong_effective_group = ObservationValues::stable();
    wrong_effective_group.credentials_mut().effective_group_id += 1;
    assert_capture_rejected(wrong_effective_group);

    let identity_mutations = [
        |values: &mut ObservationValues| values.identity.process_id += 1,
        |values: &mut ObservationValues| values.identity.thread_group_id += 1,
        |values: &mut ObservationValues| values.identity.parent_process_id += 1,
        |values: &mut ObservationValues| values.identity.cgroup_id = Some(56),
    ];
    for mutate in identity_mutations {
        let mut values = ObservationValues::stable();
        mutate(&mut values);
        assert_capture_rejected(values);
    }

    let mut exited = ObservationValues::stable();
    exited.alive = false;
    assert_capture_rejected(exited);
}

#[test]
fn every_retained_baseline_component_is_compared_across_calls() {
    let mut changed_values = Vec::new();

    let mut changed = ObservationValues::stable();
    changed.scalars.boot_id[0] ^= 1;
    changed_values.push(changed);

    let mut changed = ObservationValues::stable();
    changed.set_process_id(102);
    changed_values.push(changed);

    let mut changed = ObservationValues::stable();
    changed.identity.start_time_ticks += 1;
    changed_values.push(changed);

    let mut changed = ObservationValues::stable();
    changed.set_cgroup_id(56);
    changed_values.push(changed);

    for credential_index in 0..8 {
        let mut changed = ObservationValues::stable();
        let credentials = changed.credentials_mut();
        match credential_index {
            0 => credentials.real_user_id += 1,
            1 => credentials.real_group_id += 1,
            2 => {
                credentials.effective_user_id += 1;
                changed.scalars.effective_user_id += 1;
            }
            3 => {
                credentials.effective_group_id += 1;
                changed.scalars.effective_group_id += 1;
            }
            4 => credentials.saved_user_id += 1,
            5 => credentials.saved_group_id += 1,
            6 => credentials.filesystem_user_id += 1,
            7 => credentials.filesystem_group_id += 1,
            _ => unreachable!(),
        }
        changed_values.push(changed);
    }

    for changed in changed_values {
        assert_current_rejected(changed);
    }
}

#[test]
fn parent_change_is_cross_call_safe_but_not_intra_observation_safe() {
    let baseline = captured_baseline();
    let mut reparented = ObservationValues::stable();
    reparented.information.parent_process_id = 91;
    reparented.identity.parent_process_id = 91;
    assert!(validate_with(&mut ScriptedSource::stable(reparented), &(), baseline).is_ok());

    let mut information_changes = ScriptedSource::stable(ObservationValues::stable());
    information_changes
        .information
        .get_mut(1)
        .unwrap_or_else(|| panic!("missing second information step"))
        .as_mut()
        .unwrap_or_else(|error| panic!("unexpected scripted error: {error}"))
        .parent_process_id += 1;
    assert!(capture_with(&mut information_changes).is_err());

    let mut identity_disagrees = ObservationValues::stable();
    identity_disagrees.identity.parent_process_id += 1;
    assert_capture_rejected(identity_disagrees);
}

#[test]
fn scalar_and_information_sandwich_changes_are_rejected() {
    for scalar_field in 0..4 {
        let mut source = ScriptedSource::stable(ObservationValues::stable());
        let after = source
            .scalars
            .get_mut(1)
            .unwrap_or_else(|| panic!("missing second scalar step"))
            .as_mut()
            .unwrap_or_else(|error| panic!("unexpected scripted error: {error}"));
        match scalar_field {
            0 => after.boot_id[0] ^= 1,
            1 => after.process_id += 1,
            2 => after.effective_user_id += 1,
            3 => after.effective_group_id += 1,
            _ => unreachable!(),
        }
        assert!(capture_with(&mut source).is_err());
    }

    for information_field in 0..6 {
        let mut source = ScriptedSource::stable(ObservationValues::stable());
        let after = source
            .information
            .get_mut(1)
            .unwrap_or_else(|| panic!("missing second information step"))
            .as_mut()
            .unwrap_or_else(|error| panic!("unexpected scripted error: {error}"));
        match information_field {
            0 => after.process_id += 1,
            1 => after.thread_group_id += 1,
            2 => after.parent_process_id += 1,
            3 => after.cgroup_id = Some(56),
            4 => after.credentials = None,
            5 => {
                after
                    .credentials
                    .as_mut()
                    .unwrap_or_else(|| panic!("missing credentials"))
                    .saved_user_id += 1;
            }
            _ => unreachable!(),
        }
        assert!(capture_with(&mut source).is_err());
    }
}

#[test]
fn every_observation_operation_failure_is_redacted() {
    let expected = BrokerSessionSecurityError::ExecutionChanged;

    let mut first_scalar = ScriptedSource::stable(ObservationValues::stable());
    first_scalar.scalars[0] = Err(expected.clone());
    assert_eq!(
        capture_with(&mut first_scalar).err(),
        Some(expected.clone())
    );

    let mut open = ScriptedSource::stable(ObservationValues::stable());
    open.open = Some(Err(expected.clone()));
    assert_eq!(capture_with(&mut open).err(), Some(expected.clone()));

    let mut first_information = ScriptedSource::stable(ObservationValues::stable());
    first_information.information[0] = Err(expected.clone());
    assert_eq!(
        capture_with(&mut first_information).err(),
        Some(expected.clone())
    );

    let mut identity = ScriptedSource::stable(ObservationValues::stable());
    identity.identity[0] = Err(expected.clone());
    assert_eq!(capture_with(&mut identity).err(), Some(expected.clone()));

    let mut second_information = ScriptedSource::stable(ObservationValues::stable());
    second_information.information[1] = Err(expected.clone());
    assert_eq!(
        capture_with(&mut second_information).err(),
        Some(expected.clone())
    );

    let mut liveness = ScriptedSource::stable(ObservationValues::stable());
    liveness.alive[0] = Err(expected.clone());
    assert_eq!(capture_with(&mut liveness).err(), Some(expected.clone()));

    let mut second_scalar = ScriptedSource::stable(ObservationValues::stable());
    second_scalar.scalars[1] = Err(expected.clone());
    assert_eq!(capture_with(&mut second_scalar).err(), Some(expected));
}
