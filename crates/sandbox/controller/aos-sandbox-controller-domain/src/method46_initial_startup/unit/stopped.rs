//! Retains fixed stopped-owner PID1 samples around initial provisioning work.
//!
//! These observations share the actual Source-paid startup manager. They prove
//! bracketed inactive/dead unit DATA and compare the selected normal owner's
//! public manifest source and its Source-pinned immutable unit fragment.
//! Full unit image admission, exclusion of new jobs,
//! native cgroup population, exclusive journal custody and physical TPM
//! authority remain independent requirements.

use super::*;

use aos_sandbox_linux::cgroup::StorageCgroupLayoutV1;

const OWNERS: [(&str, &[&str]); 2] = [
    (
        "aos-sandboxd.service",
        &["/aos.slice/aos-control.slice/aos-sandboxd.service"],
    ),
    // Both layouts are fixed recipes of the actual Storage owner. Preserve
    // PID1's selected path as DATA; never probe another layout after refusal.
    (
        "aos-storaged.service",
        &[
            StorageCgroupLayoutV1::Ordinary.main_control_group_v1(),
            StorageCgroupLayoutV1::ReceivingAggregate.main_control_group_v1(),
        ],
    ),
];
const SERVICE: &[&str] = &[
    "ControlGroup",
    "LoadCredential",
    "LoadCredentialEncrypted",
    "SetCredential",
    "SetCredentialEncrypted",
    "ImportCredential",
    "ImportCredentialEx",
    "ExecStart",
    "SELinuxContext",
];
const UNIT: &[&str] = &["LoadState", "FragmentPath", "DropInPaths", "Transient"];

pub(super) struct InitialStoppedOwnersOriginalV1 {
    samples: [[RefCell<UnitPropertiesOriginalV1>; 2]; 2],
    entered: Cell<bool>,
    before_completed: Cell<bool>,
    manifest_source_match: [Cell<Option<bool>>; 2],
    fragment: RefCell<normal_fragment::NormalFragmentOriginalV1>,
}

impl InitialStoppedOwnersOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            samples: std::array::from_fn(|_| {
                std::array::from_fn(|_| RefCell::new(UnitPropertiesOriginalV1::new()))
            }),
            entered: Cell::new(false),
            before_completed: Cell::new(false),
            manifest_source_match: std::array::from_fn(|_| Cell::new(None)),
            fragment: RefCell::new(normal_fragment::NormalFragmentOriginalV1::new()),
        }
    }

    fn observe(
        &self,
        round: usize,
        runtime: Option<&tokio::runtime::Runtime>,
        manager: Option<&aos_systemd_client::SystemdClient>,
        role: Option<Method46InitialServiceRoleV1>,
        fragment: &[u8],
        profile: Option<&Method46InitialProfileDataV3>,
    ) -> Result<(), Method46InitialStartupClosedV1> {
        let selected = role.map(|role| match role {
            Method46InitialServiceRoleV1::ControllerStorageClient => 0,
            Method46InitialServiceRoleV1::StorageBroker => 1,
        });
        let mut refused = selected.is_none();
        for (index, (unit, cgroup)) in OWNERS.iter().enumerate() {
            // A failed owner cannot suppress the other independently paid read.
            let result = (|| {
                let mut sample = self.samples[round][index]
                    .try_borrow_mut()
                    .map_err(|_| Method46InitialStartupClosedV1)?;
                if sample.entered {
                    return Err(Method46InitialStartupClosedV1);
                }
                sample.entered = true;
                if tokio::runtime::Handle::try_current().is_ok() {
                    return Err(Method46InitialStartupClosedV1);
                }
                let runtime = runtime.ok_or(Method46InitialStartupClosedV1)?;
                let manager = manager.ok_or(Method46InitialStartupClosedV1)?;
                sample.result = Some(
                    runtime.block_on(
                        sample
                            .original
                            .observe_stopped_once_v1(manager, unit, SERVICE, UNIT),
                    ),
                );
                if !matches!(sample.result, Some(Ok(()))) {
                    return Err(Method46InitialStartupClosedV1);
                }
                require_loaded(
                    sample
                        .original
                        .unit_values_v2()
                        .and_then(|values| values.get(..1)),
                )?;
                let values = sample.original.service_values_v2();
                require_cgroup(
                    values
                        .and_then(|values| values.first())
                        .map(std::slice::from_ref),
                    cgroup,
                )?;
                if selected == Some(index) {
                    let properties = sample
                        .original
                        .unit_values_v2()
                        .ok_or(Method46InitialStartupClosedV1)?;
                    let path = fragment_values(
                        properties.get(1..).ok_or(Method46InitialStartupClosedV1)?,
                    )?;
                    require_fragment_name(path, unit)?;
                    if round == 1 {
                        let before = self.samples[0][index]
                            .try_borrow()
                            .map_err(|_| Method46InitialStartupClosedV1)?;
                        let initial = before
                            .original
                            .unit_values_v2()
                            .ok_or(Method46InitialStartupClosedV1)?;
                        if fragment_values(initial.get(1..).ok_or(Method46InitialStartupClosedV1)?)?
                            != path
                        {
                            return Err(Method46InitialStartupClosedV1);
                        }
                    }
                    let matched = values
                        .and_then(|values| values.get(1..7))
                        .zip(role)
                        .is_some_and(|(values, role)| {
                            delivery::require_normal_manifest_source(role, values, fragment).is_ok()
                        });
                    self.manifest_source_match[round].set(Some(matched));
                    if !matched {
                        return Err(Method46InitialStartupClosedV1);
                    }
                    normal_command::require_command(
                        values
                            .and_then(|values| values.get(7..))
                            .ok_or(Method46InitialStartupClosedV1)?,
                        role.ok_or(Method46InitialStartupClosedV1)?,
                        &profile.ok_or(Method46InitialStartupClosedV1)?.normal_image,
                    )?;
                }
                if round == 1 {
                    let before = self.samples[0][index]
                        .try_borrow()
                        .map_err(|_| Method46InitialStartupClosedV1)?;
                    let invocation = before
                        .original
                        .completed_invocation_bytes_data_v1()
                        .ok_or(Method46InitialStartupClosedV1)?;
                    if sample.original.completed_invocation_bytes_data_v1() != Some(invocation)
                        || values.and_then(|values| values.first())
                            != before
                                .original
                                .service_values_v2()
                                .and_then(|values| values.first())
                    {
                        return Err(Method46InitialStartupClosedV1);
                    }
                }
                Ok(())
            })();
            refused |= result.is_err();
        }
        if refused {
            Err(Method46InitialStartupClosedV1)
        } else {
            if round == 0 {
                let index = selected.ok_or(Method46InitialStartupClosedV1)?;
                let profile = profile.ok_or(Method46InitialStartupClosedV1)?;
                let sample = self.samples[0][index]
                    .try_borrow()
                    .map_err(|_| Method46InitialStartupClosedV1)?;
                self.fragment
                    .try_borrow_mut()
                    .map_err(|_| Method46InitialStartupClosedV1)?
                    .observe_once(
                        &sample.original,
                        OWNERS[index].0,
                        &profile.normal_unit_fragment,
                    )?;
                self.before_completed.set(true);
            }
            Ok(())
        }
    }
}

fn require_cgroup(
    values: Option<&[aos_systemd_client::OwnedValue]>,
    expected: &[&str],
) -> Result<(), Method46InitialStartupClosedV1> {
    let Some([value]) = values else {
        return Err(Method46InitialStartupClosedV1);
    };
    let Value::Str(actual) = &**value else {
        return Err(Method46InitialStartupClosedV1);
    };
    if actual.is_empty() || expected.contains(&actual.as_str()) {
        Ok(())
    } else {
        Err(Method46InitialStartupClosedV1)
    }
}

fn require_loaded(
    values: Option<&[aos_systemd_client::OwnedValue]>,
) -> Result<(), Method46InitialStartupClosedV1> {
    let Some([value]) = values else {
        return Err(Method46InitialStartupClosedV1);
    };
    if matches!(&**value, Value::Str(state) if state.as_str() == "loaded") {
        Ok(())
    } else {
        Err(Method46InitialStartupClosedV1)
    }
}

pub(super) fn receiving_memory_bytes() -> Option<usize> {
    ServicePropertiesReadOriginalV2::receiving_memory_bytes_v2(SERVICE.len(), UNIT.len())?
        .checked_mul(4)
}

impl InitialUnitOriginalV1 {
    pub(in crate::method46_initial_startup) fn stopped_units_before_completed(&self) -> bool {
        self.stopped.before_completed.get()
            && self
                .stopped
                .fragment
                .try_borrow()
                .is_ok_and(|fragment| fragment.completed())
            && self.stopped.manifest_source_match[0].get() == Some(true)
            && self.stopped.samples[0].iter().all(|sample| {
                sample.try_borrow().is_ok_and(|sample| {
                    matches!(sample.result, Some(Ok(())))
                        && sample.original.service_values_v2().is_some()
                        && sample.original.unit_values_v2().is_some()
                })
            })
    }

    pub(super) fn finish_stopped_post(
        &self,
        role: Option<Method46InitialServiceRoleV1>,
        profile: Option<&Method46InitialProfileDataV3>,
    ) -> Result<(), Method46InitialStartupClosedV1> {
        if !self.stopped.entered.get() {
            return Ok(());
        }
        let stopped = self.stopped.observe(
            1,
            self.runtime
                .as_ref()
                .and_then(|result| result.as_ref().ok()),
            self.manager
                .as_ref()
                .and_then(|original| original.client_v2())
                .map(|client| client.as_ref()),
            role,
            self.acquisition.bytes(),
            profile,
        );
        let fragment = self
            .stopped
            .fragment
            .try_borrow_mut()
            .map_err(|_| Method46InitialStartupClosedV1)
            .and_then(|mut original| original.finish_post());
        stopped.and(fragment)
    }
}

impl Method46InitialStartupOriginalV1 {
    /// Observes the fixed Controller and Storage units as stopped once.
    ///
    /// The actual Source pays all four retained before/after samples with its
    /// startup manager before construction. The final samples remain owed
    /// after either initial read refuses. Changed invocation or cgroup DATA
    /// fences the interval. This supplies no native population, writer or TPM
    /// authority, and does not prevent a later PID1 job from starting.
    ///
    /// # Errors
    /// Refuses an unavailable Source, missing unit admission, reentry, nested
    /// Runtime, live/failed/missing owner, nonzero PID, foreign cgroup or any
    /// native/property failure, mutable/changed normal fragment or a digest
    /// differing from the same startup's profile. Originals and both fragment
    /// posts stay resident through Source posts.
    pub fn observe_stopped_owner_units_once_v1(
        &mut self,
    ) -> Result<(), Method46InitialStartupClosedV1> {
        self.source
            .get_mut()
            .require_current_v1()
            .map_err(|_| self.closed)?;
        let body = self.body.as_ref().ok_or(self.closed)?;
        let unit = &body.unit;
        if self.first.get().is_some()
            || !unit.initial_admitted()
            || unit.stopped.entered.replace(true)
        {
            return Err(self.fail(First::Order));
        }
        unit.stopped
            .observe(
                0,
                unit.runtime
                    .as_ref()
                    .and_then(|result| result.as_ref().ok()),
                unit.manager
                    .as_ref()
                    .and_then(|original| original.client_v2())
                    .map(|client| client.as_ref()),
                self.origin.as_ref().map(|origin| origin.role),
                unit.acquisition.bytes(),
                body.profile_decoded
                    .as_ref()
                    .and_then(|value| value.as_ref().ok()),
            )
            .map_err(|_| self.fail(First::Unit))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(text: &str) -> aos_systemd_client::OwnedValue {
        aos_systemd_client::OwnedValue::try_from(Value::from(text.to_owned())).unwrap()
    }

    #[test]
    fn stopped_owner_requires_a_loaded_unit_in_the_original_property_sample() {
        assert!(require_loaded(Some(&[value("loaded")])).is_ok());
        for state in [
            "not-found",
            "masked",
            "error",
            "bad-setting",
            "stub",
            "merged",
            "",
        ] {
            assert!(require_loaded(Some(&[value(state)])).is_err());
        }
        assert!(require_loaded(None).is_err());
        assert!(require_loaded(Some(&[])).is_err());
        assert!(require_loaded(Some(&[aos_systemd_client::OwnedValue::from(false)])).is_err());
    }

    #[test]
    fn stopped_owner_cgroups_accept_only_absence_or_the_exact_fixed_owner() {
        for (_, expected) in OWNERS {
            assert!(require_cgroup(Some(&[value("")]), expected).is_ok());
            for path in expected {
                assert!(require_cgroup(Some(&[value(path)]), expected).is_ok());
            }
            assert!(
                require_cgroup(Some(&[value("/system.slice/foreign.service")]), expected).is_err()
            );
        }
        assert!(require_cgroup(Some(&[value(OWNERS[0].1[0])]), OWNERS[1].1).is_err());
    }

    #[test]
    fn stopped_owner_cgroups_reject_missing_extra_and_mistyped_values() {
        let expected = OWNERS[0].1;
        assert!(require_cgroup(None, expected).is_err());
        assert!(require_cgroup(Some(&[]), expected).is_err());
        assert!(require_cgroup(Some(&[value(""), value("")]), expected).is_err());
        assert!(
            require_cgroup(
                Some(&[aos_systemd_client::OwnedValue::from(0u32)]),
                expected
            )
            .is_err()
        );
    }

    #[test]
    fn stopped_owner_post_attempts_both_paid_slots_after_initial_refusal() {
        let original = InitialStoppedOwnersOriginalV1::new();
        original.entered.set(true);

        assert!(original.observe(0, None, None, None, b"", None).is_err());
        assert!(original.observe(1, None, None, None, b"", None).is_err());

        for round in original.samples {
            for sample in round {
                let sample = sample.into_inner();
                assert!(sample.entered);
                assert!(sample.result.is_none());
            }
        }
    }

    #[test]
    fn copied_stopped_comparisons_cannot_replace_native_samples() {
        let unit = InitialUnitOriginalV1::new();
        unit.stopped.before_completed.set(true);
        unit.stopped.manifest_source_match[0].set(Some(true));

        assert!(!unit.stopped_units_before_completed());
        assert!(unit.stopped.samples[0].iter().all(|sample| {
            let sample = sample.borrow();
            !sample.entered && sample.result.is_none()
        }));
    }

    #[test]
    fn stopped_owner_posts_survive_a_busy_startup_property_post() {
        let mut unit = InitialUnitOriginalV1::new();
        // Negative dispatch only: no positive Source or manager is fabricated.
        unit.paid = true;
        unit.stopped.entered.set(true);
        let held = unit.properties[1].borrow_mut();

        assert!(unit.finish_post(None, None).is_err());

        for sample in &unit.stopped.samples[1] {
            assert!(sample.borrow().entered);
        }
        assert!(unit.canonical_post.borrow().entered);
        drop(held);
    }

    #[test]
    fn stopped_owner_units_require_an_actual_source_before_any_read() {
        let mut startup = std::mem::ManuallyDrop::new(Method46InitialStartupOriginalV1::new(
            Method46InitialServiceRoleV1::StorageBroker,
        ));

        assert!(startup.observe_stopped_owner_units_once_v1().is_err());

        assert!(startup.body.is_none());
        assert_eq!(startup.receiving.get(), ResourceVector::ZERO);
    }
}
