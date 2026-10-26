//! Retains Source-paid normal-Root public credential delivery observations.
//!
//! The same startup manager reads only fixed configuration properties. Each
//! observation has its own unique-PID1 native bookends; both interval samples
//! must retain the same complete service tuple and configuration. These DATA
//! comparisons do not authenticate Root's process, journals or private keys.

use super::*;

const ROOT: &str = "aos-sandbox-policy-authorityd.service";
const SERVICE: &[&str] = &[
    "LoadCredential",
    "LoadCredentialEncrypted",
    "SetCredential",
    "SetCredentialEncrypted",
    "ImportCredential",
    "ImportCredentialEx",
];
const UNIT: &[&str] = &["LoadState", "FragmentPath", "DropInPaths", "Transient"];

pub(super) struct RootPublicDeliveryOriginal {
    samples: [RefCell<UnitPropertiesOriginalV1>; 2],
    before_complete: Cell<bool>,
}

impl RootPublicDeliveryOriginal {
    pub(super) fn new() -> Self {
        Self {
            samples: std::array::from_fn(|_| RefCell::new(UnitPropertiesOriginalV1::new())),
            before_complete: Cell::new(false),
        }
    }

    #[cfg(test)]
    pub(super) fn samples_entered_for_test(&self) -> bool {
        self.samples.iter().all(|sample| sample.borrow().entered)
    }

    pub(super) fn admitted_before_post(&self) -> bool {
        self.before_complete.get()
            && self.samples[0].try_borrow().is_ok_and(|sample| {
                matches!(sample.result, Some(Ok(())))
                    && sample.original.service_values_v2().is_some()
                    && sample.original.unit_values_v2().is_some()
            })
    }

    pub(super) fn observe(
        &self,
        round: usize,
        runtime: Option<&tokio::runtime::Runtime>,
        manager: Option<&aos_systemd_client::SystemdClient>,
        fragment: &[u8],
    ) -> Result<(), Method46InitialStartupClosedV1> {
        let mut sample = self.samples[round]
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
                    .observe_configuration_once_v1(manager, ROOT, SERVICE, UNIT),
            ),
        );
        if !matches!(sample.result, Some(Ok(()))) {
            return Err(Method46InitialStartupClosedV1);
        }
        let values = sample
            .original
            .unit_values_v2()
            .ok_or(Method46InitialStartupClosedV1)?;
        if !matches!(values.first().map(|value| &**value), Some(Value::Str(state))
            if state.as_str() == "loaded")
        {
            return Err(Method46InitialStartupClosedV1);
        }
        let path = fragment_values(values.get(1..).ok_or(Method46InitialStartupClosedV1)?)?;
        require_fragment_name(path, ROOT)?;
        delivery::require_normal_root_public_sources(
            sample
                .original
                .service_values_v2()
                .ok_or(Method46InitialStartupClosedV1)?,
            fragment,
        )?;

        if round == 1 {
            let before = self.samples[0]
                .try_borrow()
                .map_err(|_| Method46InitialStartupClosedV1)?;
            if !before
                .original
                .same_completed_service_tuple_data_v1(&sample.original)
                || before.original.service_values_v2() != sample.original.service_values_v2()
                || before.original.unit_values_v2() != sample.original.unit_values_v2()
            {
                return Err(Method46InitialStartupClosedV1);
            }
        } else {
            self.before_complete.set(true);
        }
        Ok(())
    }
}

pub(super) fn receiving_memory_bytes() -> Option<usize> {
    ServicePropertiesReadOriginalV2::receiving_memory_bytes_v2(SERVICE.len(), UNIT.len())?
        .checked_mul(2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copied_completion_cannot_replace_the_actual_root_configuration_sample() {
        let original = RootPublicDeliveryOriginal::new();
        original.before_complete.set(true);
        assert!(!original.admitted_before_post());
    }

    #[test]
    fn root_final_sample_stays_owed_after_the_initial_refusal() {
        let original = RootPublicDeliveryOriginal::new();

        assert!(original.observe(0, None, None, b"").is_err());
        assert!(original.observe(1, None, None, b"").is_err());

        for sample in original.samples {
            let sample = sample.into_inner();
            assert!(sample.entered);
            assert!(sample.result.is_none());
        }
    }
}
