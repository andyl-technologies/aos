//! Runs a fixed self-profile comparison through an already-held PID1 archive.
//!
//! The enclosing purpose retains its real lifetime, admission and mechanical
//! archive. This receiver neither enters C nor completes that upper purpose.
//! Its local prefix and independently owed local post retain every reached
//! native result; the borrowed archive retains the actual worker outcomes.

use std::path::PathBuf;

use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_systemd::FixedPid1PropertyArchiveV1;

use super::delivery::{self, ServiceObservationV1};
use super::local_currentness::LocalCurrentnessOriginalsV1;
use super::local_recipe::LocalCurrentness;
use super::property_values::PropertyPairV1;
use super::{ControllerProfileErrorV1, ControllerProfileLocalCurrentnessOriginalV1,
    ControllerSelfProfileOriginalV1, observer};

/// Retains one complete fixed observation under an existing purpose's archive.
///
/// The archive must be the same resident archive that the enclosing purpose
/// admitted and prepaid before this receiver is constructed. This type grants
/// no role, financial scope, observation reuse or upper completion authority.
#[must_use = "retain the receiver and its actual archive through all owed posts"]
pub struct ControllerExternalProfileObservationOriginalV1 {
    prefix: LocalCurrentness,
    prefix_originals: LocalCurrentnessOriginalsV1,
    prefix_result: Option<Result<(), ControllerProfileErrorV1>>,
    properties: Option<Result<PropertyPairV1, ControllerProfileErrorV1>>,
    decoded: Option<Result<ServiceObservationV1, ControllerProfileErrorV1>>,
    canonical: Option<std::io::Result<PathBuf>>,
    compared: Option<Result<(), ControllerProfileErrorV1>>,
    post: ControllerProfileLocalCurrentnessOriginalV1,
    post_result: Option<Result<(), ControllerProfileErrorV1>>,
    completion: Option<Result<(), ControllerProfileErrorV1>>,
    reentry: Option<ControllerProfileErrorV1>,
    first: Option<FailureStage>,
}

#[derive(Clone, Copy)]
enum FailureStage {
    Prefix,
    Properties,
    Comparison,
    Post,
}

impl ControllerExternalProfileObservationOriginalV1 {
    /// Creates inert native/result destinations without observing or admitting.
    #[must_use]
    pub fn new() -> Self {
        Self {
            prefix: LocalCurrentness::new(),
            prefix_originals: LocalCurrentnessOriginalsV1::new(),
            prefix_result: None,
            properties: None,
            decoded: None,
            canonical: None,
            compared: None,
            post: ControllerProfileLocalCurrentnessOriginalV1::new(),
            post_result: None,
            completion: None,
            reentry: None,
            first: None,
        }
    }

    /// Describes this receiver and both actual local destinations as DATA.
    ///
    /// The enclosing purpose separately pays its SAME archive's row/native
    /// geometry, row backing, worker capacity and all simultaneous receivers.
    /// This method issues no allocation permission or financial grant.
    #[must_use]
    pub fn receiving_demand_v1(
        profile: &ControllerSelfProfileOriginalV1,
        archive: &FixedPid1PropertyArchiveV1,
    ) -> Option<ResourceVector> {
        let local = profile.local_currentness_receiving_demand_v1()?;
        let inline = std::mem::size_of::<Self>()
            .checked_sub(std::mem::size_of::<ControllerProfileLocalCurrentnessOriginalV1>())?
            .checked_sub(std::mem::size_of::<LocalCurrentness>())?
            .checked_sub(std::mem::size_of::<LocalCurrentnessOriginalsV1>())?;
        // Canonical path plus the existing decoder's bounded unit/property
        // strings coexist with the original shared worker-owned tables.
        let memory = inline.checked_add(archive.materialization_limit_v1().checked_mul(3)?)?;
        local.checked_add(local).ok()?.checked_add(ResourceVector::ZERO
            // Native Result destinations and the first-stage control are
            // compiled memory. The nested local suppliers already count their
            // actual names; this wrapper creates no namespace entries.
            .with(D::MemoryBytes, u64::try_from(memory).ok()?)).ok()
    }

    /// Performs the fixed local/PID1/delivery/fragment comparison once.
    ///
    /// The enclosing purpose holds and funds the supplied archive before entry.
    /// The independent local post runs even after a failed primary prefix or
    /// property flight. No successful return completes or retires that purpose.
    ///
    /// # Errors
    /// Retains changed or unavailable native inputs, delivery or local posts.
    /// Reentry refuses without replacing any earlier result or native cause.
    pub fn observe_once(
        &mut self,
        profile: &ControllerSelfProfileOriginalV1,
        archive: &mut FixedPid1PropertyArchiveV1,
    ) -> Result<(), ControllerProfileErrorV1> {
        if self.completion.is_some() || self.prefix_result.is_some() {
            self.reentry.get_or_insert(ControllerProfileErrorV1::Service);
            return Err(ControllerProfileErrorV1::Service);
        }

        let _ = self.capture_prefix_once_v1(profile);
        let primary = if matches!(self.prefix_result, Some(Ok(()))) {
            self.observe_properties(profile, archive, None)
        } else {
            self.first = Some(FailureStage::Prefix);
            Err(ControllerProfileErrorV1::Service)
        };

        self.finish_with_post_v1(profile, primary)
    }

    /// Captures the same actual local prefix before the caller waits for a slot.
    ///
    /// # Errors
    /// Retains native prefix refusal or repeated entry. The caller still owes
    /// the fixed local post; this method grants no role or property observation.
    pub fn capture_prefix_once_v1(&mut self, profile: &ControllerSelfProfileOriginalV1)
        -> Result<(), ControllerProfileErrorV1>
    {
        if self.completion.is_some() || self.prefix_result.is_some() {
            self.reentry.get_or_insert(ControllerProfileErrorV1::Service);
            return Err(ControllerProfileErrorV1::Service);
        }
        self.prefix_result = Some(self.prefix.capture_prefix_observed(profile, &mut self.prefix_originals));
        if matches!(self.prefix_result, Some(Ok(()))) { Ok(()) } else {
            self.first = Some(FailureStage::Prefix);
            Err(ControllerProfileErrorV1::Service)
        }
    }

    /// Receives the same prepared property tables through the actual borrowed slot.
    ///
    /// The enclosing deadline-bearing owner rechecks its original absolute
    /// cutoff after acquiring this slot and immediately before this method.
    ///
    /// # Errors
    /// Retains failed preparation or property entry. The actual caller drops
    /// its joined worker slot before finishing comparison and the local post.
    pub fn observe_prepared_under_slot_once_v1(
        &mut self, profile: &ControllerSelfProfileOriginalV1,
        archive: &mut FixedPid1PropertyArchiveV1,
        slot: &mut aos_systemd::FixedPid1PropertyWorkerSlotV1,
    ) -> Result<(), ControllerProfileErrorV1> {
        if self.completion.is_some() || self.properties.is_some()
            || !matches!(self.prefix_result, Some(Ok(())))
        {
            self.reentry.get_or_insert(ControllerProfileErrorV1::Service);
            return Err(ControllerProfileErrorV1::Service);
        }
        let _ = profile;
        self.properties = Some(observer::read_controller_startup_under_slot_v1(archive, slot));
        if matches!(self.properties, Some(Ok(_))) { Ok(()) } else {
            self.first = Some(FailureStage::Properties);
            Err(ControllerProfileErrorV1::Service)
        }
    }

    /// Compares the actual returned property tables after the worker slot drops.
    ///
    /// # Errors
    /// Retains incomplete/repeated property entry, decoding, canonicalization
    /// or independently owed local refusal. It completes no enclosing purpose.
    pub fn finish_prepared_properties_once_v1(&mut self, profile: &ControllerSelfProfileOriginalV1)
        -> Result<(), ControllerProfileErrorV1>
    {
        if self.completion.is_some() || self.properties.is_none() {
            self.reentry.get_or_insert(ControllerProfileErrorV1::Service);
            return Err(ControllerProfileErrorV1::Service);
        }
        let primary = self.compare_properties_v1(profile);
        self.finish_with_post_v1(profile, primary)
    }

    /// Performs the independently owed local post without entering PID1 IO.
    ///
    /// # Errors
    /// Retains incomplete/repeated prefix or local refusal; this cannot report
    /// a complete profile comparison when its property stage was not entered.
    pub fn observe_local_post_without_properties_once_v1(
        &mut self, profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerProfileErrorV1> {
        if self.completion.is_some() || self.properties.is_some() || self.prefix_result.is_none() {
            self.reentry.get_or_insert(ControllerProfileErrorV1::Service);
            return Err(ControllerProfileErrorV1::Service);
        }
        self.finish_with_post_v1(profile, Err(ControllerProfileErrorV1::Service))
    }

    fn finish_with_post_v1(
        &mut self, profile: &ControllerSelfProfileOriginalV1,
        primary: Result<(), ControllerProfileErrorV1>,
    ) -> Result<(), ControllerProfileErrorV1> {
        self.post_result = Some(profile.observe_local_currentness_retaining_v1(&mut self.post));
        if self.first.is_none() && !matches!(self.post_result, Some(Ok(()))) {
            self.first = Some(FailureStage::Post);
        }
        self.completion = Some(match (primary, &self.post_result) {
            (Ok(()), Some(Ok(()))) => Ok(()),
            (Err(first), _) => Err(first),
            _ => Err(ControllerProfileErrorV1::Service),
        });
        if matches!(self.completion, Some(Ok(()))) {
            Ok(())
        } else {
            Err(ControllerProfileErrorV1::Service)
        }
    }

    fn observe_properties(
        &mut self,
        profile: &ControllerSelfProfileOriginalV1,
        archive: &mut FixedPid1PropertyArchiveV1,
        slot: Option<&mut aos_systemd::FixedPid1PropertyWorkerSlotV1>,
    ) -> Result<(), ControllerProfileErrorV1> {
        self.properties = Some(match slot {
            Some(slot) => observer::read_controller_startup_under_slot_v1(archive, slot),
            None => observer::read_controller_startup_with_archive(archive),
        });
        self.compare_properties_v1(profile)
    }

    fn compare_properties_v1(&mut self, profile: &ControllerSelfProfileOriginalV1)
        -> Result<(), ControllerProfileErrorV1>
    {
        let properties = match &self.properties {
            Some(Ok(properties)) => properties,
            _ => {
                self.first = Some(FailureStage::Properties);
                return Err(ControllerProfileErrorV1::Service);
            }
        };
        self.decoded = Some(delivery::decode_delivery_with_resource_launch(
            &properties.0, &properties.1, profile.profile_file.path(), profile.tpm_image,
            profile.nix_delivery.as_ref().map(|file| file.path()),
            profile.resource_delivery, profile.resource_launch,
        ));
        self.compared = Some((|| {
            let observed = self.decoded.as_mut().and_then(|result| result.as_mut().ok())
                .ok_or(ControllerProfileErrorV1::Service)?;
            // The original decoded result is updated by the same canonical
            // recipe; actual property tables remain shared with the worker.
            delivery::immutable_observation_in_place(observed, &mut self.canonical)?;
            delivery::require_same(&profile.observed, observed)?;
            self.prefix.capture_fragment_observed(profile, Some(&mut self.prefix_originals))
        })());
        if matches!(self.compared, Some(Ok(()))) {
            Ok(())
        } else {
            self.first = Some(FailureStage::Comparison);
            Err(ControllerProfileErrorV1::Service)
        }
    }

    /// Reports whether the actual first refusal belongs to the borrowed archive.
    ///
    /// The enclosing guarded archive owner resolves its original native failure
    /// only for this stage; a later property error cannot replace an earlier
    /// local or semantic cause.
    #[must_use]
    pub fn property_failure_is_first_v1(&self) -> bool {
        matches!(self.first, Some(FailureStage::Properties))
    }

    /// Borrows the actual first directly resident local or comparison cause.
    ///
    /// For a property-native first refusal, the same enclosing archive's guarded
    /// failure view provides the richer native cause while this stopping marker
    /// and the entire receiver remain resident.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first {
            Some(FailureStage::Prefix) => self.prefix.failure_observed(Some(&self.prefix_originals))
                .or_else(|| error(&self.prefix_result)),
            Some(FailureStage::Properties) => error(&self.properties),
            Some(FailureStage::Comparison) => error(&self.decoded)
                .or_else(|| error(&self.canonical))
                .or_else(|| self.prefix.failure_observed(Some(&self.prefix_originals)))
                .or_else(|| error(&self.compared)),
            Some(FailureStage::Post) => self.post.failure().or_else(|| error(&self.post_result)),
            None => self.reentry.as_ref().map(|cause| cause as _),
        }
    }
}

impl Default for ControllerExternalProfileObservationOriginalV1 {
    fn default() -> Self {
        Self::new()
    }
}

fn error<T, E: std::error::Error + 'static>(
    result: &Option<Result<T, E>>,
) -> Option<&(dyn std::error::Error + 'static)> {
    result.as_ref()?.as_ref().err().map(|cause| cause as _)
}
