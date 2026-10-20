//! Shares actual disposed startup phases under one original Controller capacity.
//!
//! The same B ledger permanently reserves this closed pool. Profile, rich
//! credential and Publisher consumers cannot construct it from numeric DATA.
//! Native owners retain their failures; only their physical positive disposal
//! advances the fixed product phase. No transition credits or resets a ledger.

use aos_sandbox_core::{ResourceDimension as D, ResourceVector};

use aos_sandbox_core::component_receiving::complete_bound_delta_v1;
use super::ControllerReceivingErrorV1;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(in crate::controller_receiving) enum CredentialPurposeV1 {
    SourceGenesis,
    PublicTls,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum StageV1 {
    RuntimeProfile,
    SourceAvailable,
    SourceActive,
    ConstructionAvailable,
    Construction,
    Enrolled,
    PublicActive,
    Serving,
}

/// Holds private fixed purposes and their permanently reserved common peak.
pub(in crate::controller_receiving) struct ControllerStartupEnvelopeV1 {
    peak: ResourceVector,
    profile: ResourceVector,
    credential_profile: ResourceVector,
    construction: ResourceVector,
    source: ResourceVector,
    public: ResourceVector,
    serving: ResourceVector,
    publisher: ResourceVector,
    public_enabled: bool,
    publisher_enabled: bool,
    source_claimed: bool,
    public_claimed: bool,
    stage: StageV1,
}

impl ControllerStartupEnvelopeV1 {
    pub(in crate::controller_receiving) fn new(
        profile: ResourceVector,
        credential_profile: ResourceVector,
        construction: ResourceVector,
        source_files: usize,
        public: ResourceVector,
        publisher: ResourceVector,
        public_enabled: bool,
        publisher_enabled: bool,
    ) -> Result<Self, ControllerReceivingErrorV1> {
        let source_files = u64::try_from(source_files)
            .map_err(|_| ControllerReceivingErrorV1::EnrollmentUnavailable)?;
        let source = credential_profile.checked_add(ResourceVector::ZERO.with(D::OpenFiles, source_files))?;
        let public_phase = credential_profile.checked_add(public)?;
        // Complete positive TLS handoff disposes every auxiliary proof FD.
        // Its normal acceptor/model memory stays resident beside future work.
        let serving = profile.checked_add(public.with(D::OpenFiles, 0))?
            .checked_add(publisher)?;
        let mut peak = ResourceVector::ZERO;
        for phase in [profile, construction, source, public_phase, serving] {
            peak = complete_bound_delta_v1(peak, phase)?.0;
        }
        Ok(Self {
            peak, profile, credential_profile, construction, source, public: public_phase, serving,
            publisher, public_enabled, publisher_enabled, source_claimed: false,
            public_claimed: false, stage: StageV1::RuntimeProfile,
        })
    }

    pub(in crate::controller_receiving) fn is_unfinished(&self) -> bool {
        self.stage != StageV1::Serving
    }

    pub(in crate::controller_receiving) const fn peak(&self) -> ResourceVector {
        self.peak
    }

    pub(in crate::controller_receiving) fn profile_disposed(&mut self) -> Result<(), ControllerReceivingErrorV1> {
        if self.stage == StageV1::RuntimeProfile {
            self.stage = StageV1::SourceAvailable;
        }
        Ok(())
    }

    pub(in crate::controller_receiving) fn claim_credential(&mut self, purpose: CredentialPurposeV1)
        -> Result<(), ControllerReceivingErrorV1>
    {
        let claimed = match purpose {
            CredentialPurposeV1::SourceGenesis if self.stage == StageV1::SourceAvailable =>
                &mut self.source_claimed,
            CredentialPurposeV1::PublicTls if self.stage == StageV1::Enrolled && self.public_enabled =>
                &mut self.public_claimed,
            _ => return Err(ControllerReceivingErrorV1::Conflict),
        };
        if *claimed {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        *claimed = true;
        Ok(())
    }

    pub(in crate::controller_receiving) fn begin_credential(&mut self, purpose: CredentialPurposeV1)
        -> Result<(ResourceVector, ResourceVector), ControllerReceivingErrorV1>
    {
        let required = match purpose {
            CredentialPurposeV1::SourceGenesis
                if self.stage == StageV1::SourceAvailable && self.source_claimed => {
                    self.stage = StageV1::SourceActive;
                    self.source
                }
            CredentialPurposeV1::PublicTls
                if self.stage == StageV1::Enrolled && self.public_claimed => {
                    self.stage = StageV1::PublicActive;
                    self.public
                }
            _ => return Err(ControllerReceivingErrorV1::Conflict),
        };
        Ok((self.peak, required))
    }

    // Only the actual same-original credential consumer invokes this after
    // native handoff, all independent profile posts and complete disposal.
    pub(in crate::controller_receiving) fn credential_disposed(&mut self, purpose: CredentialPurposeV1)
        -> Result<(), ControllerReceivingErrorV1>
    {
        self.stage = match (purpose, self.stage) {
            (CredentialPurposeV1::SourceGenesis, StageV1::SourceActive) => StageV1::ConstructionAvailable,
            (CredentialPurposeV1::PublicTls, StageV1::PublicActive) => StageV1::Serving,
            _ => return Err(ControllerReceivingErrorV1::Conflict),
        };
        Ok(())
    }

    pub(in crate::controller_receiving) fn begin_construction(&mut self) -> Result<(), ControllerReceivingErrorV1> {
        if self.stage != StageV1::ConstructionAvailable {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        self.stage = StageV1::Construction;
        Ok(())
    }

    pub(in crate::controller_receiving) fn enrolled(&mut self) -> Result<(), ControllerReceivingErrorV1> {
        if self.stage != StageV1::Construction {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        self.stage = StageV1::Enrolled;
        Ok(())
    }

    pub(in crate::controller_receiving) fn serve_without_public(&mut self) -> Result<(), ControllerReceivingErrorV1> {
        if self.public_enabled || self.stage != StageV1::Enrolled {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        self.stage = StageV1::Serving;
        Ok(())
    }

    pub(in crate::controller_receiving) fn profile_capacity(&self) -> Result<ResourceVector, ControllerReceivingErrorV1> {
        if self.stage == StageV1::RuntimeProfile {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        Ok(self.profile)
    }

    pub(in crate::controller_receiving) fn require_cache_prebank_import(&self)
        -> Result<(), ControllerReceivingErrorV1>
    {
        if self.stage != StageV1::ConstructionAvailable {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        Ok(())
    }

    pub(in crate::controller_receiving) fn construction_post_capacity(&self) -> Result<ResourceVector, ControllerReceivingErrorV1> {
        if self.stage != StageV1::Construction {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        Ok(self.credential_profile)
    }

    pub(in crate::controller_receiving) fn construction_capacity(&self) -> Result<ResourceVector, ControllerReceivingErrorV1> {
        if self.stage != StageV1::Construction {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        Ok(self.construction)
    }

    pub(in crate::controller_receiving) fn publisher_capacity(&self) -> Result<ResourceVector, ControllerReceivingErrorV1> {
        if !self.publisher_enabled || self.stage != StageV1::Serving {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        // Keep this permanent serving combination beside the same retained
        // acceptor and one actual profile scope; it is never returned as cash.
        self.peak.checked_sub(self.serving)?;
        Ok(self.publisher)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(public: bool, publisher: bool) -> ControllerStartupEnvelopeV1 {
        ControllerStartupEnvelopeV1::new(
            ResourceVector::ZERO.with(D::MemoryBytes, 10).with(D::OpenFiles, 2),
            ResourceVector::ZERO.with(D::MemoryBytes, 10).with(D::OpenFiles, 2),
            ResourceVector::ZERO.with(D::MemoryBytes, 40).with(D::OpenFiles, 8),
            24,
            if public {
                ResourceVector::ZERO.with(D::MemoryBytes, 100).with(D::OpenFiles, 24)
            } else { ResourceVector::ZERO },
            if publisher {
                ResourceVector::ZERO.with(D::MemoryBytes, 20).with(D::OpenFiles, 15)
            } else { ResourceVector::ZERO },
            public, publisher,
        ).unwrap()
    }

    #[test]
    fn every_dimension_is_reserved_at_the_complete_coexisting_phase_peak() {
        for dimension in D::ALL {
            let profile = ResourceVector::ZERO.with(dimension, 3);
            let construction = ResourceVector::ZERO.with(dimension, 17);
            let public = ResourceVector::ZERO.with(dimension, 19);
            let publisher = ResourceVector::ZERO.with(dimension, 23);
            let envelope = ControllerStartupEnvelopeV1::new(
                profile, profile, construction, 24, public, publisher, true, true,
            ).unwrap();

            for phase in [profile, construction, envelope.source, envelope.public, envelope.serving] {
                assert!(envelope.peak().checked_sub(phase).is_ok());
            }
            let expected = if dimension == D::OpenFiles { 27 } else { 45 };
            assert_eq!(envelope.peak().get(dimension), expected);
        }
    }

    #[test]
    fn narrower_credential_recipe_never_replaces_the_generic_serving_profile() {
        let generic = ResourceVector::ZERO.with(D::OpenFiles, 54);
        let credentials = ResourceVector::ZERO.with(D::OpenFiles, 40);
        let construction = ResourceVector::ZERO.with(D::OpenFiles, 70);
        let public = ResourceVector::ZERO.with(D::OpenFiles, 24);
        let publisher = ResourceVector::ZERO.with(D::OpenFiles, 15);
        let envelope = ControllerStartupEnvelopeV1::new(
            generic, credentials, construction, 24, public, publisher, true, true,
        ).unwrap();

        assert_eq!(envelope.source.get(D::OpenFiles), 64);
        assert_eq!(envelope.public.get(D::OpenFiles), 64);
        assert_eq!(envelope.serving.get(D::OpenFiles), 69);
        assert_eq!(envelope.peak().get(D::OpenFiles), 70);
    }

    #[test]
    fn a_live_or_failed_source_cannot_start_construction_or_public() {
        let mut envelope = envelope(true, true);
        assert!(envelope.claim_credential(CredentialPurposeV1::SourceGenesis).is_err());
        envelope.profile_disposed().unwrap();
        envelope.claim_credential(CredentialPurposeV1::SourceGenesis).unwrap();
        let peak = envelope.peak();
        let (capacity, required) = envelope.begin_credential(CredentialPurposeV1::SourceGenesis).unwrap();

        assert!(capacity.checked_sub(required).is_ok());
        assert!(envelope.begin_construction().is_err());
        assert!(envelope.claim_credential(CredentialPurposeV1::PublicTls).is_err());
        assert!(envelope.publisher_capacity().is_err());
        assert!(envelope.is_unfinished());
        assert_eq!(envelope.peak(), peak);
    }

    #[test]
    fn real_disposal_order_is_required_before_serving_and_never_changes_capacity() {
        let mut envelope = envelope(true, true);
        let peak = envelope.peak();
        envelope.profile_disposed().unwrap();
        envelope.claim_credential(CredentialPurposeV1::SourceGenesis).unwrap();
        envelope.begin_credential(CredentialPurposeV1::SourceGenesis).unwrap();
        envelope.credential_disposed(CredentialPurposeV1::SourceGenesis).unwrap();
        envelope.begin_construction().unwrap();
        assert!(envelope.claim_credential(CredentialPurposeV1::PublicTls).is_err());
        envelope.enrolled().unwrap();
        assert!(envelope.serve_without_public().is_err());
        envelope.claim_credential(CredentialPurposeV1::PublicTls).unwrap();
        envelope.begin_credential(CredentialPurposeV1::PublicTls).unwrap();
        assert!(envelope.publisher_capacity().is_err());
        envelope.credential_disposed(CredentialPurposeV1::PublicTls).unwrap();

        assert_eq!(envelope.publisher_capacity().unwrap().get(D::OpenFiles), 15);
        assert!(!envelope.is_unfinished());
        assert_eq!(envelope.peak(), peak);
        assert!(envelope.claim_credential(CredentialPurposeV1::SourceGenesis).is_err());
        assert!(envelope.claim_credential(CredentialPurposeV1::PublicTls).is_err());
    }

    #[test]
    fn disabled_public_requires_its_fixed_nonpublic_transition() {
        let mut envelope = envelope(false, false);
        envelope.profile_disposed().unwrap();
        envelope.claim_credential(CredentialPurposeV1::SourceGenesis).unwrap();
        envelope.begin_credential(CredentialPurposeV1::SourceGenesis).unwrap();
        envelope.credential_disposed(CredentialPurposeV1::SourceGenesis).unwrap();
        envelope.begin_construction().unwrap();
        envelope.enrolled().unwrap();
        assert!(envelope.claim_credential(CredentialPurposeV1::PublicTls).is_err());
        envelope.serve_without_public().unwrap();

        assert!(!envelope.is_unfinished());
        assert!(envelope.publisher_capacity().is_err());
        assert!(envelope.serve_without_public().is_err());
    }
}
