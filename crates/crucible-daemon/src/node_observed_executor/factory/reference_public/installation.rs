//! Authenticates the source-installed public checksum mechanism and actual peer.
//!
//! This layer establishes only the fixed measured native mechanism. Ordinary
//! scenario admission additionally requires the complete behavioral ledger;
//! this source gate cannot turn an incomplete qualification run into Ready.

use std::{cell::RefCell, rc::Rc};

use crucible::{
    node_adapters::cnp::{CnpLaunchGuard, CnpReferenceQualification},
    node_contract::{EffectKnowledge, OperationFailure},
};
use crucible_node_contract::{
    ClosedGateRecord, ContentRef, Id, IdSet, ProviderManifest, SchemaRef, Validate,
};
use crucible_node_provider::{
    ProviderError,
    bodies::RealizeResult,
    handshake::{
        HelloRequest, HelloResult, ResumedOperation, TrustedHandshakeVerifier, TrustedInstallation,
    },
    reference_service::{ReferenceProfile, ReferenceServiceBootstrap},
};

use super::{native::NativePublicEnrollment, package::InstalledPublicReferencePackage};

/// Keeps actual private installation context independent of provider assertions.
pub(super) struct SourcePublicReferenceInstallation {
    pub(super) package: Rc<InstalledPublicReferencePackage>,
    pub(super) profile: ReferenceProfile,
    pub(super) bootstrap: ReferenceServiceBootstrap,
    pub(super) qualifications: Vec<ContentRef>,
    enrollment: RefCell<Option<NativePublicEnrollment>>,
}

impl SourcePublicReferenceInstallation {
    pub(super) fn new(
        package: Rc<InstalledPublicReferencePackage>,
        profile: ReferenceProfile,
        bootstrap: ReferenceServiceBootstrap,
        qualifications: Vec<ContentRef>,
        closed_ingress: bool,
    ) -> Result<Self, ProviderError> {
        bootstrap.validate()?;
        let measured = package
            .profile(
                profile.descriptor.id.clone(),
                profile.owner.id.clone(),
                bootstrap.quantum_ps,
                bootstrap.host_budget_ns,
                closed_ingress,
            )
            .map_err(package_error)?;
        let (actual, _) = profile.bind_qualified(bootstrap.authority.clone(), &qualifications)?;
        let (expected, _) =
            measured.bind_qualified(bootstrap.authority.clone(), &qualifications)?;
        if actual != expected
            || profile.provider_manifest != measured.provider_manifest
            || profile.content_possession_schema != measured.content_possession_schema
            || profile.contents != measured.contents
            || bootstrap.node_id != profile.descriptor.id
            || bootstrap.owner_id != profile.owner.id
            || qualifications.is_empty()
            || qualifications.len() > 64
            || qualifications
                .windows(2)
                .any(|pair| pair[0].hash.digest >= pair[1].hash.digest)
        {
            return Err(ProviderError::Correlation(
                "public source installation scope differs",
            ));
        }
        for reference in &qualifications {
            let content = bootstrap
                .installed_content
                .iter()
                .find(|content| &content.reference == reference)
                .ok_or(ProviderError::Correlation(
                    "installed source qualification bytes absent",
                ))?;
            reference.verify(content.bytes.as_slice())?;
        }
        Ok(Self {
            package,
            profile,
            bootstrap,
            qualifications,
            enrollment: RefCell::new(None),
        })
    }

    pub(super) fn enrollment(&self) -> Result<NativePublicEnrollment, ProviderError> {
        self.enrollment
            .borrow()
            .as_ref()
            .cloned()
            .ok_or(ProviderError::Correlation(
                "actual public native enrollment absent",
            ))
    }
}

impl CnpReferenceQualification for SourcePublicReferenceInstallation {
    fn authenticate_provider(
        &self,
        guard: &CnpLaunchGuard,
        profile: &ReferenceProfile,
    ) -> Result<(), OperationFailure> {
        let result = (|| {
            self.package.executable("provider").map_err(package_error)?;
            self.package.executable("device").map_err(package_error)?;
            if guard.provider_pid().is_none()
                || guard.supervision_id().get() == 0
                || profile.implementation != self.profile.implementation
                || profile.descriptor != self.profile.descriptor
                || profile.provider_manifest != self.profile.provider_manifest
                || profile.configuration_ref != self.profile.configuration_ref
            {
                return Err(ProviderError::Correlation(
                    "foreign actual public source realization",
                ));
            }
            if let Some(original) = self.enrollment.borrow().as_ref() {
                original.authenticate(&self.package, &self.bootstrap.resource_limits)?;
            }
            Ok(())
        })();
        result.map_err(no_effect)
    }

    fn authenticate_realization(
        &self,
        guard: &CnpLaunchGuard,
        realized: &RealizeResult,
        gate: &ClosedGateRecord,
        companion: u32,
    ) -> Result<(), OperationFailure> {
        let result = (|| {
            if realized.prepared_token != self.bootstrap.prepared_token
                || gate.gate_id != self.bootstrap.gate_id
                || !gate.gate_closed
                || gate.prepared_token != self.bootstrap.prepared_token
                || gate.owner_ids != [self.profile.owner.id.clone()]
                || !gate.extensions.is_empty()
            {
                return Err(ProviderError::Correlation(
                    "actual public stopped gate differs",
                ));
            }
            let provider = guard
                .provider_pid()
                .ok_or(ProviderError::Correlation("actual public provider absent"))?;
            let actual = NativePublicEnrollment::enroll(
                provider,
                companion,
                guard.supervision_id(),
                &self.package,
                &self.bootstrap.resource_limits,
            )?;
            let mut enrollment = self.enrollment.borrow_mut();
            if enrollment
                .as_ref()
                .is_some_and(|original| original != &actual)
            {
                return Err(ProviderError::Correlation(
                    "original public enrollment changed",
                ));
            }
            *enrollment = Some(actual);
            Ok(())
        })();
        result.map_err(|error| OperationFailure {
            effects: EffectKnowledge::Unknown,
            reason: error.to_string(),
        })
    }
}

impl TrustedHandshakeVerifier for SourcePublicReferenceInstallation {
    fn authenticate_exchange(
        &mut self,
        _: &Id,
        installation: &TrustedInstallation,
        request: &HelloRequest,
        result: &HelloResult,
    ) -> Result<(), ProviderError> {
        if installation.session_id != self.bootstrap.authority.session_id
            || installation.incarnation_id != self.bootstrap.authority.incarnation_id
            || installation.measured_implementation != self.profile.implementation
            || installation.launch_receipt != self.bootstrap.admission_receipt
            || request.admission_token != self.bootstrap.admission_token
            || request.session_id != self.bootstrap.authority.session_id
            || request.resume_session.is_some()
            || result.provider_identity != self.profile.provider_manifest
        {
            return Err(ProviderError::Correlation(
                "public handshake changed private installation",
            ));
        }
        Ok(())
    }

    fn verify_contract_selection(
        &mut self,
        manifest: &ProviderManifest,
        features: &IdSet,
        schemas: &[SchemaRef],
        guarantees: &ContentRef,
    ) -> Result<(), ProviderError> {
        let (binding, _) = self
            .profile
            .bind_qualified(self.bootstrap.authority.clone(), &self.qualifications)?;
        if features != &super::unit::required_features()?
            || manifest != &self.profile.provider_manifest
            || guarantees != &binding.compatibility.guarantees_ref
        {
            return Err(ProviderError::Correlation(
                "public peer selected a foreign installed contract",
            ));
        }
        self.profile.content(guarantees)?;
        for schema in schemas {
            self.profile.content(&schema.definition)?;
        }
        Ok(())
    }

    fn resume_custody(
        &mut self,
        _: &Id,
        _: &Id,
        operations: &IdSet,
    ) -> Result<Vec<ResumedOperation>, ProviderError> {
        if !operations.is_empty() {
            return Err(ProviderError::Correlation(
                "fresh public installation has no replay custody",
            ));
        }
        Ok(Vec::new())
    }

    fn fence_connection(&mut self, _: &Id) -> Result<(), ProviderError> {
        Err(ProviderError::Correlation(
            "fresh public installation cannot replace an original connection",
        ))
    }
}

fn package_error(error: super::super::NodeObservedError) -> ProviderError {
    ProviderError::Io(std::io::Error::other(error.to_string()))
}

fn no_effect(error: ProviderError) -> OperationFailure {
    OperationFailure {
        effects: EffectKnowledge::None,
        reason: error.to_string(),
    }
}
