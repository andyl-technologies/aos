//! Couples exact version1 peer negotiation to original authenticated Hello custody.

use std::rc::Rc;
use std::sync::Arc;

use crucible_node_format::{
    ContentRef, ExtensionSelection, Id, IdSet, ProviderManifest, SchemaRef, Validate,
};

use super::extension_contract::{decode_bounded, exact_intersection};
use super::{
    ConnectionAuthority, EXTENSION_NEGOTIATION_V1, ExtensionOfferV1, ExtensionSelectionV1,
    Handshake, HelloRequest, HelloResult, InstalledExtensionNegotiationVerifier, ResumedOperation,
    TrustedHandshakeVerifier, TrustedInstallation,
};
use crate::ProviderError;
use crate::envelope::Envelope;

/// Owns an opt-in installed contract and the same revocable Hello registration gate.
///
/// The transport policy must explicitly map the version1 envelope key to its
/// matching feature. This wrapper cannot unwrap or downgrade its surviving
/// handshake; resumption preserves every exact selected definition.
pub struct ExtensionHandshake {
    handshake: Handshake,
    installed: Rc<dyn InstalledExtensionNegotiationVerifier>,
    selected: Option<Arc<[ExtensionSelection]>>,
    original_registry: Option<OriginalExtensionRegistryOwner>,
}

impl ExtensionHandshake {
    pub(crate) fn from_original_empty_retained<R: OriginalEmptyExtensionRegistry + 'static>(
        handshake: &mut Option<Handshake>,
        registry: &Rc<R>,
    ) -> Result<Self, ProviderError> {
        if handshake.is_none()
            || !registry.supported().is_empty()
            || !registry.required().is_empty()
        {
            return Err(ProviderError::Correlation(
                "original empty extension registry differs",
            ));
        }
        let original = handshake
            .take()
            .ok_or(ProviderError::Correlation("original handshake absent"))?;
        let installed: Rc<dyn InstalledExtensionNegotiationVerifier> = registry.clone();
        Ok(Self {
            handshake: original,
            installed,
            selected: None,
            original_registry: None,
        })
    }

    /// Retains independently installed peer contracts before any exchange.
    ///
    /// # Errors
    /// Refuses malformed or oversized installed rosters and unsupported local
    /// requirements. Installation grants no native or graph admission authority.
    pub fn new(
        handshake: Handshake,
        installed: Rc<dyn InstalledExtensionNegotiationVerifier>,
    ) -> Result<Self, ProviderError> {
        super::extension_contract::validate_roster(installed.supported())?;
        super::extension_contract::validate_roster(installed.required())?;
        if installed
            .required()
            .iter()
            .any(|required| !installed.supported().contains(required))
        {
            return Err(ProviderError::Correlation(
                "local extension requirement is not installed",
            ));
        }
        Ok(Self {
            handshake,
            installed,
            selected: None,
            original_registry: None,
        })
    }

    /// Admits a correlated original Hello with an exact installed version1 roster.
    ///
    /// Required and optional tuples are compared before host callbacks. Installed
    /// contract verification then follows actual peer authentication and precedes
    /// journal custody, stream fencing and lease rotation. Failure preserves the
    /// previous typed selection and original registration lease.
    ///
    /// # Errors
    /// Refuses missing/unsupported editions, oversized or ambiguous rosters,
    /// changed required versions/schemas, invented selections, changed resume
    /// selection, untrusted contracts, or any ordinary Hello authentication failure.
    pub fn admit_envelopes(
        &mut self,
        request: &Envelope,
        response: &Envelope,
        connection: Id,
        verifier: &mut impl TrustedHandshakeVerifier,
    ) -> Result<ConnectionAuthority, ProviderError> {
        self.admit_envelopes_with_original(request, response, connection, verifier, None)
    }

    /// Keeps the same registry negotiation while borrowing native-owned claims.
    pub(crate) fn admit_original_envelopes(
        &mut self,
        request: &Envelope,
        response: &Envelope,
        hello: &HelloRequest,
        result: &HelloResult,
        connection: Id,
        verifier: &mut impl TrustedHandshakeVerifier,
    ) -> Result<ConnectionAuthority, ProviderError> {
        self.admit_envelopes_with_original(
            request,
            response,
            connection,
            verifier,
            Some((hello, result)),
        )
    }

    fn admit_envelopes_with_original(
        &mut self,
        request: &Envelope,
        response: &Envelope,
        connection: Id,
        verifier: &mut impl TrustedHandshakeVerifier,
        original: Option<(&HelloRequest, &HelloResult)>,
    ) -> Result<ConnectionAuthority, ProviderError> {
        request.validate()?;
        response.validate()?;
        let offer: ExtensionOfferV1 =
            decode_bounded(request.extensions.get(EXTENSION_NEGOTIATION_V1).ok_or(
                ProviderError::Correlation("version1 extension offer missing"),
            )?)?;
        let selected: ExtensionSelectionV1 =
            decode_bounded(response.extensions.get(EXTENSION_NEGOTIATION_V1).ok_or(
                ProviderError::Correlation("version1 extension selection missing"),
            )?)?;
        selected.validate()?;
        let expected = exact_intersection(&offer, self.installed.as_ref())?;
        if selected != expected {
            return Err(ProviderError::Correlation(
                "peer changed exact installed extension intersection",
            ));
        }
        if self
            .selected
            .as_deref()
            .is_some_and(|original| original != selected.selected.as_slice())
        {
            return Err(ProviderError::Correlation(
                "resume changed exact original extension contracts",
            ));
        }

        // Retain the bounded immutable roster before any gate or secret rotates.
        let retained: Arc<[ExtensionSelection]> = selected.selected.into();
        let mut bridge = SelectionVerifier {
            original: verifier,
            installed: self.installed.as_ref(),
            selected: &retained,
        };
        let mut authority = match original {
            Some(original) => self.handshake.admit_envelopes_with_original(
                request,
                response,
                connection,
                &mut bridge,
                true,
                Some(original),
            )?,
            None => self.handshake.admit_envelopes_versioned(
                request,
                response,
                connection,
                &mut bridge,
                true,
            )?,
        };
        authority.extensions = Some(Arc::clone(&retained));
        self.selected = Some(retained);
        Ok(authority)
    }

    /// Verifies the controller's exact surviving typed Hello registration.
    ///
    /// Equal wire IDs or tuples cannot substitute another original private
    /// registrar. This check grants neither native nor graph qualification.
    ///
    /// # Errors
    /// Refuses a foreign, stale or contained lease, absent typed negotiation,
    /// or a selection different from the original authenticated roster.
    pub fn verify_authority(&self, authority: &ConnectionAuthority) -> Result<(), ProviderError> {
        self.handshake.verify_current_authority(authority)?;
        if self.selected.is_none() || authority.selected_extensions() != self.selected.as_deref() {
            return Err(ProviderError::Correlation(
                "controller changed original typed Hello selection",
            ));
        }
        Ok(())
    }

    /// Revokes every original registration lease while retaining native custody.
    pub fn contain(&mut self) {
        self.handshake.contain();
    }
}

struct SelectionVerifier<'a, V> {
    original: &'a mut V,
    installed: &'a dyn InstalledExtensionNegotiationVerifier,
    selected: &'a [ExtensionSelection],
}

impl<V: TrustedHandshakeVerifier> TrustedHandshakeVerifier for SelectionVerifier<'_, V> {
    fn authenticate_exchange(
        &mut self,
        connection: &Id,
        installation: &TrustedInstallation,
        request: &HelloRequest,
        result: &HelloResult,
    ) -> Result<(), ProviderError> {
        if !request
            .required_features
            .iter()
            .any(|feature| feature.as_str() == EXTENSION_NEGOTIATION_V1)
            || !result
                .selected_features
                .iter()
                .any(|feature| feature.as_str() == EXTENSION_NEGOTIATION_V1)
        {
            return Err(ProviderError::Correlation(
                "typed negotiation feature must be explicitly required and selected",
            ));
        }
        self.original
            .authenticate_exchange(connection, installation, request, result)
    }

    fn verify_contract_selection(
        &mut self,
        manifest: &ProviderManifest,
        features: &IdSet,
        schemas: &[SchemaRef],
        guarantees: &ContentRef,
    ) -> Result<(), ProviderError> {
        self.original
            .verify_contract_selection(manifest, features, schemas, guarantees)?;
        self.installed.verify_selection(self.selected, features)
    }

    fn resume_custody(
        &mut self,
        session: &Id,
        incarnation: &Id,
        operations: &IdSet,
    ) -> Result<Vec<ResumedOperation>, ProviderError> {
        self.original
            .resume_custody(session, incarnation, operations)
    }

    fn fence_connection(&mut self, connection: &Id) -> Result<(), ProviderError> {
        self.original.fence_connection(connection)
    }
}

/// Brands the audited zero-field native registry without exposing it publicly.
///
/// Only SDK service implementations can implement this marker. Its borrowed
/// projection never dispatches a registry callback or substitutes a wire label
/// for an unknown trait object's actual hidden state.
pub(crate) trait OriginalEmptyExtensionRegistry:
    InstalledExtensionNegotiationVerifier
{
}

pub(crate) struct OriginalExtensionNegotiationOwned11<'a, R: OriginalEmptyExtensionRegistry> {
    original: &'a ExtensionHandshake,
    authority: &'a ConnectionAuthority,
    registry: &'a Rc<R>,
    negotiation: super::OriginalNegotiationView<'a>,
}

impl ExtensionHandshake {
    pub(crate) fn original_owned11_negotiation_view<'a, R: OriginalEmptyExtensionRegistry>(
        &'a self,
        authority: &'a ConnectionAuthority,
        registry: &'a Rc<R>,
    ) -> Result<OriginalExtensionNegotiationOwned11<'a, R>, ProviderError> {
        self.verify_authority(authority)?;
        if !std::ptr::addr_eq(Rc::as_ptr(&self.installed), Rc::as_ptr(registry))
            || std::mem::size_of::<R>() != 0
        {
            return Err(ProviderError::Correlation(
                "original typed registry owner changed",
            ));
        }
        let selected = self.selected.as_ref().ok_or(ProviderError::Correlation(
            "original typed selection absent",
        ))?;
        if authority
            .extensions
            .as_ref()
            .is_none_or(|actual| !Arc::ptr_eq(actual, selected))
        {
            return Err(ProviderError::Correlation(
                "original typed selection backing changed",
            ));
        }
        let negotiation = self.handshake.original_negotiation_view(authority)?;
        Ok(OriginalExtensionNegotiationOwned11 {
            original: self,
            authority,
            registry,
            negotiation,
        })
    }
}

impl<R: OriginalEmptyExtensionRegistry> OriginalExtensionNegotiationOwned11<'_, R> {
    pub(crate) fn observe_owned11_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.original.verify_authority(self.authority)?;
        let ExtensionHandshake {
            handshake: _,
            installed,
            selected,
            original_registry,
        } = self.original;
        if original_registry.is_some() {
            return Err(ProviderError::Correlation(
                "native registry view requires separate host registry class",
            ));
        }
        self.negotiation.observe_owned11_metadata(observer)?;
        // Both actual strong owners refer to the same audited zero-field value:
        // the erased installed registry and the service's retained concrete Rc.
        observer.shared_original(
            crate::retained_metadata::aliases::MetadataSharedKind::InstalledRegistry,
            installed.as_ref(),
        )?;
        observer.shared_original(
            crate::retained_metadata::aliases::MetadataSharedKind::InstalledRegistry,
            self.registry.as_ref(),
        )?;
        let selected = selected
            .as_ref()
            .ok_or(ProviderError::Correlation("original selection absent"))?;
        observer.shared_original(
            crate::retained_metadata::aliases::MetadataSharedKind::SelectedExtensions,
            selected.as_ref(),
        )?;
        for definition in selected.iter() {
            observer.observe(definition)?;
        }
        Ok(())
    }
}

impl<R: OriginalEmptyExtensionRegistry> serde::Serialize
    for OriginalExtensionNegotiationOwned11<'_, R>
{
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.original
            .verify_authority(self.authority)
            .map_err(serde::ser::Error::custom)?;
        serde::Serialize::serialize(
            &(
                "source-private.original-extension-negotiation/11",
                &self.negotiation,
                "source-private.native-empty-extension-registry/11",
                "source-private.native-empty-extension-registry/11",
                &self.original.selected,
            ),
            serializer,
        )
    }
}

/// Retains the actual SDK-owned empty registry and its original creator.
///
/// This owner has no public constructor, clone, serializer or portable identity.
/// It describes actual callback storage; it grants no negotiated contract,
/// process/capture permission or native restoration right.
pub struct OriginalExtensionRegistryOwner {
    registry: Rc<OriginalSdkEmptyRegistry>,
    origin: Rc<crate::protocol_snapshot::ProtocolCaptureOwner>,
}

struct OriginalSdkEmptyRegistry;

impl OriginalEmptyExtensionRegistry for OriginalSdkEmptyRegistry {}

impl InstalledExtensionNegotiationVerifier for OriginalSdkEmptyRegistry {
    fn supported(&self) -> &[ExtensionSelection] {
        &[]
    }
    fn required(&self) -> &[ExtensionSelection] {
        &[]
    }
    fn verify_selection(
        &self,
        selected: &[ExtensionSelection],
        _: &IdSet,
    ) -> Result<(), ProviderError> {
        if selected.is_empty() {
            Ok(())
        } else {
            Err(registry_refused())
        }
    }
}

impl ExtensionHandshake {
    /// Transfers an original issuer into the closed SDK-owned empty registry.
    ///
    /// The same concrete registry Rc remains retained beside its erased callback.
    /// Its original creator is recorded once. Refusal preserves the supplied
    /// original Handshake slot; no guessed empty roster substitutes for a known
    /// callback implementation. Actual allocations need separate source credit.
    ///
    /// # Errors
    /// Refuses an absent original issuer or invalid retained registry preparation.
    pub fn from_original_empty_registry_retained(
        original: &mut Option<Handshake>,
    ) -> Result<Self, ProviderError> {
        if original.is_none() {
            return Err(registry_refused());
        }
        let owner = OriginalExtensionRegistryOwner {
            registry: Rc::new(OriginalSdkEmptyRegistry),
            origin: Rc::new(crate::protocol_snapshot::ProtocolCaptureOwner::new()),
        };
        let mut result = Self::from_original_empty_retained(original, &owner.registry)?;
        result.original_registry = Some(owner);
        Ok(result)
    }

    /// Retains the actual known registry owner from this same original wrapper.
    ///
    /// # Errors
    /// Refuses a foreign creator or a generic erased registry without this exact
    /// SDK-owned implementation. Selection labels cannot grant this owner.
    pub fn retain_original_registry_metadata_owner(
        &self,
    ) -> Result<OriginalExtensionRegistryOwner, ProviderError> {
        let owner = self
            .original_registry
            .as_ref()
            .ok_or_else(registry_refused)?;
        owner.authenticate_original(self)?;
        Ok(OriginalExtensionRegistryOwner {
            registry: owner.registry.clone(),
            origin: owner.origin.clone(),
        })
    }

    /// Reports actual issuer, selected tuple and known callback allocation data.
    ///
    /// The owning process capsule must separately check current source/registrar
    /// association. Counting retired retained data does not renew authority.
    ///
    /// # Errors
    /// Refuses a foreign creator, another wrapper/registry or traversal overflow.
    pub fn retained_metadata_facts_data(
        &self,
        owner: &OriginalExtensionRegistryOwner,
    ) -> Result<crate::retained_metadata::RetainedProtocolMetadataFacts, ProviderError> {
        owner.authenticate_original(self)?;
        let Self {
            handshake,
            installed,
            selected,
            original_registry,
        } = self;
        let retained = original_registry.as_ref().ok_or_else(registry_refused)?;
        let mut observer = crate::retained_metadata::MetadataObserver::new();
        handshake.observe_retained_metadata_data(&mut observer)?;
        observer.shared_value(installed.as_ref())?;
        retained.observe_retained_metadata(&mut observer)?;
        if let Some(selected) = selected {
            observer.shared_value(selected.as_ref())?;
            for definition in selected.iter() {
                observer.observe(definition)?;
            }
        }
        Ok(observer.finish())
    }
}

impl OriginalExtensionRegistryOwner {
    /// Authenticates the same actual wrapper, callback Rc and original creator.
    ///
    /// # Errors
    /// Refuses foreign threads/processes, another original wrapper or replaced Rc.
    pub fn authenticate_original(
        &self,
        original: &ExtensionHandshake,
    ) -> Result<(), ProviderError> {
        self.origin.ensure_current()?;
        let retained = original
            .original_registry
            .as_ref()
            .ok_or_else(registry_refused)?;
        if !Rc::ptr_eq(&self.registry, &retained.registry)
            || !Rc::ptr_eq(&self.origin, &retained.origin)
            || !std::ptr::addr_eq(Rc::as_ptr(&original.installed), Rc::as_ptr(&self.registry))
        {
            return Err(registry_refused());
        }
        Ok(())
    }

    /// Reports actual opaque owner payload views without serializing callback state.
    ///
    /// The outer owner header is caller-owned. Actual shared payload/header
    /// geometry remains distinct from negotiated capabilities and Node512 credit.
    ///
    /// # Errors
    /// Refuses a foreign creator or checked traversal/layout overflow.
    pub fn original_retained_metadata_facts(
        &self,
    ) -> Result<crate::retained_metadata::RetainedProtocolMetadataFacts, ProviderError> {
        self.origin.ensure_current()?;
        let mut observer = crate::retained_metadata::MetadataObserver::new();
        self.observe_retained_metadata(&mut observer)?;
        Ok(observer.finish())
    }

    fn observe_retained_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        let Self { registry, origin } = self;
        origin.ensure_current()?;
        observer.shared_value(registry.as_ref())?;
        observer.shared_value(origin.as_ref())
    }
}

fn registry_refused() -> ProviderError {
    ProviderError::Correlation("original closed SDK extension registry differs")
}

#[path = "original_registry_snapshot.rs"]
mod original_registry_snapshot;
pub use original_registry_snapshot::{
    ORIGINAL_HOST_EXTENSION_REGISTRY_FORMAT, OriginalExtensionRegistryView,
};

impl<R: OriginalEmptyExtensionRegistry> OriginalExtensionNegotiationOwned11<'_, R> {
    pub(crate) fn observe_unique_capture_metadata(
        &self,
        roots: &mut crate::retained_metadata::NativeCaptureMetadataRoots,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        use crate::retained_metadata::aliases::MetadataSharedKind;
        self.original.verify_authority(self.authority)?;
        let ExtensionHandshake {
            handshake,
            installed,
            selected,
            original_registry,
        } = self.original;
        if original_registry.is_some() {
            return Err(registry_refused());
        }
        handshake.observe_unique_capture_metadata_data(roots, observer)?;
        roots.observe_shared(
            observer,
            MetadataSharedKind::InstalledRegistry,
            installed.as_ref(),
        )?;
        roots.observe_shared(
            observer,
            MetadataSharedKind::InstalledRegistry,
            self.registry.as_ref(),
        )?;
        let selected = selected.as_ref().ok_or_else(registry_refused)?;
        if roots.observe_shared(
            observer,
            MetadataSharedKind::SelectedExtensions,
            selected.as_ref(),
        )? {
            for selection in selected.iter() {
                observer.observe(selection)?;
            }
        }
        Ok(())
    }
}

impl ExtensionHandshake {
    pub(crate) fn original_empty_registry_allocation_layout_data() -> Result<usize, ProviderError> {
        let root = std::mem::size_of::<OriginalSdkEmptyRegistry>()
            .checked_add(std::mem::size_of::<
                crate::protocol_snapshot::ProtocolCaptureOwner,
            >())
            .ok_or_else(registry_refused)?;
        // Metadata retains two verified registry views and one origin view.
        // Handshake/Session/Connection expose three views of the selected empty
        // Arc slice. Count every view under the owning observer convention.
        root.checked_add(
            crate::retained_metadata::requested_storage::shared_header_storage_data(
                6,
                std::mem::align_of::<crate::protocol_snapshot::ProtocolCaptureOwner>()
                    .max(std::mem::align_of::<ExtensionSelection>()),
            )?,
        )
        .ok_or_else(registry_refused)
    }
}
