//! Collects the source-selected singleton beneath original native custody.
//!
//! This private path grants collecting authority only. It cannot provide an
//! ordinary Accepted preparation or a factory token; all native originals remain
//! in the same queue before Child and before any transport effect.

use std::{
    cell::RefCell,
    collections::BTreeMap,
    os::unix::{fs::DirBuilderExt, process::CommandExt},
    path::PathBuf,
    process::{Command, Stdio},
    rc::Rc,
};

use crucible_engine::{
    node_adapters::cnp::{CnpLaunchGuard, CnpReferencePreparation},
    node_contract::{ActivationRecord, OwnerIdentity},
};
use crucible_node_format::{Bytes, ContentRef, Extensions, Id, U64, canonical};
use crucible_node_transport::{
    ProviderError,
    client::{ClientContent, ClientCustody, OriginalHelloJournal},
    envelope::{Envelope, MessageKind, Method, Nullable},
    handshake::{Handshake, HelloRequest, NegotiationPolicy, TrustedInstallation},
    reference_service::{PublicReferenceProfile, ReferenceServiceInstalledLaunchBootstrap},
};

use super::{
    super::{
        custody::{PublicPeerScope, PublicReferenceCustodyQueue},
        installation::SourcePublicReferenceInstallation,
    },
    negotiation::OriginalReferenceTransport,
};

const FRAME_BYTES: usize = 1024 * 1024;
const CONTENT_BYTES: usize = 16 * 1024 * 1024;

/// Contains host-private source selection; portable configuration cannot construct it.
pub(in crate::node_observed_executor::factory::reference_public) struct CollectingReferenceLaunch {
    pub(in crate::node_observed_executor::factory::reference_public) directory: PathBuf,
    pub(in crate::node_observed_executor::factory::reference_public) activation: ActivationRecord,
    pub(in crate::node_observed_executor::factory::reference_public) owner: OwnerIdentity,
    pub(in crate::node_observed_executor::factory::reference_public) source_roots: Vec<ContentRef>,
    pub(in crate::node_observed_executor::factory::reference_public) hello_id: Id,
    pub(in crate::node_observed_executor::factory::reference_public) connection_id: Id,
    pub(in crate::node_observed_executor::factory::reference_public) controller_nonce: Bytes,
    pub(in crate::node_observed_executor::factory::reference_public) adverse:
        Option<Rc<super::super::singleton_adverse::SingletonAdversePopulation>>,
    pub(in crate::node_observed_executor::factory::reference_public) observations:
        Rc<RefCell<Option<crucible_node_transport::client::ObservationHandle>>>,
}

/// Prepares the single fixed source collecting profile under original custody.
///
/// # Errors
/// Refuses a foreign closed source scope or uncertain native preparation. Every
/// effectful return retains the same original peer; no ordinary acceptance is issued.
pub(in crate::node_observed_executor::factory::reference_public) fn prepare(
    installed: &mut SourcePublicReferenceInstallation,
    queue: &PublicReferenceCustodyQueue,
    request: CollectingReferenceLaunch,
) -> Result<CnpReferencePreparation, ProviderError> {
    // This source-only data projection cannot authenticate ordinary class claims.
    let scope = super::ordinary_launch::OrdinaryReferenceLaunch {
        directory: request.directory.clone(),
        birth_currency: None,
        activation: request.activation.clone(),
        owner: request.owner.clone(),
        source_roots: request.source_roots.clone(),
        hello_id: request.hello_id.clone(),
        connection_id: request.connection_id.clone(),
        controller_nonce: request.controller_nonce.clone(),
    };
    super::ordinary_launch::closed_source_preflight(installed, &scope)?;
    let source = Rc::new(installed.package.retain_original_sources()?);
    let provider = installed
        .package
        .executable("provider")
        .map_err(package_error)?
        .to_path_buf();
    let device = installed
        .package
        .executable("device")
        .map_err(package_error)?
        .to_path_buf();
    let bootstrap = installed.bootstrap.clone();
    let launch = ReferenceServiceInstalledLaunchBootstrap {
        schema_version: 3,
        profile: PublicReferenceProfile::ByteLinkedV1 {
            closed_ingress: true,
        },
        bootstrap: bootstrap.clone(),
        qualification_refs: installed.qualifications.clone(),
    };
    super::geometry::bounded(&launch, CONTENT_BYTES)?;
    let launch_value =
        serde_json::to_value(launch).map_err(crucible_node_format::ContractError::from)?;
    let private_launch = canonical::canonical_json(&launch_value)?;
    canonical::parse_json_with_depth(&private_launch, CONTENT_BYTES, 64)?;
    let upload =
        super::launch_upload::OriginalLaunchUpload::reserve(&private_launch, CONTENT_BYTES)?;
    let features = super::super::unit::required_features()?;
    let (binding, _) = installed
        .profile
        .bind_qualified(bootstrap.authority.clone(), &installed.qualifications)?;
    let hello = Envelope {
        protocol: "CNP/1".into(),
        message: MessageKind::Request,
        session_id: Nullable(None),
        incarnation_id: Nullable(None),
        node_id: Nullable(None),
        execution_owner_id: Nullable(None),
        capture_owner_id: Nullable(None),
        operation_id: Nullable(None),
        request_id: Nullable(Some(request.hello_id)),
        sequence: U64::new(1),
        method: Method::Hello,
        body: serde_json::to_value(HelloRequest {
            versions: vec!["CNP/1".into()],
            session_id: bootstrap.authority.session_id.clone(),
            controller_nonce: request.controller_nonce,
            required_features: features.clone(),
            optional_features: Vec::new(),
            limits: bootstrap.limits,
            admission_token: bootstrap.admission_token.clone(),
            resume_session: None,
            extensions: Extensions::new(),
        })
        .map_err(crucible_node_format::ContractError::from)?
        .as_object()
        .cloned()
        .ok_or(ProviderError::Frame("ordinary Hello body is not an object"))?,
        extensions: Extensions::new(),
    };
    let hello_journal = OriginalHelloJournal::reserve(&hello, FRAME_BYTES, 64)?;
    let original_hello = canonical::canonical_json(
        &serde_json::to_value(&hello).map_err(crucible_node_format::ContractError::from)?,
    )?;
    let mut token = [0; 32];
    token.copy_from_slice(bootstrap.admission_token.as_slice());
    let handshake = Handshake::new(
        TrustedInstallation {
            session_id: bootstrap.authority.session_id.clone(),
            incarnation_id: bootstrap.authority.incarnation_id.clone(),
            measured_implementation: installed.profile.implementation.clone(),
            launch_receipt: bootstrap.admission_receipt.clone(),
            admission_token: token,
        },
        NegotiationPolicy {
            supported_features: features.clone(),
            required_features: features,
            provider_limits: bootstrap.limits,
            required_schemas: Vec::new(),
            required_guarantees: binding.compatibility.guarantees_ref,
            envelope_extension_features: BTreeMap::from([(
                crucible_node_transport::input_commit::INPUT_COMMIT_FEATURE.into(),
                Id::new(crucible_node_transport::input_commit::INPUT_COMMIT_FEATURE)?,
            )]),
        },
    )?;
    let journal = ClientCustody::new(4096, ClientContent::new(CONTENT_BYTES, 4096, 16_384)?)?;
    let originals = Rc::new(RefCell::new(OriginalReferenceTransport::new(
        hello_journal,
        handshake,
        journal,
        upload,
    )));
    let incidents = Rc::new(RefCell::new(None));
    let socket = request.directory.join("control.sock");
    let slot = queue.reserve(PublicPeerScope {
        activation: request.activation,
        owner: request.owner,
        implementation: installed.package.identity().clone(),
        source_roots: request.source_roots,
        source_custody: Some(source.clone()),
        publication: None,
        connection_incident: incidents.clone(),
        private_launch,
        original_hello,
        ordinary_negotiation: None,
        collecting_negotiation: Some(originals.clone()),
    })?;
    if let Some(adverse) = &request.adverse {
        adverse.reserve_conflicts(installed, &request.connection_id)?;
    }
    // Authenticate the same retained source descriptors after the final source
    // callback and before mkdir/Child; this grants no behavioral birth lease.
    source.write_originals(&mut std::io::sink())?;
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&request.directory)?;
    let mut child = Command::new(provider)
        .arg(&socket)
        .arg(device)
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()?;
    // The already-reserved queue holder owns the original pipe before any
    // fallible guard construction, fcntl, write or Hello callback.
    originals.borrow_mut().upload.stdin = child.stdin.take();
    let guard =
        CnpLaunchGuard::new(child, request.directory, slot).map_err(|failure| failure.error)?;
    let mut guard = super::ordinary_launch::negotiate_original(
        guard,
        &mut originals.borrow_mut(),
        installed,
        super::ordinary_launch::OriginalNegotiationRequest {
            hello: &hello,
            connection_id: request.connection_id,
            socket: &socket,
            incidents,
            bootstrap,
            observation: Some(request.observations.as_ref()),
        },
    )?;
    if let Some(adverse) = &request.adverse {
        let observations = request.observations.borrow();
        adverse.collect_pre_realization(
            installed,
            &mut guard,
            observations.as_ref().ok_or(ProviderError::Correlation(
                "singleton original observer absent",
            ))?,
        )?;
    }
    let mut prepared = CnpReferencePreparation::prepare(guard, installed)
        .map_err(|failure| ProviderError::Io(std::io::Error::other(failure.error.reason)))?;
    if let Some(adverse) = &request.adverse {
        let observations = request.observations.borrow();
        adverse.collect_prepared(
            installed,
            &mut prepared,
            observations.as_ref().ok_or(ProviderError::Correlation(
                "singleton original observer absent",
            ))?,
        )?;
    }
    Ok(prepared)
}

fn package_error(error: crate::node_observed_executor::NodeObservedError) -> ProviderError {
    ProviderError::Io(std::io::Error::other(error.to_string()))
}
