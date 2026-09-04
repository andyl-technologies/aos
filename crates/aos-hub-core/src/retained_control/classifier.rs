//! Mutation-method classification and hard-cut manifest validation.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::primitives::ControlError;

/// Whether an API method is public or restricted to fenced controllers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MethodExposure {
    /// Public API used by Web, CLI, and third-party clients.
    Public,
    /// Internal controller API requiring an operation lease and generation fence.
    InternalController,
}

/// Durability of a method's effects.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MethodDurability {
    /// No authoritative state changes.
    ReadOnly,
    /// Authoritative or append-only durable state changes.
    Durable,
}

/// Result shape of a reviewed apply method.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplyOutcome {
    /// Apply commits all effects transactionally and returns the resource.
    Immediate,
    /// Apply commits desired state and schedules a durable operation.
    Operation,
}

/// The only durable mutations exempt from reviewed plan/apply as append-only collaboration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppendOnlyEventKind {
    /// A non-empty change-request discussion comment.
    ChangeRequestComment,
    /// A review bound to an exact change-request revision.
    ChangeRequestReview,
}

/// Principled class assigned to every API method.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "class", rename_all = "snake_case")]
pub enum MethodClass {
    /// A read-only query.
    Read,
    /// The planning half of a reviewed mutation pair.
    Plan {
        /// Stable semantic pair identity shared with apply.
        pair: String,
    },
    /// The applying half of a reviewed mutation pair.
    Apply {
        /// Stable semantic pair identity shared with plan.
        pair: String,
        /// Whether external work requires an Operation.
        outcome: ApplyOutcome,
    },
    /// An append-only, idempotent collaboration event such as comment/review.
    AppendOnlyEvent {
        /// Narrow, typed collaboration-event exception.
        event_kind: AppendOnlyEventKind,
    },
    /// An admitted data-plane write with durable integrity and quota state.
    DataPlaneWrite,
    /// A fenced observation reported by an internal controller.
    ControllerObservation,
    /// Cancellation, retry, or resumption of an existing reviewed workflow.
    OperationLifecycle,
    /// Explicit CAS/idempotency replay of one frozen maintenance action.
    MaintenanceReplay,
    /// A user-authorized identity ceremony whose presented secret is the
    /// mutation precondition rather than an administrator-reviewed plan.
    IdentityCeremony,
}

/// One method in the generated API mutation-classification manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MethodDescriptor {
    /// Proto service name without package.
    pub service: String,
    /// Proto method name.
    pub method: String,
    /// Public or controller-only exposure.
    pub exposure: MethodExposure,
    /// Method effect durability.
    pub durability: MethodDurability,
    /// Mutation-protocol classification.
    pub class: MethodClass,
    /// Whether the method initiates or completes non-transactional external work.
    pub external_effects: bool,
}

/// One method path emitted by API descriptor generation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiMethodDescriptor {
    /// Proto service name without package.
    pub service: String,
    /// Proto method name.
    pub method: String,
    /// Protobuf input message name within `aos.hub.v1`.
    pub request: String,
    /// Protobuf output message name within `aos.hub.v1`.
    pub response: String,
    /// Canonical declaration-ordered protobuf request field names.
    #[serde(default)]
    pub request_fields: Vec<String>,
}

impl MethodDescriptor {
    /// Returns the canonical `Service/Method` path.
    #[must_use]
    pub fn path(&self) -> String {
        format!("{}/{}", self.service, self.method)
    }
}

/// One structural API-manifest validation error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestViolation {
    /// Method path, pair id, or manifest-level subject.
    pub subject: String,
    /// Stable human-readable invariant violation.
    pub reason: String,
}

/// Validates the complete mutation-method classification manifest.
///
/// The validator fails closed: every method needs an explicit class; every
/// durable desired-state mutation must be one half of exactly one plan/apply
/// pair; external reviewed effects must return an Operation; controller
/// observations cannot be public.
#[must_use]
pub fn validate_method_manifest(methods: &[MethodDescriptor]) -> Vec<ManifestViolation> {
    let mut violations = Vec::new();
    if methods.len() > 4_096 {
        violations.push(ManifestViolation {
            subject: "manifest".into(),
            reason: "method manifest must not exceed 4096 methods".into(),
        });
    }
    let mut paths = BTreeSet::new();
    let mut pairs: BTreeMap<&str, (Vec<&MethodDescriptor>, Vec<&MethodDescriptor>)> =
        BTreeMap::new();

    for method in methods {
        let path = method.path();
        if !is_proto_identifier(&method.service)
            || !is_proto_identifier(&method.method)
            || !paths.insert(path.clone())
        {
            violations.push(ManifestViolation {
                subject: path.clone(),
                reason: "method path must be non-empty and unique".into(),
            });
        }
        match &method.class {
            MethodClass::Read => {
                require_durability(
                    method,
                    MethodDurability::ReadOnly,
                    "read methods must be read-only",
                    &mut violations,
                );
                if method.external_effects {
                    violations.push(violation(
                        method,
                        "read methods cannot have external effects",
                    ));
                }
            }
            MethodClass::Plan { pair } => {
                require_durability(
                    method,
                    MethodDurability::Durable,
                    "plans are durable reviewed resources",
                    &mut violations,
                );
                if !is_canonical_pair(pair)
                    || !method.method.starts_with("Plan")
                    || method.external_effects
                {
                    violations.push(violation(
                        method,
                        "plan methods require a pair id, Plan prefix, and no external effects",
                    ));
                }
                pairs.entry(pair.as_str()).or_default().0.push(method);
            }
            MethodClass::Apply { pair, outcome } => {
                require_durability(
                    method,
                    MethodDurability::Durable,
                    "apply methods mutate durable state",
                    &mut violations,
                );
                if !is_canonical_pair(pair) || method.method.starts_with("Plan") {
                    violations.push(violation(
                        method,
                        "apply method has an invalid pair identity",
                    ));
                }
                if method.external_effects && *outcome != ApplyOutcome::Operation {
                    violations.push(violation(
                        method,
                        "external reviewed effects must return an operation",
                    ));
                }
                pairs.entry(pair.as_str()).or_default().1.push(method);
            }
            MethodClass::AppendOnlyEvent { event_kind } => {
                require_durability(
                    method,
                    MethodDurability::Durable,
                    "append-only events are durable",
                    &mut violations,
                );
                if method.external_effects {
                    violations.push(violation(
                        method,
                        "append-only collaboration events cannot perform external effects",
                    ));
                }
                let expected_path = match event_kind {
                    AppendOnlyEventKind::ChangeRequestComment => "ChangeRequestService/AddComment",
                    AppendOnlyEventKind::ChangeRequestReview => "ChangeRequestService/AddReview",
                };
                if path != expected_path {
                    violations.push(violation(
                        method,
                        "append-only exception is valid only for its canonical change-request method",
                    ));
                }
            }
            MethodClass::DataPlaneWrite => {
                require_durability(
                    method,
                    MethodDurability::Durable,
                    "data-plane admission and settlement are durable",
                    &mut violations,
                );
                if !matches!(
                    path.as_str(),
                    "ContainerService/BeginContainerPublication"
                        | "ContainerService/CommitContainerPublication"
                        | "ContainerService/AbortContainerPublication"
                        | "PublishService/BeginRegistryPublication"
                        | "PublishService/BeginRegistryPublicationManifest"
                        | "PublishService/AppendRegistryPublicationManifest"
                        | "PublishService/SealRegistryPublicationManifest"
                        | "PublishService/CommitRegistryPublication"
                        | "PublishService/AbortRegistryPublication"
                        | "PublishService/BeginRegistryPublicationMultipartUpload"
                        | "PublishService/CompleteRegistryPublicationMultipartUpload"
                        | "PublishService/AbortRegistryPublicationMultipartUpload"
                        | "PublishService/BeginReleasePublication"
                        | "PublishService/CommitReleasePublication"
                        | "PublishService/RecordReleaseQualification"
                        | "PublishService/PromoteReleasePublication"
                        | "PublishService/PublishReleaseTimestamp"
                        | "PublishService/AdvanceReleaseChannel"
                        | "BinaryCacheService/CreateCacheObjectUploads"
                        | "BinaryCacheService/RegisterCacheNarinfos"
                        | "BinaryCacheService/BeginCacheMultipartUpload"
                        | "BinaryCacheService/CompleteCacheMultipartUpload"
                        | "BinaryCacheService/AbortCacheMultipartUpload"
                ) {
                    violations.push(violation(
                        method,
                        "data-plane write exception is limited to canonical publication and cache-upload methods",
                    ));
                }
            }
            MethodClass::ControllerObservation => {
                require_durability(
                    method,
                    MethodDurability::Durable,
                    "controller observations are durable",
                    &mut violations,
                );
                if method.exposure != MethodExposure::InternalController {
                    violations.push(violation(
                        method,
                        "controller observations must not be exposed publicly",
                    ));
                }
                if !method.service.ends_with("ControllerService")
                    || !(method.method.starts_with("Report")
                        || method.method.starts_with("Complete"))
                {
                    violations.push(violation(
                        method,
                        "controller observations require a ControllerService Report/Complete method",
                    ));
                }
                if method.external_effects {
                    violations.push(violation(
                        method,
                        "controller observations report effects but do not initiate them",
                    ));
                }
            }
            MethodClass::OperationLifecycle => {
                require_durability(
                    method,
                    MethodDurability::Durable,
                    "operation lifecycle methods mutate operation state",
                    &mut violations,
                );
                if !matches!(path.as_str(),
                    "OperationService/CancelOperation" | "OperationService/RetryOperation"
                        | "DeliveryService/ResumeDeliveryDestination") {
                    violations.push(violation(
                        method,
                        "operation-lifecycle exception is limited to cancel, retry, and reviewed delivery resume",
                    ));
                }
            }
            MethodClass::MaintenanceReplay => {
                require_durability(
                    method,
                    MethodDurability::Durable,
                    "maintenance replay methods mutate durable action state",
                    &mut violations,
                );
                if path != "ContainerService/RequeueContainerGcPlacementAction"
                    || method.external_effects
                {
                    violations.push(violation(
                        method,
                        "maintenance-replay exception is limited to the local GC action requeue",
                    ));
                }
            }
            MethodClass::IdentityCeremony => {
                require_durability(
                    method,
                    MethodDurability::Durable,
                    "identity ceremonies mutate durable identity state",
                    &mut violations,
                );
                if path != "IdentityService/AcceptInvitation" || method.external_effects {
                    violations.push(violation(
                        method,
                        "identity-ceremony exception is limited to local invitation acceptance",
                    ));
                }
            }
        }
    }

    for (pair, (plans, applies)) in pairs {
        if plans.len() != 1 || applies.len() != 1 {
            violations.push(ManifestViolation {
                subject: pair.into(),
                reason: format!(
                    "reviewed mutation pair requires exactly one plan and one apply; found {} and {}",
                    plans.len(),
                    applies.len()
                ),
            });
            continue;
        }
        let canonical_names =
            plans[0].method.strip_prefix("Plan") == Some(applies[0].method.as_str());
        let registry_purge_fence_names = plans[0].service == "ContainerService"
            && plans[0].method == "PlanContainerRegistryPurgeFence"
            && applies[0].method == "ApplyContainerRegistryPurgeFence";
        if plans[0].service != applies[0].service
            || plans[0].exposure != applies[0].exposure
            || (!canonical_names && !registry_purge_fence_names)
        {
            violations.push(ManifestViolation {
                subject: pair.into(),
                reason:
                    "plan and apply must have identical service/exposure and canonical paired names"
                        .into(),
            });
        }
    }
    violations
}

/// Validates that classification covers the complete generated API descriptor.
///
/// Coverage is exact in both directions: every generated method must be
/// classified once, and the manifest cannot classify a method absent from the
/// generated descriptor.
#[must_use]
pub fn validate_descriptor_coverage(
    methods: &[MethodDescriptor],
    api_methods: &[ApiMethodDescriptor],
) -> Vec<ManifestViolation> {
    let mut violations = Vec::new();
    let classified = methods
        .iter()
        .map(MethodDescriptor::path)
        .collect::<BTreeSet<_>>();
    if classified.len() != methods.len() {
        violations.push(ManifestViolation {
            subject: "classification".into(),
            reason: "classification contains duplicate method paths".into(),
        });
    }

    let described = api_methods
        .iter()
        .map(|method| format!("{}/{}", method.service, method.method))
        .collect::<BTreeSet<_>>();
    if described.len() != api_methods.len()
        || api_methods.iter().any(|method| {
            method.service.is_empty()
                || method.method.is_empty()
                || !is_proto_identifier(&method.request)
                || !is_proto_identifier(&method.response)
                || method
                    .request_fields
                    .iter()
                    .any(|field| !is_proto_identifier(field))
        })
    {
        violations.push(ManifestViolation {
            subject: "api_descriptor".into(),
            reason: "API descriptor method paths must be non-empty and unique".into(),
        });
    }
    for missing in described.difference(&classified) {
        violations.push(ManifestViolation {
            subject: missing.clone(),
            reason: "generated API method is not classified".into(),
        });
    }
    for extra in classified.difference(&described) {
        violations.push(ManifestViolation {
            subject: extra.clone(),
            reason: "classification names no generated API method".into(),
        });
    }
    violations
}

/// Validates classification invariants and exact generated-descriptor coverage.
#[must_use]
pub fn validate_complete_method_manifest(
    methods: &[MethodDescriptor],
    api_methods: &[ApiMethodDescriptor],
) -> Vec<ManifestViolation> {
    let mut violations = validate_method_manifest(methods);
    violations.extend(validate_descriptor_coverage(methods, api_methods));
    let generated = api_methods
        .iter()
        .map(|method| (format!("{}/{}", method.service, method.method), method))
        .collect::<BTreeMap<_, _>>();
    for method in methods {
        let Some(descriptor) = generated.get(&method.path()) else {
            continue;
        };
        if matches!(method.class, MethodClass::Plan { .. })
            && descriptor.response != "TopologyPlanResponse"
            && !(method.path() == "ContainerService/PlanRunContainerGc"
                && descriptor.response == "ContainerGcPlanResponse")
        {
            violations.push(violation(
                method,
                "plan methods must independently return TopologyPlanResponse",
            ));
        }
        if matches!(method.class, MethodClass::MaintenanceReplay) {
            let mut fields = descriptor.request_fields.clone();
            fields.sort();
            if !fields.iter().map(String::as_str).eq([
                "action_id",
                "expected_resource_version",
                "idempotency_key",
                "registry",
                "run_id",
            ]) {
                violations.push(violation(
                    method,
                    "maintenance replay must bind the exact registry, run, action, CAS, and idempotency key",
                ));
            }
        }
        if method.path() == "DeliveryService/ResumeDeliveryDestination" {
            let mut fields = descriptor.request_fields.clone();
            fields.sort();
            if !fields.iter().map(String::as_str).eq([
                "expected_resource_version", "idempotency_key", "workflow_id",
            ]) {
                violations.push(violation(method,
                    "delivery resume must bind a reviewed workflow, CAS, and idempotency key"));
            }
        }
        if matches!(method.class, MethodClass::Plan { .. })
            && (!descriptor
                .request_fields
                .iter()
                .any(|field| field == "idempotency_key")
                || !descriptor
                    .request_fields
                    .iter()
                    .any(|field| field == "expected_resource_version"))
        {
            violations.push(violation(
                method,
                "plan requests must expose canonical idempotency and resource-version fields",
            ));
        }
        if matches!(method.class, MethodClass::Apply { .. }) {
            let mut fields = descriptor.request_fields.clone();
            fields.sort();
            let canonical = fields.iter().map(String::as_str).eq([
                "confirmation_hash",
                "idempotency_key",
                "plan_id",
            ]);
            let reviewed_apply_cas = [
                "ContainerService/RepairContainerUntrackedObject",
                "ContainerService/ApplyContainerRegistryPurgeFence",
            ]
            .contains(&method.path().as_str())
                && fields.iter().map(String::as_str).eq([
                    "confirmation_hash",
                    "expected_resource_version",
                    "idempotency_key",
                    "plan_id",
                ]);
            if !canonical && !reviewed_apply_cas {
                violations.push(violation(
                    method,
                    "apply requests may contain only plan_id, confirmation_hash, and idempotency_key",
                ));
            }
        }
        if matches!(method.class, MethodClass::ControllerObservation)
            && ![
                "controller_lease_id",
                "controller_generation",
                "expected_observation_version",
            ]
            .iter()
            .all(|required| {
                descriptor
                    .request_fields
                    .iter()
                    .any(|field| field == required)
            })
        {
            violations.push(violation(
                method,
                "controller observations require lease identity, generation, and observation-version fences",
            ));
        }
        if matches!(
            method.class,
            MethodClass::Apply {
                outcome: ApplyOutcome::Operation,
                ..
            }
        ) && descriptor.response != "OperationResponse"
        {
            violations.push(violation(
                method,
                "operation applies must independently return OperationResponse",
            ));
        }
    }
    violations
}

/// Projection of the independently generated public API-manifest artifact.
///
/// Extra manifest fields are deliberately ignored: coverage depends only on
/// the generator's complete method list, never on a source-level proto parser.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct GeneratedApiDescriptorArtifact {
    /// Generator-owned artifact schema identifier.
    pub manifest_version: String,
    /// Complete generated API method list.
    pub methods: Vec<ApiMethodDescriptor>,
}

impl GeneratedApiDescriptorArtifact {
    /// Returns the validated independently generated method descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Invalid`] for an unexpected artifact schema or
    /// an empty/oversized generated method list.
    pub fn api_methods(&self) -> Result<&[ApiMethodDescriptor], ControlError> {
        if self.manifest_version != "aos.hub.api/v1"
            || self.methods.is_empty()
            || self.methods.len() > 4_096
        {
            return Err(invalid(
                "api_descriptor",
                "must be a non-empty bounded aos.hub.api/v1 generated manifest",
            ));
        }
        Ok(&self.methods)
    }
}

/// Projects build-generated Connect metadata into exact API descriptors.
///
/// The input is emitted during protobuf compilation and is independent of the
/// checked-in documentation manifest.
///
/// # Errors
///
/// Returns [`ControlError::Invalid`] for a malformed, duplicate, or oversized
/// generated descriptor inventory.
pub fn api_methods_from_generated_descriptors(
    descriptors: &[aos_proto_types::ConnectMethodDescriptor],
) -> Result<Vec<ApiMethodDescriptor>, ControlError> {
    if descriptors.is_empty() || descriptors.len() > 4_096 {
        return Err(invalid(
            "api_descriptor",
            "generated path inventory is empty or oversized",
        ));
    }
    let mut seen = BTreeSet::new();
    let mut methods = Vec::with_capacity(descriptors.len());
    for descriptor in descriptors {
        let suffix = descriptor
            .path
            .strip_prefix("/aos.hub.v1.")
            .ok_or_else(|| invalid("api_descriptor", "unexpected Connect package"))?;
        let (service, method) = suffix
            .split_once('/')
            .ok_or_else(|| invalid("api_descriptor", "malformed Connect path"))?;
        let request = descriptor
            .input_type
            .strip_prefix(".aos.hub.v1.")
            .ok_or_else(|| invalid("api_descriptor", "unexpected request package"))?;
        let response = descriptor
            .output_type
            .strip_prefix(".aos.hub.v1.")
            .ok_or_else(|| invalid("api_descriptor", "unexpected response package"))?;
        if service != descriptor.service
            || method != descriptor.method
            || !is_proto_identifier(service)
            || !is_proto_identifier(method)
            || !is_proto_identifier(request)
            || !is_proto_identifier(response)
            || !seen.insert(descriptor.path.to_owned())
        {
            return Err(invalid(
                "api_descriptor",
                "generated Connect paths must be typed and unique",
            ));
        }
        methods.push(ApiMethodDescriptor {
            service: service.into(),
            method: method.into(),
            request: request.into(),
            response: response.into(),
            request_fields: descriptor
                .input_fields
                .iter()
                .map(|field| (*field).into())
                .collect(),
        });
    }
    Ok(methods)
}

fn is_proto_identifier(value: &str) -> bool {
    value
        .bytes()
        .next()
        .is_some_and(|byte| byte == b'_' || byte.is_ascii_alphabetic())
        && value
            .bytes()
            .all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

fn is_canonical_pair(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value.split('_').all(|word| {
            let mut bytes = word.bytes();
            bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
                && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
}

/// Category of a symbol forbidden after the topology hard cut.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForbiddenSymbolCategory {
    /// Removed Connect RPC or message name.
    Api,
    /// Removed CLI command hierarchy or selector.
    Cli,
    /// Removed Web route or handler.
    Web,
    /// Removed SQL table or column.
    Schema,
    /// Removed direct mutation helper or legacy subsystem.
    Code,
}

/// One exact symbol that must be absent from the production source universe.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForbiddenSymbol {
    /// Stable fixture identity.
    pub id: String,
    /// Kind of legacy surface.
    pub category: ForbiddenSymbolCategory,
    /// Exact case-sensitive symbol or path fragment.
    pub symbol: String,
    /// Historical locations retained only as review guidance, never scan scope.
    #[serde(rename = "targets")]
    pub known_locations: Vec<String>,
}

/// Versioned hard-cut forbidden-symbol fixture.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForbiddenSymbolFixture {
    /// Fixture format version.
    pub version: u32,
    /// Strictly id-sorted forbidden symbols.
    pub symbols: Vec<ForbiddenSymbol>,
}

impl ForbiddenSymbolFixture {
    /// Validates deterministic fixture structure.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Invalid`] unless version is one and entries are
    /// complete, strictly id-sorted, duplicate-free, and any known locations
    /// are canonical repository-relative paths.
    pub fn validate(&self) -> Result<(), ControlError> {
        if self.version != 1 {
            return Err(invalid("version", "must equal 1"));
        }
        if self.symbols.is_empty()
            || self.symbols.len() > 4_096
            || self.symbols.windows(2).any(|pair| pair[0].id >= pair[1].id)
        {
            return Err(invalid(
                "symbols",
                "must be non-empty, strictly id-sorted, and duplicate-free",
            ));
        }
        for entry in &self.symbols {
            if entry.id.is_empty()
                || entry.symbol.is_empty()
                || entry.known_locations.len() > 64
                || entry
                    .known_locations
                    .windows(2)
                    .any(|pair| pair[0] >= pair[1])
                || entry.known_locations.iter().any(|target| {
                    target.starts_with('/')
                        || target.ends_with('/')
                        || target.contains("..")
                        || target.trim() != target
                })
            {
                return Err(invalid(
                    "symbols",
                    "entries require ids, symbols, and canonical known locations",
                ));
            }
        }
        Ok(())
    }

    /// Discovers and scans the repository's complete production source universe.
    ///
    /// # Errors
    ///
    /// Returns an error when discovery or UTF-8 decoding fails, or when the
    /// fixture or a structural token pattern is invalid.
    pub fn scan_repository_root(
        &self,
        repository_root: &Path,
    ) -> Result<Vec<ForbiddenSymbolMatch>, ControlError> {
        self.validate()?;
        let sources = discover_production_sources(repository_root)?;
        let mut matches = Vec::new();
        for (target, source) in sources {
            let tokens = structural_tokens_for_path(&target, &source).map_err(|error| {
                invalid(
                    "source",
                    &format!("cannot tokenize '{target}' for hard-cut scanning: {error}"),
                )
            })?;
            for entry in &self.symbols {
                if entry.category == ForbiddenSymbolCategory::Web && !target.contains("/src/web/") {
                    continue;
                }
                let pattern = literal_tokens(&entry.symbol, 1);
                if pattern.is_empty() {
                    return Err(invalid("symbol", "must contain structural tokens"));
                }
                for window in tokens.windows(pattern.len()) {
                    if window
                        .iter()
                        .map(|token| token.text.as_str())
                        .eq(pattern.iter().map(|token| token.text.as_str()))
                    {
                        matches.push(ForbiddenSymbolMatch {
                            entry_id: entry.id.clone(),
                            category: entry.category,
                            symbol: entry.symbol.clone(),
                            target: target.clone(),
                            line: window[0].line,
                        });
                    }
                }
            }
        }
        Ok(matches)
    }
}

fn discover_production_sources(root: &Path) -> Result<Vec<(String, String)>, ControlError> {
    let crates_root = root.join("crates");
    let mut pending = vec![
        crates_root,
        root.join("modules"),
        root.join("pkgs"),
        root.join("systems"),
        root.join("stdenv"),
    ];
    if root.join("lib").is_dir() {
        pending.push(root.join("lib"));
    }
    let mut files = Vec::new();
    for name in ["default.nix", "flake.nix", "justfile"] {
        let file = root.join(name);
        if file.is_file() {
            files.push(file);
        }
    }
    while let Some(path) = pending.pop() {
        let entries = std::fs::read_dir(&path)
            .map_err(|_| invalid("repository_root", "cannot read a production source root"))?;
        for entry in entries {
            let entry =
                entry.map_err(|_| invalid("repository_root", "cannot read source entry"))?;
            let path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|_| invalid("repository_root", "cannot inspect source entry"))?;
            if file_type.is_dir() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if matches!(
                    name.as_ref(),
                    ".git"
                        | ".worktrees"
                        | "target"
                        | "node_modules"
                        | "vendor"
                        | "tests"
                        | "examples"
                ) {
                    continue;
                }
                pending.push(path);
            } else if file_type.is_file() && is_production_source_file(&path) {
                files.push(path);
            }
        }
    }
    files.sort();
    files.dedup();
    if files.is_empty() || files.len() > 100_000 {
        return Err(invalid(
            "repository_root",
            "production source universe is empty or oversized",
        ));
    }
    files
        .into_iter()
        .map(|path| {
            let metadata = std::fs::metadata(&path)
                .map_err(|_| invalid("source", "cannot inspect production source"))?;
            if metadata.len() > 16 * 1024 * 1024 {
                return Err(invalid("source", "production source exceeds 16 MiB"));
            }
            let relative = path
                .strip_prefix(root)
                .map_err(|_| invalid("source", "discovered source escaped repository root"))?
                .to_string_lossy()
                .replace('\\', "/");
            let source = std::fs::read_to_string(&path)
                .map_err(|_| invalid("source", "production source must be readable UTF-8"))?;
            Ok((relative, source))
        })
        .collect()
}

fn is_production_source_file(path: &Path) -> bool {
    if path.file_name().is_some_and(|name| name == "build.rs") {
        return true;
    }
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            matches!(
                extension,
                "rs" | "proto"
                    | "sql"
                    | "nix"
                    | "jq"
                    | "js"
                    | "jsx"
                    | "ts"
                    | "tsx"
                    | "css"
                    | "html"
                    | "sh"
                    | "toml"
                    | "json"
                    | "yaml"
                    | "yml"
                    | "c"
                    | "h"
                    | "cc"
                    | "cpp"
                    | "go"
                    | "py"
                    | "rb"
            )
        })
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StructuralToken {
    text: String,
    line: usize,
}

#[derive(Clone, Copy)]
enum SourceFormat {
    Rust,
    Nix,
    SlashComments,
    Sql,
    HashComments,
    Data,
}

fn structural_tokens_for_path(
    target: &str,
    source: &str,
) -> Result<Vec<StructuralToken>, ControlError> {
    let format = if target.ends_with(".rs") {
        SourceFormat::Rust
    } else if target.ends_with(".nix") {
        SourceFormat::Nix
    } else if target.ends_with(".sql") {
        SourceFormat::Sql
    } else if target.ends_with(".sh")
        || target.ends_with(".py")
        || target.ends_with(".rb")
        || target.ends_with(".yaml")
        || target.ends_with(".yml")
        || target.ends_with(".toml")
        || target.ends_with("justfile")
    {
        SourceFormat::HashComments
    } else if target.ends_with(".json") {
        SourceFormat::Data
    } else {
        SourceFormat::SlashComments
    };
    let tokens = structural_tokens(source, format)?;
    if matches!(format, SourceFormat::Rust) {
        exclude_cfg_test_items(tokens)
    } else {
        Ok(tokens)
    }
}

fn exclude_cfg_test_items(
    tokens: Vec<StructuralToken>,
) -> Result<Vec<StructuralToken>, ControlError> {
    let mut production = Vec::with_capacity(tokens.len());
    let mut index = 0;
    while index < tokens.len() {
        let Some(item_start) = cfg_test_attribute_end(&tokens, index) else {
            production.push(tokens[index].clone());
            index += 1;
            continue;
        };

        let attribute_start = index;
        index = item_start;
        let mut is_module = false;
        while index < tokens.len() && tokens[index].text != "{" && tokens[index].text != ";" {
            is_module |= tokens[index].text == "mod";
            index += 1;
        }
        if !is_module {
            production.extend(tokens[attribute_start..item_start].iter().cloned());
            index = item_start;
            continue;
        }
        if index == tokens.len() {
            return Err(invalid(
                "source",
                "cfg(test) item has no body or terminator",
            ));
        }
        if tokens[index].text == ";" {
            index += 1;
            continue;
        }
        let mut depth = 1_u32;
        index += 1;
        while index < tokens.len() && depth > 0 {
            match tokens[index].text.as_str() {
                "{" => {
                    depth = depth
                        .checked_add(1)
                        .ok_or_else(|| invalid("source", "cfg(test) item nesting overflowed"))?;
                }
                "}" => depth -= 1,
                _ => {}
            }
            index += 1;
        }
        if depth != 0 {
            // Rust unit-test modules conventionally occupy the source tail.
            // Token-level brace counting can lose braces embedded in character
            // literals, so an unmatched test-module body excludes that tail.
            index = tokens.len();
        }
    }
    Ok(production)
}

fn cfg_test_attribute_end(tokens: &[StructuralToken], start: usize) -> Option<usize> {
    let prefix = tokens.get(start..start + 5)?;
    if !prefix
        .iter()
        .map(|token| token.text.as_str())
        .eq(["#", "[", "cfg", "(", "test"])
        && !tokens
            .get(start..start + 7)?
            .iter()
            .map(|token| token.text.as_str())
            .eq(["#", "[", "cfg", "(", "all", "(", "test"])
    {
        return None;
    }
    tokens[start..]
        .iter()
        .position(|token| token.text == "]")
        .map(|offset| start + offset + 1)
}

fn structural_tokens(
    source: &str,
    format: SourceFormat,
) -> Result<Vec<StructuralToken>, ControlError> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0;
    let mut line = 1;
    while index < bytes.len() {
        if bytes[index] == b'\n' {
            line += 1;
            index += 1;
        } else if bytes[index].is_ascii_whitespace() {
            index += 1;
        } else if matches!(format, SourceFormat::Rust) && raw_string_start(bytes, index).is_some() {
            let (content_start, hashes) = raw_string_start(bytes, index)
                .ok_or_else(|| invalid("source", "raw string prefix disappeared"))?;
            let content_line = line;
            index = content_start;
            let literal_start = index;
            let mut closed = false;
            while index < bytes.len() {
                if bytes[index] == b'\n' {
                    line += 1;
                }
                if bytes[index] == b'"'
                    && bytes
                        .get(index + 1..index + 1 + hashes)
                        .is_some_and(|suffix| suffix.iter().all(|byte| *byte == b'#'))
                {
                    tokens.extend(literal_tokens(&source[literal_start..index], content_line));
                    index += 1 + hashes;
                    closed = true;
                    break;
                }
                index += 1;
            }
            if !closed {
                return Err(invalid("source", "unterminated raw string literal"));
            }
        } else if matches!(format, SourceFormat::Nix) && bytes[index..].starts_with(b"''") {
            let start = index;
            let literal_start = start + 2;
            let literal_line = line;
            index = scan_nix_string(bytes, start, NixStringKind::Indented)?;
            line += source[start..index]
                .bytes()
                .filter(|byte| *byte == b'\n')
                .count();
            tokens.extend(literal_tokens(
                &source[literal_start..index - 2],
                literal_line,
            ));
        } else if (matches!(format, SourceFormat::Rust | SourceFormat::SlashComments)
            && bytes[index..].starts_with(b"//"))
            || (matches!(format, SourceFormat::Sql) && bytes[index..].starts_with(b"--"))
            || (matches!(format, SourceFormat::Nix | SourceFormat::HashComments)
                && bytes[index] == b'#')
        {
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
        } else if !matches!(format, SourceFormat::HashComments | SourceFormat::Data)
            && bytes[index..].starts_with(b"/*")
        {
            index += 2;
            let mut depth = 1_u32;
            while index < bytes.len() && depth > 0 {
                if bytes[index..].starts_with(b"/*") {
                    depth = depth
                        .checked_add(1)
                        .ok_or_else(|| invalid("source", "comment nesting overflowed"))?;
                    index += 2;
                } else if bytes[index..].starts_with(b"*/") {
                    depth -= 1;
                    index += 2;
                } else {
                    if bytes[index] == b'\n' {
                        line += 1;
                    }
                    index += 1;
                }
            }
            if depth != 0 {
                return Err(invalid("source", "unterminated block comment"));
            }
        } else if matches!(format, SourceFormat::Rust)
            && bytes[index] == b'\''
            && bytes
                .get(index + 1)
                .is_some_and(|byte| *byte == b'_' || byte.is_ascii_alphabetic())
        {
            let mut end = index + 2;
            while end < bytes.len() && (bytes[end] == b'_' || bytes[end].is_ascii_alphanumeric()) {
                end += 1;
            }
            if bytes.get(end) != Some(&b'\'') {
                tokens.push(StructuralToken {
                    text: "'".into(),
                    line,
                });
                index += 1;
                continue;
            }
            let quote = bytes[index];
            index += 1;
            while index < bytes.len() {
                let byte = bytes[index];
                index += 1;
                if byte == quote {
                    break;
                }
            }
        } else if matches!(format, SourceFormat::Nix) && bytes[index] == b'"' {
            let start = index;
            let literal_start = start + 1;
            let literal_line = line;
            index = scan_nix_string(bytes, start, NixStringKind::DoubleQuoted)?;
            line += source[start..index]
                .bytes()
                .filter(|byte| *byte == b'\n')
                .count();
            tokens.extend(literal_tokens(
                &source[literal_start..index - 1],
                literal_line,
            ));
        } else if !matches!(format, SourceFormat::Nix)
            && matches!(bytes[index], b'"' | b'\'' | b'`')
        {
            let quote = bytes[index];
            index += 1;
            let literal_start = index;
            let literal_line = line;
            let mut escaped = false;
            let mut closed = false;
            while index < bytes.len() {
                let byte = bytes[index];
                index += 1;
                if byte == b'\n' {
                    line += 1;
                }
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == quote {
                    tokens.extend(literal_tokens(
                        &source[literal_start..index - 1],
                        literal_line,
                    ));
                    closed = true;
                    break;
                }
            }
            if !closed {
                return Err(invalid("source", "unterminated string literal"));
            }
        } else if bytes[index] == b'_' || bytes[index].is_ascii_alphabetic() {
            let start = index;
            index += 1;
            while index < bytes.len()
                && (bytes[index] == b'_'
                    || bytes[index].is_ascii_alphanumeric()
                    || (matches!(format, SourceFormat::Nix) && bytes[index] == b'\''))
            {
                index += 1;
            }
            tokens.push(StructuralToken {
                text: source[start..index].to_string(),
                line,
            });
        } else {
            tokens.push(StructuralToken {
                text: char::from(bytes[index]).to_string(),
                line,
            });
            index += 1;
        }
    }
    Ok(tokens)
}

fn literal_tokens(value: &str, line: usize) -> Vec<StructuralToken> {
    let bytes = value.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0;
    let mut current_line = line;
    while index < bytes.len() {
        if bytes[index] == b'\n' {
            current_line += 1;
            index += 1;
        } else if bytes[index] == b'_' || bytes[index].is_ascii_alphabetic() {
            let start = index;
            index += 1;
            while index < bytes.len()
                && (bytes[index] == b'_' || bytes[index].is_ascii_alphanumeric())
            {
                index += 1;
            }
            tokens.push(StructuralToken {
                text: value[start..index].to_owned(),
                line: current_line,
            });
        } else if !bytes[index].is_ascii_whitespace() {
            tokens.push(StructuralToken {
                text: char::from(bytes[index]).to_string(),
                line: current_line,
            });
            index += 1;
        } else {
            index += 1;
        }
    }
    tokens
}

#[derive(Clone, Copy)]
enum NixStringKind {
    DoubleQuoted,
    Indented,
}

fn scan_nix_string(bytes: &[u8], start: usize, kind: NixStringKind) -> Result<usize, ControlError> {
    let mut index = start
        + match kind {
            NixStringKind::DoubleQuoted => 1,
            NixStringKind::Indented => 2,
        };
    while index < bytes.len() {
        match kind {
            NixStringKind::DoubleQuoted => {
                if bytes[index] == b'\\' {
                    index = (index + 2).min(bytes.len());
                } else if bytes[index..].starts_with(b"${") {
                    index = scan_nix_interpolation(bytes, index + 2)?;
                } else if bytes[index] == b'"' {
                    return Ok(index + 1);
                } else {
                    index += 1;
                }
            }
            NixStringKind::Indented => {
                if bytes[index..].starts_with(b"''$") {
                    index += 3;
                } else if bytes[index..].starts_with(b"'''") || bytes[index..].starts_with(b"''\\")
                {
                    index += 3;
                } else if bytes[index..].starts_with(b"${") {
                    index = scan_nix_interpolation(bytes, index + 2)?;
                } else if bytes[index..].starts_with(b"''") {
                    return Ok(index + 2);
                } else {
                    index += 1;
                }
            }
        }
    }
    let reason = match kind {
        NixStringKind::DoubleQuoted => "unterminated Nix string literal",
        NixStringKind::Indented => "unterminated Nix indented string",
    };
    Err(invalid("source", reason))
}

fn scan_nix_interpolation(bytes: &[u8], mut index: usize) -> Result<usize, ControlError> {
    let mut depth = 1_u32;
    while index < bytes.len() {
        if bytes[index] == b'#' {
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
        } else if bytes[index..].starts_with(b"/*") {
            index += 2;
            let mut comment_depth = 1_u32;
            while index < bytes.len() && comment_depth > 0 {
                if bytes[index..].starts_with(b"/*") {
                    comment_depth = comment_depth
                        .checked_add(1)
                        .ok_or_else(|| invalid("source", "comment nesting overflowed"))?;
                    index += 2;
                } else if bytes[index..].starts_with(b"*/") {
                    comment_depth -= 1;
                    index += 2;
                } else {
                    index += 1;
                }
            }
            if comment_depth != 0 {
                return Err(invalid("source", "unterminated block comment"));
            }
        } else if bytes[index..].starts_with(b"''") {
            index = scan_nix_string(bytes, index, NixStringKind::Indented)?;
        } else if bytes[index] == b'"' {
            index = scan_nix_string(bytes, index, NixStringKind::DoubleQuoted)?;
        } else if bytes[index] == b'{' {
            depth = depth
                .checked_add(1)
                .ok_or_else(|| invalid("source", "Nix interpolation nesting overflowed"))?;
            index += 1;
        } else if bytes[index] == b'}' {
            depth -= 1;
            index += 1;
            if depth == 0 {
                return Ok(index);
            }
        } else {
            index += 1;
        }
    }
    Err(invalid("source", "unterminated Nix interpolation"))
}

fn raw_string_start(bytes: &[u8], index: usize) -> Option<(usize, usize)> {
    let mut cursor = if bytes.get(index) == Some(&b'r') {
        index + 1
    } else if bytes.get(index) == Some(&b'b') && bytes.get(index + 1) == Some(&b'r') {
        index + 2
    } else {
        return None;
    };
    let hashes_start = cursor;
    while bytes.get(cursor) == Some(&b'#') {
        cursor += 1;
    }
    if bytes.get(cursor) == Some(&b'"') {
        Some((cursor + 1, cursor - hashes_start))
    } else {
        None
    }
}

/// One forbidden-symbol occurrence found by a hard-cut scan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForbiddenSymbolMatch {
    /// Stable fixture-entry identity.
    pub entry_id: String,
    /// Kind of legacy surface matched.
    pub category: ForbiddenSymbolCategory,
    /// Canonical structural token pattern matched.
    pub symbol: String,
    /// Repository-relative source path.
    pub target: String,
    /// One-based line number.
    pub line: usize,
}

fn require_durability(
    method: &MethodDescriptor,
    expected: MethodDurability,
    reason: &str,
    violations: &mut Vec<ManifestViolation>,
) {
    if method.durability != expected {
        violations.push(violation(method, reason));
    }
}

fn violation(method: &MethodDescriptor, reason: &str) -> ManifestViolation {
    ManifestViolation {
        subject: method.path(),
        reason: reason.into(),
    }
}

fn invalid(field: &'static str, reason: &str) -> ControlError {
    ControlError::Invalid {
        field,
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reviewed_pairs_and_explicit_exceptions_validate() {
        let methods = vec![
            MethodDescriptor {
                service: "ChannelService".into(),
                method: "PlanAdvanceChannel".into(),
                exposure: MethodExposure::Public,
                durability: MethodDurability::Durable,
                class: MethodClass::Plan {
                    pair: "advance_channel".into(),
                },
                external_effects: false,
            },
            MethodDescriptor {
                service: "ChannelService".into(),
                method: "AdvanceChannel".into(),
                exposure: MethodExposure::Public,
                durability: MethodDurability::Durable,
                class: MethodClass::Apply {
                    pair: "advance_channel".into(),
                    outcome: ApplyOutcome::Operation,
                },
                external_effects: true,
            },
            MethodDescriptor {
                service: "ChangeRequestService".into(),
                method: "AddComment".into(),
                exposure: MethodExposure::Public,
                durability: MethodDurability::Durable,
                class: MethodClass::AppendOnlyEvent {
                    event_kind: AppendOnlyEventKind::ChangeRequestComment,
                },
                external_effects: false,
            },
        ];
        assert!(validate_method_manifest(&methods).is_empty());
    }

    #[test]
    fn public_controller_and_unpaired_mutation_fail_closed() {
        let methods = vec![
            MethodDescriptor {
                service: "DeliveryService".into(),
                method: "ReconcileGateway".into(),
                exposure: MethodExposure::Public,
                durability: MethodDurability::Durable,
                class: MethodClass::ControllerObservation,
                external_effects: false,
            },
            MethodDescriptor {
                service: "IdentityService".into(),
                method: ["Plan", "Mint", "Token"].concat(),
                exposure: MethodExposure::Public,
                durability: MethodDurability::Durable,
                class: MethodClass::Plan {
                    pair: "mint_token".into(),
                },
                external_effects: false,
            },
        ];
        assert_eq!(validate_method_manifest(&methods).len(), 3);
    }

    #[test]
    fn data_plane_writes_use_an_exact_method_allowlist() {
        let write = |service: &str, method: &str| MethodDescriptor {
            service: service.into(),
            method: method.into(),
            exposure: MethodExposure::Public,
            durability: MethodDurability::Durable,
            class: MethodClass::DataPlaneWrite,
            external_effects: false,
        };
        assert!(validate_method_manifest(&[
            write("BinaryCacheService", "CreateCacheObjectUploads"),
            write("BinaryCacheService", "RegisterCacheNarinfos"),
        ])
        .is_empty());
        assert_eq!(
            validate_method_manifest(&[write("IdentityService", &["Mint", "Token"].concat(),)])
                .len(),
            1
        );
    }

    #[test]
    fn descriptor_coverage_fails_for_missing_extra_and_duplicate_methods() {
        let methods = vec![MethodDescriptor {
            service: "InstanceService".into(),
            method: "GetBranding".into(),
            exposure: MethodExposure::Public,
            durability: MethodDurability::ReadOnly,
            class: MethodClass::Read,
            external_effects: false,
        }];
        let descriptor = vec![
            ApiMethodDescriptor {
                service: "InstanceService".into(),
                method: "GetBranding".into(),
                request: "GetBrandingRequest".into(),
                response: "BrandingResponse".into(),
                request_fields: vec!["instance_id".into()],
            },
            ApiMethodDescriptor {
                service: "InstanceService".into(),
                method: "GetIdentityAndSignup".into(),
                request: "GetIdentityAndSignupRequest".into(),
                response: "IdentityAndSignupResponse".into(),
                request_fields: vec!["instance_id".into()],
            },
        ];
        let violations = validate_complete_method_manifest(&methods, &descriptor);
        assert_eq!(violations.len(), 1);

        let duplicate = vec![descriptor[0].clone(), descriptor[0].clone()];
        assert!(!validate_descriptor_coverage(&methods, &duplicate).is_empty());
        assert!(api_methods_from_generated_descriptors(&[
            aos_proto_types::ConnectMethodDescriptor {
                path: "/aos.hub.v1.InstanceService/GetBranding",
                service: "InstanceService",
                method: "GetBranding",
                input_type: ".aos.hub.v1.GetBrandingRequest",
                output_type: ".aos.hub.v1.BrandingResponse",
                input_fields: &["instance_id"],
            },
            aos_proto_types::ConnectMethodDescriptor {
                path: "/aos.hub.v1.InstanceService/GetBranding",
                service: "InstanceService",
                method: "GetBranding",
                input_type: ".aos.hub.v1.GetBrandingRequest",
                output_type: ".aos.hub.v1.BrandingResponse",
                input_fields: &["instance_id"],
            },
        ])
        .is_err());
    }

    #[test]
    fn descriptor_contract_rejects_mutable_apply_request_fields() {
        let methods = vec![
            MethodDescriptor {
                service: "RegistryService".into(),
                method: "PlanUpdateRegistry".into(),
                exposure: MethodExposure::Public,
                durability: MethodDurability::Durable,
                class: MethodClass::Plan {
                    pair: "update_registry".into(),
                },
                external_effects: false,
            },
            MethodDescriptor {
                service: "RegistryService".into(),
                method: "UpdateRegistry".into(),
                exposure: MethodExposure::Public,
                durability: MethodDurability::Durable,
                class: MethodClass::Apply {
                    pair: "update_registry".into(),
                    outcome: ApplyOutcome::Immediate,
                },
                external_effects: false,
            },
        ];
        let descriptors = vec![
            ApiMethodDescriptor {
                service: "RegistryService".into(),
                method: "PlanUpdateRegistry".into(),
                request: "PlanUpdateRegistryRequest".into(),
                response: "TopologyPlanResponse".into(),
                request_fields: vec![
                    "idempotency_key".into(),
                    "expected_resource_version".into(),
                    "display_name".into(),
                ],
            },
            ApiMethodDescriptor {
                service: "RegistryService".into(),
                method: "UpdateRegistry".into(),
                request: "UpdateRegistryRequest".into(),
                response: "RegistryResponse".into(),
                request_fields: vec![
                    "plan_id".into(),
                    "confirmation_hash".into(),
                    "idempotency_key".into(),
                    "display_name".into(),
                ],
            },
        ];
        assert!(validate_complete_method_manifest(&methods, &descriptors)
            .iter()
            .any(|violation| violation.reason.contains("apply requests may contain only")));
    }

    #[test]
    fn descriptor_contract_allows_only_the_declared_reviewed_apply_cas_exceptions() {
        let methods = vec![
            MethodDescriptor {
                service: "ContainerService".into(),
                method: "PlanRepairContainerUntrackedObject".into(),
                exposure: MethodExposure::Public,
                durability: MethodDurability::Durable,
                class: MethodClass::Plan {
                    pair: "repair_container_untracked_object".into(),
                },
                external_effects: false,
            },
            MethodDescriptor {
                service: "ContainerService".into(),
                method: "RepairContainerUntrackedObject".into(),
                exposure: MethodExposure::Public,
                durability: MethodDurability::Durable,
                class: MethodClass::Apply {
                    pair: "repair_container_untracked_object".into(),
                    outcome: ApplyOutcome::Operation,
                },
                external_effects: true,
            },
            MethodDescriptor {
                service: "ContainerService".into(),
                method: "PlanContainerRegistryPurgeFence".into(),
                exposure: MethodExposure::Public,
                durability: MethodDurability::Durable,
                class: MethodClass::Plan {
                    pair: "container_registry_purge_fence".into(),
                },
                external_effects: false,
            },
            MethodDescriptor {
                service: "ContainerService".into(),
                method: "ApplyContainerRegistryPurgeFence".into(),
                exposure: MethodExposure::Public,
                durability: MethodDurability::Durable,
                class: MethodClass::Apply {
                    pair: "container_registry_purge_fence".into(),
                    outcome: ApplyOutcome::Immediate,
                },
                external_effects: false,
            },
        ];
        let descriptors = vec![
            ApiMethodDescriptor {
                service: "ContainerService".into(),
                method: "PlanRepairContainerUntrackedObject".into(),
                request: "PlanRepairContainerUntrackedObjectRequest".into(),
                response: "TopologyPlanResponse".into(),
                request_fields: vec![
                    "registry".into(),
                    "expected_resource_version".into(),
                    "idempotency_key".into(),
                ],
            },
            ApiMethodDescriptor {
                service: "ContainerService".into(),
                method: "RepairContainerUntrackedObject".into(),
                request: "RepairContainerUntrackedObjectRequest".into(),
                response: "OperationResponse".into(),
                request_fields: vec![
                    "plan_id".into(),
                    "confirmation_hash".into(),
                    "idempotency_key".into(),
                    "expected_resource_version".into(),
                ],
            },
            ApiMethodDescriptor {
                service: "ContainerService".into(),
                method: "PlanContainerRegistryPurgeFence".into(),
                request: "PlanContainerRegistryPurgeFenceRequest".into(),
                response: "TopologyPlanResponse".into(),
                request_fields: vec![
                    "registry".into(),
                    "action".into(),
                    "expected_resource_version".into(),
                    "idempotency_key".into(),
                ],
            },
            ApiMethodDescriptor {
                service: "ContainerService".into(),
                method: "ApplyContainerRegistryPurgeFence".into(),
                request: "ApplyContainerRegistryPurgeFenceRequest".into(),
                response: "ContainerRegistryPurgeFenceResponse".into(),
                request_fields: vec![
                    "plan_id".into(),
                    "confirmation_hash".into(),
                    "idempotency_key".into(),
                    "expected_resource_version".into(),
                ],
            },
        ];
        assert!(validate_complete_method_manifest(&methods, &descriptors).is_empty());

        let mut adjacent_methods = methods;
        adjacent_methods[1].method = "RepairOtherObject".into();
        let mut adjacent_descriptors = descriptors;
        adjacent_descriptors[1].method = "RepairOtherObject".into();
        assert!(
            validate_complete_method_manifest(&adjacent_methods, &adjacent_descriptors)
                .iter()
                .any(|violation| violation.reason.contains("apply requests may contain only"))
        );
    }

    #[test]
    fn hard_cut_matching_is_structural_and_inspects_runtime_strings() {
        let head = ["Hub", "Config", "Cmd"].concat();
        let tail = ["Re", "vert"].concat();
        let legacy = format!("{head}::{tail}");
        let source = format!(
            "\n            // {head} :: {tail}\n            const NOTE: &str = \"{legacy}\";\n            const RAW: &str = r##\"{legacy}\"##;\n            value.{head}\n                :: {tail}();\n"
        );
        let source_tokens = structural_tokens(&source, SourceFormat::Rust).unwrap();
        let pattern = structural_tokens(&legacy, SourceFormat::Rust).unwrap();
        let matches = source_tokens
            .windows(pattern.len())
            .filter(|window| {
                window
                    .iter()
                    .map(|token| token.text.as_str())
                    .eq(pattern.iter().map(|token| token.text.as_str()))
            })
            .collect::<Vec<_>>();
        assert_eq!(matches.len(), 3);
        assert_eq!(
            matches
                .iter()
                .map(|matched| matched[0].line)
                .collect::<Vec<_>>(),
            vec![3, 4, 5]
        );
    }

    #[test]
    fn hard_cut_matching_inspects_sql_and_config_strings_but_not_comments() {
        let legacy = format!(
            "{}::{}",
            ["Hub", "Config", "Cmd"].concat(),
            ["Re", "vert"].concat()
        );
        let pattern = structural_tokens(&legacy, SourceFormat::Sql).unwrap();
        for (source, format) in [
            (
                format!("-- {legacy}\nINSERT INTO routes VALUES ('{legacy}');"),
                SourceFormat::Sql,
            ),
            (
                format!("# {legacy}\nroute = '{legacy}'"),
                SourceFormat::HashComments,
            ),
        ] {
            let tokens = structural_tokens(&source, format).unwrap();
            let matches = tokens
                .windows(pattern.len())
                .filter(|window| {
                    window
                        .iter()
                        .map(|token| token.text.as_str())
                        .eq(pattern.iter().map(|token| token.text.as_str()))
                })
                .count();
            assert_eq!(matches, 1);
        }
    }

    #[test]
    fn nix_indented_strings_preserve_escaped_interpolation() {
        let source = "value = ''prefix ''${PATH:+:$PATH} suffix'';";
        let tokens = structural_tokens(source, SourceFormat::Nix).unwrap();
        assert!(tokens.iter().any(|token| token.text == "PATH"));
        assert!(tokens.iter().any(|token| token.text == "suffix"));
    }

    #[test]
    fn nix_identifiers_accept_trailing_apostrophes() {
        let source = "mapAttrs' = builtins.mapAttrs; folded = builtins.foldl' f init values;";
        let tokens = structural_tokens(source, SourceFormat::Nix).unwrap();
        assert!(tokens.iter().any(|token| token.text == "mapAttrs'"));
        assert!(tokens.iter().any(|token| token.text == "foldl'"));
    }

    #[test]
    fn nix_strings_allow_quoted_values_inside_interpolation() {
        let source = r#"escaped = "'${builtins.replaceStrings ["'"] ["'\\''"] value}'";"#;
        let tokens = structural_tokens(source, SourceFormat::Nix).unwrap();
        assert!(tokens.iter().any(|token| token.text == "replaceStrings"));
        assert!(tokens.iter().any(|token| token.text == "value"));
    }

    #[test]
    fn production_scan_excludes_cfg_test_items() {
        let source = "fn retained() { durable_write(); }\n#[cfg(test)] mod tests { fn helper() { legacy_write(); } }";
        let tokens =
            exclude_cfg_test_items(structural_tokens(source, SourceFormat::Rust).unwrap()).unwrap();
        assert!(tokens.iter().any(|token| token.text == "durable_write"));
        assert!(!tokens.iter().any(|token| token.text == "legacy_write"));
    }
}
