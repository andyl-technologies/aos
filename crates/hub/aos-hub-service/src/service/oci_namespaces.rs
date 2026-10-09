//! Reviewed administration of instance OCI routes and registry OCI namespaces.
//!
//! Instance OCI routes are deployment-wide delivery topology, so every route
//! method requires `iam.admin` at the instance root. Registry namespace
//! exposure is a container-administration setting on the registry and requires
//! `registry.configure` there. Both follow the ordinary immutable plan/apply
//! protocol of the control plane: a plan seals the exact inputs, the apply
//! revalidates them, and a replayed apply returns the recorded result.

use aos_hub_api as pb;
use aos_oci_types::RepositoryName;
use sha2::{Digest as _, Sha256};

use super::{
    claims_principal, parse_resource_version, RouteReservationPlanSeal, RpcError, RpcService,
};
use crate::auth::jwt::Claims;
use crate::db::{
    InstanceOciRouteRecord, InstanceOciRouteReservation, InstanceOciRouteSpec, RegistryRecord,
    SurfaceTarget,
};
use crate::domain::{Permission, Scope};

const CREATE_PLAN: &str = "create_instance_oci_route";
const UPDATE_PLAN: &str = "update_instance_oci_route";
const DELETE_PLAN: &str = "delete_instance_oci_route";
const CONVERT_PLAN: &str = "convert_route_to_instance_oci_route";
const NAMESPACE_PLAN: &str = "set_container_namespace";

/// Mutable instance-route fields an update mask may name.
const UPDATE_FIELDS: &[&str] = &[
    "spec.endpoint_generation",
    "spec.access_policy",
    "spec.default_registry",
    "spec.enabled",
];

/// Immutable create/update inputs sealed into an instance-route plan.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct InstanceOciRoutePlanInput {
    stable_id: String,
    spec: pb::InstanceOciRouteSpec,
    canonical_url: String,
    reservation: Option<RouteReservationPlanSeal>,
    bind_existing_reservation: bool,
    expected_resource_version: Option<i64>,
}

/// Immutable deletion inputs sealed into an instance-route plan.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct InstanceOciRouteDeletePlanInput {
    stable_id: String,
    expected_resource_version: i64,
}

/// Immutable conversion inputs sealed into a route-conversion plan.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct ConvertRoutePlanInput {
    route_id: String,
    expected_route_version: i64,
    instance_route_id: String,
    registry_id: i64,
    canonical_url: String,
}

/// Immutable namespace inputs sealed into a registry namespace plan.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct ContainerNamespacePlanInput {
    registry_id: i64,
    registry_stable_id: String,
    enabled: bool,
    expected_resource_version: i64,
}

/// Where a registry's OCI surface is reachable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContainerDistributionExposure {
    /// Exact ready route origin, including scheme.
    pub origin: String,
    /// Repository-name prefix clients must use on that origin, when the
    /// registry is served through an instance route under its slug.
    pub namespace: Option<String>,
}

fn confirmation_hash<T: serde::Serialize>(input: &T) -> Result<String, RpcError> {
    Ok(hex::encode(Sha256::digest(
        serde_json::to_vec(input).map_err(RpcError::internal)?,
    )))
}

fn resource_version_string(version: i64) -> String {
    version.to_string()
}

impl RpcService {
    async fn require_instance_admin(&self, auth: Option<&str>) -> Result<Claims, RpcError> {
        let claims = self.require_claims(auth)?;
        self.require_permission(&claims, Permission::IamAdmin, &Scope::root())
            .await?;
        Ok(claims)
    }

    fn instance_oci_route_message(
        record: InstanceOciRouteRecord,
    ) -> Result<pb::InstanceOciRoute, RpcError> {
        let access_policy =
            serde_json::from_str(&record.access_policy_json).map_err(RpcError::internal)?;
        Ok(pb::InstanceOciRoute {
            stable_id: record.id,
            spec: Some(pb::InstanceOciRouteSpec {
                endpoint_id: record.endpoint_id,
                endpoint_generation: record.endpoint_generation,
                access_policy: Some(access_policy),
                default_registry: record.default_registry_slug.unwrap_or_default(),
                enabled: record.enabled,
            }),
            canonical_rendered_url: record.canonical_url,
            ready: record.ready,
            resource_version: resource_version_string(record.resource_version),
            created_at: record.created_at,
            updated_at: record.updated_at,
        })
    }

    /// Normalizes one desired instance-route spec against live topology.
    async fn instance_oci_route_spec(
        &self,
        spec: &pb::InstanceOciRouteSpec,
    ) -> Result<(InstanceOciRouteSpec, String, crate::db::EndpointRecord), RpcError> {
        let endpoint = self
            .db
            .endpoint(&spec.endpoint_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("endpoint"))?;
        let revision = self
            .db
            .endpoint_revision(&endpoint.id, spec.endpoint_generation)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("endpoint generation"))?;
        if !matches!(revision.spec.ingress_kind.as_str(), "hub" | "layer7") {
            return Err(RpcError::invalid(
                "an instance OCI route requires a hub or layer7 endpoint generation",
            ));
        }
        let access_policy = spec
            .access_policy
            .clone()
            .ok_or_else(|| RpcError::invalid("accessPolicy is required"))?;
        let (access_policy_kind, access_policy_json, _, _, _, _, _) =
            Self::route_access_policy_fields(access_policy)?;
        if !matches!(access_policy_kind.as_str(), "public" | "hub_auth") {
            return Err(RpcError::invalid(
                "an instance OCI route access policy must be public or hub-auth",
            ));
        }
        let default_registry_id = if spec.default_registry.is_empty() {
            None
        } else {
            Some(
                self.db
                    .registry_by_slug(&spec.default_registry)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| RpcError::not_found("default registry"))?
                    .id,
            )
        };
        let canonical_url = self.rendered_route_url(&endpoint, "").await?;
        Ok((
            InstanceOciRouteSpec {
                endpoint_id: endpoint.id.clone(),
                endpoint_generation: spec.endpoint_generation,
                endpoint_ingress_kind: revision.spec.ingress_kind,
                access_policy_kind,
                access_policy_digest: hex::encode(Sha256::digest(access_policy_json.as_bytes())),
                access_policy_json,
                default_registry_id,
                enabled: spec.enabled,
            },
            canonical_url,
            endpoint,
        ))
    }

    /// Lists every instance OCI route.
    ///
    /// # Errors
    ///
    /// Returns authentication, authorization, or database errors.
    pub async fn list_instance_oci_routes(
        &self,
        auth: Option<&str>,
        _req: pb::ListInstanceOciRoutesRequest,
    ) -> Result<pb::ListInstanceOciRoutesResponse, RpcError> {
        self.require_instance_admin(auth).await?;
        let routes = self
            .db
            .list_instance_oci_routes()
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .map(Self::instance_oci_route_message)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(pb::ListInstanceOciRoutesResponse { routes })
    }

    /// Returns one instance OCI route by stable identity.
    ///
    /// # Errors
    ///
    /// Returns authentication, authorization, not-found, or database errors.
    pub async fn get_instance_oci_route(
        &self,
        auth: Option<&str>,
        req: pb::GetTopologyResourceRequest,
    ) -> Result<pb::InstanceOciRouteResponse, RpcError> {
        self.require_instance_admin(auth).await?;
        let record = self
            .db
            .instance_oci_route(&req.stable_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("instance OCI route"))?;
        Ok(pb::InstanceOciRouteResponse {
            route: Some(Self::instance_oci_route_message(record)?),
        })
    }

    /// Plans creation of an instance OCI route at a host root.
    ///
    /// An equal URL reservation under any retained key refuses the plan unless
    /// `bind_existing_reservation` is set, in which case the plan records that
    /// the route will bind the existing reservation.
    ///
    /// # Errors
    ///
    /// Returns authentication, authorization, validation, not-found,
    /// already-exists, reservation, or database errors.
    pub async fn plan_create_instance_oci_route(
        &self,
        auth: Option<&str>,
        req: pb::PlanInstanceOciRouteMutationRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_instance_admin(auth).await?;
        if !req.expected_resource_version.is_empty() || !req.update_mask.is_empty() {
            return Err(RpcError::invalid(
                "instance OCI route creation forbids expectedResourceVersion and updateMask",
            ));
        }
        if req.stable_id.is_empty() {
            return Err(RpcError::invalid("stableId is required"));
        }
        if self
            .db
            .instance_oci_route(&req.stable_id)
            .await
            .map_err(RpcError::internal)?
            .is_some()
        {
            return Err(RpcError::AlreadyExists(
                "instance OCI route already exists".to_string(),
            ));
        }
        let spec_message = req
            .spec
            .ok_or_else(|| RpcError::invalid("spec is required"))?;
        let (spec, canonical_url, endpoint) = self.instance_oci_route_spec(&spec_message).await?;
        let reservation = self
            .route_reservation_plan_seal(&endpoint, "", &canonical_url)
            .await?;
        let candidates = reservation_candidates(&reservation)?;
        let reserved = self
            .db
            .route_url_reservation_exists(&candidates)
            .await
            .map_err(RpcError::internal)?;
        if reserved && !req.bind_existing_reservation {
            return Err(RpcError::FailedPrecondition(
                "the host root URL is already reserved; set bindExistingReservation to bind it \
                 to the instance OCI route"
                    .to_string(),
            ));
        }

        let mut effects = vec![format!(
            "create instance OCI route '{}' at {canonical_url}",
            req.stable_id
        )];
        let mut warnings = Vec::new();
        if reserved {
            effects.push("bind the existing URL reservation for that host root".to_string());
            warnings.push(
                "the reservation was left by an earlier route; instance routes may bind it \
                 because the instance is not a tenant"
                    .to_string(),
            );
        }
        effects.push(format!(
            "access policy {}; {}",
            spec.access_policy_kind,
            if spec.enabled { "enabled" } else { "disabled" }
        ));
        if !spec_message.default_registry.is_empty() {
            effects.push(format!(
                "serve registry '{}' for repository names without a namespace prefix",
                spec_message.default_registry
            ));
        }
        let input = InstanceOciRoutePlanInput {
            stable_id: req.stable_id,
            spec: spec_message,
            canonical_url,
            reservation: Some(reservation),
            bind_existing_reservation: req.bind_existing_reservation,
            expected_resource_version: None,
        };
        let confirmation = confirmation_hash(&input)?;
        self.create_control_plan(
            &claims,
            CREATE_PLAN,
            "instance",
            &input,
            &req.idempotency_key,
            effects,
            warnings,
            Some(confirmation),
        )
        .await
    }

    /// Applies an instance OCI route creation plan exactly once.
    ///
    /// # Errors
    ///
    /// Returns authentication, authorization, plan, precondition, or database
    /// errors.
    pub async fn create_instance_oci_route(
        &self,
        auth: Option<&str>,
        req: pb::ApplyTopologyPlanRequest,
    ) -> Result<pb::InstanceOciRouteResponse, RpcError> {
        let claims = self
            .require_control_plan_permission(auth, &req.plan_id, Permission::IamAdmin)
            .await?;
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                CREATE_PLAN,
                Some(&req.confirmation_hash),
                &req.idempotency_key,
            )
            .await?
        {
            return Ok(response);
        }
        self.begin_control_plan_apply(
            auth,
            &req.plan_id,
            CREATE_PLAN,
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, InstanceOciRoutePlanInput) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                CREATE_PLAN,
                Some(&req.confirmation_hash),
            )
            .await?;
        let (spec, canonical_url, endpoint) = self.instance_oci_route_spec(&input.spec).await?;
        if canonical_url != input.canonical_url {
            return Err(RpcError::FailedPrecondition(
                "instance OCI route canonical URL changed after planning".to_string(),
            ));
        }
        let sealed = input.reservation.as_ref().ok_or_else(|| {
            RpcError::internal(anyhow::anyhow!(
                "instance OCI route create plan has no reservation seal"
            ))
        })?;
        let current = self
            .route_reservation_plan_seal(&endpoint, "", &canonical_url)
            .await?;
        if current != *sealed {
            return Err(RpcError::FailedPrecondition(
                "route reservation keyring changed after planning; create a new plan".to_string(),
            ));
        }
        let candidates = reservation_candidates(sealed)?;
        let active_digest = candidates
            .iter()
            .find(|(version, _)| *version == sealed.active_version)
            .map(|(_, digest)| digest.clone())
            .ok_or_else(|| {
                RpcError::internal(anyhow::anyhow!("active reservation digest is missing"))
            })?;
        let record = self
            .db
            .create_instance_oci_route(
                &input.stable_id,
                &spec,
                &canonical_url,
                &InstanceOciRouteReservation {
                    key_version: sealed.active_version,
                    digest: &active_digest,
                    candidates: &candidates,
                    bind_existing: input.bind_existing_reservation,
                },
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        self.record_instance_route_audit(
            &claims,
            "instance.oci_route.created",
            &plan.plan_id,
            &record.id,
        )
        .await;
        let response = pb::InstanceOciRouteResponse {
            route: Some(Self::instance_oci_route_message(record)?),
        };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// Plans a configuration update that keeps the route's URL identity.
    ///
    /// # Errors
    ///
    /// Returns authentication, authorization, validation, not-found, stale
    /// version, or database errors.
    pub async fn plan_update_instance_oci_route(
        &self,
        auth: Option<&str>,
        req: pb::PlanInstanceOciRouteMutationRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_instance_admin(auth).await?;
        if req.bind_existing_reservation {
            return Err(RpcError::invalid(
                "bindExistingReservation applies to instance OCI route creation only",
            ));
        }
        let current = self
            .db
            .instance_oci_route(&req.stable_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("instance OCI route"))?;
        let expected = parse_resource_version(&req.expected_resource_version, 0)?;
        if expected <= 0 || expected != current.resource_version {
            return Err(RpcError::FailedPrecondition(
                "instance OCI route resource version is required and must be current".to_string(),
            ));
        }
        let mask = req
            .update_mask
            .iter()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        if mask.is_empty()
            || mask.len() != req.update_mask.len()
            || mask.iter().any(|field| !UPDATE_FIELDS.contains(field))
        {
            return Err(RpcError::invalid(
                "updateMask must contain unique mutable instance OCI route fields",
            ));
        }
        let desired = req
            .spec
            .ok_or_else(|| RpcError::invalid("spec is required"))?;
        if !desired.endpoint_id.is_empty() && desired.endpoint_id != current.endpoint_id {
            return Err(RpcError::invalid(
                "an instance OCI route endpoint identity is immutable",
            ));
        }
        let current_message = Self::instance_oci_route_message(current.clone())?;
        let mut merged = current_message
            .spec
            .ok_or_else(|| RpcError::internal(anyhow::anyhow!("instance route spec is missing")))?;
        let mut effects = Vec::new();
        if mask.contains("spec.endpoint_generation") {
            merged.endpoint_generation = desired.endpoint_generation;
            effects.push(format!(
                "move to endpoint generation {}",
                desired.endpoint_generation
            ));
        }
        if mask.contains("spec.access_policy") {
            merged.access_policy = desired.access_policy;
            effects.push("replace the access policy".to_string());
        }
        if mask.contains("spec.default_registry") {
            merged.default_registry = desired.default_registry;
            effects.push(if merged.default_registry.is_empty() {
                "stop serving a default registry for unprefixed repository names".to_string()
            } else {
                format!(
                    "serve registry '{}' for repository names without a namespace prefix",
                    merged.default_registry
                )
            });
        }
        if mask.contains("spec.enabled") {
            merged.enabled = desired.enabled;
            effects.push(if merged.enabled {
                "enable the route".to_string()
            } else {
                "disable the route".to_string()
            });
        }
        let (_, canonical_url, _) = self.instance_oci_route_spec(&merged).await?;
        if canonical_url != current.canonical_url {
            return Err(RpcError::internal(anyhow::anyhow!(
                "instance OCI route canonical URL drifted from its endpoint"
            )));
        }
        let input = InstanceOciRoutePlanInput {
            stable_id: req.stable_id,
            spec: merged,
            canonical_url,
            reservation: None,
            bind_existing_reservation: false,
            expected_resource_version: Some(expected),
        };
        let confirmation = confirmation_hash(&input)?;
        self.create_control_plan(
            &claims,
            UPDATE_PLAN,
            "instance",
            &input,
            &req.idempotency_key,
            effects,
            Vec::new(),
            Some(confirmation),
        )
        .await
    }

    /// Applies an instance OCI route update plan exactly once.
    ///
    /// # Errors
    ///
    /// Returns authentication, authorization, plan, precondition, or database
    /// errors.
    pub async fn update_instance_oci_route(
        &self,
        auth: Option<&str>,
        req: pb::ApplyTopologyPlanRequest,
    ) -> Result<pb::InstanceOciRouteResponse, RpcError> {
        let claims = self
            .require_control_plan_permission(auth, &req.plan_id, Permission::IamAdmin)
            .await?;
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                UPDATE_PLAN,
                Some(&req.confirmation_hash),
                &req.idempotency_key,
            )
            .await?
        {
            return Ok(response);
        }
        self.begin_control_plan_apply(
            auth,
            &req.plan_id,
            UPDATE_PLAN,
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, InstanceOciRoutePlanInput) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                UPDATE_PLAN,
                Some(&req.confirmation_hash),
            )
            .await?;
        let (spec, canonical_url, _) = self.instance_oci_route_spec(&input.spec).await?;
        if canonical_url != input.canonical_url {
            return Err(RpcError::FailedPrecondition(
                "instance OCI route canonical URL changed after planning".to_string(),
            ));
        }
        let expected = input.expected_resource_version.ok_or_else(|| {
            RpcError::internal(anyhow::anyhow!(
                "instance OCI route update plan has no version"
            ))
        })?;
        let updated = self
            .db
            .update_instance_oci_route(&input.stable_id, &spec, expected)
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        if !updated {
            return Err(RpcError::FailedPrecondition(
                "instance OCI route changed after planning".to_string(),
            ));
        }
        let record = self
            .db
            .instance_oci_route(&input.stable_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("instance OCI route"))?;
        self.record_instance_route_audit(
            &claims,
            "instance.oci_route.updated",
            &plan.plan_id,
            &record.id,
        )
        .await;
        let response = pb::InstanceOciRouteResponse {
            route: Some(Self::instance_oci_route_message(record)?),
        };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// Plans deletion of a disabled instance OCI route.
    ///
    /// The permanent URL reservation stays; a later instance route may bind it
    /// again through `bindExistingReservation`.
    ///
    /// # Errors
    ///
    /// Returns authentication, authorization, validation, not-found, stale
    /// version, precondition, or database errors.
    pub async fn plan_delete_instance_oci_route(
        &self,
        auth: Option<&str>,
        req: pb::PlanDeleteTopologyResourceRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_instance_admin(auth).await?;
        let current = self
            .db
            .instance_oci_route(&req.stable_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("instance OCI route"))?;
        let expected = req
            .expected_resource_version
            .as_deref()
            .ok_or_else(|| RpcError::invalid("expectedResourceVersion is required"))
            .and_then(|value| parse_resource_version(value, 0))?;
        if expected != current.resource_version {
            return Err(RpcError::FailedPrecondition(
                "instance OCI route resource version is stale".to_string(),
            ));
        }
        if current.enabled {
            return Err(RpcError::FailedPrecondition(
                "disable the instance OCI route before deleting it".to_string(),
            ));
        }
        let input = InstanceOciRouteDeletePlanInput {
            stable_id: req.stable_id.clone(),
            expected_resource_version: expected,
        };
        let confirmation = confirmation_hash(&input)?;
        self.create_control_plan(
            &claims,
            DELETE_PLAN,
            "instance",
            &input,
            &req.idempotency_key,
            vec![format!(
                "delete instance OCI route '{}' at {}",
                req.stable_id, current.canonical_url
            )],
            vec!["the permanent URL reservation remains and may be bound again".to_string()],
            Some(confirmation),
        )
        .await
    }

    /// Applies an instance OCI route deletion plan exactly once.
    ///
    /// # Errors
    ///
    /// Returns authentication, authorization, plan, precondition, or database
    /// errors.
    pub async fn delete_instance_oci_route(
        &self,
        auth: Option<&str>,
        req: pb::ApplyDeleteTopologyResourceRequest,
    ) -> Result<pb::DeleteTopologyResourceResponse, RpcError> {
        let claims = self
            .require_control_plan_permission(auth, &req.plan_id, Permission::IamAdmin)
            .await?;
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                DELETE_PLAN,
                Some(&req.confirmation_hash),
                &req.idempotency_key,
            )
            .await?
        {
            return Ok(response);
        }
        self.begin_control_plan_apply(
            auth,
            &req.plan_id,
            DELETE_PLAN,
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, InstanceOciRouteDeletePlanInput) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                DELETE_PLAN,
                Some(&req.confirmation_hash),
            )
            .await?;
        let deleted = self
            .db
            .delete_instance_oci_route(&input.stable_id, input.expected_resource_version)
            .await
            .map_err(RpcError::internal)?;
        if !deleted {
            return Err(RpcError::FailedPrecondition(
                "instance OCI route changed or was enabled after planning".to_string(),
            ));
        }
        self.record_instance_route_audit(
            &claims,
            "instance.oci_route.deleted",
            &plan.plan_id,
            &input.stable_id,
        )
        .await;
        let response = pb::DeleteTopologyResourceResponse { deleted: true };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// Plans the in-place conversion of a registry-bound OCI route.
    ///
    /// The route must be a hub-proxy route at a host root that serves only OCI
    /// with a public or hub-auth policy. Its rendered URL and reservation are
    /// kept; its registry's namespace is enabled and becomes the new route's
    /// default so unnamespaced references keep resolving.
    ///
    /// # Errors
    ///
    /// Returns authentication, authorization, validation, not-found, stale
    /// version, precondition, or database errors.
    pub async fn plan_convert_route_to_instance_oci_route(
        &self,
        auth: Option<&str>,
        req: pb::PlanConvertRouteToInstanceOciRouteRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_instance_admin(auth).await?;
        let route = self
            .db
            .route(&req.route_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("route"))?;
        let expected = parse_resource_version(&req.expected_resource_version, 0)?;
        if expected <= 0 || expected != route.resource_version {
            return Err(RpcError::FailedPrecondition(
                "route resource version is required and must be current".to_string(),
            ));
        }
        let SurfaceTarget::Registry(registry_id) = route.surface else {
            return Err(RpcError::FailedPrecondition(
                "only a registry route can become an instance OCI route".to_string(),
            ));
        };
        let snapshot = self
            .db
            .route_snapshot(&req.route_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("route configuration"))?;
        if route.mode != "hub_proxy" || !route.base_path.is_empty() || !snapshot.spec.serves_oci {
            return Err(RpcError::FailedPrecondition(
                "only a hub-proxy OCI route at the host root can become an instance OCI route"
                    .to_string(),
            ));
        }
        if snapshot.spec.serves_git || snapshot.spec.serves_cache || snapshot.spec.serves_web {
            return Err(RpcError::FailedPrecondition(
                "the route also serves git, cache, or web; create an instance OCI route that \
                 binds the existing reservation, then update this route to drop oci"
                    .to_string(),
            ));
        }
        if !matches!(
            snapshot.spec.access_policy_kind.as_str(),
            "public" | "hub_auth"
        ) {
            return Err(RpcError::FailedPrecondition(
                "an instance OCI route access policy must be public or hub-auth".to_string(),
            ));
        }
        let registry = self
            .db
            .registry_by_id(registry_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("registry"))?;
        require_namespace_slug(&registry)?;
        let instance_route_id = if req.stable_id.is_empty() {
            format!("instance-oci-route:{}", uuid::Uuid::new_v4().simple())
        } else {
            req.stable_id.clone()
        };
        if self
            .db
            .instance_oci_route(&instance_route_id)
            .await
            .map_err(RpcError::internal)?
            .is_some()
        {
            return Err(RpcError::AlreadyExists(
                "instance OCI route already exists".to_string(),
            ));
        }
        let input = ConvertRoutePlanInput {
            route_id: req.route_id.clone(),
            expected_route_version: expected,
            instance_route_id: instance_route_id.clone(),
            registry_id,
            canonical_url: snapshot.canonical_url.clone(),
        };
        let confirmation = confirmation_hash(&input)?;
        self.create_control_plan(
            &claims,
            CONVERT_PLAN,
            "instance",
            &input,
            &req.idempotency_key,
            vec![
                format!(
                    "convert route '{}' into instance OCI route '{instance_route_id}' at {}",
                    req.route_id, snapshot.canonical_url
                ),
                "keep the existing URL reservation".to_string(),
                format!("enable the OCI namespace of registry '{}'", registry.slug),
                format!(
                    "serve registry '{}' for repository names without a namespace prefix",
                    registry.slug
                ),
                format!("retire route '{}'", req.route_id),
            ],
            vec![format!(
                "references of the form <host>/<repository> keep resolving to registry '{}' \
                 until the default registry is cleared",
                registry.slug
            )],
            Some(confirmation),
        )
        .await
    }

    /// Applies a route conversion plan exactly once.
    ///
    /// # Errors
    ///
    /// Returns authentication, authorization, plan, precondition, or database
    /// errors.
    pub async fn convert_route_to_instance_oci_route(
        &self,
        auth: Option<&str>,
        req: pb::ApplyTopologyPlanRequest,
    ) -> Result<pb::InstanceOciRouteResponse, RpcError> {
        let claims = self
            .require_control_plan_permission(auth, &req.plan_id, Permission::IamAdmin)
            .await?;
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                CONVERT_PLAN,
                Some(&req.confirmation_hash),
                &req.idempotency_key,
            )
            .await?
        {
            return Ok(response);
        }
        self.begin_control_plan_apply(
            auth,
            &req.plan_id,
            CONVERT_PLAN,
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, ConvertRoutePlanInput) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                CONVERT_PLAN,
                Some(&req.confirmation_hash),
            )
            .await?;
        let actor_id = claims_principal(&claims).map(|principal| principal.id);
        let record = self
            .db
            .convert_route_to_instance_oci_route(
                &input.route_id,
                input.expected_route_version,
                &input.instance_route_id,
                &claims.owner_kind,
                actor_id,
                &claims.sub,
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        if record.canonical_url != input.canonical_url
            || record.default_registry_id != Some(input.registry_id)
        {
            return Err(RpcError::internal(anyhow::anyhow!(
                "converted instance OCI route does not match its plan"
            )));
        }
        self.record_instance_route_audit(
            &claims,
            "instance.oci_route.converted",
            &plan.plan_id,
            &record.id,
        )
        .await;
        let response = pb::InstanceOciRouteResponse {
            route: Some(Self::instance_oci_route_message(record)?),
        };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// Returns one registry's reviewed OCI namespace state.
    ///
    /// # Errors
    ///
    /// Returns authentication, authorization, not-found, or database errors.
    pub async fn get_container_namespace(
        &self,
        auth: Option<&str>,
        req: pb::GetContainerNamespaceRequest,
    ) -> Result<pb::ContainerNamespaceResponse, RpcError> {
        let registry = self.registry_or_not_found(&req.registry).await?;
        self.require_read(auth, &registry).await?;
        let namespace = self
            .db
            .registry_oci_namespace(registry.id)
            .await
            .map_err(RpcError::internal)?;
        Ok(pb::ContainerNamespaceResponse {
            namespace: Some(pb::ContainerNamespace {
                registry: registry.slug,
                enabled: namespace.enabled,
                resource_version: resource_version_string(namespace.resource_version),
                updated_at: namespace.updated_at,
            }),
        })
    }

    /// Plans enabling or disabling one registry's OCI namespace.
    ///
    /// # Errors
    ///
    /// Returns authentication, authorization, validation, not-found, stale
    /// version, or database errors.
    pub async fn plan_set_container_namespace(
        &self,
        auth: Option<&str>,
        req: pb::PlanSetContainerNamespaceRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let registry = self.registry_or_not_found(&req.registry).await?;
        self.require_permission(
            &claims,
            Permission::RegistryConfigure,
            &self.registry_scope(&registry).await?,
        )
        .await?;
        let expected = parse_resource_version(&req.expected_resource_version, 0)?;
        let current = self
            .db
            .registry_oci_namespace(registry.id)
            .await
            .map_err(RpcError::internal)?;
        if expected != current.resource_version {
            return Err(RpcError::FailedPrecondition(
                "container namespace resource version is stale".to_string(),
            ));
        }
        if req.enabled {
            require_namespace_slug(&registry)?;
        }
        let (effects, warnings) = if req.enabled {
            (
                vec![format!(
                    "enable the OCI namespace '{}' on every enabled instance OCI route",
                    registry.slug
                )],
                vec![format!(
                    "repositories become reachable as <host>/{}/<repository>",
                    registry.slug
                )],
            )
        } else {
            (
                vec![format!("disable the OCI namespace '{}'", registry.slug)],
                vec![format!(
                    "references <host>/{}/<repository> stop resolving on instance OCI routes",
                    registry.slug
                )],
            )
        };
        let input = ContainerNamespacePlanInput {
            registry_id: registry.id,
            registry_stable_id: registry.stable_id.clone(),
            enabled: req.enabled,
            expected_resource_version: expected,
        };
        let confirmation = confirmation_hash(&input)?;
        self.create_control_plan(
            &claims,
            NAMESPACE_PLAN,
            &registry.scope_key,
            &input,
            &req.idempotency_key,
            effects,
            warnings,
            Some(confirmation),
        )
        .await
    }

    /// Applies a registry OCI namespace plan exactly once.
    ///
    /// # Errors
    ///
    /// Returns authentication, authorization, plan, precondition, or database
    /// errors.
    pub async fn set_container_namespace(
        &self,
        auth: Option<&str>,
        req: pb::ApplyTopologyPlanRequest,
    ) -> Result<pb::ContainerNamespaceResponse, RpcError> {
        let claims = self
            .require_control_plan_permission(auth, &req.plan_id, Permission::RegistryConfigure)
            .await?;
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                NAMESPACE_PLAN,
                Some(&req.confirmation_hash),
                &req.idempotency_key,
            )
            .await?
        {
            return Ok(response);
        }
        self.begin_control_plan_apply(
            auth,
            &req.plan_id,
            NAMESPACE_PLAN,
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, ContainerNamespacePlanInput) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                NAMESPACE_PLAN,
                Some(&req.confirmation_hash),
            )
            .await?;
        let registry = self
            .db
            .registry_by_id(input.registry_id)
            .await
            .map_err(RpcError::internal)?
            .filter(|registry| registry.stable_id == input.registry_stable_id)
            .ok_or_else(|| {
                RpcError::FailedPrecondition("registry identity changed after planning".to_string())
            })?;
        let applied = self
            .db
            .set_registry_oci_namespace(registry.id, input.enabled, input.expected_resource_version)
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        if !applied {
            return Err(RpcError::FailedPrecondition(
                "container namespace changed after planning".to_string(),
            ));
        }
        let actor_id = claims_principal(&claims).map(|principal| principal.id);
        if let Err(error) = self
            .db
            .record_audit(
                &claims.owner_kind,
                actor_id,
                &claims.sub,
                "container.namespace",
                &registry.scope_key,
                Some(&plan.plan_id),
                None,
                None,
                Some(if input.enabled { "enabled" } else { "disabled" }),
            )
            .await
        {
            tracing::warn!(error = %format!("{error:#}"), "recording container.namespace audit");
        }
        let namespace = self
            .db
            .registry_oci_namespace(registry.id)
            .await
            .map_err(RpcError::internal)?;
        let response = pb::ContainerNamespaceResponse {
            namespace: Some(pb::ContainerNamespace {
                registry: registry.slug,
                enabled: namespace.enabled,
                resource_version: resource_version_string(namespace.resource_version),
                updated_at: namespace.updated_at,
            }),
        };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// Finds the enabled, ready instance OCI route that exposes one registry.
    ///
    /// A namespace exposure is preferred over a default-registry exposure
    /// because its references are stable across registries.
    pub(crate) async fn instance_oci_route_exposure(
        &self,
        registry: &RegistryRecord,
    ) -> Result<Option<ContainerDistributionExposure>, RpcError> {
        let routes = self
            .db
            .list_instance_oci_routes()
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .filter(|route| route.enabled && route.ready)
            .collect::<Vec<_>>();
        if routes.is_empty() {
            return Ok(None);
        }
        let namespace = self
            .db
            .registry_oci_namespace(registry.id)
            .await
            .map_err(RpcError::internal)?;
        if namespace.enabled {
            if let Some(route) = routes.first() {
                return Ok(Some(ContainerDistributionExposure {
                    origin: route.canonical_url.clone(),
                    namespace: Some(registry.slug.clone()),
                }));
            }
        }
        Ok(routes
            .iter()
            .find(|route| route.default_registry_id == Some(registry.id))
            .map(|route| ContainerDistributionExposure {
                origin: route.canonical_url.clone(),
                namespace: None,
            }))
    }

    async fn record_instance_route_audit(
        &self,
        claims: &Claims,
        action: &str,
        plan_id: &str,
        route_id: &str,
    ) {
        let actor_id = claims_principal(claims).map(|principal| principal.id);
        if let Err(error) = self
            .db
            .record_audit(
                &claims.owner_kind,
                actor_id,
                &claims.sub,
                action,
                "",
                Some(plan_id),
                None,
                None,
                Some(route_id),
            )
            .await
        {
            tracing::warn!(error = %format!("{error:#}"), action, "recording instance OCI route audit");
        }
    }
}

/// Decodes the sealed reservation candidates into `(version, digest)` pairs.
fn reservation_candidates(
    seal: &RouteReservationPlanSeal,
) -> Result<Vec<(i64, Vec<u8>)>, RpcError> {
    seal.candidates
        .iter()
        .map(|candidate| {
            hex::decode(&candidate.digest)
                .map(|digest| (candidate.key_version, digest))
                .map_err(RpcError::internal)
        })
        .collect()
}

/// Requires a registry slug that is also a valid repository-name prefix.
fn require_namespace_slug(registry: &RegistryRecord) -> Result<(), RpcError> {
    RepositoryName::parse(&registry.slug)
        .map(|_| ())
        .map_err(|_| {
            RpcError::FailedPrecondition(format!(
                "registry slug '{}' is not a valid OCI repository namespace",
                registry.slug
            ))
        })
}
