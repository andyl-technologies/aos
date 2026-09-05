//! Complete surface topology projection using scoped, joined database reads.
//!
//! Authorization is unchanged. Each response resolves its surface once and
//! reuses its placement names; route snapshots join the exact current head.
//! Canonical endpoint expansion is bounded by the three supported audiences.

use super::*;

impl RpcService {
    /// Returns the complete current topology projection for one surface.
    ///
    /// # Errors
    /// Returns an error when surface authorization fails, a database read fails,
    /// or persisted topology references cannot be projected.
    pub async fn get_surface_topology(
        &self,
        auth: Option<&str>,
        req: pb::GetSurfaceTopologyRequest,
    ) -> Result<pb::GetSurfaceTopologyResponse, RpcError> {
        let surface = self.readable_topology_surface(auth, req.surface).await?;
        let owner_scope_key = self.route_surface_owner_scope(surface).await?;
        self.require_delivery_scope(auth, &owner_scope_key, Permission::RouteRead)
            .await?;
        let surface_message = self.route_surface_message(surface).await?;

        let placement_records = self
            .db
            .surface_topology_placements(surface)
            .await
            .map_err(RpcError::internal)?;
        let placement_names = placement_records
            .iter()
            .map(|(placement, _)| (placement.id, placement.name.clone()))
            .collect::<BTreeMap<_, _>>();
        let placements = placement_records
            .into_iter()
            .map(|(placement, binding)| Self::placement_message_with_binding(placement, binding))
            .collect::<Result<_, _>>()?;
        let route_records = self
            .db
            .surface_topology_routes(surface)
            .await
            .map_err(RpcError::internal)?;
        let route_endpoints = route_records
            .iter()
            .map(|record| (record.route.id.clone(), record.route.endpoint_id.clone()))
            .collect::<BTreeMap<_, _>>();
        let routes = route_records
            .into_iter()
            .map(|record| {
                let target = Self::surface_route_target(&record)?;
                Self::route_message_from_parts(
                    record.route,
                    record.snapshot,
                    target,
                    surface_message.clone(),
                )
            })
            .collect::<Result<_, _>>()?;

        let advertisements = self
            .db
            .surface_topology_advertisements(surface)
            .await
            .map_err(RpcError::internal)?;
        let mut canonical_endpoint_ids = BTreeSet::new();
        let route_advertisements = advertisements
            .into_iter()
            .map(|record| {
                if let Some(endpoint) = route_endpoints.get(&record.route_id) {
                    canonical_endpoint_ids.insert(endpoint.clone());
                }
                pb::RouteAdvertisement {
                    surface: Some(surface_message.clone()),
                    audience: record.audience,
                    route_id: record.route_id,
                    resource_version: record.resource_version.to_string(),
                }
            })
            .collect();
        let write_authority = self
            .db
            .surface_write_authority(surface)
            .await
            .map_err(RpcError::internal)?
            .map(|authority| {
                let desired = placement_names
                    .get(&authority.desired_placement_id)
                    .cloned()
                    .ok_or_else(|| {
                        RpcError::internal(anyhow::anyhow!("desired writer is missing"))
                    })?;
                let observed = authority
                    .observed_placement_id
                    .map(|id| {
                        placement_names.get(&id).cloned().ok_or_else(|| {
                            RpcError::internal(anyhow::anyhow!("observed writer is missing"))
                        })
                    })
                    .transpose()?
                    .unwrap_or_default();
                Ok::<_, RpcError>(Self::write_authority_message_with_names(
                    authority, desired, observed,
                ))
            })
            .transpose()?;

        let placement_policies = self
            .db
            .surface_topology_policies(surface)
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .map(|record| pb::PlacementPolicy {
                stable_id: record.identity.id,
                surface: Some(surface_message.clone()),
                name: record.identity.name,
                kind: record.kind,
                current_revision: record.revision,
                current_content_digest: record.content_digest,
                resource_version: record.identity.resource_version.to_string(),
                created_at: record.identity.created_at,
                updated_at: record.identity.updated_at,
            })
            .collect();
        let placement_equivalences = self
            .db
            .list_placement_equivalences(surface)
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .map(|record| pb::PlacementEquivalence {
                stable_id: record.id,
                surface: Some(surface_message.clone()),
                placement_a: record.placement_a,
                placement_b: record.placement_b,
                evidence_digest: record.evidence_digest,
                state: record.state,
                resource_version: record.resource_version.to_string(),
                confirmed_at: record.confirmed_at,
            })
            .collect();
        let mut canonical_endpoints = Vec::with_capacity(canonical_endpoint_ids.len());
        for endpoint_id in canonical_endpoint_ids {
            let endpoint = self
                .db
                .endpoint(&endpoint_id)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| {
                    RpcError::internal(anyhow::anyhow!("route advertisement endpoint is missing"))
                })?;
            canonical_endpoints.push(self.endpoint_message(endpoint).await?);
        }
        let active_operations = self
            .db
            .list_active_surface_operations(surface)
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .map(|operation| pb::OperationRef {
                operation_id: operation.operation_id,
                kind: operation.operation_kind,
                state: operation.state,
                created_at: operation.created_at,
            })
            .collect();
        Ok(pb::GetSurfaceTopologyResponse {
            surface: Some(surface_message),
            placements,
            routes,
            route_advertisements,
            write_authority,
            placement_policies,
            placement_equivalences,
            canonical_endpoints,
            active_operations,
        })
    }

    fn surface_route_target(
        record: &crate::db::SurfaceRouteProjection,
    ) -> Result<pb::route_target::Target, RpcError> {
        let spec = &record.snapshot.spec;
        let delivery_kind = if spec.mode == "hub_redirect" {
            pb::HubDeliveryKind::Redirect
        } else {
            pb::HubDeliveryKind::Proxy
        } as i32;
        if spec.placement_id.is_some() {
            let placement_name = record
                .placement_name
                .clone()
                .ok_or_else(|| RpcError::internal(anyhow::anyhow!("route placement is missing")))?;
            if spec.mode == "direct" {
                Ok(pb::route_target::Target::DirectGatewayPlacement(
                    pb::DirectGatewayPlacementTarget {
                        placement_name,
                        gateway_id: spec.gateway_id.clone().unwrap_or_default(),
                        gateway_generation: spec.gateway_generation.unwrap_or_default(),
                    },
                ))
            } else {
                Ok(pb::route_target::Target::HubPlacement(
                    pb::HubPlacementTarget {
                        placement_name,
                        delivery_kind,
                    },
                ))
            }
        } else {
            let policy_name = record
                .policy_name
                .clone()
                .ok_or_else(|| RpcError::internal(anyhow::anyhow!("route policy is missing")))?;
            let revision = record.policy_revision.ok_or_else(|| {
                RpcError::internal(anyhow::anyhow!("route policy revision is missing"))
            })?;
            Ok(pb::route_target::Target::HubPolicyRevision(
                pb::HubPolicyRevisionTarget {
                    policy_name,
                    revision,
                    delivery_kind,
                },
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::surface_topology::tests::{count_queries, topology_fixture};
    use crate::db::TokenAuth;
    use std::sync::atomic::Ordering;

    impl RpcService {
        /// Returns the complete current topology projection for one surface.
        async fn legacy_surface_topology(
            &self,
            auth: Option<&str>,
            req: pb::GetSurfaceTopologyRequest,
        ) -> Result<pb::GetSurfaceTopologyResponse, RpcError> {
            let surface = self
                .readable_topology_surface(auth, req.surface.clone())
                .await?;
            let owner_scope_key = self.route_surface_owner_scope(surface).await?;
            self.require_delivery_scope(auth, &owner_scope_key, Permission::RouteRead)
                .await?;
            let placement_records = self
                .db
                .list_surface_placements(surface)
                .await
                .map_err(RpcError::internal)?;
            let mut placements = Vec::with_capacity(placement_records.len());
            for record in placement_records {
                placements.push(self.placement_message(record).await?);
            }
            let route_records = self
                .db
                .list_routes(surface)
                .await
                .map_err(RpcError::internal)?;
            let mut routes = Vec::with_capacity(route_records.len());
            for record in &route_records {
                routes.push(self.route_message(record.clone()).await?);
            }
            let mut route_advertisements = Vec::new();
            let mut canonical_endpoint_ids = BTreeSet::new();
            for audience in ["git", "nix_cache", "web"] {
                if let Some(record) = self
                    .db
                    .route_advertisement(surface, audience)
                    .await
                    .map_err(RpcError::internal)?
                {
                    route_advertisements.push(pb::RouteAdvertisement {
                        surface: Some(self.route_surface_message(surface).await?),
                        audience: record.audience,
                        route_id: record.route_id.clone(),
                        resource_version: record.resource_version.to_string(),
                    });
                    if let Some(route) = route_records
                        .iter()
                        .find(|route| route.id == record.route_id)
                    {
                        canonical_endpoint_ids.insert(route.endpoint_id.clone());
                    }
                }
            }
            let write_authority = self
                .db
                .surface_write_authority(surface)
                .await
                .map_err(RpcError::internal)?;
            let policy_records = self
                .db
                .list_placement_policy_identities(surface)
                .await
                .map_err(RpcError::internal)?;
            let mut placement_policies = Vec::with_capacity(policy_records.len());
            for record in policy_records {
                placement_policies.push(self.placement_policy_message(record).await?);
            }
            let equivalence_records = self
                .db
                .list_placement_equivalences(surface)
                .await
                .map_err(RpcError::internal)?;
            let mut placement_equivalences = Vec::with_capacity(equivalence_records.len());
            for record in equivalence_records {
                placement_equivalences.push(self.placement_equivalence_message(record).await?);
            }
            let mut canonical_endpoints = Vec::with_capacity(canonical_endpoint_ids.len());
            for endpoint_id in canonical_endpoint_ids {
                let endpoint = self
                    .db
                    .endpoint(&endpoint_id)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| {
                        RpcError::internal(anyhow::anyhow!(
                            "route advertisement endpoint is missing"
                        ))
                    })?;
                canonical_endpoints.push(self.endpoint_message(endpoint).await?);
            }
            let active_operations = self
                .db
                .list_active_surface_operations(surface)
                .await
                .map_err(RpcError::internal)?
                .into_iter()
                .map(|operation| pb::OperationRef {
                    operation_id: operation.operation_id,
                    kind: operation.operation_kind,
                    state: operation.state,
                    created_at: operation.created_at,
                })
                .collect();
            Ok(pb::GetSurfaceTopologyResponse {
                surface: Some(self.route_surface_message(surface).await?),
                placements,
                routes,
                route_advertisements,
                write_authority: match write_authority {
                    Some(authority) => Some(self.write_authority_message(authority).await?),
                    None => None,
                },
                placement_policies,
                placement_equivalences,
                canonical_endpoints,
                active_operations,
            })
        }
    }

    #[tokio::test]
    async fn surface_topology_matches_legacy_wire_with_fewer_queries() {
        let (db, _) = topology_fixture().await;
        let (db, queries) = count_queries(db);
        let (mut service, _) = super::super::cache_upload_tests::delivery_test_service().await;
        service.db = Arc::new(db);
        let org = service
            .db
            .org_by_slug("route-probes")
            .await
            .unwrap()
            .unwrap();
        let user = service
            .db
            .create_user("projection@example.test", None)
            .await
            .unwrap();
        service
            .db
            .grant_membership("user", user, &org.stable_id, Role::Owner.as_str())
            .await
            .unwrap();
        let token = service
            .jwt_keys
            .mint(
                &TokenAuth {
                    token_id: "projection-test".into(),
                    owner: Principal::user(user),
                    scope: Scope::try_parse(&org.stable_id).unwrap(),
                    permissions: vec![Permission::Read, Permission::RouteRead],
                },
                3600,
            )
            .unwrap();
        let auth = format!("Bearer {token}");
        let request = pb::GetSurfaceTopologyRequest {
            surface: Some(pb::SurfaceRef {
                target: Some(pb::surface_ref::Target::RegistrySlug(
                    "route-probes/route-probes".into(),
                )),
            }),
        };
        queries.store(0, Ordering::Relaxed);
        let expected = service
            .legacy_surface_topology(Some(&auth), request.clone())
            .await
            .unwrap();
        let old_count = queries.load(Ordering::Relaxed);
        queries.store(0, Ordering::Relaxed);
        let actual = service
            .get_surface_topology(Some(&auth), request)
            .await
            .unwrap();
        let new_count = queries.load(Ordering::Relaxed);
        assert_eq!(actual, expected);
        assert!(
            old_count >= new_count + 20,
            "expected bounded expansion: {old_count} -> {new_count}"
        );
        eprintln!("surface topology SQL calls: {old_count} -> {new_count}");
        let denied = service
            .get_surface_topology(
                Some(&auth),
                pb::GetSurfaceTopologyRequest {
                    surface: Some(pb::SurfaceRef {
                        target: Some(pb::surface_ref::Target::RegistrySlug(
                            "unrelated-topology/main".into(),
                        )),
                    }),
                },
            )
            .await;
        assert!(
            denied.is_err(),
            "joining projections must not bypass surface authorization"
        );
    }
}
