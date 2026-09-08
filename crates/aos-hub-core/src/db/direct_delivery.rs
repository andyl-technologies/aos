//! Verified public object destinations selected by current delivery advertisements.

use anyhow::Result;

use super::{Database, DeliveryActivationRoute, PlacementReadRequirement, SurfaceTarget};

impl Database {
    /// Resolves a public CDN object only while routing and publication evidence agree.
    pub(crate) async fn public_object_delivery_url(
        &self,
        registry_id: i64,
        object_key: &str,
        sha256: &str,
        byte_size: u64,
    ) -> Result<Option<String>> {
        let surface = SurfaceTarget::Registry(registry_id);
        let Some(advertisement) = self.route_advertisement(surface, "nix_cache").await? else {
            return Ok(None);
        };
        let Some(route) = self.route(&advertisement.route_id).await? else {
            return Ok(None);
        };
        let (Some(generation), Some(digest)) =
            (route.configuration_generation, route.configuration_digest)
        else {
            return Ok(None);
        };
        let target = DeliveryActivationRoute {
            route_id: route.id.clone(),
            generation,
            digest,
            resource_version: route.resource_version,
        };
        if route.surface != surface || !self.delivery_workflow_route_ready(&target).await? {
            return Ok(None);
        }

        let Some(snapshot) = self.route_snapshot(&route.id).await? else {
            return Ok(None);
        };
        let Some(placement_id) = snapshot.spec.placement_id else {
            return Ok(None);
        };
        if snapshot.spec.access_policy_kind != "public" {
            return Ok(None);
        }
        let placements = self
            .readable_surface_placements(
                surface,
                PlacementReadRequirement::ImmutableObject(object_key),
            )
            .await?;
        if !placements
            .candidates
            .iter()
            .any(|placement| placement.id == placement_id)
        {
            return Ok(None);
        }

        let Some(row) = self
            .backend
            .query_opt(
                "SELECT m.registry_publication_id FROM placement_delivery_manifest_heads h
             JOIN placement_delivery_manifests m ON m.manifest_id = h.manifest_id
             WHERE h.placement_id = ?1 AND m.registry_id = ?2
               AND m.kind = 'registry_publication'",
                &vals![placement_id, registry_id],
            )
            .await?
        else {
            return Ok(None);
        };
        let publication_id: String = row.get(0)?;
        let Some(object) = self
            .registry_publication_verified_object_at_placement(
                &publication_id,
                placement_id,
                object_key,
            )
            .await?
        else {
            return Ok(None);
        };
        if object.sha256 != sha256 || u64::try_from(object.byte_size).ok() != Some(byte_size) {
            return Ok(None);
        }

        // Append segments rather than resolving a relative URL: object names must
        // never replace the verified destination's authority or placement prefix.
        let Ok(mut url) = url::Url::parse(&snapshot.canonical_url) else {
            return Ok(None);
        };
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Ok(None);
        }
        let Ok(mut path) = url.path_segments_mut() else {
            return Ok(None);
        };
        path.pop_if_empty();
        for segment in object_key.split('/') {
            if segment.is_empty() || matches!(segment, "." | "..") {
                return Ok(None);
            }
            path.push(segment);
        }
        drop(path);
        Ok(Some(url.into()))
    }
}
