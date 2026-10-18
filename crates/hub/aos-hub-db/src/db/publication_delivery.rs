//! Publication identities used by direct delivery routes.
//!
//! A delivery manifest records the exact ready publication physically present
//! at a complete placement. Route probes still independently verify delivery;
//! recording a publication never makes a route healthy or canonical.

use anyhow::Result;

use crate::backend::Statement;

use super::Database;

impl Database {
    /// Records delivery manifests for the current ready registry publication.
    ///
    /// Retries repair publications created before delivery manifests were
    /// recorded. Both writes remain fenced by the current publication and the
    /// placement's published watermark, so an older retry cannot rewind a head.
    ///
    /// # Errors
    /// Returns an error if publication identities or placement evidence cannot
    /// be persisted.
    pub async fn refresh_registry_publication_delivery_manifests(
        &self,
        publication_id: &str,
    ) -> Result<()> {
        self.backend
            .batch(&[
                Statement::new(
                    "INSERT INTO placement_delivery_manifests
                     (manifest_id, placement_id, registry_id, kind,
                      registry_publication_id, content_digest, published_at)
                     SELECT 'registry:' || pub.publication_id || ':' || p.id,
                       p.id, pub.registry_id, 'registry_publication',
                       pub.publication_id, pub.manifest_digest, pub.completed_at
                     FROM registry_publications pub
                     JOIN registry_publication_state current
                       ON current.registry_id = pub.registry_id
                      AND current.current_publication_id = pub.publication_id
                     JOIN registry_publication_placements pp
                       ON pp.publication_id = pub.publication_id AND pp.state = 'ready'
                     JOIN surface_placements p
                       ON p.id = pp.placement_id AND p.registry_id = pub.registry_id
                      AND p.kind = 'complete'
                     JOIN registry_placement_publication_watermarks watermark
                       ON watermark.placement_id = p.id
                      AND watermark.mutable_publication_id = pub.publication_id
                     WHERE pub.publication_id = ?1 AND pub.state = 'ready'
                     ON CONFLICT(manifest_id) DO NOTHING",
                    vals![publication_id].to_vec(),
                ),
                Statement::new(
                    "INSERT INTO placement_delivery_manifest_heads
                     (placement_id, registry_id, manifest_id, updated_at)
                     SELECT manifest.placement_id, manifest.registry_id,
                       manifest.manifest_id, manifest.published_at
                     FROM placement_delivery_manifests manifest
                     JOIN registry_publication_state current
                       ON current.registry_id = manifest.registry_id
                      AND current.current_publication_id = manifest.registry_publication_id
                     JOIN registry_placement_publication_watermarks watermark
                       ON watermark.placement_id = manifest.placement_id
                      AND watermark.mutable_publication_id = manifest.registry_publication_id
                     WHERE manifest.registry_publication_id = ?1
                     ON CONFLICT(placement_id) DO UPDATE SET
                       registry_id = excluded.registry_id,
                       manifest_id = excluded.manifest_id,
                       resource_version = placement_delivery_manifest_heads.resource_version + 1,
                       updated_at = excluded.updated_at
                     WHERE placement_delivery_manifest_heads.manifest_id <> excluded.manifest_id",
                    vals![publication_id].to_vec(),
                ),
            ])
            .await?;

        Ok(())
    }
}
