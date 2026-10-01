"""Compare authoritative registry indexes from the same signed source bytes.

The fleet driver supplies real Native SQLite, Worker HubDb, and hybrid
PostgreSQL readers. Queries replace relational foreign keys with source names
and exclude execution leases, local row IDs, and wall-clock observation times.
Signed source timestamps, object identities, and complete artifact metadata
remain part of the comparison.
"""

import hashlib
import json


def registry_index_observations(query, slug):
    """Read published index data without mixing in discarded build attempts."""
    registry = "(SELECT id FROM registries WHERE slug = " + sql_literal(slug) + ")"
    by_registry = " WHERE registry_id = " + registry
    observations = {}

    # The retention digest binds local placement IDs, observation times and
    # incremental publication history. Validate each local identity separately;
    # compare the signed contents below across deployments.
    identities = query(
        "SELECT generation, content_digest FROM registry_index" + by_registry
    )
    assert len(identities) == 1, identities
    generation, digest = identities[0]
    assert generation > 0 and isinstance(digest, str), identities
    assert (
        len(digest) == 64
        and all(character in "0123456789abcdef" for character in digest)
    ), identities

    def observe(name, fields, table, predicate=by_registry):
        observations[name] = query("SELECT " + fields + " FROM " + table + predicate)

    observe(
        "index",
        "state, error, last_indexed_commit, name, description, refs_digest, "
        "cache_stack, readme, support_json",
        "registry_index",
    )
    observe("packages", "name, description, homepage, license, maintainer, sysroot", "packages")
    observe("releases", "semver, tag_oid, commit_oid, signer, tagged_at, pack_present", "releases")
    observe("channels", "name, frontier, active", "channels")
    observe("channel_floors", "channel, floor", "channel_floors")
    observe("keys", "key_id, public_key, status", "key_rosters")
    observe("release_records", "tag_oid, record_json", "release_records")
    observe("release_notes", "tag_oid, body", "release_browse_notes")

    container_repository = " JOIN oci_repositories repository ON repository.id = projection.repository_id"
    container_predicate = " WHERE projection.registry_id = " + registry
    observe(
        "container_roots",
        "projection.release_tag, repository.name, projection.container_name, "
        "projection.index_digest, projection.source_commit, projection.verified_tag_oid, projection.catalog_digest",
        "oci_release_roots projection" + container_repository,
        container_predicate,
    )
    observe(
        "container_closure_members",
        "projection.release_tag, repository.name, projection.root_digest, projection.store_path, "
        "projection.nar_hash, projection.nar_size, projection.layer_digest, projection.is_direct",
        "oci_release_closure_members projection" + container_repository,
        container_predicate,
    )
    observe(
        "container_evidence",
        "projection.release_tag, repository.name, projection.root_digest, projection.evidence_kind, "
        "projection.digest, projection.media_type, projection.verification, projection.referrer_digest",
        "oci_release_evidence projection" + container_repository,
        container_predicate,
    )
    observe(
        "container_provenance",
        "projection.release_tag, repository.name, projection.root_digest, projection.package_name, "
        "projection.channel_name, projection.signed_release_root, projection.catalog_digest, projection.verification",
        "oci_release_provenance projection" + container_repository,
        container_predicate,
    )
    observe(
        "container_layers",
        "repository.name, projection.root_digest, projection.manifest_digest, projection.ordinal, "
        "projection.digest, projection.media_type, projection.compressed_byte_size, "
        "projection.unpacked_byte_size, projection.diff_id, projection.closure_group",
        "oci_release_layers projection" + container_repository,
        container_predicate,
    )
    observe(
        "versions",
        "package.name, version.version, version.previous",
        "package_versions version JOIN packages package ON package.id = version.package_id",
        " WHERE package.registry_id = " + registry,
    )
    observe(
        "platforms",
        "package.name, version.version, platform.platform, platform.store_path, "
        "platform.nar_hash, platform.nar_size, platform.closure_size, platform.refs, "
        "platform.images, platform.source_drv",
        "version_platforms platform JOIN package_versions version ON version.id = platform.version_id "
        "JOIN packages package ON package.id = version.package_id",
        " WHERE package.registry_id = " + registry,
    )
    observe(
        "channel_partitions",
        "channel.name, partition.bucket, partition.release",
        "channel_partitions partition JOIN channels channel ON channel.id = partition.channel_id",
        " WHERE channel.registry_id = " + registry,
    )
    observe(
        "catalog_artifacts",
        "source_revision, package_name, package_version, platform, artifact_kind, "
        "store_path, store_hash, metadata_digest",
        "registry_catalog_artifacts",
    )
    observe(
        "documentation",
        "indexed_commit, package_name, package_version, platform, format, store_path, "
        "nar_hash, nar_size, document_sha256, document_size, semantic_schema_sha256, "
        "system_module_nar_hash",
        "package_documentation",
    )
    observe(
        "browse_catalogs",
        "source_commit, packages_json, content_digest, package_count, documentation_count, default_release",
        "release_browse_catalogs",
    )
    observe(
        "browse_nodes",
        "source_commit, node_key, parent_key, path_json, label, sort_key, child_count, entry_count",
        "release_browse_tree_nodes",
    )
    observe("browse_ancestors", "source_commit, ancestor_key, node_key", "release_browse_tree_ancestors")
    observe(
        "browse_entries",
        "source_commit, entry_key, node_key, document_sha256, package_name, package_version, "
        "platform, kind, document_key, title, summary, type_signature",
        "release_browse_tree_entries",
    )

    published_snapshots = (
        "release_artifact_snapshot_heads head "
        "JOIN release_artifact_snapshots snapshot "
        "ON snapshot.snapshot_id = head.complete_artifact_snapshot_id "
        "JOIN releases release ON release.id = head.release_id"
    )
    snapshot_predicate = " WHERE head.registry_id = " + registry
    observe(
        "artifact_snapshots",
        "release.semver, snapshot.source_commit, snapshot.verified_tag_oid, "
        "snapshot.manifest_digest, snapshot.state, snapshot.expected_artifact_count, "
        "snapshot.actual_artifact_count, snapshot.error",
        published_snapshots,
        snapshot_predicate,
    )
    observe(
        "release_artifacts",
        "release.semver, artifact.package_name, artifact.package_version, artifact.platform, "
        "artifact.artifact_kind, artifact.store_path, artifact.store_hash, artifact.metadata_digest",
        published_snapshots + " JOIN release_artifacts artifact ON artifact.snapshot_id = snapshot.snapshot_id",
        snapshot_predicate,
    )
    observe(
        "release_documentation",
        "release.semver, document.package_name, document.package_version, document.platform, "
        "document.artifact_kind, document.store_path, document.store_hash, document.format, "
        "document.nar_hash, document.nar_size, document.document_sha256, document.document_size, "
        "document.semantic_schema_sha256, document.system_module_nar_hash, document.metadata_digest",
        published_snapshots + " JOIN release_package_documentation document "
        "ON document.snapshot_id = snapshot.snapshot_id",
        snapshot_predicate,
    )

    # Providers can enumerate equal rows in different orders. Canonicalize only
    # ordering: source values, including serialized metadata, stay byte exact.
    return {
        name: sorted(rows, key=lambda row: json.dumps(row, sort_keys=True, separators=(",", ":")))
        for name, rows in observations.items()
    }


def assert_registry_index_parity(readers, slug, *, container_index_digest):
    """Require equal nonempty signed release, artifact, and channel snapshots."""
    snapshots = {
        mode: registry_index_observations(query, slug)
        for mode, query in readers.items()
    }
    baseline = snapshots["hybrid"]
    assert len(baseline["releases"]) == 2, baseline["releases"]
    assert baseline["packages"] and baseline["platforms"] and baseline["release_artifacts"], baseline
    assert baseline["channel_floors"] == [["stable", "2.0.0"]], baseline["channel_floors"]
    assert len(baseline["channel_partitions"]) == 256, len(baseline["channel_partitions"])
    roots = baseline["container_roots"]
    assert len(roots) == 1, roots
    assert roots[0][1:4] == ["aos", "aos", container_index_digest], roots
    for projection in (
        "container_roots", "container_closure_members", "container_evidence",
        "container_provenance", "container_layers",
    ):
        assert baseline[projection], (projection, baseline[projection])

    for mode, snapshot in snapshots.items():
        differences = {
            table: {"hybrid": baseline[table], mode: snapshot[table]}
            for table in baseline if baseline[table] != snapshot[table]
        }
        assert not differences, (mode, differences)

    encoded = json.dumps(baseline, sort_keys=True, separators=(",", ":")).encode()
    print("signed registry index runtime parity:", {
        "modes": list(snapshots),
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "rows_by_table": {name: len(rows) for name, rows in baseline.items()},
    })


def sql_literal(value):
    """Quote a fixed qualification identifier for each supported SQL dialect."""
    return "'" + value.replace("'", "''") + "'"
