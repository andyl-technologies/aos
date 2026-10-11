//! Short-lived inventory plans over an already resolved binding publication.
//!
//! Construction does not publish a binding or acquire a provider lease. The
//! invocation owner checks current SQL before and after the existing executor.

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::storage_work::{
    protected_inspection::ProtectedInspectionSource, StorageBindingSnapshot,
    StorageCredentialSelector, StorageObjectIdentity, StorageWorkOperation, StorageWorkPlan,
};

use crate::external_object::InventoryDomainMode;

/// Constructs and checks the exact plan before the Worker opens a provider.
///
/// # Errors
/// Refuses an expired publication, missing purpose credential, invalid path or
/// mismatched plan shape through the existing binding authorizer.
pub(crate) fn build(
    snapshot: &StorageBindingSnapshot,
    placement_id: i64,
    placement_resource_version: i64,
    placement_prefix: &str,
    operation: StorageWorkOperation,
    now: i64,
) -> Result<StorageWorkPlan> {
    let credential_references = if snapshot.access_mode == "public" {
        Vec::new()
    } else {
        operation
            .credential_purposes()
            .iter()
            .map(|purpose| {
                let credential = snapshot
                    .credentials
                    .iter()
                    .find(|credential| credential.purpose == *purpose)
                    .context("inventory publication lacks its purpose credential")?;
                Ok(StorageCredentialSelector {
                    purpose: credential.purpose.clone(),
                    generation: credential.generation,
                })
            })
            .collect::<Result<Vec<_>>>()?
    };
    let plan = StorageWorkPlan {
        version: 1,
        plan_id: uuid::Uuid::new_v4().simple().to_string(),
        deployment_id: snapshot.deployment_id.clone(),
        issued_at: now,
        expires_at: now
            .checked_add(30)
            .context("inventory cutoff overflow")?
            .min(snapshot.expires_at),
        placement_id,
        placement_resource_version,
        binding_id: snapshot.binding_id,
        binding_resource_version: snapshot.binding_resource_version,
        binding_kind: snapshot.binding_kind.clone(),
        binding_snapshot_revision: Some(snapshot.revision()?),
        credential_references,
        placement_prefix: placement_prefix.into(),
        operation,
    };
    snapshot.authorizes(&plan, &plan.deployment_id, now)?;
    Ok(plan)
}

/// Checks the actual result against its installed source mode and signed key.
///
/// # Errors
/// Refuses crossed version/closure forms, missing evidence, a substituted key,
/// or another permanent physical source. This check grants no read permission.
pub(crate) fn validate_source(
    mode: InventoryDomainMode,
    plan: &StorageWorkPlan,
    path: &str,
    binding_prefix: &str,
    identity: &StorageObjectIdentity,
    source: Option<&ProtectedInspectionSource>,
) -> Result<()> {
    ensure!(
        identity.key == plan.object_key(path)?,
        "inventory source key differs"
    );
    aos_hub_core::surface_write::strong_if_match_etag(&identity.etag)?;
    match mode {
        InventoryDomainMode::Versioned => {
            ensure!(
                source.is_none()
                    && identity
                        .provider_version
                        .as_deref()
                        .is_some_and(aos_hub_core::storage_work::valid_provider_version),
                "versioned inventory lacks its genuine provider version"
            );
        }
        InventoryDomainMode::ProtectedVersionless => {
            source
                .context("protected inventory lacks its saved source")?
                .validate_identity(plan, path, binding_prefix, identity)?;
        }
        InventoryDomainMode::Unconfigured => {
            anyhow::bail!("unconfigured inventory cannot use the installed executor")
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_hub_core::storage_work::StorageCredentialReference;

    fn snapshot() -> StorageBindingSnapshot {
        StorageBindingSnapshot {
            version: 1,
            deployment_id: "inventory-deployment".into(),
            binding_id: 3,
            binding_resource_version: 4,
            binding_stable_id: "inventory-binding".into(),
            binding_kind: "s3".into(),
            object_bucket: "inventory-bucket".into(),
            object_prefix: "managed/binding".into(),
            endpoint_scheme: "https".into(),
            endpoint_host_kind: "dns".into(),
            endpoint_host_bytes: b"objects.example.invalid".to_vec(),
            endpoint_port: Some(443),
            signing_region: "auto".into(),
            access_mode: "private".into(),
            credentials: ["list", "read"]
                .into_iter()
                .map(|purpose| StorageCredentialReference {
                    purpose: purpose.into(),
                    generation: 5,
                    secret_version_ref: format!("secret://inventory/{purpose}/v1"),
                    fingerprint: "4".repeat(64),
                })
                .collect(),
            issued_at: 100,
            expires_at: 200,
        }
    }

    fn head() -> StorageWorkOperation {
        StorageWorkOperation::Head {
            path: format!("oci/blobs/sha256/{}", "a".repeat(64)),
        }
    }

    #[test]
    fn plans_are_fresh_short_lived_and_bound_to_exact_publication() {
        let snapshot = snapshot();
        let first = build(&snapshot, 7, 8, "registry", head(), 101).unwrap();
        let second = build(&snapshot, 7, 8, "registry", head(), 101).unwrap();
        assert_ne!(first.plan_id, second.plan_id);
        assert_eq!(first.expires_at, 131);
        assert_eq!(
            first.binding_snapshot_revision,
            Some(snapshot.revision().unwrap())
        );
        assert_eq!(first.credential_references[0].purpose, "read");
        assert_eq!(first.placement_id, 7);
        assert_eq!(first.placement_resource_version, 8);

        let mut changed = snapshot.clone();
        changed.binding_resource_version += 1;
        assert!(changed
            .authorizes(&first, &first.deployment_id, 101)
            .is_err());
    }

    #[test]
    fn near_expiry_is_not_renewed_and_expired_publication_refuses() {
        let mut snapshot = snapshot();
        snapshot.expires_at = 110;
        let plan = build(&snapshot, 7, 8, "registry", head(), 101).unwrap();
        assert_eq!(plan.expires_at, 110);
        assert!(build(&snapshot, 7, 8, "registry", head(), 111).is_err());
    }

    #[test]
    fn listing_cannot_borrow_the_read_credential() {
        let mut snapshot = snapshot();
        let operation = StorageWorkOperation::ListPage {
            prefix: "oci/blobs/sha256/".into(),
            cursor: None,
            limit: 1,
        };
        let plan = build(&snapshot, 7, 8, "registry", operation.clone(), 101).unwrap();
        assert_eq!(plan.credential_references[0].purpose, "list");
        snapshot
            .credentials
            .retain(|credential| credential.purpose != "list");
        assert!(build(&snapshot, 7, 8, "registry", operation, 101).is_err());
    }

    #[test]
    fn installed_source_modes_preserve_versions_and_refuse_crossed_evidence() {
        use aos_hub_core::storage_authority::{
            control::StorageAuthorityObjectScope, external_object::copy::source::CopySourceClosure,
            lease::LeaseInteger, GuardIncarnation, PhysicalStorageAuthorityId, StorageGuardStamp,
        };

        let snapshot = snapshot();
        let operation = head();
        let StorageWorkOperation::Head { path } = operation.clone() else {
            unreachable!()
        };
        let plan = build(&snapshot, 7, 8, "registry", operation, 101).unwrap();
        let mut identity = StorageObjectIdentity {
            key: plan.object_key(&path).unwrap(),
            size: 64,
            etag: "\"tag\"".into(),
            provider_version: Some("actual-provider-v1".into()),
        };
        validate_source(
            InventoryDomainMode::Versioned,
            &plan,
            &path,
            &snapshot.object_prefix,
            &identity,
            None,
        )
        .unwrap();
        assert!(validate_source(
            InventoryDomainMode::ProtectedVersionless,
            &plan,
            &path,
            &snapshot.object_prefix,
            &identity,
            None
        )
        .is_err());
        assert!(validate_source(
            InventoryDomainMode::Unconfigured,
            &plan,
            &path,
            &snapshot.object_prefix,
            &identity,
            None
        )
        .is_err());

        let authority =
            PhysicalStorageAuthorityId::parse("11111111-1111-4111-8111-111111111111").unwrap();
        let source = ProtectedInspectionSource {
            version: 1,
            scope: StorageAuthorityObjectScope {
                guard_namespace_id: "inventory-guard".into(),
                physical_authority_id: authority.clone(),
                full_key: aos_hub_core::keymap::r2_key(&snapshot.object_prefix, &identity.key),
            },
            closure: CopySourceClosure {
                guard_stamp: StorageGuardStamp {
                    physical_authority_id: authority,
                    incarnation: GuardIncarnation::parse("1").unwrap(),
                },
                receipt_digest: "b".repeat(64),
                sha256: "a".repeat(64),
                bytes: LeaseInteger::new(64).unwrap(),
                etag: Some(identity.etag.clone()),
            },
        };
        assert!(validate_source(
            InventoryDomainMode::Versioned,
            &plan,
            &path,
            &snapshot.object_prefix,
            &identity,
            Some(&source)
        )
        .is_err());
        assert!(validate_source(
            InventoryDomainMode::ProtectedVersionless,
            &plan,
            &path,
            &snapshot.object_prefix,
            &identity,
            Some(&source)
        )
        .is_err());
        identity.provider_version = None;
        validate_source(
            InventoryDomainMode::ProtectedVersionless,
            &plan,
            &path,
            &snapshot.object_prefix,
            &identity,
            Some(&source),
        )
        .unwrap();
        assert!(validate_source(
            InventoryDomainMode::Versioned,
            &plan,
            &path,
            &snapshot.object_prefix,
            &identity,
            None
        )
        .is_err());
        assert!(validate_source(
            InventoryDomainMode::ProtectedVersionless,
            &plan,
            &path,
            "another-binding",
            &identity,
            Some(&source)
        )
        .is_err());
        identity.size += 1;
        assert!(validate_source(
            InventoryDomainMode::ProtectedVersionless,
            &plan,
            &path,
            &snapshot.object_prefix,
            &identity,
            Some(&source)
        )
        .is_err());
    }
}
