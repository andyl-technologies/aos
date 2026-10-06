//! Browser registry admission and exact file transfers through the shared engine.

use aos_proto_types::direct_upload::DirectCapabilitiesTarget;
use aos_proto_types::*;
use web_sys::File;

use crate::direct_upload_model::operation_id;
use crate::publication_upload_model::{
    next_chunk, publication_target, validate_progress, AdmissionHead, AdmissionSeal,
    ValidatedInventory,
};
use crate::transport::ApiClient;
use crate::workflows::cache_objects::direct::{checkpoint::Checkpoint, upload_target};

/// Begins or resumes the original publication using authenticated server policy.
///
/// # Errors
/// Refuses unknown policy, changed manifest/actor, failed private persistence or
/// missing admission acknowledgment; it never selects another byte route.
pub(super) async fn begin(
    client: &ApiClient,
    mut request: BeginRegistryPublicationRequest,
) -> Result<RegistryPublication, String> {
    let Some(actor) = client
        .publication_actor()
        .await
        .map_err(|error| error.to_string())?
    else {
        return client
            .call(PUBLISH_SERVICE_BEGIN_REGISTRY_PUBLICATION_PATH, &request)
            .await
            .map_err(|error| error.to_string());
    };
    let registry: GetRegistryResponse = client
        .call_publication(
            REGISTRY_SERVICE_GET_REGISTRY_PATH,
            &GetRegistryRequest {
                slug: request.registry.clone(),
            },
            &actor,
        )
        .await
        .map_err(|error| error.to_string())?;
    let registry = registry
        .registry
        .ok_or("The selected registry no longer exists")?;
    request.registry = registry.slug;
    let inventory = ValidatedInventory::new(std::mem::take(&mut request.objects))?;
    let key = format!(
        "publication-admission:{}",
        operation_id(
            "publication",
            &actor.0,
            &(&actor.1, &registry.stable_id, &request.generation),
        )?
    );
    let checkpoint = Checkpoint::open().await?;
    let retained = checkpoint.get::<AdmissionHead>(&key).await?;
    if request.parent_publication_id.is_empty() {
        if let Some(head) = &retained {
            request.parent_publication_id = head.begin.parent_publication_id.clone();
        } else {
            let ready: ListRegistryPublicationsResponse = client
                .call_publication(
                    PUBLISH_SERVICE_LIST_REGISTRY_PUBLICATIONS_PATH,
                    &ListRegistryPublicationsRequest {
                        registry: request.registry.clone(),
                        state: "ready".into(),
                        page_size: 1,
                        page_token: String::new(),
                    },
                    &actor,
                )
                .await
                .map_err(|error| error.to_string())?;
            if let Some(parent) = ready.publications.first() {
                request.parent_publication_id = parent.publication_id.clone();
            }
        }
    }
    let mut head = AdmissionHead {
        deployment: actor.0.clone(),
        principal: actor.1.clone(),
        begin: BeginRegistryPublicationManifestRequest {
            registry: request.registry,
            generation: request.generation,
            refs_digest: request.refs_digest,
            default_commit: request.default_commit,
            parent_publication_id: request.parent_publication_id,
            manifest_digest: inventory.digest().to_string(),
            object_count: inventory.len() as u32,
        },
        publication_id: retained.and_then(|head| head.publication_id),
    };
    head = checkpoint.put(&key, &head).await?;
    let mut session: RegistryPublicationManifestSession = client
        .call_publication(
            PUBLISH_SERVICE_BEGIN_REGISTRY_PUBLICATION_MANIFEST_PATH,
            &head.begin,
            &actor,
        )
        .await
        .map_err(|error| error.to_string())?;
    head.validate_session(&session)?;
    head.publication_id = Some(session.publication_id.clone());
    head = checkpoint.put(&key, &head).await?;

    while session.admitted_object_count < session.object_count {
        let chunk = next_chunk(&head, &session, &inventory)?;
        // An authenticated Begin may renew a metadata lease. Keep every prior
        // exact Append record; renewal never changes its index, digest or source.
        let lease = operation_id("manifest-lease", &actor.0, &chunk.request.lease_token)?;
        let chunk_key = format!("{key}:chunk:{}:{lease}", chunk.request.chunk_index);
        let chunk = checkpoint.put(&chunk_key, &chunk).await?;
        let expected = session.admitted_object_count as usize + chunk.request.objects.len();
        let next: RegistryPublicationManifestSession = client
            .call_publication(
                PUBLISH_SERVICE_APPEND_REGISTRY_PUBLICATION_MANIFEST_PATH,
                &chunk.request,
                &actor,
            )
            .await
            .map_err(|error| error.to_string())?;
        head.validate_session(&next)?;
        if next.admitted_object_count as usize != expected
            || next.next_chunk_index != session.next_chunk_index + 1
            || next.lease_token != session.lease_token
        {
            return Err("The Hub changed the original manifest page progress".into());
        }
        session = next;
    }
    let seal = AdmissionSeal {
        actor: actor.clone(),
        request: SealRegistryPublicationManifestRequest {
            publication_id: session.publication_id,
            lease_token: session.lease_token,
        },
    };
    let lease = operation_id("manifest-lease", &actor.0, &seal.request.lease_token)?;
    let seal = checkpoint
        .put(&format!("{key}:seal:{lease}"), &seal)
        .await?;
    let value: RegistryPublication = client
        .call_publication(
            PUBLISH_SERVICE_SEAL_REGISTRY_PUBLICATION_MANIFEST_PATH,
            &seal.request,
            &seal.actor,
        )
        .await
        .map_err(|error| error.to_string())?;
    head.validate_publication(&value)?;
    Ok(value)
}

/// Uploads only one declared file; final publication visibility remains separate.
///
/// # Errors
/// Refuses changed source/actor, failed durable progress, provider refusal or
/// unknown effects; original incomplete work remains available for resume.
pub(super) async fn upload(
    client: &ApiClient,
    value: &RegistryPublication,
    object: &RegistryPublicationObject,
    file: File,
) -> Result<RegistryPublication, String> {
    let target = DirectCapabilitiesTarget::Publication {
        publication_id: value.publication_id.clone(),
    };
    let mut actor = None;
    if let Some(capabilities) = client
        .discover_upload(&target)
        .await
        .map_err(|error| error.to_string())?
    {
        actor = Some((
            capabilities.deployment_id.clone(),
            capabilities.principal_id.clone(),
        ));
        let (target, phase, source) = publication_target(value, object)?;
        upload_target(
            client.clone(),
            capabilities,
            target,
            phase,
            file,
            Some(source),
        )
        .await?;
    } else {
        if object.upload_url.is_empty() {
            return Err("This server has no supported upload route for the selected file".into());
        }
        client
            .put_publication_object(&object.upload_url, &file)
            .await
            .map_err(|error| error.to_string())?;
    }
    let request = GetRegistryPublicationRequest {
        publication_id: value.publication_id.clone(),
    };
    let next = if let Some(actor) = actor {
        client
            .call_publication(
                PUBLISH_SERVICE_GET_REGISTRY_PUBLICATION_PATH,
                &request,
                &actor,
            )
            .await
    } else {
        client
            .call(PUBLISH_SERVICE_GET_REGISTRY_PUBLICATION_PATH, &request)
            .await
    }
    .map_err(|error| error.to_string())?;
    validate_progress(value, &next, object.object_id)?;
    Ok(next)
}
