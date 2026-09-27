//! Native observation of a service installed by the boot image.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use aos_ability_model::{AbilityValue, IncarnationId};
use aos_provider_protocol::{
    ROOT_RESOURCE_OBSERVATION_REQUEST_SCHEMA, ROOT_RESOURCE_OBSERVATION_RESULT_SCHEMA,
    RootResourceObservationRequest, RootResourceObservationResult,
    validate_root_resource_observation,
};
use aos_systemd::{PinnedSystemdManager, UnitActiveState};

use crate::HandlerRole;
use crate::model::ServiceRealization;
use crate::render::{RenderedService, render_service};

const STATIC_UNIT_ROOT: &str = "/etc/systemd/system";

pub(super) async fn observe(
    role: HandlerRole,
    request: RootResourceObservationRequest,
) -> Result<RootResourceObservationResult> {
    ensure!(
        request.schema == ROOT_RESOURCE_OBSERVATION_REQUEST_SCHEMA,
        "unsupported root resource observation request"
    );
    ensure!(
        role == HandlerRole::Service,
        "selected systemd handler cannot observe an image-owned service"
    );
    let realization =
        aos_ability_validate::resolve_static_expression(&request.resource.realization)
            .context("image-owned service realization depends on a runtime result")?;
    let realization: ServiceRealization = serde_json::from_value(realization.as_json().clone())
        .context("decoding image-owned service realization")?;
    let rendered = render_service(&realization)?;

    let root = super::root_observation::observe(role, request.root.clone()).await?;
    let manager = PinnedSystemdManager::connect().await?;
    ensure!(
        root.incarnation == Some(IncarnationId::new(manager.incarnation().token())?),
        "systemd manager changed after root observation"
    );

    let files_before = static_files_match(Path::new(STATIC_UNIT_ROOT), &rendered);
    let unit_identity = manager.unit_identity(&rendered.primary_unit).await?;
    let (fragment, drop_ins) = manager
        .unit_definition_paths_exact(&rendered.primary_unit, &unit_identity)
        .await?;
    let loaded_from_image = fragment_matches(
        Path::new(STATIC_UNIT_ROOT)
            .join(&rendered.primary_unit)
            .as_path(),
        Path::new(&fragment),
    ) && drop_ins.is_empty();
    let active_state = manager
        .active_state_exact(&rendered.primary_unit, &unit_identity)
        .await?;
    let manager_current = !manager
        .needs_daemon_reload_exact(&rendered.primary_unit, &unit_identity)
        .await?;
    let files_after = static_files_match(Path::new(STATIC_UNIT_ROOT), &rendered);
    ensure!(
        manager.unit_identity(&rendered.primary_unit).await? == unit_identity,
        "systemd unit identity changed during image resource observation"
    );
    let files_match = files_before && files_after;
    let state_matches = if realization.enabled {
        active_state.is_active()
    } else {
        active_state == UnitActiveState::Inactive
    };
    let ready = files_match && loaded_from_image && manager_current && state_matches;

    let result = RootResourceObservationResult {
        schema: ROOT_RESOURCE_OBSERVATION_RESULT_SCHEMA.to_string(),
        root,
        resource: request.resource.resource.clone(),
        observed_revision: ready.then_some(request.resource.revision),
        ready,
        evidence: AbilityValue::new(serde_json::json!({
            "schema": "aos.systemd.image-service-observation/v1",
            "primary_unit": rendered.primary_unit,
            "unit_identity": unit_identity,
            "files_match": files_match,
            "loaded_from_image": loaded_from_image,
            "manager_current": manager_current,
            "active_state": active_state.label(),
        }))?,
    };
    validate_root_resource_observation(&request, &result)?;
    Ok(result)
}

fn static_files_match(root: &Path, rendered: &RenderedService) -> bool {
    rendered
        .units
        .iter()
        .all(|unit| fs::read(root.join(&unit.name)).is_ok_and(|bytes| bytes == unit.bytes))
        && rendered.links.iter().all(|link| {
            fs::read_link(root.join(&link.path))
                .is_ok_and(|target| target == Path::new(&link.target))
        })
}

fn fragment_matches(expected: &Path, loaded: &Path) -> bool {
    expected
        .canonicalize()
        .ok()
        .zip(loaded.canonicalize().ok())
        .is_some_and(|(expected, loaded)| expected == loaded)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;

    use super::{fragment_matches, static_files_match};
    use crate::render::{RenderedService, RenderedServiceLink, RenderedServiceUnit};

    #[test]
    fn image_files_must_match_the_rendered_unit_and_installation_links() {
        let root = tempfile::tempdir().expect("temporary unit root");
        let rendered = RenderedService {
            primary_unit: "example.service".to_string(),
            units: vec![RenderedServiceUnit {
                name: "example.service".to_string(),
                bytes: b"[Service]\nExecStart=/example\n".to_vec(),
            }],
            links: vec![RenderedServiceLink {
                path: "multi-user.target.wants/example.service".to_string(),
                target: "../example.service".to_string(),
            }],
        };
        let install = root.path().join("multi-user.target.wants");
        fs::create_dir(&install).expect("installation directory");
        fs::write(
            root.path().join("example.service"),
            &rendered.units[0].bytes,
        )
        .expect("unit file");
        symlink("../example.service", install.join("example.service")).expect("installation link");

        assert!(static_files_match(root.path(), &rendered));
        assert!(fragment_matches(
            &root.path().join("example.service"),
            &root.path().join("example.service")
        ));

        fs::write(
            root.path().join("example.service"),
            b"[Service]\nExecStart=/other\n",
        )
        .expect("changed unit file");
        assert!(!static_files_match(root.path(), &rendered));
    }
}
