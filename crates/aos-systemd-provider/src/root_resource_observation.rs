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
use crate::model::{ServiceActivationOwner, ServiceReadinessMechanism, ServiceRealization};
use crate::render::{RenderedService, render_service};
use crate::semantic::resolve_unit_identity;

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
    ensure!(
        realization.activation_owner == ServiceActivationOwner::Image,
        "stage-entry observation requires an image-owned service root"
    );
    let (_, primary_source) = resolve_unit_identity(&realization.systemd_unit)?;
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
    let mut loaded_from_image = fragment_matches(
        &Path::new(STATIC_UNIT_ROOT).join(&primary_source),
        Path::new(&fragment),
    ) && drop_ins.is_empty();
    let active_state = manager
        .active_state_exact(&rendered.primary_unit, &unit_identity)
        .await?;
    // A one-shot controller remains activating while it establishes the
    // resources it owns. Its own live process is the stage-entry evidence.
    let own_process_running = if realization.enabled
        && active_state == UnitActiveState::Activating
        && realization.readiness_mechanism == Some(ServiceReadinessMechanism::ProcessRunning)
    {
        let unit_cgroup = manager
            .service_control_group_exact(&rendered.primary_unit, &unit_identity)
            .await?;
        let process_cgroups =
            fs::read_to_string("/proc/self/cgroup").context("reading observer process cgroups")?;
        process_belongs_to_unit(&unit_cgroup, &process_cgroups)
    } else {
        false
    };
    let mut manager_current = !manager
        .needs_daemon_reload_exact(&rendered.primary_unit, &unit_identity)
        .await?;
    let mut socket_states_match = true;
    let mut unit_identities = vec![(rendered.primary_unit.clone(), unit_identity.clone())];
    for name in companion_units(&rendered, &primary_source) {
        let identity = manager.unit_identity(name).await?;
        let (fragment, drop_ins) = manager.unit_definition_paths_exact(name, &identity).await?;
        loaded_from_image &= fragment_matches(
            &Path::new(STATIC_UNIT_ROOT).join(name),
            Path::new(&fragment),
        ) && drop_ins.is_empty();
        manager_current &= !manager.needs_daemon_reload_exact(name, &identity).await?;
        if realization
            .socket_start_units
            .iter()
            .any(|socket| socket == name)
        {
            let socket_state = manager.active_state_exact(name, &identity).await?;
            socket_states_match &= if realization.enabled {
                socket_state.is_active()
            } else {
                socket_state == UnitActiveState::Inactive
            };
        }
        unit_identities.push((name.to_string(), identity));
    }
    let files_after = static_files_match(Path::new(STATIC_UNIT_ROOT), &rendered);
    for (name, identity) in &unit_identities {
        ensure!(
            manager.unit_identity(name).await? == *identity,
            "systemd unit identity changed during image resource observation"
        );
    }
    let files_match = files_before && files_after;
    let state_matches = if realization.enabled {
        active_state.is_active() || own_process_running
    } else {
        active_state == UnitActiveState::Inactive
    };
    let ready =
        files_match && loaded_from_image && manager_current && state_matches && socket_states_match;

    let result = RootResourceObservationResult {
        schema: ROOT_RESOURCE_OBSERVATION_RESULT_SCHEMA.to_string(),
        root,
        resource: request.resource.resource.clone(),
        observed_revision: ready.then_some(request.resource.revision),
        ready,
        evidence: AbilityValue::new(serde_json::json!({
            "schema": "aos.systemd.image-service-observation/v1",
            "primary_unit": rendered.primary_unit,
            "unit_identities": unit_identities,
            "files_match": files_match,
            "loaded_from_image": loaded_from_image,
            "manager_current": manager_current,
            "active_state": active_state.label(),
            "own_process_running": own_process_running,
            "socket_states_match": socket_states_match,
        }))?,
    };
    validate_root_resource_observation(&request, &result)?;
    Ok(result)
}

fn process_belongs_to_unit(unit_cgroup: &str, process_cgroups: &str) -> bool {
    if !unit_cgroup.starts_with('/')
        || unit_cgroup == "/"
        || unit_cgroup.ends_with('/')
        || unit_cgroup.contains("//")
    {
        return false;
    }

    process_cgroups.lines().any(|line| {
        let mut fields = line.splitn(3, ':');
        let (Some(hierarchy), Some(controllers), Some(process_cgroup)) =
            (fields.next(), fields.next(), fields.next())
        else {
            return false;
        };
        let is_systemd_hierarchy = (hierarchy == "0" && controllers.is_empty())
            || controllers
                .split(',')
                .any(|controller| controller == "name=systemd");
        is_systemd_hierarchy
            && (process_cgroup == unit_cgroup
                || process_cgroup
                    .strip_prefix(unit_cgroup)
                    .is_some_and(|suffix| suffix.starts_with('/')))
    })
}

fn companion_units<'a>(rendered: &'a RenderedService, primary_source: &str) -> Vec<&'a str> {
    // An instance loads its template fragment; systemd need not expose the
    // template itself as another loaded unit object.
    rendered
        .units
        .iter()
        .filter(|unit| unit.name != primary_source)
        .map(|unit| unit.name.as_str())
        .collect()
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

    use super::{companion_units, fragment_matches, process_belongs_to_unit, static_files_match};
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

    #[test]
    fn template_instance_observes_companions_without_loading_the_template_as_a_unit() {
        let rendered = RenderedService {
            primary_unit: "worker@one.service".to_string(),
            units: vec![
                RenderedServiceUnit {
                    name: "worker@.service".to_string(),
                    bytes: Vec::new(),
                },
                RenderedServiceUnit {
                    name: "worker.socket".to_string(),
                    bytes: Vec::new(),
                },
            ],
            links: Vec::new(),
        };

        assert_eq!(
            companion_units(&rendered, "worker@.service"),
            ["worker.socket"]
        );
    }

    #[test]
    fn activating_service_requires_the_observer_in_its_own_cgroup() {
        let unit = "/system.slice/bootstrap.service";
        assert!(process_belongs_to_unit(
            unit,
            "0::/system.slice/bootstrap.service\n"
        ));
        assert!(process_belongs_to_unit(
            unit,
            "0::/system.slice/bootstrap.service/child\n"
        ));
        assert!(process_belongs_to_unit(
            unit,
            "5:name=systemd:/system.slice/bootstrap.service\n"
        ));
        assert!(!process_belongs_to_unit(
            unit,
            "0::/system.slice/bootstrap.service-other\n"
        ));
        assert!(!process_belongs_to_unit(
            unit,
            "0::/system.slice/another.service\n"
        ));
        assert!(!process_belongs_to_unit(
            "/",
            "0::/system.slice/bootstrap.service\n"
        ));
    }
}
