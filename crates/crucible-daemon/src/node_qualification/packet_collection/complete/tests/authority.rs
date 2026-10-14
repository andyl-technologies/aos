//! Exercises original preparation ownership while every behavioral case remains unexecuted.

use super::*;
use crucible::node_adapters::cnp::{
    CnpSemanticConformanceAuthority, CnpSemanticRegistrationPolicy, CnpSemanticSource,
};

fn collection_authority(
    scene: &Scene,
) -> (
    PacketCompleteGraphOwner,
    Rc<super::super::InstalledPacketCompleteCollectionAuthority>,
) {
    use crucible_node_contract::{Bytes, U64};
    use crucible_node_provider::{
        reference_packet::service::PacketNative5SourceLaunch, reference_service::InstalledContent,
    };
    let owner = PacketCompleteGraphOwner::install(scene.request(&scene.world.content)).unwrap();
    let policy = owner.graph_policy().unwrap();
    let bytes = configuration::encoded(&scene.world.coordinator);
    let reference = canonical::content_ref(&bytes, "application/json").unwrap();
    let launches = std::array::from_fn(|member| {
        let program = match &scene.world.programmes[member] {
            PacketConnectedSourceProgram::Producer { program } => {
                PacketConnectedSourceProgram::Producer {
                    program: program.clone(),
                }
            }
            PacketConnectedSourceProgram::Reactive { program } => {
                PacketConnectedSourceProgram::Reactive {
                    program: program.clone(),
                }
            }
        };
        let selected = storage_selection();
        PacketNative5SourceLaunch {
            capture_profile: crucible_node_provider::reference_packet::service::PacketNative5CaptureProfile::OriginalArrays6,
            schema_version: 5,
            selection: scene.world.coordinator.participants[member].clone(),
            program,
            controller_pid: U64::new(u64::from(std::process::id())),
            controller_uid: U64::new(0),
            controller_executable: scene.measurements.host.clone(),
            admission_token: Bytes::new(vec![7; 32]),
            initial_coordinator: InstalledContent {
                reference: reference.clone(),
                bytes: Bytes::new(bytes.clone()),
            },
            limits: selected.limits,
            storage: selected.storage,
            effects: scene
                ._directory
                .path()
                .join(format!("effect-{member}.sock")),
        }
    });
    let authority = super::super::InstalledPacketCompleteCollectionAuthority::install(
        super::super::PacketCompleteCollectionRequest {
            roster: scene.roster.clone(),
            host: scene.world.host_source.clone(),
            graph_policy: policy,
            world: &scene.world.world,
            requirements: &scene.world.requirements,
            content: &scene.world.content,
            coordinator: &scene.world.coordinator,
            launches,
            directories: std::array::from_fn(|member| {
                scene._directory.path().join(format!("peer-{member}"))
            }),
            limits: crate::node_qualification::QualificationLimits::default(),
            maximum_audit_bytes: 8 * 1024 * 1024,
        },
    )
    .unwrap();
    (owner, authority)
}

#[test]
fn preparation_authority_retains_all_original_obligations_and_refused_plan() {
    let scene = Scene::new();
    let (_graph_owner, authority) = collection_authority(&scene);

    authority.current().unwrap();
    let plan = authority.witness_plan();
    assert_eq!(plan.cases.len(), 382);
    assert_eq!(plan.requirements.len(), 382);
    assert_eq!(plan.classes.len(), 5);
    assert!(
        plan.cases
            .iter()
            .all(|case| case.id.starts_with("unexecuted-original-"))
    );
    authority.collection_plan().unwrap();
}

#[test]
fn preparation_authority_refuses_equal_portable_foreign_installation() {
    let scene = Scene::new();
    let (_graph_owner, authority) = collection_authority(&scene);
    let original = scene.roster.sources[0].installation();
    let copied = crucible::node_adapters::cnp::CnpSemanticInstallation {
        provider: original.provider.clone(),
        profile: original.profile.clone(),
        descriptor: original.descriptor.clone(),
        binding: original.binding.clone(),
        capabilities: original.capabilities.clone(),
        exact_facet: original.exact_facet.clone(),
        guarantees: original.guarantees.clone(),
        owner: original.owner.clone(),
        realize: original.realize.clone(),
        admission: original.admission.clone(),
        transaction: original.transaction.clone(),
        gate: original.gate.clone(),
        admission_receipt: original.admission_receipt.clone(),
        world_binding_hash: original.world_binding_hash.clone(),
        facets: original.facets.clone(),
        receipt_schema: original.receipt_schema.clone(),
        maximum_operations: original.maximum_operations,
        maximum_result_bytes: original.maximum_result_bytes,
        maximum_authorization_bytes: original.maximum_authorization_bytes,
        maximum_semantic_bytes: original.maximum_semantic_bytes,
    };
    assert_eq!(original.descriptor, copied.descriptor);

    CnpSemanticRegistrationPolicy::authenticate(&*authority, original).unwrap();
    assert!(CnpSemanticRegistrationPolicy::authenticate(&*authority, &copied).is_err());
    assert!(
        CnpSemanticConformanceAuthority::authenticate_installation(&*authority, &copied).is_err()
    );
    authority.current().unwrap();
}

#[test]
fn preparation_authority_refuses_revoked_original_graph() {
    let scene = Scene::new();
    let (graph_owner, authority) = collection_authority(&scene);
    authority.current().unwrap();

    drop(graph_owner);

    assert!(authority.current().is_err());
    assert!(authority.collection_plan().is_err());
}
