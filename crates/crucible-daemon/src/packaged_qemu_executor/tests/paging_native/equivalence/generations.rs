//! Three live fork generations under one authenticated immutable RAM boundary.
//!
//! Each descendant receives an independently charged host owner. Promotion
//! retains every ancestor until real process reconciliation unwinds the lineage.
//! The selected checkpoint authority is consumed once by the original source.

use super::concurrent::{ActiveChild, world_config};
use super::*;

pub(super) fn run(
    model: &ResumeModel<'_>,
    input: &CrucibleAttemptExecution,
    context: &AttemptExecutionContext,
) -> RunEvidence {
    let source = input.scenario();
    let available_before = available_resources(model.prepared);
    let factory = RetainedTemplateServiceFactory::new(model.prepared, &model.config);
    let mut selected = context.take_selected_checkpoint();
    let service = Arc::new(
        factory
            .start_for_resume(source, model.checkpoint, context, &mut selected)
            .expect("one genuine selected root for the complete lineage"),
    );
    assert!(selected.is_none());
    extend_native_operations(service.context());
    let parent_config = world_config(&model.config, "generation-source", 48_000);
    let mut parent_factory = fresh_factory(&parent_config, "world");
    let parent = parent_factory
        .begin_resume(
            &model.prepared.checkpoints,
            model.checkpoint,
            crate::QemuExactResumeBasis::new(
                &source.scenario_def(),
                source,
                &model.captured.boundary.configuration,
                None,
            ),
            service.context(),
        )
        .expect("authenticated original source continuation");
    let parent_generations = parent
        .fault_evidence_snapshot()
        .expect("source process generations")
        .nodes
        .iter()
        .map(|node| node.generation)
        .collect::<Vec<_>>();
    let world = parent
        .prepare_hot_fork_source_world()
        .expect("sealed original source")
        .with_cleanup_observer(service.clone());
    let mut first = ActiveChild::start(
        world_config(&model.config, "generation-one", 48_100),
        input,
        context,
        world,
    );
    first.assert_boundary(source, &model.captured.boundary);
    let root = first.ram(context);
    let first_generations = generations(&first);
    assert_successors(&parent_generations, &first_generations);
    let first_ready = first.ready;
    let (world, first_lineage) = first
        .lifecycle
        .promote_into_descendant_template(None)
        .expect("live generation one promoted without losing parent custody");

    let second_owner = factory
        .start_comparison_child_for_test(source, context)
        .expect("independently admitted generation two owner");
    extend_native_operations(second_owner.context());
    assert_ne!(
        context.host_ram_owner_id(),
        second_owner.context().host_ram_owner_id()
    );
    let mut second = ActiveChild::start(
        world_config(&model.config, "generation-two", 48_200),
        input,
        second_owner.context(),
        world,
    );
    second.assert_boundary(source, &model.captured.boundary);
    assert_eq!(second.ram(second_owner.context()), root);
    let second_generations = generations(&second);
    assert_successors(&first_generations, &second_generations);
    let second_ready = second.ready;
    let (world, second_lineage) = second
        .lifecycle
        .promote_into_descendant_template(Some(Box::new(first_lineage)))
        .expect("live generation two retains the entire ancestor chain");

    let third_owner = factory
        .start_comparison_child_for_test(source, context)
        .expect("independently admitted generation three owner");
    extend_native_operations(third_owner.context());
    assert_ne!(
        second_owner.context().host_ram_owner_id(),
        third_owner.context().host_ram_owner_id()
    );
    let peak = model
        .config
        .retained_template_resources()
        .expect("full authored world vector");
    assert_template_charge(model.prepared, available_before, peak, 3);
    let mut third = ActiveChild::start(
        world_config(&model.config, "generation-three", 48_300),
        input,
        third_owner.context(),
        world,
    );
    third.assert_boundary(source, &model.captured.boundary);
    assert_eq!(third.ram(third_owner.context()), root);
    let third_generations = generations(&third);
    assert_successors(&second_generations, &third_generations);
    let third_ready = third.ready;

    let mut preservation_files = BTreeMap::new();
    let mut preservation_bytes = 0_u64;
    for lane in [
        "generation-source",
        "generation-one",
        "generation-two",
        "generation-three",
    ] {
        let root = model.config.host.run_root().join(lane);
        let mut processes = cgroup_processes(&model.config.host.cgroup_root().join(lane));
        assert!(
            !processes.is_empty(),
            "every retained ancestor is still alive"
        );
        processes.push(std::process::id());
        let files = unlinked_disk_files(&processes, &[root.as_path()]);
        let anonymous = inode_allocated_bytes(&files);
        assert!(
            anonymous > 0,
            "each generation has real preservation extents"
        );
        assert!(
            anonymous
                .checked_add(allocated_tree_bytes(&root))
                .expect("bounded generation backing")
                <= peak.backing_peak_bytes
        );
        for (identity, bytes) in files {
            assert!(
                preservation_files.insert(identity, bytes).is_none(),
                "descendants share no mutable preservation inode"
            );
        }
        preservation_bytes = preservation_bytes
            .checked_add(anonymous)
            .expect("bounded lineage backing");
    }
    assert_eq!(
        inode_allocated_bytes(&preservation_files),
        preservation_bytes
    );
    println!("same_root_descendant_anonymous_disk_bytes={preservation_bytes}");

    let recovered = third.stop();
    third_owner
        .release_after_world_cleanup()
        .expect("youngest child physically reaped");
    second_lineage
        .retire_source_world(recovered)
        .expect("every retained ancestor physically reaped and reconciled");
    second_owner
        .release_after_world_cleanup()
        .expect("generation two owner discharged after reap");
    service
        .release_after_world_cleanup()
        .expect("original source watcher joined after lineage retirement");
    for lane in [
        "generation-source",
        "generation-one",
        "generation-two",
        "generation-three",
    ] {
        assert!(cgroup_processes(model.config.host.cgroup_root().join(lane).as_path()).is_empty());
    }
    assert_eq!(available_resources(model.prepared), available_before);
    println!("same_root_descendant_semantic_depth={}", model.depth);
    RunEvidence {
        ready_samples: vec![first_ready, second_ready, third_ready],
        descendant_generations: vec![first_generations, second_generations, third_generations],
        completed_children: 3,
        ..RunEvidence::default()
    }
}

fn generations(child: &ActiveChild) -> Vec<u64> {
    child
        .lifecycle
        .fault_evidence_snapshot()
        .expect("actual native child process generations")
        .nodes
        .iter()
        .map(|node| node.generation)
        .collect()
}

fn assert_successors(parent: &[u64], child: &[u64]) {
    assert_eq!(parent.len(), child.len());
    assert!(!parent.is_empty());
    assert!(
        parent
            .iter()
            .zip(child)
            .all(|(parent, child)| parent.checked_add(1) == Some(*child))
    );
}
