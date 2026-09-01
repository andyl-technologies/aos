//! Atomic multi-node fault-sequence restore regressions.

use super::*;

#[test]
fn node_set_sequence_restore_rejects_late_invalid_node_without_partial_mutation()
-> Result<(), Box<dyn Error>> {
    let mut nodes = QemuNodeSet::new();
    nodes.insert(
        node_id("node-a"),
        scripted_node_with_options(
            shared_log(),
            ScriptedNodeOptions::default(),
            std::iter::empty(),
        )?,
    );
    nodes.insert(
        node_id("node-b"),
        scripted_node_with_options(
            shared_log(),
            ScriptedNodeOptions::default(),
            std::iter::empty(),
        )?,
    );

    let command_sequences = vec![(node_id("node-a"), 3), (node_id("node-b"), 3)];
    let event_sequences = vec![(node_id("node-a"), 2), (node_id("node-b"), 0)];
    assert!(
        nodes
            .restore_ordered_fault_sequences(&command_sequences, &event_sequences)
            .is_err()
    );
    assert_eq!(
        nodes
            .fault_command_sequence_entries()
            .map(|(_node, sequence)| sequence)
            .collect::<Vec<_>>(),
        vec![2, 2]
    );
    assert_eq!(
        nodes
            .fault_event_sequence_entries()
            .map(|(_node, sequence)| sequence)
            .collect::<Vec<_>>(),
        vec![1, 1]
    );
    SimulationBackend::shutdown(&mut nodes)?;
    Ok(())
}
