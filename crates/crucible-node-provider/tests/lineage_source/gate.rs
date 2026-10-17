//! Independent actual child census before input or native window effects.

use crucible_node_contract::*;
use crucible_node_provider::{client::ReferenceController, conformance::measure_executable};
use serde_json::Value;

pub(super) fn verify(controller: &ReferenceController, response: &Value) {
    let reference: ContentRef =
        serde_json::from_value(response["body"]["result"]["closed_gate_receipt"].clone()).unwrap();
    let receipt: ControlReceipt = controller.record(&reference).unwrap();
    let closed: ClosedGateRecord = controller.record(&receipt.record_ref).unwrap();
    let native = canonical::parse_json(
        controller.content(&closed.physical_status_ref).unwrap(),
        65536,
    )
    .unwrap();
    let pid: U64 = serde_json::from_value(native["child_pid"].clone()).unwrap();
    let start: U64 = serde_json::from_value(native["original_kernel_start_ticks"].clone()).unwrap();
    let expected: ContentRef = serde_json::from_value(native["native_executable"].clone()).unwrap();
    let process = format!("/proc/{}", pid.get());
    let stat = std::fs::read_to_string(format!("{process}/stat")).unwrap();
    let fields: Vec<_> = stat[stat.rfind(')').unwrap() + 1..]
        .split_ascii_whitespace()
        .collect();

    assert_eq!(native["schema"], "crucible.reference.lineage-origin.v1");
    assert_eq!(
        native["dialect"],
        crucible_node_provider::reference_lineage::DIALECT
    );
    assert_eq!(native["application_status"], "parked");
    assert_eq!(native["physical_pause"], "unknown");
    assert_eq!(
        fields[1].parse::<u64>().unwrap(),
        u64::from(controller.peer_pid())
    );
    assert_eq!(fields[2].parse::<u64>().unwrap(), pid.get());
    assert_eq!(fields[19].parse::<u64>().unwrap(), start.get());
    assert_ne!(pid.get(), u64::from(controller.peer_pid()));
    assert_eq!(
        measure_executable(std::path::Path::new(&format!("{process}/exe"))).unwrap(),
        expected
    );

    let initialize: ContentRef =
        serde_json::from_value(native["initialize_request"].clone()).unwrap();
    let ready: ContentRef =
        serde_json::from_value(native["initialize_response_wire"].clone()).unwrap();
    let original = canonical::parse_json(controller.content(&initialize).unwrap(), 65536).unwrap();
    let wire = controller.content(&ready).unwrap();
    let prefix: [u8; 4] = wire[..4].try_into().unwrap();
    assert_eq!(u32::from_be_bytes(prefix) as usize, wire.len() - 4);
    let reply = canonical::parse_json(&wire[4..], 65536).unwrap();
    assert_eq!(original["command"], "initialize");
    assert_eq!(reply["result"], "ready");
    for (request, origin) in [
        ("owner", "owner"),
        ("incarnation", "incarnation"),
        ("generation", "owner_generation"),
        ("dialect", "dialect"),
    ] {
        assert_eq!(original[request], native[origin]);
        assert_eq!(reply[request], native[origin]);
    }
    assert_eq!(reply["child_pid"], native["child_pid"]);
}
