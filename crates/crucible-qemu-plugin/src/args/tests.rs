//! Unit tests for the complete plugin argument grammar.

use super::*;

#[test]
fn plugin_args_parse_required_simfd_and_slot() {
    let args = PluginArgs::parse("simfd=3,slot=2,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=7,network_tx_next_seq=23,storage_completed_history_epochs=1048576,storage_completed_history_gaps=1048576")
        .unwrap_or_else(|error| panic!("minimal args should parse: {error}"));

    assert_eq!(args.sim_fd(), 3);
    assert_eq!(args.slot(), 2);
    assert_eq!(args.process_generation(), 7);
    assert_eq!(args.network_tx_next_seq(), 23);
    assert_eq!(
        args.storage_history_limits(),
        PluginStorageHistoryLimits::compiled_maximum()
    );
    assert_eq!(args.inherited_fds(), None);
    assert_eq!(args.whitebox(), PluginSwitch::Off);
    assert_eq!(args.whitebox_setup(), None);
    assert_eq!(args.campaign_marker_parking(), PluginSwitch::Off);
    assert_eq!(args.app_random(), None);
    assert_eq!(args.coverage(), PluginSwitch::Off);
    assert_eq!(args.fingerprint(), PluginSwitch::Off);
    assert_eq!(args.validate_slot_index(3), Ok(()));
}

#[test]
fn campaign_marker_parking_requires_explicit_whitebox_launch_opt_in() {
    let base = "simfd=3,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=1,network_tx_next_seq=0,storage_completed_history_epochs=1048576,storage_completed_history_gaps=1048576";
    assert_eq!(
        PluginArgs::parse(&format!("{base},campaign_marker_parking=on")),
        Err(PluginArgsParseError::CampaignMarkerParkingRequiresWhitebox)
    );

    let enabled = PluginArgs::parse(&format!(
        "{base},whitebox=on,whitebox_setup=x86-port-00e7-unclaimed-v1,campaign_marker_parking=on"
    ))
    .unwrap_or_else(|error| panic!("explicit campaign marker parking should parse: {error}"));
    assert_eq!(enabled.campaign_marker_parking(), PluginSwitch::On);
}

#[test]
fn plugin_args_require_and_validate_authored_storage_history_limits() {
    let prefix = "simfd=3,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=1,network_tx_next_seq=0";
    assert_eq!(
        PluginArgs::parse(prefix),
        Err(PluginArgsParseError::MissingRequiredKey {
            key: PLUGIN_ARG_STORAGE_COMPLETED_HISTORY_EPOCHS,
        })
    );
    assert_eq!(
        PluginArgs::parse(&format!(
            "{prefix},storage_completed_history_epochs=0,storage_completed_history_gaps=1"
        )),
        Err(PluginArgsParseError::InvalidResourceLimit {
            key: PLUGIN_ARG_STORAGE_COMPLETED_HISTORY_EPOCHS,
            value: String::from("0"),
            hard: HARD_STORAGE_COMPLETED_HISTORY_EPOCHS,
        })
    );
    assert_eq!(
        PluginArgs::parse(&format!(
            "{prefix},storage_completed_history_epochs=1,storage_completed_history_gaps=1048577"
        )),
        Err(PluginArgsParseError::InvalidResourceLimit {
            key: PLUGIN_ARG_STORAGE_COMPLETED_HISTORY_GAPS,
            value: String::from("1048577"),
            hard: HARD_STORAGE_COMPLETED_HISTORY_GAPS,
        })
    );
}

#[test]
fn plugin_args_parse_optional_fds_and_switches() {
    let args = PluginArgs::parse(
        "simfd=4,slot=1,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=8,network_tx_next_seq=0,storage_completed_history_epochs=1048576,storage_completed_history_gaps=1048576,shmemfd=5,wakefd=6,whitebox=on,whitebox_setup=x86-port-00e7-unclaimed-v1,coverage=off,fingerprint=on",
    )
    .unwrap_or_else(|error| panic!("complete args should parse: {error}"));

    assert_eq!(args.sim_fd(), 4);
    assert_eq!(args.slot(), 1);
    assert_eq!(
        args.inherited_fds(),
        Some(PluginInheritedFds {
            shmem_fd: 5,
            wake_fd: 6,
        })
    );
    assert!(args.whitebox().is_on());
    assert_eq!(
        args.whitebox_setup(),
        Some(WhiteboxSetupAttestation::X86Port00e7UnclaimedV1)
    );
    assert!(!args.coverage().is_on());
    assert!(args.fingerprint().is_on());
}

#[test]
fn plugin_args_reject_missing_required_keys() {
    assert_eq!(
        PluginArgs::parse(
            "slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=1,network_tx_next_seq=0,storage_completed_history_epochs=1048576,storage_completed_history_gaps=1048576"
        ),
        Err(PluginArgsParseError::MissingRequiredKey { key: "simfd" })
    );
    assert_eq!(
        PluginArgs::parse("simfd=3"),
        Err(PluginArgsParseError::MissingRequiredKey { key: "slot" })
    );
    assert_eq!(
        PluginArgs::parse(
            "simfd=3,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111"
        ),
        Err(PluginArgsParseError::MissingRequiredKey {
            key: PLUGIN_ARG_PROCESS_GENERATION,
        })
    );
    assert_eq!(
        PluginArgs::parse(
            "simfd=3,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=1"
        ),
        Err(PluginArgsParseError::MissingRequiredKey {
            key: PLUGIN_ARG_NETWORK_TX_NEXT_SEQ,
        })
    );
    assert_eq!(
        PluginArgs::parse(
            "simfd=3,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=0,network_tx_next_seq=0,storage_completed_history_epochs=1048576,storage_completed_history_gaps=1048576"
        ),
        Err(PluginArgsParseError::InvalidProcessGeneration {
            value: String::from("0"),
        })
    );
}

#[test]
fn plugin_args_reject_malformed_unknown_and_duplicate_keys() {
    assert_eq!(
        PluginArgs::parse("simfd=3,slot"),
        Err(PluginArgsParseError::MalformedArgument {
            argument: String::from("slot"),
        })
    );
    assert_eq!(
        PluginArgs::parse(
            "simfd=3,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=1,network_tx_next_seq=0,storage_completed_history_epochs=1048576,storage_completed_history_gaps=1048576,mode=on"
        ),
        Err(PluginArgsParseError::UnknownKey {
            key: String::from("mode"),
        })
    );
    assert_eq!(
        PluginArgs::parse(
            "simfd=3,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=1,network_tx_next_seq=0,storage_completed_history_epochs=1048576,storage_completed_history_gaps=1048576,slot=1"
        ),
        Err(PluginArgsParseError::DuplicateKey {
            key: String::from("slot"),
        })
    );
}

#[test]
fn plugin_args_reject_bad_fd_slot_and_switch_values() {
    assert_eq!(
        PluginArgs::parse(
            "simfd=-1,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=1,network_tx_next_seq=0,storage_completed_history_epochs=1048576,storage_completed_history_gaps=1048576"
        ),
        Err(PluginArgsParseError::InvalidFd {
            key: "simfd",
            value: String::from("-1"),
        })
    );
    assert_eq!(
        PluginArgs::parse(
            "simfd=control,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=1,network_tx_next_seq=0,storage_completed_history_epochs=1048576,storage_completed_history_gaps=1048576"
        ),
        Err(PluginArgsParseError::InvalidFd {
            key: "simfd",
            value: String::from("control"),
        })
    );
    assert_eq!(
        PluginArgs::parse(
            "simfd=3,slot=guest,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=1,network_tx_next_seq=0,storage_completed_history_epochs=1048576,storage_completed_history_gaps=1048576"
        ),
        Err(PluginArgsParseError::InvalidSlot {
            key: "slot",
            value: String::from("guest"),
        })
    );
    assert_eq!(
        PluginArgs::parse(
            "simfd=3,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=1,network_tx_next_seq=0,storage_completed_history_epochs=1048576,storage_completed_history_gaps=1048576,coverage=true"
        ),
        Err(PluginArgsParseError::InvalidSwitch {
            key: "coverage",
            value: String::from("true"),
        })
    );
}

#[test]
fn plugin_args_require_whitebox_setup_attestation_exactly_when_enabled() {
    assert_eq!(
        PluginArgs::parse(
            "simfd=3,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=1,network_tx_next_seq=0,storage_completed_history_epochs=1048576,storage_completed_history_gaps=1048576,whitebox=on"
        ),
        Err(PluginArgsParseError::MissingWhiteboxSetup {
            key: PLUGIN_ARG_WHITEBOX_SETUP,
        })
    );
    assert_eq!(
        PluginArgs::parse(
            "simfd=3,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=1,network_tx_next_seq=0,storage_completed_history_epochs=1048576,storage_completed_history_gaps=1048576,whitebox=on,whitebox_setup=x86-port-00e8-unclaimed-v1"
        ),
        Err(PluginArgsParseError::InvalidWhiteboxSetup {
            key: PLUGIN_ARG_WHITEBOX_SETUP,
            value: String::from("x86-port-00e8-unclaimed-v1"),
        })
    );
    assert_eq!(
        PluginArgs::parse(
            "simfd=3,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=1,network_tx_next_seq=0,storage_completed_history_epochs=1048576,storage_completed_history_gaps=1048576,whitebox=off,whitebox_setup=x86-port-00e7-unclaimed-v1"
        ),
        Err(PluginArgsParseError::WhiteboxSetupWhileDisabled {
            key: PLUGIN_ARG_WHITEBOX_SETUP,
        })
    );
}

#[test]
fn plugin_args_reject_partial_inherited_descriptor_pair() {
    assert_eq!(
        PluginArgs::parse(
            "simfd=3,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=1,network_tx_next_seq=0,storage_completed_history_epochs=1048576,storage_completed_history_gaps=1048576,shmemfd=4"
        ),
        Err(PluginArgsParseError::IncompleteInheritedDescriptors)
    );
    assert_eq!(
        PluginArgs::parse(
            "simfd=3,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=1,network_tx_next_seq=0,storage_completed_history_epochs=1048576,storage_completed_history_gaps=1048576,wakefd=5"
        ),
        Err(PluginArgsParseError::IncompleteInheritedDescriptors)
    );
}

#[test]
fn plugin_args_validate_slot_against_node_count() {
    let args = PluginArgs::parse("simfd=3,slot=2,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=1,network_tx_next_seq=0,storage_completed_history_epochs=1048576,storage_completed_history_gaps=1048576")
        .unwrap_or_else(|error| panic!("args should parse: {error}"));

    assert_eq!(args.validate_slot_index(3), Ok(()));
    assert_eq!(
        args.validate_slot_index(2),
        Err(PluginArgsParseError::SlotOutOfRange {
            slot: 2,
            node_count: 2,
        })
    );
    assert_eq!(
        args.validate_slot_index(0),
        Err(PluginArgsParseError::SlotOutOfRange {
            slot: 2,
            node_count: 0,
        })
    );
}

#[test]
fn independent_pager_launch_requires_complete_nonaliasing_fresh_authority() {
    let base = "simfd=3,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=42,network_tx_next_seq=0,storage_completed_history_epochs=1048576,storage_completed_history_gaps=1048576,shmemfd=4,wakefd=5,whitebox=off,coverage=off";
    let authority = format!(
        "ram_control_fd=9,ram_control_session={},ram_control_daemon={},ram_control_owner={},ram_control_node={},ram_control_owner_generation=42,ram_control_arena_generation=7,ram_control_template=0",
        "44".repeat(32),
        "11".repeat(32),
        "22".repeat(32),
        "33".repeat(32)
    );
    let parsed = PluginArgs::parse(&format!("{base},{authority}")).unwrap();
    let control = parsed.ram_control().unwrap();
    assert_eq!(control.descriptor, 9);
    assert_eq!(control.target.owner_generation, 42);
    assert_eq!(control.target.arena_generation, 7);
    for invalid in [
        authority.replace("ram_control_fd=9", "ram_control_fd=3"),
        authority.replace("ram_control_fd=9", "ram_control_fd=4"),
        authority.replace(
            "ram_control_owner_generation=42",
            "ram_control_owner_generation=042",
        ),
        authority.replace(
            "ram_control_arena_generation=7",
            "ram_control_arena_generation=0",
        ),
        authority.replace("ram_control_template=0", "ram_control_template=true"),
        "ram_control_fd=9".to_owned(),
    ] {
        assert!(PluginArgs::parse(&format!("{base},{invalid}")).is_err());
    }
}

#[test]
fn ram_resource_envelope_is_complete_exact_and_independent_of_placement() {
    let base = "simfd=3,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=1,network_tx_next_seq=0,storage_completed_history_epochs=1,storage_completed_history_gaps=1";
    let resources = "ram_metadata_budget=8192,ram_resident_peak=32768,ram_backing_peak=65536,ram_metadata_peak=8192,ram_staging_peak=4096,ram_io_slots=1,ram_cpu_slots=1,ram_task_slots=3,ram_fd_slots=7";
    let args = PluginArgs::parse(&format!("{base},{resources}")).unwrap();
    let envelope = args.ram_resources().unwrap();
    assert_eq!(envelope.resident_peak_bytes, 32768);
    assert_eq!(envelope.backing_peak_bytes, 65536);
    assert_eq!(envelope.metadata_bytes, args.ram_metadata_budget().unwrap());
    assert_eq!(envelope.paging_io_slots, 1);
    for invalid in [
        resources.replace(",ram_fd_slots=7", ""),
        resources.replace("ram_io_slots=1", "ram_io_slots=01"),
        resources.replace("ram_metadata_peak=8192", "ram_metadata_peak=4096"),
        resources.replace(
            "ram_resident_peak=32768",
            "ram_resident_peak=18446744073709551616",
        ),
    ] {
        assert!(PluginArgs::parse(&format!("{base},{invalid}")).is_err());
    }
}

#[test]
fn private_spill_requires_canonical_separate_nonaliasing_quota() {
    let base = "simfd=3,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=42,network_tx_next_seq=0,storage_completed_history_epochs=1048576,storage_completed_history_gaps=1048576,shmemfd=4,wakefd=5";
    let authority = format!(
        "ram_control_fd=9,ram_control_session={},ram_control_daemon={},ram_control_owner={},ram_control_node={},ram_control_owner_generation=42,ram_control_arena_generation=7,ram_control_template=0",
        "44".repeat(32),
        "11".repeat(32),
        "22".repeat(32),
        "33".repeat(32)
    );
    let resources = "ram_resident_peak=1024,ram_backing_peak=2048,ram_metadata_peak=256,ram_staging_peak=128,ram_io_slots=1,ram_cpu_slots=1,ram_task_slots=16,ram_fd_slots=32,ram_metadata_budget=256";
    let prefix = format!("{base},{authority},{resources}");
    let parsed =
        PluginArgs::parse(&format!("{prefix},ram_spill_fd=11,ram_spill_quota=1024")).unwrap();
    assert_eq!(parsed.ram_spill_descriptor(), Some(11));
    assert_eq!(parsed.ram_spill_quota(), Some(1024));

    for role in [
        "ram_spill_fd=9,ram_spill_quota=1024",
        "ram_spill_fd=10,ram_spill_quota=1024",
        "ram_spill_fd=4,ram_spill_quota=1024",
        "ram_spill_fd=011,ram_spill_quota=1024",
        "ram_spill_fd=11,ram_spill_quota=01024",
        "ram_spill_fd=11,ram_spill_quota=0",
        "ram_spill_fd=11,ram_spill_quota=2049",
        "ram_spill_fd=11",
        "ram_spill_quota=1024",
    ] {
        assert_eq!(
            PluginArgs::parse(&format!("{prefix},{role}")),
            Err(PluginArgsParseError::InvalidRamSpillDescriptor)
        );
    }
}
