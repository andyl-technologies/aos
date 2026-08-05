//! Unit tests for the complete plugin argument grammar.

use super::*;

#[test]
fn plugin_args_parse_required_simfd_and_slot() {
    let args = PluginArgs::parse("simfd=3,slot=2,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111")
        .unwrap_or_else(|error| panic!("minimal args should parse: {error}"));

    assert_eq!(args.sim_fd(), 3);
    assert_eq!(args.slot(), 2);
    assert_eq!(args.inherited_fds(), None);
    assert_eq!(args.whitebox(), PluginSwitch::Off);
    assert_eq!(args.whitebox_setup(), None);
    assert_eq!(args.app_random(), None);
    assert_eq!(args.coverage(), PluginSwitch::Off);
    assert_eq!(args.fingerprint(), PluginSwitch::Off);
    assert_eq!(args.fingerprint_oracle(), PluginSwitch::Off);
    assert_eq!(args.state_dump(), None);
    assert_eq!(args.validate_slot_index(3), Ok(()));
}

#[test]
fn plugin_args_parse_optional_fds_and_switches() {
    let args = PluginArgs::parse(
        "simfd=4,slot=1,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,shmemfd=5,wakefd=6,whitebox=on,whitebox_setup=x86-port-00e7-unclaimed-v1,coverage=off,fingerprint=on,fingerprint_oracle=on",
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
    assert!(args.fingerprint_oracle().is_on());
    assert_eq!(args.state_dump(), None);
}

#[test]
fn plugin_args_require_fingerprint_for_synchronous_oracle() {
    assert_eq!(
        PluginArgs::parse(
            "simfd=4,slot=1,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,fingerprint_oracle=on"
        ),
        Err(PluginArgsParseError::FingerprintOracleWithoutFingerprint)
    );
}

#[test]
fn plugin_args_parse_terminal_state_dump_as_complete_group() {
    let args = PluginArgs::parse(
        "simfd=4,slot=1,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,fingerprint=on,state_dump_target=4000001,state_dump_path=/tmp/dump.bin",
    )
    .unwrap_or_else(|error| panic!("state-dump args should parse: {error}"));
    let dump = args
        .state_dump()
        .unwrap_or_else(|| panic!("state-dump config should be present"));
    assert_eq!(dump.target_icount(), 4_000_001);
    assert_eq!(dump.output_path(), Path::new("/tmp/dump.bin"));
}

#[test]
fn plugin_args_reject_incomplete_or_unscoped_state_dump() {
    assert_eq!(
        PluginArgs::parse(
            "simfd=4,slot=1,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,fingerprint=on,state_dump_target=1"
        ),
        Err(PluginArgsParseError::IncompleteStateDump)
    );
    assert_eq!(
        PluginArgs::parse(
            "simfd=4,slot=1,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,state_dump_target=1,state_dump_path=/tmp/dump.bin"
        ),
        Err(PluginArgsParseError::StateDumpWithoutFingerprint)
    );
    assert!(matches!(
        PluginArgs::parse(
            "simfd=4,slot=1,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,fingerprint=on,state_dump_target=1,state_dump_path=relative"
        ),
        Err(PluginArgsParseError::InvalidStateDumpPath { .. })
    ));
}

#[test]
fn plugin_args_reject_missing_required_keys() {
    assert_eq!(
        PluginArgs::parse(
            "slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111"
        ),
        Err(PluginArgsParseError::MissingRequiredKey { key: "simfd" })
    );
    assert_eq!(
        PluginArgs::parse("simfd=3"),
        Err(PluginArgsParseError::MissingRequiredKey { key: "slot" })
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
            "simfd=3,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,mode=on"
        ),
        Err(PluginArgsParseError::UnknownKey {
            key: String::from("mode"),
        })
    );
    assert_eq!(
        PluginArgs::parse(
            "simfd=3,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,slot=1"
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
            "simfd=-1,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111"
        ),
        Err(PluginArgsParseError::InvalidFd {
            key: "simfd",
            value: String::from("-1"),
        })
    );
    assert_eq!(
        PluginArgs::parse(
            "simfd=control,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111"
        ),
        Err(PluginArgsParseError::InvalidFd {
            key: "simfd",
            value: String::from("control"),
        })
    );
    assert_eq!(
        PluginArgs::parse(
            "simfd=3,slot=guest,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111"
        ),
        Err(PluginArgsParseError::InvalidSlot {
            key: "slot",
            value: String::from("guest"),
        })
    );
    assert_eq!(
        PluginArgs::parse(
            "simfd=3,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,coverage=true"
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
            "simfd=3,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,whitebox=on"
        ),
        Err(PluginArgsParseError::MissingWhiteboxSetup {
            key: PLUGIN_ARG_WHITEBOX_SETUP,
        })
    );
    assert_eq!(
        PluginArgs::parse(
            "simfd=3,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,whitebox=on,whitebox_setup=x86-port-00e8-unclaimed-v1"
        ),
        Err(PluginArgsParseError::InvalidWhiteboxSetup {
            key: PLUGIN_ARG_WHITEBOX_SETUP,
            value: String::from("x86-port-00e8-unclaimed-v1"),
        })
    );
    assert_eq!(
        PluginArgs::parse(
            "simfd=3,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,whitebox=off,whitebox_setup=x86-port-00e7-unclaimed-v1"
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
            "simfd=3,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,shmemfd=4"
        ),
        Err(PluginArgsParseError::IncompleteInheritedDescriptors)
    );
    assert_eq!(
        PluginArgs::parse(
            "simfd=3,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,wakefd=5"
        ),
        Err(PluginArgsParseError::IncompleteInheritedDescriptors)
    );
}

#[test]
fn plugin_args_validate_slot_against_node_count() {
    let args = PluginArgs::parse("simfd=3,slot=2,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111")
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
