//! Derives one readonly manager schedule from the actual pinned Host profile.
//!
//! Wire bounds describe the existing fixed PID1 query and concrete property
//! schema. They are DATA requirements, not financial capacity or authority.
//! The real Host original separately prepays construction and each extension.

use aos_systemd::ReadonlyPropertyReceiveScheduleV2;

use super::{ControlProfileV2, OriginErrorV2, MAXIMUM_ATTEMPTS, EXECUTION_ATTEMPTS};

// Each actual observation has8 initial and6 final PID1 calls. The full Host
// query adds22 requested properties; the producer query adds2. No Subscribe,
// GetAll, proxy cache, worker, NameOwnerChanged or signal match is installed.
const BOOKEND_CALLS: usize = 14;
const FULL_QUERY_CALLS: usize = BOOKEND_CALLS + 22;
const PRODUCER_QUERY_CALLS: usize = BOOKEND_CALLS + 2;
const CALLS_PER_ROUND: usize = FULL_QUERY_CALLS + PRODUCER_QUERY_CALLS;

// The installed Phase0 verifier uses one Host hardening query, two Host filter
// queries, two target hardening queries, and two exact service-cgroup queries.
// The latter use GetUnit plus nine Gets on the same cache-disabled connection.
// Hostd has not sent READY: its three observations use StartingOrRunning
// (14 bookend calls). The active shifted target uses Active (12).
const PHASE0_BASE_CUSTOM_CALLS: usize = (BOOKEND_CALLS + 4)
    + 2 * (BOOKEND_CALLS + 3) + 2 * (12 + 6) + 2 * 10;
// Boot adds Host Requires/After and two successful oneshot observations. Each
// publisher sample has 14 bookend calls, 26 Service Gets and 3 Unit Gets.
const HOST_DEPENDENCY_CALLS: usize = 2;
const PUBLISHER_SAMPLE_CALLS: usize = BOOKEND_CALLS + 26 + 3;
const PUBLISHER_SAMPLES: usize = 2;
const PHASE0_CUSTOM_CALLS: usize = PHASE0_BASE_CUSTOM_CALLS
    + HOST_DEPENDENCY_CALLS + PUBLISHER_SAMPLES * PUBLISHER_SAMPLE_CALLS;
const PHASE0_OBSERVER_ROUNDS: usize = 2;

pub(super) struct HostReadonlyManagerScheduleV2 {
    pub(super) initial: ReadonlyPropertyReceiveScheduleV2,
    pub(super) phase_materialized_bytes: usize,
    pub(super) startup_materialized_bytes: usize,
    startup_outgoing_messages: usize,
    pub(super) phase_outgoing_messages: usize,
}

impl HostReadonlyManagerScheduleV2 {
    // This is the actual added readonly manager/pair receiving requirement,
    // not a complete Host boot/worker/program peak. Those existing obligations
    // remain in the same declared Control interval and must fit alongside it.
    pub(super) fn control_preparation_demand_v2(&self)
        -> Option<aos_sandbox_core::ResourceVector>
    {
        use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
        use aos_sandbox_broker::receiving::OriginalEnrollmentPairAttemptV1;

        // Admission reaches two pair observations; the remaining six public
        // rechecks each reach one. Positive pair boot readers remain resident.
        let pairs = MAXIMUM_ATTEMPTS;
        // Admission has one primary and one independent post; each of the six
        // later checks has one post. Each actual subject reader stays resident.
        let (subject_memory, subject_files, _) =
            aos_sandbox_linux::guest_confinement::CurrentThreadSubjectOriginalV1::receiving_demand_v1()?;
        let (negative_memory, negative_files, _) =
            aos_sandbox_linux::pidfd::PidFdNegativeIdentityOriginalV1::receiving_demand_v1()?;
        let memory = aos_systemd::ReadonlyPropertyManagerOriginalV2::receiving_memory_bytes_v2(self.initial)?
            .checked_add(pairs.checked_mul(OriginalEnrollmentPairAttemptV1::receiving_memory_bytes_v2()?)?)?
            .checked_add(2 * std::mem::size_of::<super::HostComponentControlStartupV2>())?
            .checked_add((MAXIMUM_ATTEMPTS + 1).checked_mul(
                aos_sandbox_linux::boot::RootOriginalKernelBootIdAttemptV1::dominant_requested_bytes_v1()?)?)?
            .checked_add(MAXIMUM_ATTEMPTS.checked_mul(65_536 + 4096)?)?
            .checked_add(MAXIMUM_ATTEMPTS.checked_mul(subject_memory)?)?
            .checked_add(negative_memory)?;
        let incoming = self.initial.raw_receive_bytes_v2().0;
        let outgoing = self.startup_outgoing_messages
            .checked_mul(self.initial.maximum_request_bytes())?
            .checked_add(4 * 1024)?;
        let bytes = |amount| u64::try_from(amount).ok();
        Some(ResourceVector::ZERO
            .with(D::MemoryBytes, bytes(memory)?)
            .with(D::OpenFiles, bytes(pairs.checked_add(MAXIMUM_ATTEMPTS + 1)?.checked_add(self.initial.maximum_native_files_v2())?
                .checked_add(MAXIMUM_ATTEMPTS.checked_mul(subject_files)?)?.checked_add(negative_files)?)?)
            // The repeated boot readers name one proc entry; the system bus
            // connection names one Unix socket; the two actual retained proc inputs
            // name status and cgroup. Result slots/scalars are not
            // resident namespace metadata entries.
            // Subject observations reuse one additional proc namespace entry.
            .with(D::MetadataEntries, 5)
            .with(D::NetworkBytes, bytes(incoming.checked_add(outgoing)?)?)
            .with(D::ConcurrentOperations, 1))
    }

    pub(super) fn for_profile(
        profile: &ControlProfileV2,
        profile_path: &std::path::Path,
    ) -> Result<Self, OriginErrorV2> {
        let add = |left: usize, right: usize| left.checked_add(right).ok_or(OriginErrorV2::Binding);
        let multiply = |left: usize, right: usize| left.checked_mul(right).ok_or(OriginErrorV2::Binding);
        let path = profile_path.to_str().ok_or(OriginErrorV2::Binding)?;

        // A valid command contains the same pinned strings, one repeated argv0
        // path,10 fixed scalar/container fields and their maximum alignments.
        // Counting actual strings/commands avoids multiplying the largest
        // profile body by every scalar RPC. Empty pre/post arrays remain valid.
        let mut command_values = command_array_bytes(std::slice::from_ref(&profile.argv))?;
        command_values = add(command_values, command_array_bytes(&profile.exec_start_pre)?)?;
        command_values = add(command_values, command_array_bytes(&profile.exec_start_post)?)?;

        // Properties.Get wraps one concrete value in a variant. These exact
        // fixed tables are2 OpenFile tuples and2 extra FD names. Scalar values
        // (timestamps, limits, flags and invocation bytes) have fixed widths.
        let open_files = add(string_bytes(profile.pid1_path.len())?, string_bytes(path.len())?)?;
        let roles = ["aos-host-pid1-image", "aos-host-startup-profile",
            "aos-resource-image-policy-v1", "aos-resource-pid1-enrollment-v1"];
        let mut fixed_values = 0;
        for role in roles {
            fixed_values = add(fixed_values, string_bytes(role.len())?)?;
        }
        fixed_values = add(fixed_values, open_files)?;
        fixed_values = add(fixed_values, command_values)?;
        // FragmentPath's existing predicate admits at most4096 bytes. Remaining
        // fixed strings include cgroup, context, state, unit ID and invocation.
        fixed_values = add(fixed_values, string_bytes(4096)?)?;
        fixed_values = add(fixed_values, multiply(FULL_QUERY_CALLS, string_bytes(255)?)?)?;

        // D-Bus names/signatures have at most255 bytes. A legitimate response
        // has sender, destination, signature and optional error-name fields,
        // each with its real encoding and alignment; no128MiB placeholder is
        // used. Incoming malformed data is refused before announced growth.
        let reply_header = add(32, multiply(4, add(255, 16)?)?)?;
        // The outgoing producer sends only the fixed DBus/Manager/Properties
        // names and at most two bounded strings. Its small wire requirement
        // is independent of a large pinned ExecStart property response.
        let maximum_request = add(reply_header, add(multiply(2, string_bytes(255)?)?, 32)?)?;
        let full = add(fixed_values, multiply(FULL_QUERY_CALLS, reply_header)?)?;
        let producer_values = multiply(PRODUCER_QUERY_CALLS, string_bytes(255)?)?;
        let producer = add(multiply(PRODUCER_QUERY_CALLS, reply_header)?, producer_values)?;
        let per_round = add(full, producer)?;

        // Capture slot0 has no PID1 call; admission slot1 has both before and
        // after queries. The other6 old slots each enter only their post. The
        // old public MAX8 limit is unchanged. Prepare and Accept each own2 slots; Authorize and first Observe own2 more each.
        let startup_rounds = MAXIMUM_ATTEMPTS;
        let all_rounds = add(startup_rounds, EXECUTION_ATTEMPTS)?;
        let phase0_calls = add(PHASE0_CUSTOM_CALLS,
            multiply(PHASE0_OBSERVER_ROUNDS, CALLS_PER_ROUND)?)?;
        let outgoing = add(add(multiply(all_rounds, CALLS_PER_ROUND)?, 1)?, phase0_calls)?;
        let incoming = add(outgoing, 2)?;
        // The fixed compiled filter profile is also the actual allow-list used
        // by the Phase0 comparator. Its literal strings bound both filter
        // responses without allocating or parsing JSON before the quote.
        let filter = phase0_filter_wire_bytes_v2()?;
        let custom_values = add(multiply(PHASE0_BASE_CUSTOM_CALLS, string_bytes(255)?)?,
            add(multiply(2, filter)?, multiply(2, string_bytes(4096)?)?)?)?;
        let custom = add(custom_values, multiply(PHASE0_BASE_CUSTOM_CALLS, reply_header)?)?;
        let publisher = phase0_publisher_value_bytes_v1()?;
        let maximum_message = add(reply_header,
            fixed_values.max(producer_values).max(filter).max(string_bytes(4096)?)
                .max(publisher.maximum))?;
        // Requires/After can contain semantically invalid string arrays. Their
        // count is not trusted or inferred from a private profile: the SAME
        // native-enforced per-message ceiling bounds each complete reply.
        // The existing decoded_geometry_for_schedule_v2 prices Vec<String>
        // and its projection from this total materialized byte requirement.
        let dependencies = multiply(HOST_DEPENDENCY_CALLS, maximum_message)?;
        let publisher_sample = add(publisher.total,
            multiply(PUBLISHER_SAMPLE_CALLS, reply_header)?)?;
        let custom = add(custom, add(dependencies,
            multiply(PUBLISHER_SAMPLES, publisher_sample)?)?)?;
        // Initial Hello/two signals, AUTH carryover and one next primary header
        // stay in the original Control lane. Execution extends only after its
        // independent same-HostService full-vector consumption.
        let startup_materialized_bytes = add(multiply(startup_rounds, per_round)?,
            add(multiply(3, reply_header)?, 16)?)?;
        let startup_materialized_bytes = add(startup_materialized_bytes,
            add(custom, multiply(PHASE0_OBSERVER_ROUNDS, per_round)?)?)?;
        let initial = ReadonlyPropertyReceiveScheduleV2::new(
            outgoing, incoming, maximum_message, maximum_request, startup_materialized_bytes,
        ).map_err(|_| OriginErrorV2::Binding)?;

        Ok(Self {
            initial,
            phase_materialized_bytes: multiply(2, per_round)?,
            startup_materialized_bytes,
            startup_outgoing_messages: add(add(multiply(startup_rounds, CALLS_PER_ROUND)?, 1)?,
                phase0_calls)?,
            phase_outgoing_messages: multiply(2, CALLS_PER_ROUND)?,
        })
    }
}

struct PublisherValueBytesV1 {
    total: usize,
    maximum: usize,
}

fn phase0_publisher_command_bytes_v1() -> Result<usize, OriginErrorV2> {
    // The canonical publisher comparator requires one command with argv0 and
    // --boot-preparation-v1. Both path occurrences obey the SAME shared
    // schema::require_store_path predicate's 1024-byte ceiling. This quote
    // neither opens nor parses the publisher's private immutable profile.
    let path = string_bytes(1024)?;
    let mode = string_bytes("--boot-preparation-v1".len())?;
    16_usize.checked_add(96).and_then(|bytes| bytes.checked_add(path))
        .and_then(|bytes| bytes.checked_add(path))
        .and_then(|bytes| bytes.checked_add(mode)).ok_or(OriginErrorV2::Binding)
}

fn phase0_publisher_value_bytes_v1() -> Result<PublisherValueBytesV1, OriginErrorV2> {
    let add = |left: usize, right: usize| left.checked_add(right).ok_or(OriginErrorV2::Binding);
    let command = phase0_publisher_command_bytes_v1()?;
    let path = string_bytes(1024)?;
    let mut open_files = 16_usize;
    for role in ["aos-runtime-deployment-startup-profile", "aos-runtime-deployment-pid1-image"] {
        // Each a(sst) tuple has its two actual strings, readonly u64 flag and
        // maximum tuple/u64 alignment. No descriptor is transferred here.
        open_files = add(open_files, add(24, add(path, string_bytes(role.len())?)?)?)?;
    }
    // ExecStartPre/Post, ExecReload/Condition, DropInPaths and extra FD names
    // are the six exact empty arrays required by the successful comparator.
    let arrays = add(add(command, open_files)?, 6 * 16)?;
    // Bookends and remaining fixed scalars/strings retain the old 255-byte
    // scalar allowance. FragmentPath separately obeys the shared store bound;
    // the two nonempty arrays have their concrete source shapes above.
    let scalar_values = PUBLISHER_SAMPLE_CALLS.checked_mul(string_bytes(255)?)
        .ok_or(OriginErrorV2::Binding)?;
    Ok(PublisherValueBytesV1 {
        total: add(add(scalar_values, path)?, arrays)?,
        maximum: command.max(open_files).max(path).max(string_bytes(255)?),
    })
}

fn phase0_filter_wire_bytes_v2() -> Result<usize, OriginErrorV2> {
    // This selected source contains no escaped strings. Count every actual
    // literal (including the three keys) as a D-Bus string; the keys provide
    // conservative comparison-codec overhead without namespace charges.
    #[cfg(not(target_arch = "x86_64"))]
    return Err(OriginErrorV2::Binding);
    #[cfg(target_arch = "x86_64")]
    let source = super::super::HOST_SYSCALL_PROFILE;
    #[cfg(not(target_arch = "x86_64"))]
    let source = "";
    if source.as_bytes().contains(&b'\\') {
        return Err(OriginErrorV2::Binding);
    }
    let mut bytes: usize = 4 + 7 + 4 + 7; // bool/array headers and maximum alignment
    for literal in source.split('"').skip(1).step_by(2) {
        bytes = bytes.checked_add(string_bytes(literal.len())?)
            .ok_or(OriginErrorV2::Binding)?;
    }
    Ok(bytes)
}

fn string_bytes(length: usize) -> Result<usize, OriginErrorV2> {
    // u32 length, NUL and at most3 alignment bytes; the surrounding variant
    // header/alignment has separate space in the concrete table bound.
    length.checked_add(8).ok_or(OriginErrorV2::Binding)
}

fn command_array_bytes(commands: &[Vec<String>]) -> Result<usize, OriginErrorV2> {
    let mut bytes = 16_usize;
    for command in commands {
        let path = command.first().ok_or(OriginErrorV2::Binding)?;
        bytes = bytes.checked_add(96).and_then(|bytes| bytes.checked_add(string_bytes(path.len()).ok()?))
            .ok_or(OriginErrorV2::Binding)?;
        for argument in command {
            bytes = bytes.checked_add(string_bytes(argument.len())?).ok_or(OriginErrorV2::Binding)?;
        }
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_wire_bound_follows_actual_argv_and_empty_auxiliary_arrays() {
        assert_eq!(command_array_bytes(&[]).unwrap(), 16);
        let command = vec!["/nix/store/host/bin/host".to_owned(), "a".repeat(70_000)];
        let bound = command_array_bytes(&[command.clone()]).unwrap();

        assert!(bound > 70_000);
        assert!(bound < 2 * 70_000);
        assert_eq!(command_array_bytes(&[command.clone(), command]).unwrap(), 2 * bound - 16);
    }

    #[test]
    fn component_phase0_prices_its_actual_custom_and_observer_rosters() {
        assert_eq!(PHASE0_BASE_CUSTOM_CALLS, 108);
        assert_eq!(HOST_DEPENDENCY_CALLS, 2);
        assert_eq!(PUBLISHER_SAMPLE_CALLS, 43);
        assert_eq!(PHASE0_CUSTOM_CALLS, 196);
        assert_eq!(PHASE0_OBSERVER_ROUNDS * CALLS_PER_ROUND, 104);
        assert_eq!(PHASE0_CUSTOM_CALLS + PHASE0_OBSERVER_ROUNDS * CALLS_PER_ROUND, 300);
        let filter = phase0_filter_wire_bytes_v2().unwrap();
        let literal_bytes: usize = super::super::super::HOST_SYSCALL_PROFILE
            .split('"').skip(1).step_by(2).map(str::len).sum();
        assert!(filter > literal_bytes);
        assert!(filter < 98_504);
    }

    #[test]
    fn publisher_quote_uses_the_actual_two_argument_command_and_empty_arrays() {
        let path = format!("/nix/store/{}-{}", "0".repeat(32), "p".repeat(980));
        assert_eq!(path.len(), 1024);
        aos_sandbox_broker::profile_data::schema::require_store_path(&path).unwrap();
        let command = vec![path.clone(), "--boot-preparation-v1".to_owned()];

        let quote = phase0_publisher_value_bytes_v1().unwrap();
        assert_eq!(phase0_publisher_command_bytes_v1().unwrap(),
            command_array_bytes(&[command]).unwrap());
        assert!(quote.maximum >= phase0_publisher_command_bytes_v1().unwrap());
        assert!(quote.total > quote.maximum + 6 * command_array_bytes(&[]).unwrap());
        assert!(quote.maximum < 3 * string_bytes(path.len()).unwrap());

        assert!(aos_sandbox_broker::profile_data::schema::require_store_path(
            &(path + "p")).is_err());
    }

    #[test]
    fn boot_schedule_funds_all_requests_and_two_bounded_dependency_replies() {
        // Geometry-only input: this creates no validated profile or native
        // original. The actual caller supplies its already pinned profile.
        let profile = ControlProfileV2 {
            version: 3,
            pid1_path: "/nix/store/pid1/lib/systemd/systemd".to_owned(),
            pid1_sha256: [1; 32],
            host_path: "/nix/store/host/bin/aos-sandbox-hostd".to_owned(),
            host_sha256: [2; 32],
            argv: vec!["/nix/store/host/bin/aos-sandbox-hostd".to_owned()],
            exec_start_pre: Vec::new(),
            exec_start_post: Vec::new(),
            unit_sha256: [3; 32],
            policy_path: "/nix/store/policy/policy".to_owned(),
            policy_sha256: [4; 32],
            payload_programs_path: "/nix/store/programs/programs".to_owned(),
            payload_programs_sha256: [5; 32],
            parent_resources: [0; 22],
            cpu_period_usec: 1,
            host_service_limits: [0; 4],
            kind: "host".to_owned(),
            node: [6; 16],
            resource_epoch: [7; 16],
            resource_policy_sha256: [8; 32],
            host_service: [0; 22],
            host_control: [0; 22],
            host_execution_receiving: None,
        };

        let schedule = HostReadonlyManagerScheduleV2::for_profile(
            &profile, std::path::Path::new("/nix/store/profile/profile.json")).unwrap();

        assert_eq!(schedule.initial.outgoing_messages(), 1237);
        assert_eq!(schedule.initial.incoming_messages(), 1239);
        assert_eq!(schedule.startup_outgoing_messages, 717);
        assert_eq!(schedule.phase_outgoing_messages, 104);
        assert_eq!(schedule.initial.maximum_materialized_bytes(),
            schedule.startup_materialized_bytes);
        let publisher = phase0_publisher_value_bytes_v1().unwrap();
        assert!(schedule.initial.maximum_message_bytes() > publisher.maximum);
        assert!(schedule.startup_materialized_bytes
            > 2 * schedule.initial.maximum_message_bytes() + 2 * publisher.total);
        assert!(aos_systemd::ReadonlyPropertyManagerOriginalV2::receiving_memory_bytes_v2(
            schedule.initial).is_some());
    }

    #[test]
    fn finite_round_count_preserves_old_limits_and_prices_the_launch_interval() {
        assert_eq!(MAXIMUM_ATTEMPTS * CALLS_PER_ROUND + 1, 417);

        // Prepare, Accept, Authorize and first Observe retain their old eight
        // rounds. The genuine Launch adds its own before and independent post.
        let launch_rounds = 2;
        assert_eq!(EXECUTION_ATTEMPTS, 8 + launch_rounds);
        assert_eq!((MAXIMUM_ATTEMPTS + EXECUTION_ATTEMPTS - launch_rounds) * CALLS_PER_ROUND + 1, 833);
        assert_eq!((MAXIMUM_ATTEMPTS + EXECUTION_ATTEMPTS) * CALLS_PER_ROUND + 1, 937);
    }
}
