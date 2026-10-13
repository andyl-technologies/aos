/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (C) 2026 Andyl, Inc.
 * Actual selected exec-state codec controls; no source authority is exercised.
 */
#include "crucible_exec_custody.h"
#include "crucible_restart_writer.h"

#include <cassert>
#include <cstdio>

namespace {

using dmtcp_crucible::exec_state::State;
namespace codec = dmtcp_crucible::exec_state;

State original;
State candidate;
unsigned char body[codec::MaximumBytes];
unsigned char round_trip[codec::MaximumBytes];

void populate()
{
    original.log.initialized = true;
    original.log.process = 719;
    original.log.uid = 103;
    original.log.count = 2;
    original.log.attempt_count = 2;
    original.log.attempted = 8;
    original.log.root_descriptor = 57;
    original.log.root_device = 187;
    original.log.root_inode = 987;
    std::memcpy(original.log.log_path, "/example/private/log", 21);
    std::memcpy(original.log.log_leaf, "log", 4);

    auto &first = original.log.messages[0];
    std::memcpy(first.body, "a\0bc", 4);
    first.length = 4;
    first.completed = true;
    first.attempted[0] = true;
    first.written[0] = 4;
    // This suffix is original retained storage, not printable message text.
    first.body[7000] = static_cast<char>(0xc7);

    auto &second = original.log.messages[1];
    std::memcpy(second.body, "fail", 4);
    second.length = 4;
    second.completed = true;
    second.attempted[1] = true;
    second.written[1] = -1;
    second.write_error[1] = ENOSPC;
    original.log.refusal.store(dmtcp_crucible::log_writer::Refusal::WriteFailure);

    for (unsigned index = 0; index < 2; ++index) {
        auto &sink = original.log.sinks[index];
        sink.descriptor = 828 + index;
        sink.original_descriptor = 2 + index;
        sink.device = 19;
        sink.inode = 641 + index;
        sink.attempted = 4;
        sink.adopted = true;
        sink.birth_attempted = index == 1;
        auto &attempt = original.log.attempts[index];
        attempt.message = index;
        attempt.sink = index;
        attempt.charged = 4;
        attempt.written = index == 0 ? 4 : -1;
        attempt.write_error = index == 0 ? 0 : ENOSPC;
    }

    original.control.process.store(719);
    original.control.count = 2;
    original.channels.process = 719;
    original.channels.count = 1;
    original.channels.channels[0].device = 73;
    original.channels.channels[0].inode = 997;
    for (unsigned index = 0; index < 2; ++index) {
        auto &frame = original.control.frames[index];
        frame.attempted.store(true);
        frame.outgoing = index == 0;
        frame.complete = index == 0;
        frame.settled.store(true);
        frame.channel = -1;
        frame.extent = dmtcp_crucible::ControlHeaderBytes + 6;
        frame.transferred = index == 0 ? frame.extent : 3;
        frame.error = index == 0 ? 0 : ECONNRESET;
        frame.close_error = index == 0 ? 0 : EBADF;
        frame.header[0] = static_cast<unsigned char>(0x80 + index);
        frame.body[0] = 0;
        frame.body[1] = static_cast<unsigned char>(0xf0 + index);
        frame.body[dmtcp_crucible::ControlPayloadBytes - 1] = 0xa7;
    }
    original.requests = 64;
    original.probes = 1;
    original.exec_attempts = 1;
}

void complete_preservation()
{
    const size_t extent = codec::encode(original, body, sizeof(body));
    assert(extent > 5 * 1024 * 1024 && extent < sizeof(body));
    assert(codec::decode(body, extent, candidate));
    const size_t restored_extent = codec::encode(candidate, round_trip, sizeof(round_trip));
    assert(restored_extent == extent);
    assert(std::memcmp(body, round_trip, extent) == 0);
    assert(candidate.log.attempted == 8);
    assert(candidate.log.messages[1].written[1] == -1);
    assert(candidate.log.messages[1].write_error[1] == ENOSPC);
    assert(candidate.log.messages[0].body[7000] == static_cast<char>(0xc7));
    assert(candidate.control.frames[1].transferred == 3);
    assert(candidate.control.frames[1].body[dmtcp_crucible::ControlPayloadBytes - 1] == 0xa7);
    assert(candidate.requests == 64 && candidate.probes == 1);
    assert(!dmtcp_crucible::log_writer::account().initialized);

    assert(!codec::decode(body, extent - 1, candidate));
    body[extent] = 0;
    assert(!codec::decode(body, extent + 1, candidate));
    body[8] = 2;
    assert(!codec::decode(body, extent, candidate));
    body[8] = 1;
    body[16] ^= 1;
    assert(!codec::decode(body, extent, candidate));
    body[16] ^= 1;
    assert(codec::encode(original, round_trip, extent - 1) == 0);
    assert(!dmtcp_crucible::log_writer::account().initialized);
}

void original_debits_cannot_be_renewed()
{
    original.log.attempted = 0;
    assert(!codec::consistent(original));
    original.log.attempted = 8;
    original.log.sinks[0].attempted = 0;
    assert(!codec::consistent(original));
    original.log.sinks[0].attempted = 4;
    original.log.attempts[1].message = 0;
    original.log.attempts[1].sink = 0;
    assert(!codec::consistent(original));
    original.log.attempts[1].message = 1;
    original.log.attempts[1].sink = 1;
    original.log.messages[1].write_error[1] = 0;
    assert(!codec::consistent(original));
    original.log.messages[1].write_error[1] = ENOSPC;
    original.requests = 65;
    assert(!codec::consistent(original));
    original.requests = 64;
    original.probes = 2;
    assert(!codec::consistent(original));
    original.probes = 1;
    original.exec_attempts = 2;
    assert(!codec::consistent(original));
    original.exec_attempts = 1;
    assert(codec::consistent(original));
}

void live_lease_and_foreign_owner_are_refused()
{
    original.channels.channels[0].incoming.store(true);
    assert(!codec::consistent(original));
    original.channels.channels[0].incoming.store(false);
    original.control.frames[0].settled.store(false);
    assert(!codec::consistent(original));
    original.control.frames[0].settled.store(true);
    original.control.frames[0].channel = 0;
    assert(!codec::consistent(original));
    original.control.frames[0].channel = -1;
    original.control.process.store(720);
    assert(!codec::consistent(original));
    original.control.process.store(719);
    original.channels.count = 2;
    original.channels.channels[1].device = 73;
    original.channels.channels[1].inode = 997;
    assert(!codec::consistent(original));
    original.channels.count = 1;
    assert(codec::consistent(original));
}

void checked_scalar_decoding()
{
    unsigned char invalid_boolean[8] = {2};
    codec::Reader boolean(invalid_boolean, sizeof(invalid_boolean));
    bool flag = false;
    boolean.boolean(flag);
    assert(!boolean.complete());

    unsigned char overflow[8] = {};
    overflow[4] = 1;
    codec::Reader integer(overflow, sizeof(overflow));
    unsigned value = 0;
    integer.unsigned_value(value);
    assert(!integer.complete());

    unsigned char negative[8];
    std::memset(negative, 0xff, sizeof(negative));
    codec::Reader signed_integer(negative, sizeof(negative));
    int descriptor = 0;
    signed_integer.signed_value(descriptor);
    assert(signed_integer.complete() && descriptor == -1);
}

void complete_descriptor_records()
{
    namespace native = dmtcp_crucible::exec_custody;
    static native::Transfer first;
    static native::Transfer second;
    static unsigned char encoded[128 * 1024];
    static unsigned char restored[128 * 1024];
    first.process.host = 0xff00112233445566;
    first.process.process = 719;
    first.process.time = 0x8877665544332211;
    first.process.generation = UINT32_MAX;
    first.parent.host = 71;
    first.parent.process = 7;
    first.parent.time = 733;
    first.parent.generation = 3;
    for (unsigned index = 0; index < 32; ++index) first.cookie[index] = index;
    for (unsigned fd = 0; fd < native::DescriptorLimit; ++fd) {
        auto &row = first.descriptors[fd];
        row.present = fd % 2 == 0;
        row.flags = FD_CLOEXEC;
        row.status = O_RDONLY | O_LARGEFILE;
        row.device = 431;
        row.inode = fd + 900;
        row.mode = S_IFREG | 0600;
        row.uid = 103;
        row.offset = fd == 0 ? std::int64_t{-1} : static_cast<std::int64_t>(fd) * 17;
    }
    codec::Writer writer(encoded, sizeof(encoded));
    native::descriptor_fields(writer, first);
    assert(writer.valid());
    codec::Reader reader(encoded, writer.size());
    native::descriptor_fields(reader, second);
    assert(reader.complete());
    codec::Writer verify(restored, sizeof(restored));
    native::descriptor_fields(verify, second);
    assert(verify.valid() && verify.size() == writer.size());
    assert(std::memcmp(encoded, restored, writer.size()) == 0);
    assert(second.process.host == first.process.host);
    assert(second.process.time == first.process.time);
    assert(second.process.generation == UINT32_MAX);
    assert(second.parent.process == 7);
    assert(second.descriptors[0].offset == -1);
    assert(second.descriptors[1023].inode == 1923);
    encoded[28] = 1;
    codec::Reader generation_overflow(encoded, writer.size());
    native::descriptor_fields(generation_overflow, second);
    assert(!generation_overflow.complete());
    encoded[28] = 0;
    encoded[96] = 2;
    codec::Reader malformed(encoded, writer.size());
    native::descriptor_fields(malformed, second);
    assert(!malformed.complete());
    assert(!dmtcp_crucible::log_writer::account().initialized);
}

void kernel_identity_selection()
{
    namespace identity = dmtcp_crucible::kernel_identity;
    assert(unsetenv("CRUCIBLE_CAPTURE_EXEC_CUSTODY_POLICY") == 0);
    assert(identity::read(SYS_getpid) == -1 && errno == EACCES);
    assert(!DMTCP_IS_PROTECTED_FD(PROTECTED_CRUCIBLE_EXEC_FD));
    assert(setenv("CRUCIBLE_CAPTURE_EXEC_CUSTODY_POLICY", "exec-custody.v1", 1) == 0);
    assert(DMTCP_IS_PROTECTED_FD(PROTECTED_CRUCIBLE_EXEC_FD));
    assert(identity::read(SYS_getpid) == getpid());
    assert(identity::read(SYS_gettid) == getpid());
    assert(identity::read(SYS_read) == -1 && errno == EACCES);
    assert(setenv("CRUCIBLE_CAPTURE_EXEC_CUSTODY_POLICY", "unknown", 1) == 0);
    assert(identity::read(SYS_getpid) == -1 && errno == EACCES);
    assert(unsetenv("CRUCIBLE_CAPTURE_EXEC_CUSTODY_POLICY") == 0);
    assert(!dmtcp_crucible::log_writer::account().initialized);
}

void terminal_filename_policy()
{
    using dmtcp_crucible::restart_writer::filename_policy_admitted;
    assert(unsetenv("CRUCIBLE_CAPTURE_EXEC_CUSTODY_POLICY") == 0);
    assert(unsetenv("CRUCIBLE_CAPTURE_CONTROL_PARK_POLICY") == 0);
    assert(unsetenv("CRUCIBLE_CAPTURE_WRITER_COHORT_POLICY") == 0);
    assert(filename_policy_admitted(true));
    assert(!filename_policy_admitted(false));
    assert(setenv("CRUCIBLE_CAPTURE_EXEC_CUSTODY_POLICY", "exec-custody.v1", 1) == 0);
    assert(!filename_policy_admitted(false));
    assert(setenv("CRUCIBLE_CAPTURE_CONTROL_PARK_POLICY", "terminal.v1", 1) == 0);
    assert(!filename_policy_admitted(false));
    assert(setenv("CRUCIBLE_CAPTURE_WRITER_COHORT_POLICY", "cohort.v1", 1) == 0);
    assert(filename_policy_admitted(false));
    assert(setenv("CRUCIBLE_CAPTURE_CONTROL_PARK_POLICY", "unknown", 1) == 0);
    assert(!filename_policy_admitted(false));
    assert(unsetenv("CRUCIBLE_CAPTURE_EXEC_CUSTODY_POLICY") == 0);
    assert(setenv("CRUCIBLE_CAPTURE_CONTROL_PARK_POLICY", "terminal.v1", 1) == 0);
    assert(!filename_policy_admitted(false));
    assert(unsetenv("CRUCIBLE_CAPTURE_CONTROL_PARK_POLICY") == 0);
    assert(unsetenv("CRUCIBLE_CAPTURE_WRITER_COHORT_POLICY") == 0);
}

class KernelDescriptors {
  public:
    int open_directory()
    {
        return ::open("/proc/self/fd", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    }

    long read_entries(int directory, unsigned char *body, size_t extent)
    {
        return ::syscall(SYS_getdents64, directory, body, extent);
    }

    long close_directory(int directory)
    {
        return ::close(directory);
    }
};

void actual_high_descriptor_refusal()
{
    namespace scope = dmtcp_crucible::descriptor_scope;
    KernelDescriptors kernel;
    assert(scope::bounded_namespace(kernel));
    struct rlimit original_limits = {};
    assert(getrlimit(RLIMIT_NOFILE, &original_limits) == 0);
    assert(original_limits.rlim_max >= 2 * scope::Limit);
    const struct rlimit creation_limits = {2 * scope::Limit, original_limits.rlim_max};
    assert(setrlimit(RLIMIT_NOFILE, &creation_limits) == 0);
    const int high = fcntl(STDIN_FILENO, F_DUPFD, scope::Limit);
    assert(high >= static_cast<int>(scope::Limit));
    const struct rlimit lowered = {scope::Limit, scope::Limit};
    assert(setrlimit(RLIMIT_NOFILE, &lowered) == 0);
    // The kernel descriptor survives both reduced limits and would be missing
    // from a numerical 0..1023 scan. Actual procfs enumeration refuses it.
    assert(fcntl(high, F_GETFD) >= 0);
    assert(!scope::bounded_namespace(kernel));
    assert(close(high) == 0);
    assert(scope::bounded_namespace(kernel));

    unsigned char record[24] = {};
    const std::uint16_t extent = sizeof(record);
    std::memcpy(record + 16, &extent, sizeof(extent));
    std::memcpy(record + 19, "1024", 5);
    scope::Namespace out_of_range;
    assert(!out_of_range.observe(record, sizeof(record)));
    std::memcpy(record + 19, "0000", 5);
    scope::Namespace noncanonical;
    assert(!noncanonical.observe(record, sizeof(record)));
    std::memcpy(record + 19, "17", 3);
    scope::Namespace duplicate;
    assert(duplicate.observe(record, sizeof(record)));
    assert(!duplicate.observe(record, sizeof(record)));
    scope::Namespace truncated;
    assert(!truncated.observe(record, sizeof(record) - 1));
    assert(!dmtcp_crucible::log_writer::account().initialized);
}

} // namespace

int main()
{
    populate();
    complete_preservation();
    original_debits_cannot_be_renewed();
    live_lease_and_foreign_owner_are_refused();
    checked_scalar_decoding();
    complete_descriptor_records();
    kernel_identity_selection();
    terminal_filename_policy();
    actual_high_descriptor_refusal();
    std::puts("selected exec codec: eight control groups PASS; no native authority");
}
