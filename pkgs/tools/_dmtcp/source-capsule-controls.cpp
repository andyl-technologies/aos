/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (C) 2026 Andyl, Inc.
 * Source capsule/account model controls; no source issuance or native authority.
 */
#include "crucible_exec_state.h"
#include "crucible_source_capsule.h"
#include "crucible_source_custody.h"
#include "crucible_source_capsule_reader.h"
#include <cassert>
#include <cstdio>

namespace {
namespace capsule = dmtcp_crucible::source_capsule;
namespace state = dmtcp_crucible::exec_state;
state::State original;
unsigned char body[capsule::MaximumBytes];

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


void complete_envelope()
{
    capsule::Header original_header;
    original_header.process = 21;
    original_header.thread = 23;
    original_header.uid = 0;
    original_header.worker = 24;
    original_header.descriptor = 843;
    original_header.device = 47;
    original_header.inode = 53;
    for (unsigned index = 0; index < capsule::SectionCount; ++index) {
        original_header.section_bytes[index] = capsule::SectionLimits[index];
    }
    original_header.cookie[0] = 0;
    original_header.cookie[31] = 0xfe;

    const size_t extent = capsule::extent(original_header);
    assert(extent > 8 * 1024 * 1024 && extent < sizeof(body));
    assert(capsule::encode(original_header, body, sizeof(body)));
    capsule::Header borrowed;
    assert(capsule::decode(body, extent, borrowed));
    assert(borrowed.process == 21 && borrowed.thread == 23 && borrowed.uid == 0);
    assert(borrowed.worker == 24 && borrowed.descriptor == 843);
    assert(borrowed.inode == 53 && borrowed.cookie[31] == 0xfe);
    for (unsigned index = 0; index < capsule::SectionCount; ++index) {
        assert(borrowed.section_bytes[index] == capsule::SectionLimits[index]);
    }
    assert(!capsule::decode(body, extent - 1, borrowed));
    assert(!capsule::decode(body, extent + 1, borrowed));
    body[15] = 2;
    assert(!capsule::decode(body, extent, borrowed));
    body[15] = 1;
    body[159] = 1;
    assert(!capsule::decode(body, extent, borrowed));
    body[159] = 0;
    assert(!capsule::encode(original_header, body, capsule::HeaderBytes - 1));
    original_header.section_bytes[2] += 1;
    assert(capsule::extent(original_header) == 0);
    original_header.section_bytes[2] = 0;
    assert(capsule::extent(original_header) == 0);
    original_header.section_bytes[2] = capsule::SectionLimits[2];
    original_header.worker = original_header.process;
    assert(capsule::extent(original_header) == 0);
    original_header.worker = 24;
    original_header.descriptor = 1024;
    assert(capsule::extent(original_header) == 0);
    original_header.descriptor = 843;
    original_header.process = static_cast<std::uint64_t>(INT32_MAX) + 1;
    assert(capsule::extent(original_header) == 0);
}

void nonrenewing_export()
{
    capsule::OriginalExport refused;
    assert(!refused.reserve(512));
    refused.admitted = true;
    assert(!refused.reserve(capsule::HeaderBytes - 1));
    assert(!refused.reserve(capsule::MaximumBytes + 1));
    assert(refused.reserve(512));
    assert(!refused.reserve(512));
    assert(refused.attempted && refused.charged == 512 && !refused.settled);
    assert(!refused.finish(513, 0));
    assert(!refused.finish(-2, EIO));
    assert(!refused.finish(-1, 0));
    assert(!refused.finish(512, EIO));
    assert(refused.finish(13, 0));
    assert(refused.settled && refused.written == 13 && refused.charged == 512);
    assert(!refused.finish(512, 0));
    assert(!refused.reserve(512));

    capsule::OriginalExport failed;
    failed.admitted = true;
    assert(failed.reserve(512));
    assert(failed.finish(-1, ENOSPC));
    assert(failed.charged == 512 && failed.written == -1 && failed.error == ENOSPC);
    assert(!failed.reserve(512));
}

void coordinator_exec_debits()
{
    populate();
    assert(state::consistent(original));
    assert(state::consistent_attempts(original, 1));
    assert(!state::consistent_attempts(original, 0));
    original.exec_attempts = 0;
    assert(!state::consistent(original));
    assert(state::consistent_attempts(original, 0));
    assert(!state::consistent_attempts(original, 2));
    original.log.attempted = 0;
    assert(!state::consistent_attempts(original, 0));
    original.log.attempted = 8;
    original.channels.channels[0].incoming.store(true);
    assert(!state::consistent_attempts(original, 0));
}

void full_restart_storage()
{
    namespace custody = dmtcp_crucible::source_custody;
    dmtcp_crucible::restart_writer::OriginalAccount source;
    dmtcp_crucible::restart_writer::OriginalAccount borrowed;
    source.initialized = true;
    source.process = 719;
    source.uid = 103;
    source.root_descriptor = 41;
    source.device = 123;
    source.root_inode = 789;
    source.count = 1;
    source.attempted_links = 1;
    source.charged = 13;
    std::memcpy(source.root, "/private/image", 15);
    source.root[PATH_MAX - 1] = static_cast<char>(0xcf);
    auto &file = source.files[0];
    std::memcpy(file.leaf, "script", 7);
    file.descriptor = 59;
    file.device = 123;
    file.inode = 791;
    file.charged = 13;
    file.adopted = true;
    file.close_attempted = true;
    file.closed = true;
    source.files[63].leaf[255] = static_cast<char>(0xe1);
    auto &link = source.links[0];
    std::memcpy(link.alias, "latest", 7);
    link.file_index = 0;
    link.charged = 7;
    link.unlink_attempted = true;
    link.create_attempted = true;
    link.created = true;
    source.links[63].alias[255] = static_cast<char>(0xe2);

    state::Writer encoded(body, capsule::SectionLimits[1]);
    custody::restart_fields(encoded, source);
    assert(encoded.valid());
    state::Reader decoded(body, encoded.size());
    custody::restart_fields(decoded, borrowed);
    assert(decoded.complete());
    assert(borrowed.root_descriptor == 41 && borrowed.process == 719);
    assert(borrowed.root[PATH_MAX - 1] == static_cast<char>(0xcf));
    assert(borrowed.files[0].descriptor == 59 && borrowed.files[0].charged == 13);
    assert(borrowed.files[0].closed && borrowed.files[0].close_attempted);
    assert(borrowed.files[63].leaf[255] == static_cast<char>(0xe1));
    assert(borrowed.links[0].charged == 7 && borrowed.links[0].created);
    assert(borrowed.links[63].alias[255] == static_cast<char>(0xe2));
    assert(!dmtcp_crucible::restart_writer::account().initialized);
}

void full_final_storage()
{
    static dmtcp_crucible::OriginalFinalExchange source;
    static dmtcp_crucible::OriginalFinalExchange borrowed;
    source.settled.store(true);
    source.attempted = true;
    source.received = true;
    source.acknowledged = true;
    source.process = 719;
    source.body_length = 3;
    source.request_transferred = 211;
    source.response_transferred = 208;
    source.request[0] = 0xfa;
    source.response[207] = 0xfe;
    source.body[0] = 0;
    source.body[1] = 0x89;
    source.body[2] = 0;
    source.body[sizeof(source.body) - 1] = 0xca;

    state::Writer encoded(body, capsule::SectionLimits[2]);
    dmtcp_crucible::source_custody::final_fields(encoded, source);
    assert(encoded.valid());
    state::Reader decoded(body, encoded.size());
    dmtcp_crucible::source_custody::final_fields(decoded, borrowed);
    assert(decoded.complete());
    assert(borrowed.settled.load() && borrowed.attempted && borrowed.acknowledged);
    assert(borrowed.body_length == 3 && borrowed.request_transferred == 211);
    assert(std::memcmp(source.request, borrowed.request, sizeof(source.request)) == 0);
    assert(std::memcmp(source.response, borrowed.response, sizeof(source.response)) == 0);
    assert(std::memcmp(source.body, borrowed.body, sizeof(source.body)) == 0);
    assert(!dmtcp_crucible::final_exchange().attempted);
}

}

int main(int argc, char **argv)
{
    if (argc == 2 || argc == 3) {
        FILE *input = std::fopen(argv[1], "rb");
        assert(input != nullptr);
        const size_t extent = std::fread(body, 1, sizeof(body), input);
        assert(extent < sizeof(body) && std::feof(input) && !std::ferror(input));
        assert(std::fclose(input) == 0);
        static capsule::Candidate candidate;
        const bool accepted_preservation = capsule::decode_preservation(body, extent, candidate);
        if (argc == 3) {
            assert(std::strcmp(argv[2], "refused") == 0);
            assert(!accepted_preservation);
        } else {
            assert(accepted_preservation);
        }
        assert(!dmtcp_crucible::log_writer::account().initialized);
        assert(!dmtcp_crucible::restart_writer::account().initialized);
        assert(!dmtcp_crucible::final_exchange().attempted);
        puts(argc == 3 ? "authored native capsule mutation REFUSED; no native authority" :
             "actual original native capsule readback PASS; no native authority");
        return 0;
    }
    assert(argc == 1);
    complete_envelope();
    nonrenewing_export();
    coordinator_exec_debits();
    full_restart_storage();
    full_final_storage();
    puts("source capsule: five control groups PASS; no native authority");
}
