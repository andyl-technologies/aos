/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (C) 2026 Andyl, Inc.
 * Original map-envelope accounting controls; no native source authority.
 */
#include "crucible_map_envelope.h"
#include "crucible_map_source_capsule.h"
#include "crucible_map_codec.h"

#include <cassert>
#include <cerrno>
#include <cstdio>

namespace {
namespace envelope = dmtcp_crucible::map_envelope;
envelope::OriginalAccount source;
unsigned char body[envelope::WireBodyBytes];
unsigned char cookie[32];

void exact_original_geometry()
{
    assert(envelope::request_geometry(18, 110688, 110706 + envelope::PrefixBytes));
    assert(!envelope::request_geometry(18, 110688, 110706));
    assert(!envelope::request_geometry(0, 110688, 110688 + envelope::PrefixBytes));
    assert(!envelope::request_geometry(18, 0, 18 + envelope::PrefixBytes));
    assert(!envelope::request_geometry(envelope::OriginalBodyBytes, 1,
                                      envelope::OriginalBodyBytes + 1 + envelope::PrefixBytes));
    assert(envelope::request_geometry(18, envelope::OriginalBodyBytes - 18,
                                     envelope::WireBodyBytes));
    assert(envelope::reply_geometry(2, 2 + envelope::PrefixBytes));
    assert(envelope::reply_geometry(110688, 110688 + envelope::PrefixBytes));
    assert(!envelope::reply_geometry(0, envelope::PrefixBytes));
    assert(!envelope::reply_geometry(envelope::OriginalBodyBytes + 1,
                                    envelope::WireBodyBytes + 1));
}

void explicit_original_prefix()
{
    cookie[31] = 0xfb;
    envelope::prefix(body, cookie, false);
    assert(envelope::prefix_matches(body, sizeof(body), cookie, false));
    assert(!envelope::prefix_matches(body, sizeof(body), cookie, true));
    assert(!envelope::prefix_matches(body, envelope::PrefixBytes - 1, cookie, false));
    body[8] = 1;
    assert(!envelope::prefix_matches(body, sizeof(body), cookie, false));
    envelope::prefix(body, cookie, true);
    assert(envelope::prefix_matches(body, sizeof(body), cookie, true));
    body[7] = '2';
    assert(!envelope::prefix_matches(body, sizeof(body), cookie, true));
}

void exact_map_strings()
{
    std::memset(body, 'x', sizeof(body));
    constexpr char key[] = "ProcSelfMaps_Ckpt";
    std::memcpy(body, key, sizeof(key));
    body[110705] = 0;
    assert(envelope::exact_cstrings(body, 110706, 2));
    assert(!envelope::exact_cstrings(body, 110706, 1));
    assert(!envelope::exact_cstrings(body, 110705, 2));
    body[envelope::OriginalBodyBytes - 1] = 0;
    assert(!envelope::exact_cstrings(body, envelope::OriginalBodyBytes, 2));
    body[110705] = 'x';
    assert(envelope::exact_cstrings(body, envelope::OriginalBodyBytes, 2));
    assert(!envelope::exact_cstrings(body, envelope::OriginalBodyBytes + 1, 2));
    assert(!envelope::exact_cstrings(body, envelope::OriginalBodyBytes, 3));
    assert(!envelope::exact_cstrings(body, envelope::OriginalBodyBytes, 0));
}

unsigned char capsule_body[dmtcp_crucible::map_source_capsule::MaximumBytes];

void complete_map_capsule_envelope()
{
    namespace capsule = dmtcp_crucible::map_source_capsule;
    capsule::Header header;
    header.process = 21;
    header.thread = 23;
    header.uid = 103;
    header.worker = 24;
    header.descriptor = 843;
    header.device = 47;
    header.inode = 53;
    for (unsigned index = 0; index < capsule::SectionCount; ++index)
        header.section_bytes[index] = capsule::SectionLimits[index];
    header.cookie[31] = 0xfe;
    const size_t extent = capsule::extent(header);
    assert(extent > 19 * 1024 * 1024 && extent < sizeof(capsule_body));
    assert(capsule::encode(header, capsule_body, sizeof(capsule_body)));
    capsule::Header readback;
    assert(capsule::decode(capsule_body, extent, readback));
    assert(readback.process == 21 && readback.worker == 24 && readback.cookie[31] == 0xfe);
    for (unsigned index = 0; index < capsule::SectionCount; ++index)
        assert(readback.section_bytes[index] == capsule::SectionLimits[index]);
    assert(!capsule::decode(capsule_body, extent - 1, readback));
    capsule_body[15] = 2;
    assert(!capsule::decode(capsule_body, extent, readback));
    capsule_body[15] = 1;
    capsule_body[191] = 1;
    assert(!capsule::decode(capsule_body, extent, readback));
    capsule_body[191] = 0;
    std::memcpy(capsule_body, "DCPCCP01", 8);
    assert(!capsule::decode(capsule_body, extent, readback));

    capsule::OriginalExport output;
    output.admitted = true;
    assert(output.reserve(extent));
    assert(output.finish(13, 0));
    assert(output.charged == extent && output.written == 13 && output.settled);
    assert(!output.reserve(extent) && !output.finish(14, 0));
    header.section_bytes[4] += 1;
    assert(capsule::extent(header) == 0);
}

void distinct_large_final_codec()
{
    namespace codec = dmtcp_crucible::map_codec;
    constexpr size_t payload = 8 * 1024 * 1024;
    std::memset(capsule_body, 0, sizeof(capsule_body));
    unsigned char expected[17] = {};
    expected[16] = 0xc7;
    std::uint64_t marker = 0x0102030405060708ULL;
    codec::Writer writer(capsule_body, codec::MaximumBytes);
    writer.unsigned_value(marker);
    writer.bytes(capsule_body + 12 * 1024 * 1024, payload);
    writer.bytes(expected, sizeof(expected));
    assert(writer.valid() && writer.size() == 8 + payload + sizeof(expected));
    assert(capsule_body[0] == 8 && capsule_body[7] == 1);
    std::uint64_t borrowed = 0;
    codec::Reader reader(capsule_body, writer.size());
    reader.unsigned_value(borrowed);
    reader.bytes(capsule_body + 12 * 1024 * 1024, payload);
    unsigned char suffix[17] = {};
    reader.bytes(suffix, sizeof(suffix));
    assert(reader.complete() && borrowed == marker && suffix[16] == 0xc7);
    codec::Writer oversized(capsule_body, codec::MaximumBytes + 1);
    assert(!oversized.valid());
    codec::Reader truncated(capsule_body, 7);
    truncated.unsigned_value(borrowed);
    assert(!truncated.complete());
    capsule_body[0] = 2;
    std::memset(capsule_body + 1, 0, 7);
    codec::Reader noncanonical(capsule_body, 8);
    bool bit = false;
    noncanonical.boolean(bit);
    assert(!noncanonical.complete());
}

void lifetime_request_and_reply_charges()
{
    assert(envelope::reserve(source, false, 17, 23) == nullptr);
    source.admitted = true;
    assert(envelope::reserve(source, false, 17, 23) == nullptr);
    source.storage_reserved = sizeof(source);
    source.process = 17;
    source.uid = 23;
    assert(envelope::reserve(source, false, 18, 23) == nullptr);
    assert(envelope::reserve(source, false, 17, 24) == nullptr);
    auto *first = envelope::reserve(source, false, 17, 23);
    assert(first == &source.operations[0]);
    assert(first->charged_request == envelope::DirectionBytes);
    assert(first->charged_reply == envelope::DirectionBytes);
    assert(!envelope::consistent(source, 208));

    // Mutation followed by a partial old-value reply remains original Unknown
    // custody, with both full maximum charges retained and no reset/refund.
    first->mutated = true;
    first->request_bytes = 110706 + envelope::PrefixBytes;
    first->reply_bytes = 110688 + envelope::PrefixBytes;
    first->request.header = 208;
    first->request.body = first->request_bytes;
    first->reply.header = 208;
    first->reply.body = 13;
    first->error = EPIPE;
    first->settled.store(true);
    first->request_body[envelope::WireBodyBytes - 1] = 0xcd;
    assert(envelope::consistent(source, 208));
    assert(first->mutated && !first->acknowledged);

    auto *second = envelope::reserve(source, true, 17, 23);
    assert(second == &source.operations[1]);
    second->error = EINVAL;
    second->settled.store(true);
    assert(source.charged_request == 2 * envelope::DirectionBytes);
    assert(source.charged_reply == 2 * envelope::DirectionBytes);
    assert(envelope::consistent(source, 208));
    assert(envelope::reserve(source, true, 17, 23) == nullptr);
    assert(first->request_body[envelope::WireBodyBytes - 1] == 0xcd);

    source.charged_reply -= 1;
    assert(!envelope::consistent(source, 208));
    source.charged_reply += 1;
    first->acknowledged = true;
    assert(!envelope::consistent(source, 208));
    first->acknowledged = false;
    first->reply.body = first->reply_bytes + 1;
    assert(!envelope::consistent(source, 208));
}
}

int main()
{
    exact_original_geometry();
    explicit_original_prefix();
    exact_map_strings();
    lifetime_request_and_reply_charges();
    complete_map_capsule_envelope();
    distinct_large_final_codec();
    puts("map envelope: six control groups PASS; no native authority");
}
