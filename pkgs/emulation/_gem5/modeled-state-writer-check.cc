// SPDX-License-Identifier: MIT
#include <cassert>
#include <cstdint>
#include <stdexcept>

#include "sim/crucible_state.hh"

int
main()
{
    gem5::CrucibleStateWriter writer;
    writer.bytes("empty", nullptr, 0);
    const uint8_t abc[] = {'a', 'b', 'c'};
    writer.bytes("payload", abc, sizeof(abc));

    assert(writer.fields.at("empty.bytes") == "0");
    assert(writer.fields.at("empty.sha256") ==
           "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert(writer.fields.at("payload.bytes") == "3");
    assert(writer.fields.at("payload.sha256") ==
           "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    bool duplicate_rejected = false;
    try {
        writer.set("payload.bytes", 4);
    } catch (const std::runtime_error &) {
        duplicate_rejected = true;
    }
    assert(duplicate_rejected);

    bool missing_storage_rejected = false;
    try {
        writer.bytes("missing", nullptr, 1);
    } catch (const std::runtime_error &) {
        missing_storage_rejected = true;
    }
    assert(missing_storage_rejected);

    gem5::CrucibleStateWriter changed;
    const uint8_t abd[] = {'a', 'b', 'd'};
    changed.bytes("payload", abd, sizeof(abd));
    assert(changed.fields.at("payload.sha256") !=
           writer.fields.at("payload.sha256"));

    gem5::CrucibleStateWriter first;
    first.set("second", -9);
    first.set("first", 1u);
    gem5::CrucibleStateWriter second;
    second.set("first", 1u);
    second.set("second", -9);
    assert(first.fields == second.fields);
    assert(first.fields.at("second") == "-9");
}
