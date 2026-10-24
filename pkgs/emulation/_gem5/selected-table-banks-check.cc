// SPDX-License-Identifier: MIT
// Exercises exact table-account methods with pointer identities only.
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <memory>

#include "sim/crucible_kernel_process.hh"
#include "sim/crucible_native_cut.hh"
#include "sim/crucible_lru_births.hh"
#define private public
#include "sim/crucible_native_scope.hh"
#undef private

#include "selected-table-methods.hh"

using Scope = gem5::crucible::OriginalNodeScope;
using gem5::SimObject;
using gem5::ReplaceableEntry;

namespace
{

const SimObject *
objectIdentity(const void *marker)
{
    // These values are compared only; no native SimObject is constructed.
    return static_cast<const SimObject *>(marker);
}

const ReplaceableEntry *
entryIdentity(const void *marker)
{
    return static_cast<const ReplaceableEntry *>(marker);
}

gem5::crucible::KernelProcessObservation
currentProcess()
{
    using gem5::crucible::kernel_process_detail::rawCall;
    gem5::crucible::KernelProcessObservation process;
    process.process = rawCall(SYS_getpid);
    process.uid = rawCall(SYS_geteuid);
    assert(rawCall(SYS_gettid) == long(process.process));
    return process;
}

struct Fixture
{
    const unsigned ownerMarker = 1;
    const unsigned indexMarker = 2;
    const unsigned otherMarker = 3;
    const SimObject *owner = objectIdentity(&ownerMarker);
    const SimObject *index = objectIdentity(&indexMarker);
    const SimObject *other = objectIdentity(&otherMarker);
    Scope scope{gem5::crucible::OriginalScopeBinding{}, currentProcess()};
    std::array<unsigned, 1281> entries{};

    Fixture()
    {
        scope.objects[0].object = owner;
        scope.objects[1].object = index;
        scope.objects[2].object = other;
        scope.objectsUsed = 3;
        scope.visiting = owner;
        scope.phase = Scope::State::Walking;
    }

    void populate(std::size_t count)
    {
        assert(scope.declareTable(owner, index, count));
        for (std::size_t slot = 0; slot < count; ++slot)
            assert(scope.tableEntry(owner, index, entryIdentity(&entries[slot])));
    }
};

void
completeActualExtent()
{
    Fixture fixture;
    fixture.populate(1280);
    auto &scope = fixture.scope;
    assert(scope.tablesUsed == 1 && scope.tables[0].expected == 1280);
    scope.visiting = fixture.index;
    for (std::size_t slot = 1280; slot-- > 0;)
        assert(scope.indexedEntry(fixture.index, entryIdentity(&fixture.entries[slot])));
    assert(scope.tablesComplete(fixture.index));
    std::puts("PASS actual1280-complete-entry-index-bijection");
}

void
oversizeBeforeDebit()
{
    Fixture fixture;
    assert(!fixture.scope.declareTable(fixture.owner, fixture.index, 1281));
    assert(fixture.scope.tablesUsed == 0);
    assert(fixture.scope.tables[0].used == 0);
    assert(fixture.scope.tables[0].expected == 0);
    assert(fixture.scope.state() == Scope::State::Refused);
    std::puts("PASS oversized-declaration-refuses-before-slot-or-entry-debit");
}

void
duplicateDeclaration()
{
    Fixture fixture;
    assert(fixture.scope.declareTable(fixture.owner, fixture.index, 2));
    assert(fixture.scope.tableEntry(fixture.owner, fixture.index,
                                   entryIdentity(&fixture.entries[0])));
    assert(!fixture.scope.declareTable(fixture.owner, fixture.index, 1));
    assert(fixture.scope.tablesUsed == 1 && fixture.scope.tables[0].used == 1);
    assert(fixture.scope.tables[0].expected == 2);
    std::puts("PASS duplicate-declaration-cannot-reset-partial-account");
}

void
undeclaredEntry()
{
    Fixture fixture;
    assert(!fixture.scope.tableEntry(fixture.owner, fixture.index,
                                    entryIdentity(&fixture.entries[0])));
    assert(fixture.scope.tablesUsed == 0);
    std::puts("PASS entry-without-original-declaration-refuses");
}

void
foreignOwnerOrIndex()
{
    {
        Fixture fixture;
        assert(fixture.scope.declareTable(fixture.owner, fixture.index, 1));
        fixture.scope.visiting = fixture.other;
        assert(!fixture.scope.tableEntry(fixture.other, fixture.index,
                                        entryIdentity(&fixture.entries[0])));
        assert(fixture.scope.tables[0].used == 0);
    }
    {
        Fixture fixture;
        assert(fixture.scope.declareTable(fixture.owner, fixture.index, 1));
        assert(!fixture.scope.tableEntry(fixture.owner, fixture.other,
                                        entryIdentity(&fixture.entries[0])));
        assert(fixture.scope.tables[0].used == 0);
    }
    std::puts("PASS foreign-owner-or-index-cannot-adopt-table-account");
}

void
incompleteExtent()
{
    Fixture fixture;
    assert(fixture.scope.declareTable(fixture.owner, fixture.index, 2));
    assert(fixture.scope.tableEntry(fixture.owner, fixture.index,
                                   entryIdentity(&fixture.entries[0])));
    fixture.scope.visiting = fixture.index;
    assert(fixture.scope.indexedEntry(fixture.index,
                                     entryIdentity(&fixture.entries[0])));
    assert(!fixture.scope.tablesComplete(fixture.index));
    std::puts("PASS incomplete-declared-extent-refuses-completion");
}

void
visitedIndex()
{
    Fixture fixture;
    fixture.scope.objects[1].visit = Scope::Visit::Complete;
    assert(!fixture.scope.declareTable(fixture.owner, fixture.index, 1));
    assert(fixture.scope.tablesUsed == 0);
    std::puts("PASS visited-index-cannot-be-adopted-retrospectively");
}

void
duplicateIndex()
{
    Fixture fixture;
    fixture.populate(1);
    fixture.scope.visiting = fixture.index;
    assert(fixture.scope.indexedEntry(fixture.index,
                                     entryIdentity(&fixture.entries[0])));
    assert(!fixture.scope.indexedEntry(fixture.index,
                                      entryIdentity(&fixture.entries[0])));
    assert(fixture.scope.tables[0].used == 1);
    std::puts("PASS duplicate-index-refuses-without-renewal");
}

void
duplicateEntry()
{
    Fixture fixture;
    assert(fixture.scope.declareTable(fixture.owner, fixture.index, 2));
    assert(fixture.scope.tableEntry(fixture.owner, fixture.index,
                                   entryIdentity(&fixture.entries[0])));
    assert(!fixture.scope.tableEntry(fixture.owner, fixture.index,
                                    entryIdentity(&fixture.entries[0])));
    assert(fixture.scope.tables[0].used == 1);
    std::puts("PASS duplicate-entry-refuses-before-entry-debit");
}

} // anonymous namespace

int
main()
{
    static_assert(Scope::TableEntryCapacity == 1280);
    static_assert(Scope::TableCapacity == 16);
    completeActualExtent();
    oversizeBeforeDebit();
    duplicateDeclaration();
    undeclaredEntry();
    foreignOwnerOrIndex();
    incompleteExtent();
    visitedIndex();
    duplicateIndex();
    duplicateEntry();
    std::printf("{\"schema\":\"gem5.table-bank-component.v1\",\"controls\":9,"
                "\"table_slots\":16,\"table_entry_slots\":1280,"
                "\"scope_header_bytes\":%zu,\"table_backing_bytes\":%zu,"
                "\"native_authority\":false,\"configured_tu_qualified\":false}\n",
                sizeof(Scope), sizeof(Scope::tables));
}
