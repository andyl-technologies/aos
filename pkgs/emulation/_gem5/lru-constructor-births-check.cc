// SPDX-License-Identifier: MIT
// Exercises the actual private bank, not a native graph or source permit.
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <new>
#include <type_traits>
#include <typeinfo>

// This facade contains the byte-exact complete upstream declaration, extracted
// from the matching full source. It is not a configured gem5 translation unit.
#include "replacement-data.facade.hh"
#include "sim/crucible_kernel_process.hh"
#include "sim/crucible_native_cut.hh"
#define private public
#include "sim/crucible_native_scope.hh"
#undef private

using Bank = gem5::crucible::LruConstructorBirths;
using Data = gem5::replacement_policy::ReplacementData;

struct FixtureData : Data { std::uint64_t tick = 0; };

// Literal original source wrapper shape, with a separate fixture name. Its
// compiler quote is not the installed old binary's storageBytes() observation.
struct LiteralLifetimeWrapper
{
    alignas(gem5::crucible::OriginalNodeScope)
        unsigned char storage[sizeof(gem5::crucible::OriginalNodeScope)];
    gem5::crucible::OriginalNodeScope *active = nullptr;
    bool reserved = false;
};

const gem5::SimObject *
policyIdentity(const void *marker)
{
    // These identities are compared only. No fixture pretends to construct or
    // dereference a native SimObject, LRU policy, graph or execution permit.
    return static_cast<const gem5::SimObject *>(marker);
}

int
main()
{
    static_assert(!std::is_polymorphic_v<Data>);
    static_assert(sizeof(Data) == 1);
    static_assert(!std::is_copy_constructible_v<Bank>);
    static_assert(!std::is_move_constructible_v<Bank>);
    const unsigned firstMarker = 1;
    const unsigned secondMarker = 2;
    const auto *policy = policyIdentity(&firstMarker);
    const auto *otherPolicy = policyIdentity(&secondMarker);

    {
        std::shared_ptr<Data> data(new FixtureData());
        assert(typeid(*data) == typeid(Data));
        assert(typeid(*data) != typeid(FixtureData));
        std::puts("PASS nonpolymorphic-original-rtti-refuses-valid-data");
    }

    {
        Bank bank;
        const auto reservation = bank.reserve(policy);
        assert(!bank.complete());
        std::shared_ptr<Data> data(new FixtureData());
        assert(bank.publish(reservation, policy, data));
        assert(bank.matches(policy, data));
        assert(!bank.matches(otherPolicy, data));
        assert(!bank.matches(policy, {}));
        assert(bank.complete());
        std::puts("PASS source-birth-and-original-policy-ownership");
    }

    {
        Bank bank;
        const auto reservation = bank.reserve(policy);
        std::shared_ptr<Data> data(new FixtureData());
        assert(bank.publish(reservation, policy, data));

        std::shared_ptr<Data> foreignOwner(data.get(), [](Data *) {});
        assert(foreignOwner.get() == data.get());
        assert(!bank.matches(policy, foreignOwner));
        std::shared_ptr<Data> foreignData(new FixtureData());
        assert(!bank.matches(policy, foreignData));
        std::shared_ptr<Data> ownerless(std::shared_ptr<Data>{}, data.get());
        assert(ownerless && ownerless.use_count() == 0);
        assert(!bank.matches(policy, ownerless));
        const auto borrowedReservation = bank.reserve(otherPolicy);
        assert(!bank.publish(borrowedReservation, otherPolicy, foreignOwner));
        assert(bank.failed);
        std::puts("PASS same-pointer-foreign-control-block-and-unborn-data-refuse");
    }

    {
        Bank bank;
        alignas(FixtureData) std::byte storage[sizeof(FixtureData)];
        const auto destroy = [](Data *value) {
            static_cast<FixtureData *>(value)->~FixtureData();
        };
        const auto firstReservation = bank.reserve(policy);
        auto *first = new (storage) FixtureData();
        std::shared_ptr<Data> original(first, destroy);
        assert(bank.publish(firstReservation, policy, original));
        original.reset();
        assert(!bank.complete());

        const auto secondReservation = bank.reserve(policy);
        auto *second = new (storage) FixtureData();
        assert(second == first);
        std::shared_ptr<Data> replacement(second, destroy);
        assert(!bank.matches(policy, replacement));
        assert(!bank.publish(secondReservation, policy, replacement));
        assert(bank.failed && !bank.matches(policy, replacement));
        // No native retirement/reuse transition is implemented. Neither the
        // original slot nor a new reservation can repair that original bank.
        assert(!bank.complete() && bank.used == 2);
        std::puts("PASS expired-birth-and-actual-address-reuse-remain-distinct");
    }

    {
        Bank bank;
        const auto reservation = bank.reserve(policy);
        std::shared_ptr<Data> data(new FixtureData());
        assert(bank.publish(reservation, policy, data));
        assert(!bank.publish(reservation, policy, data));
        assert(bank.used == 1 && bank.failed);
        assert(!bank.complete() && !bank.matches(policy, data));
        std::puts("PASS repeated-publication-is-sticky-without-credit-renewal");
    }

    {
        Bank original;
        Bank foreign;
        const auto reservation = original.reserve(policy);
        std::shared_ptr<Data> data(new FixtureData());
        assert(!foreign.publish(reservation, policy, data));
        assert(foreign.failed && foreign.used == 0);
        assert(!original.complete() && original.used == 1);
        std::puts("PASS foreign-bank-reservation-cannot-be-adopted");
    }

    {
        Bank bank;
        const auto reservation = bank.reserve(policy);
        std::shared_ptr<Data> data(new FixtureData());
        assert(!bank.publish(reservation, otherPolicy, data));
        assert(bank.failed && bank.used == 1);
        assert(!bank.matches(policy, data));
        std::puts("PASS constructor-policy-cannot-be-replaced-at-publication");
    }

    {
        Bank bank;
        bank.reserve(policy);
        const auto later = bank.reserve(policy);
        std::shared_ptr<Data> data(new FixtureData());
        assert(bank.publish(later, policy, data));
        assert(!bank.complete() && bank.used == 2);
        std::puts("PASS abandoned-constructor-reservation-remains-incomplete");
    }

    {
        Bank bank;
        std::array<std::shared_ptr<Data>, Bank::Capacity> data;
        for (auto &entry : data) {
            const auto reservation = bank.reserve(policy);
            entry = std::shared_ptr<Data>(new FixtureData());
            assert(bank.publish(reservation, policy, entry));
        }
        assert(bank.complete() && bank.used == 1472);
        assert(bank.reserve(policy).bank == nullptr);
        assert(bank.failed && bank.used == 1472 && !bank.complete());
        std::puts("PASS finite-capacity-refuses-before-another-data-allocation");
    }

    std::printf("{\"schema\":\"gem5.lru-birth-component.v1\","
                "\"controls\":9,\"weak_ptr_bytes\":%zu,\"fixed_bank_bytes\":%zu,"
                "\"scope_header_bytes\":%zu,\"literal_wrapper_bytes\":%zu,"
                "\"maximum_retained_control_block_obligations\":%zu,"
                "\"native_authority\":false,\"physical_heap_qualified\":false}\n",
                sizeof(std::weak_ptr<Data>), sizeof(Bank),
                sizeof(gem5::crucible::OriginalNodeScope),
                sizeof(LiteralLifetimeWrapper), Bank::Capacity);
}
