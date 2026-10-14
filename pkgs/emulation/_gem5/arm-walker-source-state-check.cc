// SPDX-License-Identifier: MIT
// Literal native methods with modeled collaborators; no native admission.
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <typeinfo>
#include <vector>

using Tick = std::uint64_t;
static Tick fixtureTick = 73;

static Tick
curTick()
{
    return fixtureTick;
}

struct Object
{
    virtual ~Object() = default;
};

struct ArmRelease : Object {};

struct MMU : Object
{
    const ArmRelease *actualRelease;
    mutable unsigned reads = 0;

    explicit MMU(const ArmRelease *release) : actualRelease(release) {}

    const ArmRelease *release() const
    {
        ++reads;
        return actualRelease;
    }
};

struct WalkUnit : Object
{
    MMU *bound = nullptr;
    unsigned bindings = 0;

    void setMmu(MMU *value)
    {
        bound = value;
        ++bindings;
    }
};

class TableWalker;

namespace crucible
{
struct NativeClosureWalk
{
    const MMU *expectedMmu = nullptr;
    const ArmRelease *expectedRelease = nullptr;
    unsigned objects = 0;
    unsigned releaseEdges = 0;
    unsigned ports = 0;
    bool admitMmu = true;

    bool object(const TableWalker *, const Object *target, unsigned member)
    {
        ++objects;
        if (!target) return false;
        if (member == 1) return admitMmu && target == expectedMmu;
        if (member == 2) {
            ++releaseEdges;
            return target == expectedRelease;
        }
        return true;
    }

    bool port(const TableWalker *, const Object *target, unsigned member)
    {
        ++ports;
        return target && member == 5;
    }
};
} // namespace crucible

struct Port : Object
{
    bool closed = true;

    bool crucibleNativeOwned(crucible::NativeClosureWalk &, const TableWalker *) const
    {
        return closed;
    }
};

class TableWalker : public Object
{
  public:
    struct PendingSamples
    {
        struct Sample { unsigned count; Tick duration; };
        std::vector<Sample> values;

        void sample(unsigned count, Tick duration)
        {
            values.push_back({count, duration});
        }
    };

    struct Stats { PendingSamples pendingWalks; };

    MMU *mmu;
    const ArmRelease *release;
    unsigned pendingReqs;
    Tick pendingChangeTick;
    std::vector<WalkUnit *> walkUnits;
    WalkUnit *walkUnitFunctionalS1 = nullptr;
    WalkUnit *walkUnitFunctionalS2 = nullptr;
    Port *port = nullptr;
    Object *powerState = nullptr;
    Object clock;
    std::vector<int> pendingQueue;
    std::vector<int> inCompletionWalks;
    Stats stats;

    TableWalker();
    void setMmu(MMU *value);
    void pendingChange();
    bool crucibleNativeClosure(crucible::NativeClosureWalk &walk) const;

    const Object &crucibleNativeClockDomain() const
    {
        return clock;
    }
};

#include "arm-walker-source-state-methods.hh"

struct Fixture
{
    ArmRelease firstRelease;
    ArmRelease secondRelease;
    MMU first{&firstRelease};
    MMU second{&secondRelease};
    WalkUnit units[8];
    WalkUnit functionalS1;
    WalkUnit functionalS2;
    Port port;
    Object power;
    TableWalker walker;

    Fixture()
    {
        for (auto &unit : units) walker.walkUnits.push_back(&unit);
        walker.walkUnitFunctionalS1 = &functionalS1;
        walker.walkUnitFunctionalS2 = &functionalS2;
        walker.port = &port;
        walker.powerState = &power;
    }

    crucible::NativeClosureWalk walk(const MMU *mmu, const ArmRelease *release)
    {
        crucible::NativeClosureWalk result;
        result.expectedMmu = mmu;
        result.expectedRelease = release;
        return result;
    }

    void checkBindings(MMU *mmu, unsigned count)
    {
        for (const auto &unit : units)
            assert(unit.bound == mmu && unit.bindings == count);
        assert(functionalS1.bound == mmu && functionalS1.bindings == count);
        assert(functionalS2.bound == mmu && functionalS2.bindings == count);
    }
};

int
main()
{
    {
        Fixture fixture;
        assert(!fixture.walker.mmu && !fixture.walker.release);
        assert(fixture.walker.pendingReqs == 0);
        assert(fixture.walker.pendingChangeTick == fixtureTick);
        auto walk = fixture.walk(nullptr, nullptr);
        assert(!fixture.walker.crucibleNativeClosure(walk) && walk.objects == 0);
        std::puts("PASS explicit-birth-state-refuses-before-real-mmu-binding");
    }

    {
        Fixture fixture;
        fixture.walker.setMmu(&fixture.first);
        fixture.checkBindings(&fixture.first, 1);
        assert(fixture.walker.release == &fixture.firstRelease && fixture.first.reads == 1);
        auto walk = fixture.walk(&fixture.first, &fixture.firstRelease);
        assert(fixture.walker.crucibleNativeClosure(walk));
        assert(walk.objects == 14 && walk.releaseEdges == 1 && walk.ports == 1);
        std::puts("PASS actual-mmu-release-and-all-ten-unit-handoffs");
    }

    {
        Fixture fixture;
        fixture.walker.setMmu(&fixture.first);
        fixture.walker.setMmu(&fixture.second);
        fixture.checkBindings(&fixture.second, 2);
        assert(fixture.walker.release == &fixture.secondRelease);
        auto walk = fixture.walk(&fixture.second, &fixture.secondRelease);
        assert(fixture.walker.crucibleNativeClosure(walk));
        std::puts("PASS normal-rebinding-keeps-cache-and-unit-source-consistent");
    }

    {
        Fixture fixture;
        fixture.walker.setMmu(&fixture.first);
        fixture.walker.release = &fixture.secondRelease;
        auto walk = fixture.walk(&fixture.first, &fixture.firstRelease);
        assert(!fixture.walker.crucibleNativeClosure(walk));
        assert(walk.objects == 1 && walk.releaseEdges == 0 && walk.ports == 0);
        std::puts("PASS stale-release-cache-refuses-before-release-edge");
    }

    {
        Fixture fixture;
        fixture.walker.setMmu(&fixture.first);
        auto walk = fixture.walk(&fixture.second, &fixture.secondRelease);
        const auto reads = fixture.first.reads;
        assert(!fixture.walker.crucibleNativeClosure(walk));
        assert(fixture.first.reads == reads && walk.objects == 1 && walk.releaseEdges == 0);
        std::puts("PASS foreign-mmu-edge-refuses-before-release-getter");
    }

    {
        Fixture fixture;
        fixture.walker.setMmu(&fixture.first);
        fixture.walker.pendingReqs = 1;
        auto walk = fixture.walk(&fixture.first, &fixture.firstRelease);
        assert(!fixture.walker.crucibleNativeClosure(walk) && walk.objects == 0);
        assert(fixture.walker.pendingReqs == 1);
        std::puts("PASS live-pending-count-is-retained-and-refused");
    }

    {
        Fixture fixture;
        fixture.walker.setMmu(&fixture.first);
        fixture.walker.pendingQueue.push_back(1);
        auto walk = fixture.walk(&fixture.first, &fixture.firstRelease);
        assert(!fixture.walker.crucibleNativeClosure(walk) && walk.objects == 0);
        fixture.walker.pendingQueue.clear();
        fixture.walker.inCompletionWalks.push_back(1);
        assert(!fixture.walker.crucibleNativeClosure(walk) && walk.objects == 0);
        std::puts("PASS pending-and-completion-queues-remain-mandatory");
    }

    {
        Fixture fixture;
        fixture.walker.setMmu(&fixture.first);
        fixture.port.closed = false;
        auto walk = fixture.walk(&fixture.first, &fixture.firstRelease);
        assert(!fixture.walker.crucibleNativeClosure(walk) && walk.objects == 0);
        std::puts("PASS original-port-closure-refusal-is-preserved");
    }

    {
        fixtureTick = 73;
        Fixture fixture;
        fixture.walker.setMmu(&fixture.first);
        fixtureTick = 100;
        fixture.walker.pendingQueue.push_back(1);
        fixture.walker.pendingChange();

        const auto &samples = fixture.walker.stats.pendingWalks.values;
        assert(samples.size() == 1 && samples[0].count == 0 && samples[0].duration == 27);
        assert(fixture.walker.pendingReqs == 1 && fixture.walker.pendingChangeTick == 100);
        fixture.walker.pendingChange();
        assert(samples.size() == 1);

        fixtureTick = 125;
        fixture.walker.pendingQueue.clear();
        fixture.walker.pendingChange();
        assert(samples.size() == 2 && samples[1].count == 1 && samples[1].duration == 25);
        assert(fixture.walker.pendingReqs == 0 && fixture.walker.pendingChangeTick == 125);
        auto walk = fixture.walk(&fixture.first, &fixture.firstRelease);
        assert(fixture.walker.crucibleNativeClosure(walk));
        std::puts("PASS real-pending-stat-deltas-start-at-nonzero-birth-tick");
    }

    std::puts("{\"schema\":\"gem5.arm-walker-source-component.v1\",\"controls\":9,"
              "\"modeled_collaborators\":true,\"full_constructor_qualified\":false,"
              "\"configured_tu_qualified\":false,\"native_authority\":false}");
}
