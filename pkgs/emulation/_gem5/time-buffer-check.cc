// SPDX-License-Identifier: MIT
// Exercises the real pipeline buffer with a nontrivial member constructor.

#include <cstdio>
#include <memory>

#include "base/refcnt.hh"
#include "cpu/timebuf.hh"

struct Instruction : gem5::RefCounted
{
    unsigned sequence = 31;
};

struct PipelinePayload
{
    int size;
    gem5::RefCountingPtr<Instruction> instructions[8];
    std::shared_ptr<Instruction> fault;
    unsigned long faultSequence;
    bool clearFault;
};

bool
empty(const PipelinePayload &payload)
{
    return payload.size == 0 && !payload.instructions[0] && !payload.fault &&
           payload.faultSequence == 0 && !payload.clearFault;
}

int
main()
{
    gem5::TimeBuffer<PipelinePayload> buffer(5, 5);
    for (int index = -5; index <= 5; ++index) {
        auto *payload = buffer.access(index);
        payload->size = 8;
        payload->faultSequence = 37;
        payload->clearFault = true;
        payload->instructions[0] = new Instruction;
    }

    buffer.advance();
    if (!empty(*buffer.access(5))) {
        std::fputs("recycled pipeline slot contains stale state\n", stderr);
        return 1;
    }

    return 0;
}
