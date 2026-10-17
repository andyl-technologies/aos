"""Checks production writer-generation authorization against scalar inventory fixtures.

This component fixture compiles the actual native validator and export bodies.
Its inventory callbacks model explicit refusal outcomes; it does not qualify a
live QEMU borrower barrier, userfaultfd service, or kernel placement transition.
"""

import argparse
from pathlib import Path
import subprocess
import tempfile


def function(source: str, name: str) -> str:
    start = source.index(f"int {name}(")
    opening = source.index("{", start)
    depth = 1
    cursor = opening + 1
    while depth:
        if source[cursor] == "{":
            depth += 1
        elif source[cursor] == "}":
            depth -= 1
        cursor += 1
    return source[start:cursor]


parser = argparse.ArgumentParser()
parser.add_argument("--source", required=True, type=Path)
parser.add_argument("--cc", required=True)
arguments = parser.parse_args()
source = arguments.source.read_text()
production = "\n\n".join(
    function(source, name)
    for name in (
        "qemu_plugin_crucible_ram_physical_validate_v1",
        "qemu_plugin_crucible_ram_write_generation_v1",
    )
)
fixture = r"""
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>

#define qatomic_read(pointer) (*(pointer))
static uint64_t physical_token = 11;
static uint64_t physical_topology = 7;
static uint64_t topology_generation = 7;
static uint64_t physical_device_generation = 2;
static uint64_t physical_listener_generation = 3;
static uint64_t physical_borrow_generation = 4;
static uint64_t dirty_generation = 19;
static uint64_t device_generation = 2;
static uint64_t listener_generation = 3;
static uint64_t borrow_generation = 4;
static int closure_status;
static int inventory_status;
static unsigned closure_calls;
static unsigned inventory_calls;

static uint64_t qemu_crucible_ram_physical_device_generation(void)
{
    return device_generation;
}

static uint64_t qemu_crucible_ram_physical_listener_generation(void)
{
    return listener_generation;
}

static int qemu_crucible_ram_owner_closure_validate(uint64_t token)
{
    assert(token == physical_token);
    closure_calls++;
    return closure_status;
}

static int physical_owner_inventory(uint64_t *generation)
{
    inventory_calls++;
    *generation = borrow_generation;
    return inventory_status;
}
"""
checks = r"""
static void refusal(uint64_t token, uint64_t topology, int expected)
{
    uint64_t output = UINT64_MAX;

    assert(qemu_plugin_crucible_ram_write_generation_v1(token, topology,
                                                      &output) == expected);
    assert(output == 0);
    assert(dirty_generation == 19);
}

int main(void)
{
    uint64_t output = 0;

    assert(qemu_plugin_crucible_ram_write_generation_v1(11, 7, NULL) == -EINVAL);
    refusal(0, 7, -ESTALE);
    refusal(12, 7, -ESTALE);
    refusal(11, 8, -ESTALE);
    assert(closure_calls == 0 && inventory_calls == 0);
    topology_generation++;
    refusal(11, 7, -ESTALE);
    topology_generation--;
    device_generation++;
    refusal(11, 7, -ESTALE);
    device_generation--;
    listener_generation++;
    refusal(11, 7, -ESTALE);
    listener_generation--;
    closure_status = -EPERM;
    refusal(11, 7, -EPERM);
    assert(closure_calls == 1 && inventory_calls == 0);
    closure_status = 0;
    inventory_status = -EBUSY;
    refusal(11, 7, -EBUSY);
    inventory_status = 0;
    borrow_generation++;
    refusal(11, 7, -ESTALE);
    borrow_generation--;
    assert(qemu_plugin_crucible_ram_write_generation_v1(11, 7, &output) == 0);
    assert(output == 19);
    dirty_generation = 0;
    output = UINT64_MAX;
    assert(qemu_plugin_crucible_ram_write_generation_v1(11, 7, &output) == -EOVERFLOW);
    assert(output == 0);
    puts("ram_write_generation_authorization_component=passed");
    return 0;
}
"""
with tempfile.TemporaryDirectory(prefix="ram-write-generation-") as temporary:
    temporary = Path(temporary)
    test = temporary / "authorization.c"
    binary = temporary / "authorization"
    test.write_text(fixture + "\n" + production + "\n" + checks)
    subprocess.run(
        [arguments.cc, "-std=c11", "-Wall", "-Wextra", "-Werror", str(test), "-o", str(binary)],
        check=True,
    )
    subprocess.run([str(binary)], check=True)
