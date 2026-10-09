"""Check opt-in placement and the legacy KVM component source contracts.

These checks supplement compiled transition tests. They neither observe a native
vCPU nor qualify the whole device, clock, interrupt, or output domains.
"""

import hashlib
from pathlib import Path
import sys


def body(source, declaration):
    """Select exactly one complete original production function."""
    if source.count(declaration) != 1:
        raise ValueError(f"production declaration is not unique: {declaration}")
    start = source.index(declaration)
    end = source.index("\n}\n", start) + 3
    return source[start:end]


def verify(source):
    """Preserve original editions and require guards before native effects."""
    clock_bytes = (source / "accel/kvm/crucible-clock.c").read_bytes()
    schema_bytes = (source / "qapi/run-state.json").read_bytes()
    # Complete original v1/v3 source and QAPI prefix, including the one added
    # public CPU header required for authentic paused-CPU inventory inspection.
    if hashlib.sha256(clock_bytes[:6744]).hexdigest() != (
        "f36399e0a3b79c6b793b3d39bce8eb192ffd53913ebd09b136a1d4b14802aff0"
    ):
        raise ValueError("original KVM v1/v3 implementation changed")
    if hashlib.sha256(schema_bytes[:133725]).hexdigest() != (
        "6a807fd6e62b2ce79dca0aace3bd802567c8e7fae9790d3ee2c7882c030df4bc"
    ):
        raise ValueError("original KVM QAPI prefix changed")

    clock = clock_bytes.decode()
    caller = (source / "accel/kvm/kvm-all.c").read_text()
    initialize = body(caller, "int kvm_init_vcpu(")
    assert initialize.index("kvm_crucible_userspace_bind_vcpu") < initialize.index(
        "kvm_arch_pre_create_vcpu"
    )
    put = body(caller, "static bool kvm_cpu_synchronize_put(")
    assert put.index("kvm_crucible_userspace_allow_state_put") < put.index(
        "kvm_arch_put_registers"
    )
    run = body(caller, "int kvm_cpu_exec(")
    assert run.count("kvm_vcpu_ioctl(cpu, KVM_RUN, 0)") == 1
    assert run.index("kvm_crucible_userspace_before_run") < run.index(
        "kvm_vcpu_ioctl(cpu, KVM_RUN, 0)"
    ) < run.index("kvm_crucible_userspace_after_run")
    assert run.count("kvm_crucible_userspace_after_dispatch") == 2

    setter = body(caller, "static void kvm_set_crucible_userspace(")
    assert setter.index("state->fd != -1") < setter.index(
        "state->crucible_userspace_experiment = enabled"
    )
    query = body(clock, "CrucibleKvmUserspaceInfo *qmp_x_crucible_kvm_userspace_exits(")
    assert query.index("RUN_STATE_PAUSED") < query.index("g_new0(")
    assert query.index("cpu->created && !cpu->stopped") < query.index("g_new0(")
    assert query.count("info->schema_version = 1;") == 1
    for flag in ("device_closure", "input_custody", "output_custody", "profile_qualified"):
        assert query.count(f"info->{flag} = false;") == 1
    for forbidden in ("KVM_RUN", "kvm_vcpu_ioctl", "kvm_cpu_exec", "memset("):
        assert forbidden not in query, f"inventory query must not run or clear: {forbidden}"

    schema = schema_bytes.decode()
    assert schema.count("'command': 'x-crucible-kvm-userspace-exits'") == 1
    assert "'command': 'x-crucible-kvm-userspace-clear'" not in schema
    print("KVM userspace source guards: original editions, pre-effect gates, read-only partial inventory PASS")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: kvm-userspace-exit-guards.py QEMU_SOURCE")
    verify(Path(sys.argv[1]))
