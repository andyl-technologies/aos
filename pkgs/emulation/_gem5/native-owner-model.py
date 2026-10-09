# SPDX-License-Identifier: MIT
"""Realizes the explicitly selected native owner model without running events."""


def realize(guest_isa, executable, output):
    """Constructs the bounded O3/classic-cache/DDR3 mechanism configuration."""
    import m5
    from m5.objects import (
        AddrRange, ArmO3CPU, Cache, DDR3_1600_8x8, L2XBar, MemCtrl,
        Process, Root, SEWorkload, SrcClockDomain, System, SystemXBar,
        VoltageDomain, X86O3CPU,
    )

    if guest_isa not in ("x86_64", "aarch64"):
        raise ValueError("unsupported native guest ISA")
    m5.ticks.setGlobalFrequency("1THz")
    m5.core.disableAllListeners()
    system = System()
    system.clk_domain = SrcClockDomain(
        clock="1GHz", voltage_domain=VoltageDomain()
    )
    system.mem_mode = "timing"
    system.mem_ranges = [AddrRange("512MiB")]
    system.cpu = X86O3CPU() if guest_isa == "x86_64" else ArmO3CPU()
    system.cpu.icache = Cache(
        size="32KiB", assoc=2, tag_latency=2, data_latency=2,
        response_latency=2, mshrs=8, tgts_per_mshr=8,
    )
    system.cpu.dcache = Cache(
        size="32KiB", assoc=2, tag_latency=2, data_latency=2,
        response_latency=2, mshrs=16, tgts_per_mshr=8,
    )
    system.l2bus = L2XBar()
    system.l2 = Cache(
        size="256KiB", assoc=8, tag_latency=12, data_latency=12,
        response_latency=12, mshrs=32, tgts_per_mshr=8,
    )
    system.membus = SystemXBar()
    system.cpu.icache.cpu_side = system.cpu.icache_port
    system.cpu.dcache.cpu_side = system.cpu.dcache_port
    system.cpu.icache.mem_side = system.l2bus.cpu_side_ports
    system.cpu.dcache.mem_side = system.l2bus.cpu_side_ports
    system.l2.cpu_side = system.l2bus.mem_side_ports
    system.l2.mem_side = system.membus.cpu_side_ports
    system.cpu.createInterruptController()
    if guest_isa == "x86_64":
        system.cpu.interrupts[0].pio = system.membus.mem_side_ports
        system.cpu.interrupts[0].int_requestor = system.membus.cpu_side_ports
        system.cpu.interrupts[0].int_responder = system.membus.mem_side_ports
    system.cpu.mmu.connectWalkerPorts(
        system.membus.cpu_side_ports, system.membus.cpu_side_ports
    )
    system.system_port = system.membus.cpu_side_ports
    system.mem_ctrl = MemCtrl(dram=DDR3_1600_8x8())
    system.mem_ctrl.dram.range = system.mem_ranges[0]
    system.mem_ctrl.port = system.membus.mem_side_ports
    system.workload = SEWorkload.init_compatible(executable)
    # Operational backing paths must not change the modeled guest stack or argv.
    system.cpu.workload = Process(
        executable=executable, cmd=["crucible-o3-workload"], output=output
    )
    system.cpu.createThreads()
    root = Root(full_system=False, system=system)
    m5.instantiate()
    if hasattr(m5, "crucibleConfigureConsole"):
        # The qualified stdout facet records birth inside the native syscall,
        # before another event can run. Older binaries retain diagnostic output.
        m5.crucibleConfigureConsole(int(system.cpu.workload[0].pid), 1)
    return root
