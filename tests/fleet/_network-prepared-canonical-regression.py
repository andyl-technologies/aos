"""Pending canonical Network P/O realized-network regression assertions.

This module is intentionally not an executed fleet qualification. The retired
worker-provision/worker-serve canary supplied local keys and a distinct worker
path. Its PREPARED/WORKER_OK protocol is not a canonical Source receipt.

Before calling this helper, a fleet owner must supply genuine configured Root
and Netd signed Source endowments, their completed authenticated Session/SDK
request, original signed63 request/effect/lease/D, the final protected worker
profiles, PID1 P/O escrow and FL03 completion, and the committed catalog/State
result with retained namespace custody. No default operator endowment or
synthetic Source is supplied here. Full P/O failure/ACK/death/Empty and restart
coverage still require that genuine flow; this file claims no executed PASS.

The address, permanent-neighbor, interface-down, gate-identity and packet
assertions below are retained from the old canary. Existing focused lease-gate
qualification also tests arm/disarm packet semantics independently of P/O.
"""

import json


def assert_canonical_realized_network(
    vm, *, driver_pid, namespace_fd, host_interface, sandbox_interface,
    host_address, sandbox_address, prefix_length, assignment_epoch,
    assignment_digest, network_handle, allocation_generation,
    gate_fixture, ip, nft, nsenter, socat,
):
    """Checks realized state after an independently completed genuine flow."""
    GATE_FIXTURE, IP, NFT, NSENTER, SOCAT = gate_fixture, ip, nft, nsenter, socat
    LEASE = "55" * 32
    probe_sequence = 0

    def in_sandbox(pid, namespace_fd, command):
        return (
            f"{NSENTER} --net=/proc/{pid}/fd/{namespace_fd} "
            f"{command}"
        )

    def probe(direction, expected):
        nonlocal probe_sequence
        probe_sequence += 1
        port = 43000 + probe_sequence
        result = f"/run/aos-worker-probe-{probe_sequence}"
        ready = f"{result}.ready"
        unit = f"aos-worker-receiver-{probe_sequence}"
        token = f"worker-{direction}-{probe_sequence}"

        if direction == "ingress":
            receiver = in_sandbox(
                driver_pid,
                namespace_fd,
                f"{GATE_FIXTURE} receive ipv6 {port} {result} {ready}",
            )
            sender = (
                f"printf '%s' '{token}' | {SOCAT} -u - "
                f"UDP6-DATAGRAM:[{sandbox_address}]:{port}"
            )
        else:
            assert direction == "egress", direction
            receiver = (
                f"{GATE_FIXTURE} receive ipv6 {port} {result} {ready}"
            )
            sender = in_sandbox(
                driver_pid,
                namespace_fd,
                f"{SOCAT} -u - UDP6-DATAGRAM:[{host_address}]:{port}",
            )
            sender = f"printf '%s' '{token}' | {sender}"

        vm.succeed(f"rm -f {result} {result}.tmp {ready}")
        vm.succeed(
            f"systemd-run --unit={unit} --collect --service-type=simple "
            f"{receiver}"
        )
        vm.wait_until_succeeds(f"test -s {ready}", timeout=10)
        vm.succeed(f"rm -f {ready} && {sender}")
        vm.wait_until_fails(
            f"systemctl is-active --quiet {unit}.service", timeout=10
        )
        if expected:
            observed = vm.succeed(
                f"if test -e {result}; then cat {result}; "
                "else printf __missing__; fi"
            )
            assert observed == token, (direction, observed, token)
        else:
            vm.fail(f"test -e {result}")

    host_link = json.loads(
        vm.succeed(f"{IP} -j link show dev {host_interface}")
    )[0]
    sandbox_link = json.loads(vm.succeed(in_sandbox(
        driver_pid,
        namespace_fd,
        f"{IP} -j link show dev {sandbox_interface}",
    )))[0]
    assert "UP" not in host_link["flags"], host_link
    assert "UP" not in sandbox_link["flags"], sandbox_link

    host_addresses = json.loads(
        vm.succeed(f"{IP} -j -6 address show dev {host_interface}")
    )[0]["addr_info"]
    sandbox_addresses = json.loads(vm.succeed(in_sandbox(
        driver_pid,
        namespace_fd,
        f"{IP} -j -6 address show dev {sandbox_interface}",
    )))[0]["addr_info"]
    assert any(
        address["local"] == host_address
        and address["prefixlen"] == int(prefix_length)
        and address.get("nodad") is True
        and not address.get("tentative", False)
        and not address.get("dadfailed", False)
        for address in host_addresses
    ), host_addresses
    assert any(
        address["local"] == sandbox_address
        and address["prefixlen"] == int(prefix_length)
        and address.get("nodad") is True
        and not address.get("tentative", False)
        and not address.get("dadfailed", False)
        for address in sandbox_addresses
    ), sandbox_addresses

    host_neighbors = json.loads(
        vm.succeed(f"{IP} -j -6 neighbor show dev {host_interface}")
    )
    sandbox_neighbors = json.loads(vm.succeed(in_sandbox(
        driver_pid,
        namespace_fd,
        f"{IP} -j -6 neighbor show dev {sandbox_interface}",
    )))
    assert any(
        neighbor["dst"] == sandbox_address
        and neighbor["lladdr"] == sandbox_link["address"]
        and neighbor["state"] == ["PERMANENT"]
        for neighbor in host_neighbors
    ), host_neighbors
    assert any(
        neighbor["dst"] == host_address
        and neighbor["lladdr"] == host_link["address"]
        and neighbor["state"] == ["PERMANENT"]
        for neighbor in sandbox_neighbors
    ), sandbox_neighbors

    gate_status = json.loads(vm.succeed(
        f"{GATE_FIXTURE} status-observer {network_handle}"
    ))
    assert gate_status["assignment_epoch"] == int(assignment_epoch), gate_status
    assert gate_status["allocation_generation"] == int(allocation_generation), gate_status
    assert gate_status["assignment_digest"] == assignment_digest, gate_status
    assert gate_status["ingress"]["armed"] == 0, gate_status
    assert gate_status["egress"]["armed"] == 0, gate_status
    vm.succeed(in_sandbox(
        driver_pid,
        namespace_fd,
        f"{NFT} --json list table inet aos_sandbox",
    ))

    # WORKER_OK proves only authenticated preparation and worker quiescence.
    # Independently exercise the realized namespace and fail-closed gate.
    vm.succeed(f"{IP} link set dev {host_interface} up")
    vm.succeed(in_sandbox(
        driver_pid,
        namespace_fd,
        f"{IP} link set dev {sandbox_interface} up",
    ))
    probe("ingress", False)
    probe("egress", False)

    clocks = json.loads(vm.succeed(f"{GATE_FIXTURE} clocks"))
    deadline = clocks["boottime_nanoseconds"] + 60_000_000_000
    vm.succeed(
        f"{GATE_FIXTURE} update-observer {network_handle} arm "
        f"{assignment_epoch} 1 {deadline} {LEASE}"
    )
    probe("ingress", True)
    probe("egress", True)

    vm.succeed(f"{GATE_FIXTURE} update-observer {network_handle} disarm")
    probe("ingress", False)
    probe("egress", False)
