# QEMU thorough test coverage

`qemu-thorough-test-inventory.txt` is the reviewed, sorted inventory of names
returned by the current patched QEMU Meson configuration with the `thorough`
setup. It is independent of each subsequent configure run. A missing test,
duplicate name, added test, or equal-count substitution fails the gate.

The initial inventory was retained by this source-built AOS release command:

```text
bash ./aos-dev --release build check crucible.phase7.qemuConfiguredTestInventory --no-out-link
```

The discovery artifact is
`/nix/store/30cy6hcj40izqhw9iv5imzi7y7kmqj3b-crucible-qemu-configured-test-inventory-11.1.1`.
Its actual `thorough.inventory` and `intro-tests.json` both contain 1,560
invocations, including the current HPET, xHCI, and RC4030 unit targets. The
configured source is atomic commit `5baeed9522afc63e4d9a753291f3af40f7b9d791`;
the retained build identity is
`dde2026e84dabfe213e6bfa35eb3094bf75d1929ebef5834d20b2aa767b0a1e4`.
The inherited count of 1,552 had no corresponding current inventory and
rejected this real configuration before execution.

The configured check reuses the full-suite artifact's unpack and configure
phases, dependencies, flags, Python environment, and build identity. It runs
the inventory validator's regression cases and joins both Meson's selected
names and public introspection to the checked inventory. It executes no
emulator or upstream test and therefore requires no KVM feature. Its result
explicitly states `test_execution=none`.

The full-suite check retains its native Linux KVM requirement and executes
all configured tests in the existing generic, unpatched outer VM. It checks
the named selection again inside that VM, retains Meson's per-invocation
JSON results, and requires exactly one completed successful or skipped
result for every reviewed name. A skip remains subject to the separate
existing count of 459 and exact skip inventory hash. Configuration discovery
does not authorize skips or qualify the full run.

When the configured source or dependencies change, inspect the exact named
inventory diff before updating this file. Regenerate it only from an actual
matching AOS configuration, retain that artifact and build identity, and
review the added or removed coverage. The gate never derives its expected
inventory from the configure run it is validating.
