# Problem and goals

Packages need to describe host changes without assuming that the build machine
is the installed host, or that every installation uses the same OS backend.
The package build, installation configuration, and host mutations have different
inputs and lifetimes. Treating them as one execution pass obscures those boundaries.

AOS retains package module sources with built artifacts. Installation evaluates
those sources with operator configuration in an ordinary Nix module fixed point.
Ability operations produce a typed graph of deferred effects. A durable runtime
executes the selected handlers after evaluation succeeds.

The goals are:

- Use ordinary option declarations, imports, merging, priorities, and conditional
  definitions throughout package and installation configuration.
- Let packages expose domain contracts and compatible implementations without
  introducing OS-specific interfaces into the generic module library.
- Compose handlers through typed child operations and results.
- Retain exact sources and artifacts for reconfiguration, recovery, and rollback.
- Generate package and execution documentation from the evaluated declarations.
- Keep installation scopes independent: a package profile, container, initrd, or
  host selects the modules and payloads it actually needs.

The [target state](13-target-state.md) defines the interfaces. The
[author guide](../../users/aos/runtime-abilities.md) contains executable shapes
and the build-to-runtime flow. This RFC does not itself port a kernel, toolchain,
or process transport, and an available interface is not a qualification claim.
