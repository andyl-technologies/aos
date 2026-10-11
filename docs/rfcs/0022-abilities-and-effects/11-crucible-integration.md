# Execution observation and Crucible

Execution observation is an optional runtime boundary. Package configuration
selects an observer through the ordinary module system; production execution
without an observer does not need a Crucible closure.

The controller exposes durable intent, attempted dispatch, result, and recovery
boundaries to the configured observer. Selection is tied to exact effect and
transaction identities. Observer failure stops progress when observation is
configured as required. Absence of a returned result never implies a successful
external action.

`DispatchStarted` occurs immediately before adapter invocation. It is useful
for selecting an interruption window, but is not proof that the process started
or that its mutation occurred. Tests must combine boundary evidence with durable
journal state and independent domain observations. Observe/retry semantics
remain those of the production runtime and handler.

A controlled interruption may stop the controller, handler, or guest at an
identified boundary. Recovery then uses the same production journal and handler
observation path. Test code must not rewrite completion records or replace an
indeterminate result with a synthetic success.

Crucible's licensing and process boundaries remain independent constraints:
the Apache host and QEMU-side implementation remain separate processes, with
versioned control and shared-memory protocols. This RFC does not move runtime
interpretation or guest assertions into the QEMU implementation. See the
[Crucible process-boundary policy](../0010-crucible/37-licensing-process-boundary.md).

The [execution contract](execution-contract.md) defines the handler boundary;
[qualification](10-testing-and-qualification.md) defines what its observations
can support.
