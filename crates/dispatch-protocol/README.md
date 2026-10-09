# Dispatch protocol

This crate provides portable solve-request documents, strict exact JSON decoding,
deterministic model/request commitments, and bounded framed Protobuf transport.
It depends on the generic assignment model and has no dependency on a particular
solver, platform deployment, or application controller.

`request::SolveRequest` carries an immutable problem, logical backend name,
original search options, and an optional independent hint. Quantities use
canonical decimal strings; reduced rational values preserve exact numerators and
denominators. Unknown semantic fields and duplicate JSON keys are rejected.
Executable selection and execution entitlements remain trusted caller configuration.

The worker channel uses versioned, generation-bound envelopes over private pipes
or streams. Its public-schema definitions do not imply that a remote daemon is
available. Canonical commitments operate on validated semantic data rather than
JSON member order or Protobuf serialization order.

The [published protocol artifacts](https://github.com/andyl-technologies/aos/tree/master/protocol/dispatch)
include schemas, field mappings, and cross-language vectors. The
[user guide](https://github.com/andyl-technologies/aos/blob/master/docs/users/dispatch.md)
explains CLI import/export and the execution boundary.
